"""Turn AWS credentials into an AWS Management Console sign-in URL.

Flow (AWS "custom identity broker" federation):

1. Resolve credentials: explicit keys, a named profile, or the default boto3 chain.
2. Make them temporary:
   - ``role_arn`` given        -> ``sts:AssumeRole``
   - already temporary          -> used as-is (role, SSO, instance profile, ...)
   - long-term IAM user keys    -> ``sts:GetFederationToken``
3. Exchange them at ``https://signin.aws.amazon.com/federation?Action=getSigninToken``.
4. Build ``...federation?Action=login&Destination=...&SigninToken=...``.
"""
from __future__ import annotations

import datetime as _dt
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Sequence

import boto3

USER_AGENT = "aws-signin-url"
DEFAULT_ROLE_SESSION_NAME = "aws-signin-url"
SIGNIN_TOKEN_LIFETIME = _dt.timedelta(minutes=15)

# Session policy passed to GetFederationToken when none is given. The federated
# session's permissions are the INTERSECTION of this and the IAM user's own
# policies, so this means "everything the user can already do", never more.
ALLOW_ALL_POLICY: Dict[str, Any] = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}

# partition -> (federation endpoint, console base URL)
PARTITIONS: Dict[str, tuple] = {
    "aws": ("https://signin.aws.amazon.com/federation", "https://console.aws.amazon.com/"),
    "aws-us-gov": ("https://signin.amazonaws-us-gov.com/federation", "https://console.amazonaws-us-gov.com/"),
    "aws-cn": ("https://signin.amazonaws.cn/federation", "https://console.amazonaws.cn/"),
}


class SigninError(Exception):
    """Any failure turning credentials into a sign-in URL. The message is user-facing."""


@dataclass(frozen=True)
class TempCredentials:
    access_key_id: str
    secret_access_key: str
    session_token: str
    expiration: Optional[_dt.datetime] = None


@dataclass
class SigninResult:
    url: str
    credential_source: str  # "assume-role" | "temporary" | "federation-token"
    partition: str
    destination: str
    signin_token_expires: _dt.datetime
    credentials_expire: Optional[_dt.datetime] = None
    identity_arn: Optional[str] = None
    profile: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        def iso(v):
            return v.isoformat() if isinstance(v, _dt.datetime) else v

        return {
            "profile": self.profile,
            "url": self.url,
            "credential_source": self.credential_source,
            "identity_arn": self.identity_arn,
            "partition": self.partition,
            "destination": self.destination,
            "signin_token_expires": iso(self.signin_token_expires),
            "credentials_expire": iso(self.credentials_expire),
        }


# --------------------------------------------------------------------------- helpers

def partition_for_region(region: Optional[str]) -> str:
    if region and region.startswith("us-gov-"):
        return "aws-us-gov"
    if region and region.startswith("cn-"):
        return "aws-cn"
    return "aws"


def default_region_for(partition: str) -> str:
    return {"aws": "us-east-1", "aws-us-gov": "us-gov-west-1", "aws-cn": "cn-north-1"}[partition]


def build_destination(partition: str, *, service: Optional[str] = None,
                      region: Optional[str] = None, destination: Optional[str] = None) -> str:
    """Console page to land on. ``destination`` (a full URL) wins over ``service``."""
    if destination:
        if not destination.startswith("https://"):
            raise SigninError(f"--destination must be an https:// URL, got {destination!r}")
        return destination
    console = PARTITIONS[partition][1]
    path = f"{service.strip('/')}/home" if service else "console/home"
    url = console + path
    if region:
        url += "?" + urllib.parse.urlencode({"region": region})
    return url


_FED_NAME_BAD = re.compile(r"[^\w+=,.@-]")


def federation_name_from_arn(arn: str) -> str:
    """GetFederationToken Name: 2-32 chars of [\\w+=,.@-]. Derived from the caller ARN."""
    if arn.endswith(":root"):
        name = "root"
    else:
        name = arn.rsplit("/", 1)[-1]
    name = _FED_NAME_BAD.sub("-", name)[:32]
    return name if len(name) >= 2 else DEFAULT_ROLE_SESSION_NAME


def load_policy(policy: Any) -> Optional[str]:
    """Accept a dict, a JSON string, or a path to a JSON file. Returns compact JSON."""
    if policy is None:
        return None
    if isinstance(policy, dict):
        doc = policy
    else:
        text = str(policy).strip()
        if not text.startswith("{"):
            try:
                with open(text, encoding="utf-8") as fh:
                    text = fh.read()
            except OSError as e:
                raise SigninError(f"cannot read policy file {policy!r}: {e}") from e
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as e:
            raise SigninError(f"policy is not valid JSON: {e}") from e
    return json.dumps(doc, separators=(",", ":"))


def _client_error_message(e: Exception) -> str:
    resp = getattr(e, "response", None) or {}
    err = resp.get("Error", {})
    if err:
        return f"{err.get('Code', 'Error')}: {err.get('Message', '')}".strip()
    return str(e)


def _temp_from_sts(c: Dict[str, Any]) -> TempCredentials:
    return TempCredentials(c["AccessKeyId"], c["SecretAccessKey"], c["SessionToken"], c.get("Expiration"))


# --------------------------------------------------------------------------- session / credentials

def make_session(*, profile: Optional[str] = None, access_key: Optional[str] = None,
                 secret_key: Optional[str] = None, session_token: Optional[str] = None,
                 region: Optional[str] = None) -> boto3.Session:
    if (access_key is None) != (secret_key is None):
        raise SigninError("access key and secret key must be given together")
    if access_key and profile:
        raise SigninError("pass either explicit keys or a profile, not both")
    try:
        return boto3.Session(
            profile_name=profile,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token,
            region_name=region,
        )
    except Exception as e:  # botocore.exceptions.ProfileNotFound and friends
        raise SigninError(str(e)) from e


def get_console_credentials(
    session: boto3.Session,
    *,
    region: Optional[str] = None,
    role_arn: Optional[str] = None,
    role_session_name: Optional[str] = None,
    external_id: Optional[str] = None,
    mfa_serial: Optional[str] = None,
    mfa_token: Optional[str] = None,
    duration: Optional[int] = None,
    federation_name: Optional[str] = None,
    policy: Any = None,
    policy_arns: Sequence[str] = (),
) -> tuple:
    """Return ``(TempCredentials, source, session_duration_for_signin)``."""
    try:
        creds = session.get_credentials()
    except Exception as e:
        raise SigninError(f"could not load credentials: {e}") from e
    if creds is None:
        raise SigninError("no AWS credentials found (pass keys, --profile, or set AWS_* env vars)")
    frozen = creds.get_frozen_credentials()

    partition = partition_for_region(region or session.region_name)
    sts = session.client("sts", region_name=region or session.region_name or default_region_for(partition))

    try:
        if role_arn:
            params: Dict[str, Any] = {
                "RoleArn": role_arn,
                "RoleSessionName": role_session_name or DEFAULT_ROLE_SESSION_NAME,
            }
            if duration:
                params["DurationSeconds"] = duration
            if external_id:
                params["ExternalId"] = external_id
            if mfa_serial:
                if not mfa_token:
                    raise SigninError("--mfa-serial needs an MFA code (--mfa-token)")
                params["SerialNumber"] = mfa_serial
                params["TokenCode"] = mfa_token
            if policy is not None:
                params["Policy"] = load_policy(policy)
            if policy_arns:
                params["PolicyArns"] = [{"arn": a} for a in policy_arns]
            resp = sts.assume_role(**params)
            return _temp_from_sts(resp["Credentials"]), "assume-role", duration

        if frozen.token:
            # Role / SSO / instance-profile / already-federated credentials.
            exp = getattr(creds, "_expiry_time", None)
            return (TempCredentials(frozen.access_key, frozen.secret_key, frozen.token, exp),
                    "temporary", duration)

        # Long-term IAM user (or root) keys -> GetFederationToken.
        name = federation_name
        if not name:
            name = federation_name_from_arn(sts.get_caller_identity()["Arn"])
        params = {"Name": name}
        inline = load_policy(policy)
        if inline is None and not policy_arns:
            inline = json.dumps(ALLOW_ALL_POLICY, separators=(",", ":"))
        if inline is not None:
            params["Policy"] = inline
        if policy_arns:
            params["PolicyArns"] = [{"arn": a} for a in policy_arns]
        if duration:
            params["DurationSeconds"] = duration
        resp = sts.get_federation_token(**params)
        # The console session of a federation token lasts as long as the token itself,
        # so SessionDuration is not sent to the sign-in endpoint on this path.
        return _temp_from_sts(resp["Credentials"]), "federation-token", None
    except SigninError:
        raise
    except Exception as e:
        raise SigninError(_client_error_message(e)) from e


def whoami(creds: TempCredentials, region: Optional[str] = None) -> Optional[str]:
    """Caller ARN for the temporary credentials (best effort)."""
    try:
        sts = boto3.client(
            "sts",
            aws_access_key_id=creds.access_key_id,
            aws_secret_access_key=creds.secret_access_key,
            aws_session_token=creds.session_token,
            region_name=region or "us-east-1",
        )
        return sts.get_caller_identity()["Arn"]
    except Exception:
        return None


# --------------------------------------------------------------------------- federation endpoint

Opener = Callable[..., Any]


def get_signin_token(creds: TempCredentials, *, partition: str = "aws",
                     session_duration: Optional[int] = None, timeout: float = 30,
                     opener: Opener = urllib.request.urlopen) -> str:
    endpoint = PARTITIONS[partition][0]
    session_json = json.dumps({
        "sessionId": creds.access_key_id,
        "sessionKey": creds.secret_access_key,
        "sessionToken": creds.session_token,
    })
    params = {"Action": "getSigninToken", "Session": session_json}
    if session_duration:
        params["SessionDuration"] = str(int(session_duration))
    req = urllib.request.Request(
        f"{endpoint}?{urllib.parse.urlencode(params)}",
        headers={"User-Agent": USER_AGENT},
    )
    try:
        with opener(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace").strip()[:300]
        hint = ""
        if e.code == 400 and session_duration:
            hint = " (SessionDuration may exceed what these credentials allow; role-chained sessions max out at 3600)"
        raise SigninError(f"federation endpoint returned HTTP {e.code}{hint}: {detail}") from e
    except urllib.error.URLError as e:
        raise SigninError(f"could not reach {endpoint}: {e.reason}") from e
    try:
        return json.loads(body)["SigninToken"]
    except (ValueError, KeyError) as e:
        raise SigninError(f"unexpected response from federation endpoint: {body[:200]!r}") from e


def build_login_url(signin_token: str, *, partition: str = "aws", destination: str,
                    issuer: Optional[str] = None) -> str:
    params = {"Action": "login"}
    if issuer:
        params["Issuer"] = issuer
    params["Destination"] = destination
    params["SigninToken"] = signin_token
    return f"{PARTITIONS[partition][0]}?{urllib.parse.urlencode(params)}"


# --------------------------------------------------------------------------- one-call API

def generate_login_url(
    *,
    profile: Optional[str] = None,
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
    session_token: Optional[str] = None,
    region: Optional[str] = None,
    role_arn: Optional[str] = None,
    role_session_name: Optional[str] = None,
    external_id: Optional[str] = None,
    mfa_serial: Optional[str] = None,
    mfa_token: Optional[str] = None,
    duration: Optional[int] = None,
    federation_name: Optional[str] = None,
    policy: Any = None,
    policy_arns: Sequence[str] = (),
    service: Optional[str] = None,
    destination: Optional[str] = None,
    issuer: Optional[str] = None,
    resolve_identity: bool = False,
    session: Optional[boto3.Session] = None,
    opener: Opener = urllib.request.urlopen,
) -> SigninResult:
    """Return a console sign-in URL for the given credentials.

    With no arguments it uses the default boto3 credential chain.
    """
    if duration is not None and not 900 <= int(duration) <= 129600:
        raise SigninError("duration must be between 900 and 129600 seconds")
    if session is None:
        session = make_session(profile=profile, access_key=access_key, secret_key=secret_key,
                               session_token=session_token, region=region)
    eff_region = region or session.region_name
    partition = partition_for_region(eff_region)

    creds, source, session_duration = get_console_credentials(
        session, region=region, role_arn=role_arn, role_session_name=role_session_name,
        external_id=external_id, mfa_serial=mfa_serial, mfa_token=mfa_token, duration=duration,
        federation_name=federation_name, policy=policy, policy_arns=policy_arns,
    )
    if session_duration is not None and session_duration > 43200:
        session_duration = 43200  # console sessions from role credentials cap at 12 h

    dest = build_destination(partition, service=service, region=region, destination=destination)
    token = get_signin_token(creds, partition=partition, session_duration=session_duration, opener=opener)
    now = _dt.datetime.now(_dt.timezone.utc)
    return SigninResult(
        url=build_login_url(token, partition=partition, destination=dest, issuer=issuer),
        credential_source=source,
        partition=partition,
        destination=dest,
        signin_token_expires=now + SIGNIN_TOKEN_LIFETIME,
        credentials_expire=creds.expiration,
        identity_arn=whoami(creds, eff_region or default_region_for(partition)) if resolve_identity else None,
        profile=profile,
    )
