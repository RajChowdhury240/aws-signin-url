import datetime as dt
import io
import json
import urllib.error
import urllib.parse

import boto3
import pytest
from botocore.stub import ANY, Stubber

from aws_signin_url import cli, core
from aws_signin_url.core import SigninError, generate_login_url

EXP = dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)
STS_CREDS = {"AccessKeyId": "ASIATEMPEXAMPLE0001", "SecretAccessKey": "tmpsecret",
             "SessionToken": "tmptoken", "Expiration": EXP}


@pytest.fixture(autouse=True)
def clean_env(monkeypatch, tmp_path):
    for k in list(__import__("os").environ):
        if k.startswith("AWS_"):
            monkeypatch.delenv(k, raising=False)
    cfg, cred = tmp_path / "config", tmp_path / "credentials"
    cfg.write_text(
        "[profile dev]\nregion = eu-west-1\n"
        "[profile gov]\nregion = us-gov-west-1\n"
        "[profile sso-ish]\nregion = us-east-1\n"
    )
    cred.write_text(
        "[dev]\naws_access_key_id = AKIADEVEXAMPLE00001\naws_secret_access_key = devsecret\n"
        "[gov]\naws_access_key_id = AKIAGOVEXAMPLE00001\naws_secret_access_key = govsecret\n"
        "[sso-ish]\naws_access_key_id = ASIASSOEXAMPLE00001\naws_secret_access_key = ssosecret\n"
        "aws_session_token = ssotoken\n"
    )
    monkeypatch.setenv("AWS_CONFIG_FILE", str(cfg))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(cred))


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeOpener:
    def __init__(self, token="SIGNIN-TOKEN-123"):
        self.token, self.requests = token, []

    def __call__(self, req, timeout=None):
        self.requests.append(req.full_url)
        return FakeResp(json.dumps({"SigninToken": self.token}).encode())

    @property
    def last_params(self):
        return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.requests[-1]).query))


@pytest.fixture
def sts_stub(monkeypatch):
    """Every boto3 STS client created through a Session gets the same stubbed client."""
    client = boto3.client("sts", region_name="us-east-1",
                          aws_access_key_id="x", aws_secret_access_key="y")
    stub = Stubber(client)
    monkeypatch.setattr(boto3.Session, "client", lambda self, *a, **k: client)
    with stub:
        yield stub
    stub.assert_no_pending_responses()


def _query(url):
    return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))


# ---------------------------------------------------------------- IAM user keys

def test_iam_user_keys_use_federation_token(sts_stub):
    sts_stub.add_response("get_caller_identity",
                          {"Arn": "arn:aws:iam::123456789012:user/path/alice", "Account": "123456789012", "UserId": "AIDA"})
    sts_stub.add_response("get_federation_token", {"Credentials": STS_CREDS},
                          {"Name": "alice", "Policy": json.dumps(core.ALLOW_ALL_POLICY, separators=(",", ":"))})
    op = FakeOpener()
    r = generate_login_url(access_key="AKIAEXAMPLE", secret_key="s", opener=op)

    assert r.credential_source == "federation-token"
    session = json.loads(op.last_params["Session"])
    assert session == {"sessionId": "ASIATEMPEXAMPLE0001", "sessionKey": "tmpsecret", "sessionToken": "tmptoken"}
    assert "SessionDuration" not in op.last_params  # never sent for federation tokens
    q = _query(r.url)
    assert r.url.startswith("https://signin.aws.amazon.com/federation?")
    assert q["Action"] == "login" and q["SigninToken"] == "SIGNIN-TOKEN-123"
    assert q["Destination"] == "https://console.aws.amazon.com/console/home"
    assert r.credentials_expire == EXP


def test_federation_duration_policy_and_name(sts_stub, tmp_path):
    pol = tmp_path / "p.json"
    pol.write_text('{"Version": "2012-10-17", "Statement": []}')
    sts_stub.add_response("get_federation_token", {"Credentials": STS_CREDS}, {
        "Name": "bob", "Policy": '{"Version":"2012-10-17","Statement":[]}',
        "PolicyArns": [{"arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}], "DurationSeconds": 3600})
    op = FakeOpener()
    generate_login_url(access_key="AKIA", secret_key="s", federation_name="bob", policy=str(pol),
                       policy_arns=["arn:aws:iam::aws:policy/ReadOnlyAccess"], duration=3600, opener=op)
    assert "SessionDuration" not in op.last_params


def test_policy_arns_alone_skip_allow_all(sts_stub):
    sts_stub.add_response("get_federation_token", {"Credentials": STS_CREDS},
                          {"Name": "bob", "PolicyArns": [{"arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}]})
    generate_login_url(access_key="AKIA", secret_key="s", federation_name="bob",
                       policy_arns=["arn:aws:iam::aws:policy/ReadOnlyAccess"], opener=FakeOpener())


@pytest.mark.parametrize("arn,name", [
    ("arn:aws:iam::123456789012:root", "root"),
    ("arn:aws:iam::123456789012:user/a", "aws-signin-url"),
    ("arn:aws:iam::123456789012:user/" + "x" * 40, "x" * 32),
    ("arn:aws:iam::123456789012:user/name+with=ok,chars.@-", "name+with=ok,chars.@-"),
])
def test_federation_name_from_arn(arn, name):
    assert core.federation_name_from_arn(arn) == name


# ---------------------------------------------------------------- roles / temporary

def test_temporary_keys_used_as_is(sts_stub):
    op = FakeOpener()
    r = generate_login_url(access_key="ASIAEXAMPLE", secret_key="s", session_token="t", duration=7200, opener=op)
    assert r.credential_source == "temporary"
    assert json.loads(op.last_params["Session"])["sessionId"] == "ASIAEXAMPLE"
    assert op.last_params["SessionDuration"] == "7200"


def test_assume_role_with_mfa_and_external_id(sts_stub):
    sts_stub.add_response("assume_role", {"Credentials": STS_CREDS}, {
        "RoleArn": "arn:aws:iam::123456789012:role/Admin", "RoleSessionName": "me",
        "DurationSeconds": 3600, "ExternalId": "ext", "SerialNumber": "arn:aws:iam::123456789012:mfa/me", "TokenCode": "123456"})
    op = FakeOpener()
    r = generate_login_url(access_key="AKIA", secret_key="s", role_arn="arn:aws:iam::123456789012:role/Admin",
                           role_session_name="me", external_id="ext", mfa_serial="arn:aws:iam::123456789012:mfa/me", mfa_token="123456",
                           duration=3600, opener=op)
    assert r.credential_source == "assume-role"
    assert op.last_params["SessionDuration"] == "3600"


def test_role_console_session_capped_at_12h(sts_stub):
    sts_stub.add_response("assume_role", {"Credentials": STS_CREDS}, {
        "RoleArn": "arn:aws:iam::123456789012:role/R", "RoleSessionName": "aws-signin-url", "DurationSeconds": 50000})
    op = FakeOpener()
    generate_login_url(access_key="AKIA", secret_key="s", role_arn="arn:aws:iam::123456789012:role/R", duration=50000, opener=op)
    assert op.last_params["SessionDuration"] == "43200"


def test_mfa_serial_without_code_errors(sts_stub):
    with pytest.raises(SigninError, match="MFA code"):
        generate_login_url(access_key="AKIA", secret_key="s", role_arn="arn:aws:iam::123456789012:role/R", mfa_serial="arn:aws:iam::123456789012:mfa/me",
                           opener=FakeOpener())


def test_sts_error_is_readable(sts_stub):
    sts_stub.add_client_error("assume_role", "AccessDenied", "not authorized to perform sts:AssumeRole")
    with pytest.raises(SigninError, match="AccessDenied: not authorized"):
        generate_login_url(access_key="AKIA", secret_key="s", role_arn="arn:aws:iam::123456789012:role/R", opener=FakeOpener())


# ---------------------------------------------------------------- profiles / partitions / destination

def test_profile_long_term_keys(sts_stub):
    sts_stub.add_response("get_caller_identity", {"Arn": "arn:aws:iam::1:user/dev-user"})
    sts_stub.add_response("get_federation_token", {"Credentials": STS_CREDS}, {"Name": "dev-user", "Policy": ANY})
    r = generate_login_url(profile="dev", service="s3", opener=FakeOpener())
    assert r.profile == "dev"
    assert r.destination == "https://console.aws.amazon.com/s3/home"


def test_profile_with_session_token_is_temporary(sts_stub):
    op = FakeOpener()
    r = generate_login_url(profile="sso-ish", opener=op)
    assert r.credential_source == "temporary"
    assert json.loads(op.last_params["Session"])["sessionToken"] == "ssotoken"


def test_govcloud_profile_switches_partition(sts_stub):
    sts_stub.add_response("get_federation_token", {"Credentials": STS_CREDS}, {"Name": "gov-user", "Policy": ANY})
    op = FakeOpener()
    r = generate_login_url(profile="gov", federation_name="gov-user", opener=op)
    assert r.partition == "aws-us-gov"
    assert op.requests[0].startswith("https://signin.amazonaws-us-gov.com/federation?")
    assert r.url.startswith("https://signin.amazonaws-us-gov.com/federation?")
    assert r.destination.startswith("https://console.amazonaws-us-gov.com/")


def test_unknown_profile():
    with pytest.raises(SigninError, match="nope"):
        generate_login_url(profile="nope", opener=FakeOpener())


def test_no_credentials(monkeypatch):
    monkeypatch.setenv("AWS_CONFIG_FILE", "/nonexistent")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    with pytest.raises(SigninError, match="no AWS credentials"):
        generate_login_url(opener=FakeOpener())


@pytest.mark.parametrize("kw,expected", [
    ({}, "https://console.aws.amazon.com/console/home"),
    ({"service": "ec2", "region": "eu-west-1"}, "https://console.aws.amazon.com/ec2/home?region=eu-west-1"),
    ({"destination": "https://console.aws.amazon.com/iam/home#/users"}, "https://console.aws.amazon.com/iam/home#/users"),
])
def test_build_destination(kw, expected):
    assert core.build_destination("aws", **kw) == expected


def test_destination_must_be_https():
    with pytest.raises(SigninError):
        core.build_destination("aws", destination="javascript:alert(1)")


def test_partition_for_region():
    assert core.partition_for_region("cn-north-1") == "aws-cn"
    assert core.partition_for_region("us-gov-east-1") == "aws-us-gov"
    assert core.partition_for_region(None) == "aws"


def test_issuer_in_login_url():
    url = core.build_login_url("T", destination="https://console.aws.amazon.com/", issuer="https://idp.example")
    assert _query(url)["Issuer"] == "https://idp.example"


def test_bad_inputs():
    with pytest.raises(SigninError, match="together"):
        generate_login_url(access_key="AKIA", opener=FakeOpener())
    with pytest.raises(SigninError, match="duration"):
        generate_login_url(access_key="AKIA", secret_key="s", duration=60, opener=FakeOpener())
    with pytest.raises(SigninError, match="not valid JSON"):
        core.load_policy("{nope")


def test_federation_http_error():
    def opener(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 400, "Bad", {}, io.BytesIO(b"bad session"))
    creds = core.TempCredentials("A", "B", "C")
    with pytest.raises(SigninError, match="HTTP 400.*bad session"):
        core.get_signin_token(creds, opener=opener)


# ---------------------------------------------------------------- CLI

@pytest.fixture
def cli_opener(monkeypatch):
    op = FakeOpener()
    real = core.generate_login_url
    monkeypatch.setattr(cli, "generate_login_url", lambda **kw: real(opener=op, **kw))
    return op


def test_cli_multiple_profiles(sts_stub, cli_opener, capsys):
    sts_stub.add_response("get_caller_identity", {"Arn": "arn:aws:iam::1:user/dev-user"})
    sts_stub.add_response("get_federation_token", {"Credentials": STS_CREDS}, {"Name": "dev-user", "Policy": ANY})
    assert cli.main(["-p", "dev", "-p", "sso-ish", "-q"]) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert [l.split("\t")[0] for l in lines] == ["dev", "sso-ish"]
    assert all(l.split("\t")[1].startswith("https://signin.aws.amazon.com/federation?Action=login") for l in lines)


def test_cli_single_prints_bare_url(sts_stub, cli_opener, capsys):
    assert cli.main(["-p", "sso-ish"]) == 0
    out, err = capsys.readouterr()
    assert out.startswith("https://signin.aws.amazon.com/federation?Action=login")
    assert "temporary credentials used as-is" in err


def test_cli_json(sts_stub, cli_opener, capsys, monkeypatch):
    monkeypatch.setattr(core, "whoami", lambda *a, **k: "arn:aws:sts::1:assumed-role/R/s")
    assert cli.main(["-p", "sso-ish", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["identity_arn"] == "arn:aws:sts::1:assumed-role/R/s"
    assert data["credential_source"] == "temporary"


def test_cli_prompts_for_secret(sts_stub, cli_opener, capsys, monkeypatch):
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": "prompted")
    assert cli.main(["--access-key", "ASIAX", "--session-token", "t", "-q"]) == 0
    assert json.loads(cli_opener.last_params["Session"])["sessionKey"] == "prompted"


def test_cli_partial_failure_exit_code(sts_stub, cli_opener, capsys):
    assert cli.main(["-p", "sso-ish", "-p", "missing"]) == 1
    out, err = capsys.readouterr()
    assert "sso-ish\thttps://" in out and "[missing]" in err


def test_cli_list_profiles(capsys):
    assert cli.main(["--list-profiles"]) == 0
    assert set(capsys.readouterr().out.split()) == {"dev", "gov", "sso-ish"}


def test_cli_keys_and_profile_conflict(capsys):
    assert cli.main(["-p", "dev", "--access-key", "A", "--secret-key", "B"]) == 2
