"""aws-signin-url command line."""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import webbrowser
from typing import List, Optional

import boto3

from . import __version__
from .core import SigninError, generate_login_url

SOURCE_LABEL = {
    "federation-token": "IAM user keys -> sts:GetFederationToken",
    "assume-role": "sts:AssumeRole",
    "temporary": "temporary credentials used as-is",
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aws-signin-url",
        description="Print an AWS Management Console sign-in URL for IAM user keys, roles, or named profiles.",
        epilog=(
            "examples:\n"
            "  aws-signin-url                          # default credential chain\n"
            "  aws-signin-url -p dev -p prod           # one URL per profile\n"
            "  aws-signin-url --access-key AKIA...     # prompts for the secret key\n"
            "  aws-signin-url -p dev --role-arn arn:aws:iam::123456789012:role/Admin\n"
            "  aws-signin-url -p dev --service s3 --region eu-west-1 --open\n"
            "\nThe printed URL is a bearer credential: anyone who opens it gets the session."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    src = p.add_argument_group("credentials (default: boto3 credential chain)")
    src.add_argument("-p", "--profile", action="append", default=[], metavar="NAME",
                     help="named profile from ~/.aws/config; repeat for several URLs")
    src.add_argument("--all-profiles", action="store_true", help="one URL for every configured profile")
    src.add_argument("--list-profiles", action="store_true", help="list configured profiles and exit")
    src.add_argument("--access-key", metavar="AKID", help="access key ID (IAM user AKIA... or temporary ASIA...)")
    src.add_argument("--secret-key", metavar="SECRET",
                     help="secret access key; omit to be prompted (keeps it out of shell history)")
    src.add_argument("--session-token", metavar="TOKEN", help="session token for temporary keys")

    role = p.add_argument_group("assume a role first")
    role.add_argument("--role-arn", metavar="ARN", help="role to assume with the resolved credentials")
    role.add_argument("--role-session-name", metavar="NAME", help="default: aws-signin-url")
    role.add_argument("--external-id", metavar="ID")
    role.add_argument("--mfa-serial", metavar="ARN", help="MFA device ARN; prompts for the code if --mfa-token is omitted")
    role.add_argument("--mfa-token", metavar="CODE")

    sess = p.add_argument_group("session")
    sess.add_argument("-d", "--duration", type=int, metavar="SECONDS",
                      help="session length, 900-129600 (federation token) or up to 43200 (role console session)")
    sess.add_argument("--name", dest="federation_name", metavar="NAME",
                      help="federated user name for IAM user keys (default: the IAM user name)")
    sess.add_argument("--policy", metavar="JSON|FILE",
                      help="session policy to scope the session down (default for IAM users: Allow *:*, "
                           "which is intersected with the user's own permissions)")
    sess.add_argument("--policy-arn", action="append", default=[], metavar="ARN",
                      help="managed session policy ARN; repeatable")

    dest = p.add_argument_group("destination")
    dest.add_argument("-r", "--region", help="console region; us-gov-* and cn-* switch partition")
    dest.add_argument("-s", "--service", help="console service to open, e.g. s3, ec2, iam, cloudtrail")
    dest.add_argument("--destination", metavar="URL", help="full console URL to land on (overrides --service)")
    dest.add_argument("--issuer", metavar="URL", help="URL the console sends users to when the session ends")

    out = p.add_argument_group("output")
    out.add_argument("-o", "--open", action="store_true", help="open the URL in the default browser")
    out.add_argument("--json", action="store_true", help="print JSON (includes identity ARN and expiry)")
    out.add_argument("-q", "--quiet", action="store_true", help="print only the URL")
    return p


def _profiles(args) -> List[Optional[str]]:
    if args.all_profiles:
        return list(boto3.Session().available_profiles)
    return args.profile or [None]


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_profiles:
        for name in boto3.Session().available_profiles:
            print(name)
        return 0

    explicit_keys = bool(args.access_key or args.secret_key)
    if explicit_keys and (args.profile or args.all_profiles):
        print("aws-signin-url: error: use explicit keys or profiles, not both", file=sys.stderr)
        return 2
    if args.secret_key and not args.access_key:
        print("aws-signin-url: error: --secret-key needs --access-key", file=sys.stderr)
        return 2
    if args.access_key and not args.secret_key:
        args.secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY") or getpass.getpass("Secret access key: ")

    profiles = _profiles(args)
    if not profiles:
        print("aws-signin-url: error: no profiles configured", file=sys.stderr)
        return 1
    multi = len(profiles) > 1

    if args.mfa_serial and not args.mfa_token:
        if not sys.stdin.isatty():
            print("aws-signin-url: error: --mfa-serial needs --mfa-token when not interactive", file=sys.stderr)
            return 2
        args.mfa_token = input("MFA code: ").strip()

    results, failures = [], 0
    for prof in profiles:
        try:
            r = generate_login_url(
                profile=prof,
                access_key=args.access_key, secret_key=args.secret_key, session_token=args.session_token,
                region=args.region,
                role_arn=args.role_arn, role_session_name=args.role_session_name,
                external_id=args.external_id, mfa_serial=args.mfa_serial, mfa_token=args.mfa_token,
                duration=args.duration, federation_name=args.federation_name,
                policy=args.policy, policy_arns=args.policy_arn,
                service=args.service, destination=args.destination, issuer=args.issuer,
                resolve_identity=args.json,
            )
        except SigninError as e:
            failures += 1
            label = f"[{prof}] " if prof else ""
            print(f"aws-signin-url: {label}{e}", file=sys.stderr)
            continue

        results.append(r)
        if args.json:
            continue
        if not args.quiet:
            label = f"[{prof}] " if prof else ""
            print(f"{label}{SOURCE_LABEL[r.credential_source]}; link valid for 15 min", file=sys.stderr)
        print(f"{prof}\t{r.url}" if multi else r.url, flush=True)
        if args.open:
            webbrowser.open(r.url)

    if args.json:
        payload = [r.to_dict() for r in results]
        print(json.dumps(payload if multi else (payload[0] if payload else None), indent=2))
        if args.open:
            for r in results:
                webbrowser.open(r.url)

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
