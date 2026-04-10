"""Command line entry point for network authentication."""

from __future__ import annotations

import argparse
import json
import os
import sys

from .client import AuthenticationError, LoginConfig, NetworkAuthenticator, UserDevice


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.username:
        parser.error("missing username, pass --username or set NETWORK_AUTH_USERNAME")
    if not args.password:
        parser.error("missing password, pass --password or set NETWORK_AUTH_PASSWORD")
    if not args.base_url:
        parser.error("missing base URL, pass --base-url or set NETWORK_AUTH_BASE_URL")

    config = LoginConfig(
        username=args.username,
        password=args.password,
        domain=args.domain,
        base_url=args.base_url,
        ac_id=args.ac_id,
        user_ip=args.ip,
        otp=args.otp,
        double_stack=args.double_stack,
        timeout=args.timeout,
        device=UserDevice(device=args.device, platform=args.platform),
    )

    client = NetworkAuthenticator(config)
    try:
        response = client.login(host=args.host)
    except AuthenticationError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except Exception as exc:  # pragma: no cover - network failure path
        print(f"Login failed: {exc}", file=sys.stderr)
        return 1

    if args.json or not response.get("suc_msg"):
        target = sys.stdout if response.get("suc_msg") else sys.stderr
        print(json.dumps(response, ensure_ascii=False, indent=2), file=target)
        return 0 if response.get("suc_msg") else 1

    print(response["suc_msg"])
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Login to an SRun-based network portal.")
    parser.add_argument("--username", default=os.getenv("NETWORK_AUTH_USERNAME"))
    parser.add_argument("--password", default=os.getenv("NETWORK_AUTH_PASSWORD"))
    parser.add_argument("--domain", default=os.getenv("NETWORK_AUTH_DOMAIN", ""))
    parser.add_argument("--base-url", default=os.getenv("NETWORK_AUTH_BASE_URL"))
    parser.add_argument("--ac-id", default=os.getenv("NETWORK_AUTH_AC_ID", "1"))
    parser.add_argument("--ip", default=os.getenv("NETWORK_AUTH_IP"))
    parser.add_argument("--host", default=os.getenv("NETWORK_AUTH_HOST"))
    parser.add_argument("--device", default=os.getenv("NETWORK_AUTH_DEVICE", "Linux"))
    parser.add_argument("--platform", default=os.getenv("NETWORK_AUTH_PLATFORM", "Linux"))
    parser.add_argument("--timeout", type=float, default=float(os.getenv("NETWORK_AUTH_TIMEOUT", "10")))
    parser.add_argument("--json", action="store_true", default=_env_flag("NETWORK_AUTH_JSON"))
    parser.add_argument(
        "--otp",
        action=argparse.BooleanOptionalAction,
        default=_env_flag("NETWORK_AUTH_OTP"),
        help="Use OTP mode instead of MD5 mode.",
    )
    parser.add_argument(
        "--double-stack",
        action=argparse.BooleanOptionalAction,
        default=_env_flag("NETWORK_AUTH_DOUBLE_STACK"),
        help="Enable the double-stack login parameter.",
    )
    return parser


def _env_flag(name: str) -> bool:
    value = os.getenv(name)
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}
