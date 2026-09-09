"""Command line entry point for Dr.COM/ePortal authentication."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys

from .client import (
    AuthenticationError,
    ClientInfo,
    LoginOptions,
    NetworkAuthenticator,
    PortalConfig,
    client_info_from_portal_url,
    failure_message,
    host_from_portal_url,
    is_online,
    normalize_mac,
    operation_succeeded,
)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    host = args.host or host_from_portal_url(args.portal_url)
    if not host:
        parser.error("missing authentication host, pass --host or set DRCOM_HOST")

    client = NetworkAuthenticator(PortalConfig(host=host, timeout=args.timeout))

    try:
        client_info = build_client_info(args, client)
        if args.command == "status":
            response = client.status()
        elif args.command == "logout":
            response = client.logout(client_info)
        else:
            response = client.login(build_login_options(args), client_info)
    except AuthenticationError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 2

    return print_response(args.command, response, args.json, client)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Login to a Dr.COM/ePortal campus network.")
    parser.add_argument("command", choices=("login", "logout", "status"), help="要执行的操作")
    parser.add_argument("-H", "--host", default=env("DRCOM_HOST", "NETWORK_AUTH_HOST"), help="认证服务器地址")
    parser.add_argument("--portal-url", default=env("DRCOM_PORTAL_URL", "NETWORK_AUTH_PORTAL_URL"), help="可选原始入口 URL，用作自动探测失败时的兼容兜底")
    parser.add_argument("--timeout", type=float, default=float(env("DRCOM_TIMEOUT", "NETWORK_AUTH_TIMEOUT", default="8")), help="请求超时秒数")
    parser.add_argument("--json", action="store_true", default=env_flag("DRCOM_JSON", "NETWORK_AUTH_JSON"), help="输出完整 JSON 响应")
    parser.add_argument("--ip", default=env("DRCOM_IP", "NETWORK_AUTH_IP"), help="手动覆盖自动探测到的终端 IPv4")
    parser.add_argument("--ipv6", default=env("DRCOM_IPV6", "NETWORK_AUTH_IPV6"), help="手动指定终端 IPv6")
    parser.add_argument("--mac", default=env("DRCOM_MAC", "NETWORK_AUTH_MAC"), help="手动指定终端 MAC，可带冒号或横线")
    parser.add_argument("--vlan", default=env("DRCOM_VLAN", "NETWORK_AUTH_VLAN"), help="手动指定 VLAN ID")
    parser.add_argument("--ac-ip", default=env("DRCOM_AC_IP", "NETWORK_AUTH_AC_IP"), help="手动指定接入控制器 IP")
    parser.add_argument("--ac-name", default=env("DRCOM_AC_NAME", "NETWORK_AUTH_AC_NAME"), help="手动指定接入控制器名称")
    parser.add_argument("-u", "--username", default=env("DRCOM_USERNAME", "NETWORK_AUTH_USERNAME"), help="学号/账号")
    parser.add_argument("-p", "--password", default=env("DRCOM_PASSWORD", "NETWORK_AUTH_PASSWORD"), help="密码")
    parser.add_argument("--suffix", default=env("DRCOM_SUFFIX", "NETWORK_AUTH_SUFFIX", default=""), help="账号后缀，例如 @xyw / @dx / @lt")
    parser.add_argument("--prefix", default=env("DRCOM_PREFIX", "NETWORK_AUTH_PREFIX", default=",0,"), help="账号前缀；PC 网页端默认 ,0,")
    parser.add_argument("--raw-account", action="store_true", default=env_flag("DRCOM_RAW_ACCOUNT", "NETWORK_AUTH_RAW_ACCOUNT"), help="直接发送账号，不自动添加前缀/后缀/大写转换")
    parser.add_argument("--preserve-case", action="store_true", default=env_flag("DRCOM_PRESERVE_CASE", "NETWORK_AUTH_PRESERVE_CASE"), help="保留账号大小写；默认模拟网页转大写")
    parser.add_argument("--force", action="store_true", help="即使当前 IP 已在线也重新发送登录请求")
    return parser


def build_login_options(args: argparse.Namespace) -> LoginOptions:
    if not args.username:
        raise AuthenticationError("未提供账号；请使用 -u 或 DRCOM_USERNAME")
    return LoginOptions(
        username=args.username,
        password=password_for(args),
        suffix=args.suffix,
        prefix=args.prefix,
        raw_account=args.raw_account,
        preserve_case=args.preserve_case,
        force=args.force,
    )


def build_client_info(args: argparse.Namespace, client: NetworkAuthenticator) -> ClientInfo | None:
    if not any((args.portal_url, args.ip, args.ipv6, args.mac, args.vlan, args.ac_ip, args.ac_name)):
        return None

    current = client_info_from_portal_url(args.portal_url) if args.portal_url else client.client_info()
    return ClientInfo(
        ip=args.ip or current.ip,
        ipv6=args.ipv6 if args.ipv6 is not None else current.ipv6,
        mac=normalize_mac(args.mac) if args.mac else current.mac,
        vlan=args.vlan or current.vlan,
        ac_ip=args.ac_ip or current.ac_ip,
        ac_name=args.ac_name or current.ac_name,
    )


def password_for(args: argparse.Namespace) -> str:
    if args.password:
        return args.password
    if not sys.stdin.isatty():
        raise AuthenticationError("未提供密码；请使用 -p 或 DRCOM_PASSWORD")
    return getpass.getpass("Password: ")


def print_response(command: str, response: dict, raw_json: bool, client: NetworkAuthenticator) -> int:
    if raw_json:
        print(json.dumps(response, ensure_ascii=False, indent=2))
        return 0 if command == "status" or operation_succeeded(response) else 1

    if command == "status":
        if is_online(response):
            print(f"在线：{response.get('uid')}  IP={response.get('v4ip') or response.get('v46ip') or response.get('ss5')}")
        else:
            print("未在线")
        return 0

    if operation_succeeded(response):
        if response.get("already_online"):
            print(f"已在线：{response.get('uid')}，未重复登录")
        else:
            print(f"{operation_label(command)}成功")
        return 0

    print(f"{operation_label(command)}失败：{failure_message(response)}", file=sys.stderr)
    print_error_detail(client)
    return 1


def print_error_detail(client: NetworkAuthenticator) -> None:
    try:
        info = client.client_info()
        detail = client.error_detail(info.ip, info.mac)
    except AuthenticationError:
        return
    if detail.get("errcode"):
        print(f"Portal 详情：{detail['errcode']}", file=sys.stderr)


def operation_label(command: str) -> str:
    return {"login": "登录", "logout": "注销"}.get(command, command)


def env(*names: str, default: str | None = None) -> str | None:
    for name in names:
        value = os.getenv(name)
        if value is not None:
            return value
    return default


def env_flag(*names: str) -> bool:
    return str(env(*names, default="")).strip().lower() in {"1", "true", "yes", "on"}
