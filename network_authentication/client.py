"""Dr.COM/ePortal authentication client."""

from __future__ import annotations

import json
import random
import re
import socket
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import OpenerDirector, Request, build_opener


DEFAULT_TIMEOUT = 8.0
DEFAULT_JS_VERSION = "3.3.2"
ZERO_MACS = {"", "000000000000", "111111111111"}
UNKNOWN_CLIENT_IP = "unknown-client-ip"
ZERO_CLIENT_MAC = "000000000000"

IP_QUERY_KEYS = ("ip", "wlanuserip", "userip", "user-ip", "UserIP", "uip", "station_ip")
MAC_QUERY_KEYS = ("mac", "usermac", "wlanusermac", "umac", "client_mac", "station_mac")
VLAN_QUERY_KEYS = ("vlan", "vlanid")
AC_IP_QUERY_KEYS = ("wlanacip", "acip", "switchip", "nasip", "nas-ip")
AC_NAME_QUERY_KEYS = ("wlanacname", "sysname", "nasname", "nas-name")

PORTAL_RET_CODES = {
    1: "账号或密码不正确",
    2: "终端 IP 已经在线",
    3: "系统繁忙",
    4: "未知错误",
    5: "REQ_CHALLENGE 失败",
    6: "REQ_CHALLENGE 超时",
    7: "Radius 认证失败",
    8: "Radius 认证超时",
    9: "Radius 下线失败",
    10: "Radius 下线超时",
    11: "其他错误",
    998: "Portal 协议参数不全",
}


class AuthenticationError(RuntimeError):
    """Raised when the Dr.COM portal cannot complete the requested operation."""


@dataclass(frozen=True, slots=True)
class PortalConfig:
    host: str
    timeout: float = DEFAULT_TIMEOUT
    js_version: str = DEFAULT_JS_VERSION
    eportal_port: int = 801

    def __post_init__(self) -> None:
        object.__setattr__(self, "host", normalize_host(self.host))

    @property
    def base_url(self) -> str:
        return f"http://{self.host}"

    @property
    def eportal_url(self) -> str:
        return f"http://{self.host}:{self.eportal_port}/eportal/"


@dataclass(frozen=True, slots=True)
class ClientInfo:
    ip: str
    ipv6: str = ""
    mac: str = "000000000000"
    vlan: str = "1"
    ac_ip: str = ""
    ac_name: str = ""


@dataclass(frozen=True, slots=True)
class LoginOptions:
    username: str
    password: str
    suffix: str = ""
    prefix: str = ",0,"
    raw_account: bool = False
    preserve_case: bool = False
    force: bool = False


class NetworkAuthenticator:
    """HTTP client that mirrors the discovered Dr.COM browser flow."""

    def __init__(
        self,
        config: PortalConfig,
        opener: OpenerDirector | None = None,
        source_ip_detector: Callable[[str], str] | None = None,
    ) -> None:
        self.config = config
        self.opener = opener or build_opener()
        self.source_ip_detector = source_ip_detector or detect_source_ip
        self._callback_id = random.randint(1000, 9999)

    def status(self) -> dict[str, Any]:
        # The local Dr.COM endpoint rejects unrelated fields. Only send JSONP noise.
        return self._jsonp(f"{self.config.base_url}/drcom/chkstatus", {})

    def login(self, options: LoginOptions, client_info: ClientInfo | None = None) -> dict[str, Any]:
        current_status = self.status()
        info = client_info or self.client_info(current_status, require_ip=False)
        if is_online(current_status) and not options.force and same_client_ip(current_status, info):
            return {**current_status, "already_online": True}
        if info.ip == UNKNOWN_CLIENT_IP:
            info = self.client_info(current_status)

        params = {
            "login_method": "1",
            "user_account": build_account(options),
            "user_password": options.password,
            "wlan_user_ip": info.ip,
            "wlan_user_ipv6": info.ipv6,
            "wlan_user_mac": info.mac,
            "wlan_ac_ip": info.ac_ip,
            "wlan_ac_name": info.ac_name,
            "jsVersion": self.config.js_version,
        }
        return self._jsonp(f"{self.config.eportal_url}?c=Portal&a=login", params)

    def logout(self, client_info: ClientInfo | None = None) -> dict[str, Any]:
        status_data = self.status()
        info = client_info or self.client_info(status_data)
        params = {
            "login_method": "1",
            "user_account": "drcom",
            "user_password": "123",
            "ac_logout": "1",
            "register_mode": "1",
            "wlan_user_ip": info.ip,
            "wlan_user_ipv6": info.ipv6,
            "wlan_vlan_id": info.vlan,
            "wlan_user_mac": info.mac,
            "wlan_ac_ip": info.ac_ip,
            "wlan_ac_name": info.ac_name,
            "jsVersion": self.config.js_version,
        }
        return self._jsonp(f"{self.config.eportal_url}?c=Portal&a=logout", params)

    def client_info(self, status_data: dict[str, Any] | None = None, *, require_ip: bool = True) -> ClientInfo:
        data = status_data or self.status()
        status_ip = first_text(data, "v46ip", "v4ip", "ss5")
        client_ip = self.source_ip_detector(self.config.host) or status_ip
        if not client_ip and require_ip:
            raise AuthenticationError("无法自动识别终端 IPv4；请使用 --ip 或 DRCOM_IP 指定")
        return ClientInfo(
            ip=client_ip or UNKNOWN_CLIENT_IP,
            ipv6=first_text(data, "myv6ip"),
            mac=portal_mac(data),
            vlan=first_text(data, "vlanid", "vid") or "1",
            ac_ip=first_text(data, "wlan_ac_ip", "wlanacip"),
            ac_name=first_text(data, "wlan_ac_name", "wlanacname"),
        )

    def error_detail(self, ip: str, mac: str) -> dict[str, Any]:
        return self._jsonp(f"{self.config.eportal_url}?c=Portal&a=getErrCode", {"ip": ip, "mac": mac})

    def _jsonp(self, url: str, params: dict[str, Any]) -> dict[str, Any]:
        callback = self._next_callback()
        query = {key: value for key, value in params.items() if value is not None}
        query["callback"] = callback
        query["v"] = random.randint(500, 10499)
        return parse_jsonp(self._get(url, query), callback=callback)

    def _get(self, url: str, params: dict[str, Any]) -> str:
        request = Request(
            build_url(url, params),
            headers={
                "Accept": "*/*",
                "Referer": f"{self.config.base_url}/",
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) network-authentication/2.0",
            },
            method="GET",
        )
        try:
            with self.opener.open(request, timeout=self.config.timeout) as response:
                payload = response.read()
                charset = response.headers.get_content_charset()
        except HTTPError as exc:
            detail = decode_portal_text(exc.read(), exc.headers.get_content_charset())
            raise AuthenticationError(f"HTTP {exc.code}: {detail[:240]}") from exc
        except URLError as exc:
            raise AuthenticationError(f"连接认证服务器失败：{exc.reason}") from exc

        return decode_portal_text(payload, charset)

    def _next_callback(self) -> str:
        self._callback_id += 1
        return f"dr{self._callback_id}"


def build_url(url: str, params: dict[str, Any]) -> str:
    query = urlencode({key: value for key, value in params.items() if value is not None})
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}{query}" if query else url


def build_account(options: LoginOptions) -> str:
    username = options.username.strip()
    if not username:
        raise AuthenticationError("账号不能为空")
    if options.raw_account:
        return username
    normalized = username if options.preserve_case else username.upper()
    return f"{options.prefix}{normalized}{options.suffix}"


def is_online(status_data: dict[str, Any]) -> bool:
    return str(status_data.get("result")) == "1" and bool(status_data.get("uid"))


def same_client_ip(status_data: dict[str, Any], client_info: ClientInfo | None) -> bool:
    if client_info is None:
        return True
    status_ip = first_text(status_data, "v46ip", "v4ip", "ss5")
    return not status_ip or status_ip == client_info.ip


def operation_succeeded(data: dict[str, Any]) -> bool:
    result = data.get("result")
    ret_code = data.get("ret_code")
    return result in (1, "1", "ok") or ret_code in (2, "2")


def failure_message(data: dict[str, Any]) -> str:
    ret_code = data.get("ret_code")
    if ret_code is not None:
        try:
            return PORTAL_RET_CODES.get(int(ret_code), f"ret_code={ret_code}")
        except (TypeError, ValueError):
            return f"ret_code={ret_code}"
    msg = data.get("msg")
    return str(msg) if msg else json.dumps(data, ensure_ascii=False)


def parse_jsonp(payload: str, *, callback: str | None = None) -> dict[str, Any]:
    text = payload.strip()
    if text.startswith("{"):
        return json.loads(text)

    pattern = rf"{re.escape(callback)}\s*\((.*)\)\s*;?\s*$" if callback else r"^[^(]+\((.*)\)\s*;?\s*$"
    match = re.search(pattern, text, re.S)
    if not match:
        raise AuthenticationError(f"接口未返回有效 JSONP：{payload[:240]}")

    try:
        return json.loads(match.group(1))
    except json.JSONDecodeError as exc:
        raise AuthenticationError(f"JSONP 内容解析失败：{payload[:240]}") from exc


def decode_portal_text(payload: bytes, charset: str | None = None) -> str:
    encodings = [charset] if charset else []
    encodings.extend(["utf-8", "gb18030"])
    for encoding in dict.fromkeys(enc for enc in encodings if enc):
        try:
            return payload.decode(encoding)
        except UnicodeDecodeError:
            continue
    return payload.decode("utf-8", errors="replace")


def normalize_host(host: str) -> str:
    clean = host.strip()
    parsed = urlsplit(clean if "://" in clean else f"//{clean}")
    normalized = parsed.hostname or clean.strip("/")
    if not normalized:
        raise AuthenticationError("认证服务器地址不能为空")
    return normalized


def detect_source_ip(host: str, socket_factory: Callable[[int, int], Any] = socket.socket) -> str:
    """Return the IPv4 address selected for traffic to the portal host."""
    try:
        with socket_factory(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((normalize_host(host), 80))
            candidate = str(sock.getsockname()[0])
    except OSError:
        return ""

    return candidate if is_ipv4(candidate) else ""


def is_ipv4(value: str) -> bool:
    try:
        return ip_address(value).version == 4
    except ValueError:
        return False


def host_from_portal_url(portal_url: str | None) -> str | None:
    if not portal_url:
        return None
    return urlsplit(portal_url.strip()).hostname


def client_info_from_portal_url(portal_url: str) -> ClientInfo:
    params = parse_qs(urlsplit(portal_url.strip()).query, keep_blank_values=True)
    return ClientInfo(
        ip=query_value(params, IP_QUERY_KEYS) or UNKNOWN_CLIENT_IP,
        ipv6=query_value(params, ("wlanuseripv6", "useripv6", "ipv6")),
        mac=normalize_optional_mac(query_value(params, MAC_QUERY_KEYS)),
        vlan=query_value(params, VLAN_QUERY_KEYS) or "1",
        ac_ip=query_value(params, AC_IP_QUERY_KEYS),
        ac_name=query_value(params, AC_NAME_QUERY_KEYS),
    )


def normalize_mac(mac: str) -> str:
    compact = mac.replace(":", "").replace("-", "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{12}", compact):
        raise AuthenticationError("MAC 地址应为 12 位十六进制，可带冒号或横线")
    return compact


def normalize_optional_mac(mac: str) -> str:
    return normalize_mac(mac) if mac else ZERO_CLIENT_MAC


def query_value(params: dict[str, list[str]], keys: tuple[str, ...]) -> str:
    for key in keys:
        values = params.get(key)
        if values and values[0].strip():
            return values[0].strip()
    return ""


def first_text(data: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = data.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def best_mac(data: dict[str, Any]) -> str:
    for key in ("ss4", "olmac"):
        value = str(data.get(key) or "").replace(":", "").replace("-", "").lower()
        if value not in ZERO_MACS:
            return value
    return ZERO_CLIENT_MAC


def portal_mac(data: dict[str, Any]) -> str:
    value = first_text(data, "ss4", "olmac").replace(":", "").replace("-", "").lower()
    return value or ZERO_CLIENT_MAC
