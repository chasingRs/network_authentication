"""HTTP client for SRun-based portal authentication."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import OpenerDirector, Request, build_opener

from .crypto import build_checksum, encode_user_info, password_md5

TOKEN_API = "/cgi-bin/get_challenge"
AUTH_API = "/cgi-bin/srun_portal"
_JSONP_PATTERN = re.compile(r"^[^(]+\((.*)\)\s*;?\s*$", re.DOTALL)


class AuthenticationError(RuntimeError):
    """Raised when the portal login flow cannot be completed."""


@dataclass(slots=True)
class UserDevice:
    device: str = "Linux"
    platform: str = "Linux"


@dataclass(slots=True)
class LoginConfig:
    username: str
    password: str
    domain: str = ""
    base_url: str = ""
    ac_id: str = "1"
    user_ip: str | None = None
    otp: bool = False
    double_stack: bool = False
    timeout: float = 10.0
    callback: str = "callback"
    n: int = 200
    type: int = 1
    enc_ver: str = "srun_bx1"
    device: UserDevice = field(default_factory=UserDevice)

    @property
    def full_username(self) -> str:
        return f"{self.username}{self.domain}"


class NetworkAuthenticator:
    """Authenticate against an SRun portal using the same flow as the original script."""

    def __init__(self, config: LoginConfig, opener: OpenerDirector | None = None) -> None:
        if not config.base_url:
            raise AuthenticationError("Missing portal base URL. Pass --base-url or set NETWORK_AUTH_BASE_URL.")
        self.config = config
        self.opener = opener or build_opener()
        self.user_agent = "network-authentication/1.0.0"
        parsed_base_url = urlsplit(self.config.base_url)
        self._portal_netloc = parsed_base_url.netloc or urlsplit(self._build_url("/")).netloc

    def get_challenge(self, *, host: str | None = None) -> dict[str, Any]:
        text = self._get(
            TOKEN_API,
            {
                "callback": self.config.callback,
                "username": self.config.full_username,
                "ip": self.config.user_ip,
            },
            host=host,
        )
        return self._parse_api_response(text)

    def build_login_params(self, *, challenge: str, user_ip: str | None = None, host: str | None = None) -> dict[str, Any]:
        ip = "" if host else (user_ip or self.config.user_ip or "")
        username = self.config.full_username
        hmd5 = password_md5(self.config.password, challenge)
        info = encode_user_info(
            {
                "username": username,
                "password": self.config.password,
                "ip": ip,
                "acid": self.config.ac_id,
                "enc_ver": self.config.enc_ver,
            },
            challenge,
        )
        checksum = build_checksum(
            token=challenge,
            username=username,
            hmd5=hmd5,
            ac_id=self.config.ac_id,
            ip=ip,
            n=self.config.n,
            type_=self.config.type,
            info=info,
        )

        password = f"{{OTP}}{self.config.password}" if self.config.otp else f"{{MD5}}{hmd5}"
        return {
            "callback": self.config.callback,
            "action": "login",
            "username": username,
            "password": password,
            "os": self.config.device.device,
            "name": self.config.device.platform,
            "double_stack": 1 if self.config.double_stack and not host else 0,
            "chksum": checksum,
            "info": info,
            "ac_id": self.config.ac_id,
            "ip": ip,
            "n": self.config.n,
            "type": self.config.type,
        }

    def login(self, *, host: str | None = None) -> dict[str, Any]:
        challenge_response = self.get_challenge(host=host)
        challenge = challenge_response.get("challenge")
        if not challenge:
            raise AuthenticationError(f"Cannot get challenge: {challenge_response}")

        user_ip = challenge_response.get("online_ip") or self.config.user_ip
        params = self.build_login_params(challenge=challenge, user_ip=user_ip, host=host)

        return parse_jsonp(self._get(AUTH_API, params, host=host))

    def _build_url(self, path: str) -> str:
        return urljoin(self.config.base_url.rstrip("/") + "/", path.lstrip("/"))

    def _get(self, path: str, params: dict[str, Any], *, host: str | None = None) -> str:
        query = urlencode({key: value for key, value in params.items() if value is not None})
        url = self._build_url(path)
        if query:
            url = f"{url}?{query}"
        if host:
            url = self._override_url_host(url, host)

        headers = {"User-Agent": self.user_agent}
        if host:
            headers["Host"] = self._portal_netloc
        request = Request(url, headers=headers, method="GET")
        with self.opener.open(request, timeout=self.config.timeout) as response:
            charset = response.headers.get_content_charset() or "utf-8"
            return response.read().decode(charset, errors="replace")

    @staticmethod
    def _override_url_host(url: str, host: str) -> str:
        parts = urlsplit(url)
        return urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))

    @staticmethod
    def _parse_api_response(payload: str) -> dict[str, Any]:
        try:
            return parse_jsonp(payload)
        except (json.JSONDecodeError, AuthenticationError) as exc:
            preview = payload.strip().replace("\n", "\\n")
            if len(preview) > 200:
                preview = preview[:200] + "..."
            raise AuthenticationError(f"Unexpected portal response: {preview}") from exc


def parse_jsonp(payload: str) -> dict[str, Any]:
    text = payload.strip()
    if text.startswith("{"):
        return json.loads(text)

    match = _JSONP_PATTERN.match(text)
    if not match:
        raise AuthenticationError(f"Unexpected portal response: {payload}")

    return json.loads(match.group(1))
