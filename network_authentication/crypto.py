"""Protocol helpers used by the SRun login flow."""

from __future__ import annotations

import base64
import hashlib
import json

STD_BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
SRUN_BASE64_ALPHABET = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
_BASE64_TRANSLATION = str.maketrans(STD_BASE64_ALPHABET, SRUN_BASE64_ALPHABET)
_DELTA = 0x9E3779B9


def password_md5(password: str, token: str | None = None) -> str:
    """Match the original Node.js md5(password, token) behaviour.

    The original package used the `md5` npm module, whose second argument is an
    options object rather than the challenge token. Passing the token therefore
    had no effect, and the actual result was simply `md5(password)`.
    """

    del token
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def sha1_hex(value: str) -> str:
    """Return a SHA-1 hex digest."""

    return hashlib.sha1(value.encode("utf-8")).hexdigest()


def encode_user_info(info: dict[str, str], token: str) -> str:
    """Encode the `info` field required by the portal login API."""

    payload = json.dumps(info, separators=(",", ":"), ensure_ascii=False)
    encoded = _xencode(payload, token)
    encoded_bytes = encoded.encode("latin1")
    base64_value = base64.b64encode(encoded_bytes).decode("ascii").translate(_BASE64_TRANSLATION)
    return "{SRBX1}" + base64_value


def build_checksum(
    *,
    token: str,
    username: str,
    hmd5: str,
    ac_id: str,
    ip: str,
    n: int,
    type_: int,
    info: str,
) -> str:
    """Build the SHA-1 checksum required by the portal login API."""

    pieces = [
        token,
        username,
        token,
        hmd5,
        token,
        ac_id,
        token,
        ip,
        token,
        str(n),
        token,
        str(type_),
        token,
        info,
    ]
    return sha1_hex("".join(pieces))


def _xencode(value: str, key: str) -> str:
    if not value:
        return ""

    data = _string_to_uint32_array(value, include_length=True)
    key_values = _string_to_uint32_array(key, include_length=False)
    while len(key_values) < 4:
        key_values.append(0)

    n = len(data) - 1
    z = data[n]
    rounds = 6 + 52 // (n + 1)
    total = 0

    for _ in range(rounds):
        total = (total + _DELTA) & 0xFFFFFFFF
        e = (total >> 2) & 3

        for p in range(n):
            y = data[p + 1]
            mix = ((z >> 5) ^ (y << 2)) + (((y >> 3) ^ (z << 4)) ^ (total ^ y))
            mix = (mix + (key_values[(p & 3) ^ e] ^ z)) & 0xFFFFFFFF
            data[p] = (data[p] + mix) & 0xFFFFFFFF
            z = data[p]

        y = data[0]
        mix = ((z >> 5) ^ (y << 2)) + (((y >> 3) ^ (z << 4)) ^ (total ^ y))
        mix = (mix + (key_values[(n & 3) ^ e] ^ z)) & 0xFFFFFFFF
        data[n] = (data[n] + mix) & 0xFFFFFFFF
        z = data[n]

    return _uint32_array_to_string(data, include_length=False)


def _string_to_uint32_array(value: str, *, include_length: bool) -> list[int]:
    data: list[int] = []
    for index in range(0, len(value), 4):
        chunk = (
            _char_code(value, index)
            | (_char_code(value, index + 1) << 8)
            | (_char_code(value, index + 2) << 16)
            | (_char_code(value, index + 3) << 24)
        )
        data.append(chunk & 0xFFFFFFFF)

    if include_length:
        data.append(len(value))

    return data


def _uint32_array_to_string(values: list[int], *, include_length: bool) -> str:
    raw = bytearray()
    for value in values:
        raw.extend(
            (
                value & 0xFF,
                (value >> 8) & 0xFF,
                (value >> 16) & 0xFF,
                (value >> 24) & 0xFF,
            )
        )

    if include_length:
        length = values[-1]
        raw = raw[:length]

    return raw.decode("latin1")


def _char_code(value: str, index: int) -> int:
    if index >= len(value):
        return 0
    return ord(value[index])
