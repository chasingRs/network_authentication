import unittest

from network_authentication.client import LoginConfig, NetworkAuthenticator


class _FakeHeaders:
    @staticmethod
    def get_content_charset() -> str:
        return "utf-8"


class _FakeResponse:
    def __init__(self, payload: str) -> None:
        self._payload = payload
        self.headers = _FakeHeaders()

    def read(self) -> bytes:
        return self._payload.encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


class _RecordingOpener:
    def __init__(self, payloads: list[str]) -> None:
        self._payloads = list(payloads)
        self.requests = []

    def open(self, request, timeout: float):
        self.requests.append((request, timeout))
        return _FakeResponse(self._payloads.pop(0))


class NetworkAuthenticatorTests(unittest.TestCase):
    def test_login_uses_host_override_for_http_requests(self):
        opener = _RecordingOpener(
            [
                'callback({"challenge":"token","online_ip":"1.2.3.4"})',
                'callback({"suc_msg":"login ok"})',
            ]
        )
        config = LoginConfig(username="alice", password="secret", base_url="http://portal.example.com")
        client = NetworkAuthenticator(config, opener=opener)

        response = client.login(host="10.0.0.1")

        self.assertEqual(response["suc_msg"], "login ok")
        first_request, _ = opener.requests[0]
        second_request, _ = opener.requests[1]
        self.assertTrue(first_request.full_url.startswith("http://10.0.0.1/cgi-bin/get_challenge"))
        self.assertTrue(second_request.full_url.startswith("http://10.0.0.1/cgi-bin/srun_portal"))
        self.assertEqual(first_request.get_header("Host"), "portal.example.com")
        self.assertEqual(second_request.get_header("Host"), "portal.example.com")
