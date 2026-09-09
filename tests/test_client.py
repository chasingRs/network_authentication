import unittest

from network_authentication.client import (
    AuthenticationError,
    ClientInfo,
    LoginOptions,
    NetworkAuthenticator,
    PortalConfig,
    best_mac,
    build_account,
    client_info_from_portal_url,
    decode_portal_text,
    host_from_portal_url,
    normalize_host,
    parse_jsonp,
    portal_mac,
)


class _FakeHeaders:
    def __init__(self, charset: str | None = "utf-8") -> None:
        self._charset = charset

    def get_content_charset(self) -> str | None:
        return self._charset


class _FakeResponse:
    def __init__(self, payload: bytes | str, charset: str | None = "utf-8") -> None:
        self._payload = payload.encode("utf-8") if isinstance(payload, str) else payload
        self.headers = _FakeHeaders(charset)

    def read(self) -> bytes:
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


class _RecordingOpener:
    def __init__(self, payloads: list[bytes | str], charset: str | None = "utf-8") -> None:
        self._payloads = list(payloads)
        self._charset = charset
        self.requests = []

    def open(self, request, timeout: float):
        self.requests.append((request, timeout))
        return _FakeResponse(self._payloads.pop(0), self._charset)


class DrcomClientTests(unittest.TestCase):
    def test_parse_jsonp_accepts_callback_wrappers(self):
        self.assertEqual(parse_jsonp('{"result":1}'), {"result": 1})
        self.assertEqual(parse_jsonp('dr1001({"result":1})', callback="dr1001"), {"result": 1})

    def test_decode_portal_text_falls_back_to_gbk(self):
        self.assertEqual(decode_portal_text("彭康健".encode("gb18030"), "utf-8"), "彭康健")

    def test_build_account_matches_pc_portal_format(self):
        options = LoginOptions(username="student_id", password="secret")
        self.assertEqual(build_account(options), ",0,STUDENT_ID")

    def test_raw_account_is_not_changed(self):
        options = LoginOptions(username=",0,student_id@carrier", password="secret", raw_account=True)
        self.assertEqual(build_account(options), ",0,student_id@carrier")

    def test_status_uses_local_drcom_endpoint(self):
        opener = _RecordingOpener(['dr1001({"result":0})'])
        client = NetworkAuthenticator(PortalConfig(host="portal.example.edu"), opener=opener)
        client._callback_id = 1000

        response = client.status()

        self.assertEqual(response, {"result": 0})
        request, timeout = opener.requests[0]
        self.assertEqual(timeout, 8.0)
        self.assertTrue(request.full_url.startswith("http://portal.example.edu/drcom/chkstatus?"))
        self.assertIn("callback=dr1001", request.full_url)

    def test_login_posts_eportal_parameters_after_offline_status(self):
        opener = _RecordingOpener(
            [
                'dr1001({"result":0,"v46ip":"client-ip","ss4":"000000000000","olmac":"aabbccddeeff","v6ip":"client-ipv6"})',
                'dr1002({"result":"1"})',
            ]
        )
        client = NetworkAuthenticator(PortalConfig(host="http://portal.example.edu/"), opener=opener)
        client._callback_id = 1000

        response = client.login(LoginOptions(username="student_id", password="secret"))

        self.assertEqual(response, {"result": "1"})
        login_url = opener.requests[1][0].full_url
        self.assertTrue(login_url.startswith("http://portal.example.edu:801/eportal/?c=Portal&a=login&"))
        self.assertIn("user_account=%2C0%2CSTUDENT_ID", login_url)
        self.assertIn("wlan_user_ip=client-ip", login_url)
        self.assertIn("wlan_user_ipv6=", login_url)
        self.assertIn("wlan_user_mac=000000000000", login_url)

    def test_login_skips_when_already_online(self):
        opener = _RecordingOpener(['dr1001({"result":1,"uid":"student_id"})'])
        client = NetworkAuthenticator(PortalConfig(host="portal.example.edu"), opener=opener)
        client._callback_id = 1000

        response = client.login(LoginOptions(username="student_id", password="secret"))

        self.assertTrue(response["already_online"])
        self.assertEqual(len(opener.requests), 1)

    def test_login_does_not_skip_when_portal_url_ip_differs(self):
        opener = _RecordingOpener(
            [
                'dr1001({"result":1,"uid":"student_id","v46ip":"status-client-ip"})',
                'dr1002({"result":"1"})',
            ]
        )
        client = NetworkAuthenticator(PortalConfig(host="portal.example.edu"), opener=opener)
        client._callback_id = 1000

        response = client.login(LoginOptions(username="student_id", password="secret"), ClientInfo(ip="portal-client-ip"))

        self.assertEqual(response, {"result": "1"})
        self.assertEqual(len(opener.requests), 2)

    def test_logout_uses_manual_client_info_when_present(self):
        opener = _RecordingOpener(
            [
                'dr1001({"result":1,"uid":"student_id"})',
                'dr1002({"result":"1"})',
            ]
        )
        client = NetworkAuthenticator(PortalConfig(host="portal.example.edu"), opener=opener)
        client._callback_id = 1000

        response = client.logout(ClientInfo(ip="manual-client-ip", mac="aabbccddeeff", vlan="client-vlan"))

        self.assertEqual(response, {"result": "1"})
        logout_url = opener.requests[1][0].full_url
        self.assertIn("wlan_user_ip=manual-client-ip", logout_url)
        self.assertIn("wlan_user_mac=aabbccddeeff", logout_url)
        self.assertIn("wlan_vlan_id=client-vlan", logout_url)

    def test_best_mac_prefers_real_values(self):
        self.assertEqual(best_mac({"ss4": "000000000000", "olmac": "42:35:48:53:3b:fa"}), "423548533bfa")

    def test_portal_mac_matches_browser_field_priority(self):
        self.assertEqual(portal_mac({"ss4": "000000000000", "olmac": "42:35:48:53:3b:fa"}), "000000000000")

    def test_normalize_host_strips_scheme_and_path(self):
        self.assertEqual(normalize_host("http://portal.example.edu/"), "portal.example.edu")

    def test_portal_url_extracts_host_and_client_context(self):
        portal_url = "http://portal.example.edu/a79.htm?wlanuserip=client-ip&wlanacname=ac-name&url=http%3A%2F%2Fconnectivity.example%2Fgenerate_204"

        self.assertEqual(host_from_portal_url(portal_url), "portal.example.edu")
        self.assertEqual(client_info_from_portal_url(portal_url), ClientInfo(ip="client-ip", ac_name="ac-name"))

    def test_parse_jsonp_rejects_wrong_callback(self):
        with self.assertRaises(AuthenticationError):
            parse_jsonp('dr1002({"result":1})', callback="dr1001")
