import unittest

from network_authentication.client import parse_jsonp
from network_authentication.crypto import build_checksum, encode_user_info, password_md5


class CryptoTests(unittest.TestCase):
    def test_encode_user_info_matches_original_javascript(self) -> None:
        encoded = encode_user_info(
            {
                "username": "test_user",
                "password": "test_pass",
                "ip": "client-ip",
                "acid": "1",
                "enc_ver": "srun_bx1",
            },
            "abcdef123456",
        )

        self.assertEqual(
            encoded,
            "{SRBX1}2Xf1B4c/+MsdEeCeTWAmG0IsHvyxETyWlgmmmRN56AfVGSqpuhoCZHbcwxK5CkACA6RGnP3S7foKPYuO2RgNTeSprroEZtNF7vebyOu6C0ZRbElhFVYnUACUUH8Yg/UvHCshU+==",
        )

    def test_password_md5_and_checksum_match_original_javascript(self) -> None:
        token = "abcdef123456"
        username = "test_user"
        password = "test_pass"
        info = encode_user_info(
            {
                "username": username,
                "password": password,
                "ip": "client-ip",
                "acid": "1",
                "enc_ver": "srun_bx1",
            },
            token,
        )
        hashed_password = password_md5(password, token)

        self.assertEqual(hashed_password, "4ac1b63dca561d274c6055ebf3ed97db")
        self.assertEqual(
            build_checksum(
                token=token,
                username=username,
                hmd5=hashed_password,
                ac_id="1",
                ip="client-ip",
                n=200,
                type_=1,
                info=info,
            ),
            "91dab8a93f0f67bf6904738d53215c940d6a8805",
        )


class JsonpTests(unittest.TestCase):
    def test_parse_jsonp_payload(self) -> None:
        payload = 'callback({"error":"ok","suc_msg":"login_ok"});'
        self.assertEqual(parse_jsonp(payload)["suc_msg"], "login_ok")

    def test_parse_json_payload(self) -> None:
        payload = '{"challenge":"abc","online_ip":"client-ip"}'
        self.assertEqual(parse_jsonp(payload)["challenge"], "abc")


if __name__ == "__main__":
    unittest.main()
