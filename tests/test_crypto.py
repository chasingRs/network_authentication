import unittest

from network_authentication.client import parse_jsonp
from network_authentication.crypto import build_checksum, encode_user_info, password_md5


class CryptoTests(unittest.TestCase):
    def test_encode_user_info_matches_original_javascript(self) -> None:
        encoded = encode_user_info(
            {
                "username": "test_user",
                "password": "test_pass",
                "ip": "10.0.0.8",
                "acid": "1",
                "enc_ver": "srun_bx1",
            },
            "abcdef123456",
        )

        self.assertEqual(
            encoded,
            "{SRBX1}gsak0MlnuRVMjXA7JM8SN2banhwEjSvUkxF2sNIvU5xjuM+cFX8djfW93qwZUebBo7Ytib2x+GXhRX1yvPZ6W/sxDEbqcae0AjF10EQCQSMOPWSzae7Wo9BaWedzGPX8neqR+S==",
        )

    def test_password_md5_and_checksum_match_original_javascript(self) -> None:
        token = "abcdef123456"
        username = "test_user"
        password = "test_pass"
        info = encode_user_info(
            {
                "username": username,
                "password": password,
                "ip": "10.0.0.8",
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
                ip="10.0.0.8",
                n=200,
                type_=1,
                info=info,
            ),
            "81875d6f382a74b3870e137b4575bfd70d017465",
        )


class JsonpTests(unittest.TestCase):
    def test_parse_jsonp_payload(self) -> None:
        payload = 'callback({"error":"ok","suc_msg":"login_ok"});'
        self.assertEqual(parse_jsonp(payload)["suc_msg"], "login_ok")

    def test_parse_json_payload(self) -> None:
        payload = '{"challenge":"abc","online_ip":"10.0.0.8"}'
        self.assertEqual(parse_jsonp(payload)["challenge"], "abc")


if __name__ == "__main__":
    unittest.main()
