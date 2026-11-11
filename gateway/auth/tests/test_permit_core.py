import base64
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

import permit_core as p  # noqa: E402

# Shared with croakcode test/delegation/permit-parity.test.ts: the same inputs
# must give the same hashes in both languages.
PARITY = [
    ({"command": "ls"}, "4cf29611a66934862f29acfcc817e30b905c1ab73d5e65831413eb6b454d49db"),
    ({"b": 1, "a": {"d": [2, {"z": 1, "y": 2}], "c": "x"}}, "8280fefe643f84bbeee696cffe0ba03a09974c0b6c325c8e2890d386e245b530"),
    ({"n": 1.0, "m": 2.5, "neg": -3}, "060665a8709da3f60738f77f6bbd2b6fc4bd8881b97be14e011a38ff61c918d2"),
    ({"text": "한글 \"따옴표\" \n줄바꿈 \\ /"}, "4656a21193f397daafb30fdb2cdc4571eb2d5a86c02141f01926be27586afda5"),
    ({"empty": {}, "list": [], "nul": None, "t": True}, "a3849bb2ba1ce30a15c6d237c4be53ac3ae7fb1569de03844fcef4b88d3e234d"),
]

def unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class Canonical(unittest.TestCase):
    def test_sorted_keys_and_no_spaces(self):
        self.assertEqual(p.canonical_json({"b": 1, "a": {"d": [2, {"z": 1, "y": 2}], "c": "x"}}), '{"a":{"c":"x","d":[2,{"y":2,"z":1}]},"b":1}')

    def test_integral_floats_match_javascript(self):
        self.assertEqual(p.canonical_json({"n": 1.0, "m": 2.5}), '{"m":2.5,"n":1}')
        self.assertEqual(p.args_hash({"n": 1.0}), p.args_hash({"n": 1}))

    def test_unicode_is_not_escaped(self):
        self.assertEqual(p.canonical_json({"t": "한글"}), '{"t":"한글"}')

    def test_non_finite_numbers_are_refused(self):
        with self.assertRaises(ValueError):
            p.canonical_json({"x": float("nan")})

    def test_parity_with_croakcode(self):
        # croakcode test/delegation/permit-parity.test.ts holds the same table.
        for value, expected in PARITY:
            with self.subTest(value=value):
                self.assertEqual(p.args_hash(value), expected)


class Token(unittest.TestCase):
    def test_signature_covers_the_payload_segment(self):
        key = Ed25519PrivateKey.generate()
        token = p.sign_token({"aud": "croakcode", "x": 1}, key)
        segment, signature = token.split(".")
        key.public_key().verify(unb64url(signature), segment.encode("ascii"))
        self.assertEqual(json.loads(unb64url(segment)), {"aud": "croakcode", "x": 1})

    def test_payload_has_a_30_second_life_and_a_nonce(self):
        req = {"sid": "s", "pid": "p", "rid": "r", "tool": "bash", "args": "a" * 64, "rev": 0}
        a, b = p.payload(req, 1000), p.payload(req, 1000)
        self.assertEqual(a["exp"] - a["iat"], 30_000)
        self.assertEqual(a["aud"], "croakcode")
        self.assertNotEqual(a["nonce"], b["nonce"])

    def test_key_file_and_public_key(self):
        key = Ed25519PrivateKey.generate()
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        try:
            loaded = p.load_private_key(f.name)
            self.assertIsNotNone(loaded)
            self.assertEqual(len(base64.b64decode(p.public_key_b64(loaded))), 32)
        finally:
            os.unlink(f.name)
        self.assertIsNone(p.load_private_key("/nonexistent/key.pem"))


class Request(unittest.TestCase):
    good = {"sid": "ses_1", "pid": "apr_1", "rid": "run_1", "tool": "bash", "args": "0" * 64, "rev": 2}

    def test_accepts_a_well_formed_request(self):
        self.assertEqual(p.parse_request(self.good), self.good)

    def test_rejects_bad_fields(self):
        for key, value in [("sid", ""), ("tool", None), ("args", "xyz"), ("args", "A" * 64), ("rev", -1), ("rev", True), ("pid", "x" * 201)]:
            with self.subTest(key=key, value=value):
                with self.assertRaises(ValueError) as err:
                    p.parse_request({**self.good, key: value})
                self.assertEqual(str(err.exception), key)

    def test_tool_patterns_follow_the_gate(self):
        self.assertTrue(p.tool_denied("bash", ["bash"]))
        self.assertTrue(p.tool_denied("rhwp_hwp_open", ["rhwp_*"]))
        self.assertFalse(p.tool_denied("read", ["bash", "web*"]))


if __name__ == "__main__":
    unittest.main()


class ClientSettings(unittest.TestCase):
    def test_login_carries_the_requirement_and_the_public_key(self):
        key = Ed25519PrivateKey.generate()
        self.assertEqual(p.client_settings(True, key), {"required": True, "public_key": p.public_key_b64(key)})
        self.assertEqual(p.client_settings(False, key)["required"], False)

    def test_no_signing_key_means_no_public_key(self):
        self.assertEqual(p.client_settings(True, None), {"required": True, "public_key": None})
