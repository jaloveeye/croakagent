import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import auth_core as c  # noqa: E402


def kst(*args):
    return datetime(*args, tzinfo=c.KST)


class SessionEnd(unittest.TestCase):
    def test_monday_login_lasts_the_week(self):
        self.assertEqual(c.session_end(kst(2026, 11, 2, 9, 0)), kst(2026, 11, 8))  # Mon -> Sun 00:00

    def test_saturday_night_ends_at_midnight(self):
        self.assertEqual(c.session_end(kst(2026, 11, 7, 23, 30)), kst(2026, 11, 8))

    def test_sunday_login_lasts_until_next_sunday(self):
        self.assertEqual(c.session_end(kst(2026, 11, 8, 0, 0)), kst(2026, 11, 15))
        self.assertEqual(c.session_end(kst(2026, 11, 8, 15, 0)), kst(2026, 11, 15))

    def test_uses_korean_time_for_utc_input(self):
        # 2026-11-07 16:00 UTC is Sunday 01:00 in Korea.
        self.assertEqual(c.session_end(datetime(2026, 11, 7, 16, 0, tzinfo=timezone.utc)), kst(2026, 11, 15))

    def test_access_token_never_outlives_session(self):
        now = kst(2026, 11, 7, 20, 0)
        self.assertEqual(c.access_end(now, c.session_end(now)), kst(2026, 11, 8))
        monday = kst(2026, 11, 2, 9, 0)
        self.assertEqual(c.access_end(monday, c.session_end(monday)), monday + timedelta(hours=24))


class Pkce(unittest.TestCase):
    def test_rfc7636_example(self):
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        self.assertEqual(c.pkce_challenge(verifier), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
        self.assertTrue(c.pkce_ok(verifier, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"))

    def test_rejects_wrong_or_short_verifier(self):
        self.assertFalse(c.pkce_ok("x" * 43, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"))
        self.assertFalse(c.pkce_ok("short", c.pkce_challenge("short")))


class Codes(unittest.TestCase):
    def test_code_shape_and_normalize(self):
        code = c.new_code()
        self.assertRegex(code, r"^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$")
        self.assertEqual(c.normalize_code(code.lower().replace("-", " ")), code.replace("-", ""))

    def test_sign_roundtrip_and_tamper(self):
        secret = b"k" * 32
        signed = c.sign(secret, "nonce123")
        self.assertEqual(c.unsign(secret, signed), "nonce123")
        self.assertIsNone(c.unsign(secret, signed[:-1] + "0"))
        self.assertIsNone(c.unsign(b"x" * 32, signed))
        self.assertIsNone(c.unsign(secret, "garbage"))


class Accounts(unittest.TestCase):
    def test_usernames(self):
        self.assertTrue(c.valid_username("alice"))
        self.assertFalse(c.valid_username("Admin"))
        self.assertFalse(c.valid_username("a"))
        self.assertFalse(c.valid_username("kim;drop"))

    def test_passwords(self):
        self.assertIsNotNone(c.password_problem("short"))
        self.assertIsNotNone(c.password_problem("alice-password-1", "alice"))
        self.assertIsNone(c.password_problem("correct horse battery", "alice"))

    def test_lockout_window(self):
        now = kst(2026, 11, 6, 12, 0)
        self.assertTrue(c.locked(5, now - timedelta(minutes=5), now))
        self.assertFalse(c.locked(5, now - timedelta(minutes=16), now))
        self.assertFalse(c.locked(4, now, now))


if __name__ == "__main__":
    unittest.main()
