import datetime as dt
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import croak_store  # noqa: E402


class Store(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        croak_store.DATA_DIR = self.tmp.name
        croak_store._last_purge = 0.0

    def tearDown(self):
        self.tmp.cleanup()

    def test_append_writes_private_daily_files(self):
        now = dt.datetime(2026, 11, 6, 3, 0, tzinfo=dt.timezone.utc)
        croak_store.append("audit", {"action": "pass"}, now=now)
        croak_store.append("audit", {"action": "mask"}, now=now)
        path = os.path.join(self.tmp.name, "audit", f"{now.astimezone().strftime('%Y-%m-%d')}.jsonl")
        with open(path) as f:
            rows = [json.loads(l) for l in f]
        self.assertEqual([r["action"] for r in rows], ["pass", "mask"])
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(os.path.dirname(path)).st_mode & 0o777, 0o700)

    def test_owner_from_environment(self):
        os.environ["CROAK_DATA_UID"] = str(os.getuid())
        os.environ["CROAK_DATA_GID"] = str(os.getgid())
        try:
            croak_store.append("archive", {"x": 1})
        finally:
            del os.environ["CROAK_DATA_UID"], os.environ["CROAK_DATA_GID"]
        directory = os.path.join(self.tmp.name, "archive")
        path = os.path.join(directory, os.listdir(directory)[0])
        self.assertEqual((os.stat(path).st_uid, os.stat(directory).st_uid), (os.getuid(), os.getuid()))

    def test_purge_removes_old_days_only(self):
        for kind in ("audit", "archive"):
            os.makedirs(os.path.join(self.tmp.name, kind))
            for day in ("2026-07-01", "2026-08-08", "2026-11-05", "notes"):
                open(os.path.join(self.tmp.name, kind, f"{day}.jsonl"), "w").close()
        now = dt.datetime(2026, 11, 6, 12).timestamp()
        deleted = croak_store.purge(90, now=now, force=True)
        self.assertEqual(sorted(os.path.basename(p) for p in deleted), ["2026-07-01.jsonl", "2026-07-01.jsonl"])
        self.assertEqual(croak_store.purge(90, now=now + 60), [])  # at most hourly

    def test_session_owner_is_first_claimer(self):
        self.assertEqual(croak_store.claim_session("ses_1", "kim"), "kim")
        self.assertEqual(croak_store.claim_session("ses_1", "lee"), "kim")
        self.assertEqual(croak_store.claim_session("../../etc/ses", "lee"), "lee")
        files = os.listdir(os.path.join(self.tmp.name, "sessions"))
        self.assertTrue(all(len(f) == 69 and "/" not in f for f in files))
        path = os.path.join(self.tmp.name, "sessions", files[0])
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_purge_removes_old_session_owners(self):
        croak_store.claim_session("old", "kim")
        croak_store.claim_session("new", "kim")
        directory = os.path.join(self.tmp.name, "sessions")
        now = dt.datetime(2026, 11, 6, 12).timestamp()
        old = sorted(os.listdir(directory))[0]
        os.utime(os.path.join(directory, old), (now - 91 * 86400, now - 91 * 86400))
        for f in os.listdir(directory):
            if f != old:
                os.utime(os.path.join(directory, f), (now, now))
        croak_store.purge(90, now=now, force=True)
        self.assertEqual(len(os.listdir(directory)), 1)


if __name__ == "__main__":
    unittest.main()
