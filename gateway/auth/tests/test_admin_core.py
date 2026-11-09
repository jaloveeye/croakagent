import json
import os
import sys
import tempfile
import unittest
from datetime import date

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import admin_core as a  # noqa: E402


def rec(ts, user="kim", action="pass", violation=None, agent="dev-main", **extra):
    r = {"ts": ts, "user": user, "action": action, "agent": agent, "model": "default", **extra}
    if violation:
        r["violation"] = violation
    return r


class Read(unittest.TestCase):
    def test_reads_days_in_order_and_skips_broken_lines(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "audit"))
            for day, rows in {"2026-11-02": ['{"n": 1}', "not json", '{"n": 2}'], "2026-11-04": ['{"n": 3}']}.items():
                with open(os.path.join(d, "audit", f"{day}.jsonl"), "w") as f:
                    f.write("\n".join(rows) + "\n")
            got = [r["n"] for r in a.read("audit", date(2026, 11, 1), date(2026, 11, 5), d)]
            self.assertEqual(got, [1, 2, 3])
            self.assertEqual(list(a.read("archive", date(2026, 11, 1), date(2026, 11, 5), d)), [])


class Days(unittest.TestCase):
    def test_kst_day_from_utc(self):
        self.assertEqual(a.kst_day("2026-11-06T16:00:00+00:00"), "2026-11-07")
        self.assertEqual(a.kst_day("2026-11-06T14:59:59+00:00"), "2026-11-06")

    def test_read_kst_crosses_utc_files(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "audit"))
            with open(os.path.join(d, "audit", "2026-11-06.jsonl"), "w") as f:
                f.write('{"ts": "2026-11-06T10:00:00+00:00", "n": 1}\n{"ts": "2026-11-06T16:00:00+00:00", "n": 2}\n')
            got = [r["n"] for r in a.read_kst("audit", date(2026, 11, 7), date(2026, 11, 7), d)]
            self.assertEqual(got, [2])


class Stats(unittest.TestCase):
    def test_counts_requests_blocks_and_tokens(self):
        audit = [
            rec("2026-11-02T09:00:00+09:00"),
            rec("2026-11-02T09:01:00+09:00", action="block", violation="secret"),
            rec("2026-11-03T09:00:00+09:00", user="lee", agent="dev-doc", violation="secret_in_history", action="mask"),
            {"ts": "2026-11-03T09:00:00+09:00", "action": "archive_error"},
        ]
        usage = [
            {"ts": "2026-11-02T09:00:05+09:00", "user": "kim", "agent": "dev-main", "model": "default", "usage": {"total_tokens": 100}},
            {"ts": "2026-11-03T09:00:05+09:00", "user": "lee", "agent": "dev-doc", "model": "default",
             "usage": {"prompt_tokens": 30, "completion_tokens": 20, "total_tokens": None}},
        ]
        s = a.stats(audit, usage)
        self.assertEqual(s["totals"], {"requests": 3, "blocked": 1, "violations": 2, "tokens": 150})
        self.assertEqual([d["key"] for d in s["days"]], ["2026-11-02", "2026-11-03"])
        kim = next(u for u in s["users"] if u["key"] == "kim")
        self.assertEqual((kim["requests"], kim["blocked"], kim["tokens"]), (2, 1, 100))
        self.assertEqual(s["users"][0]["key"], "kim")  # most requests first


class Alerts(unittest.TestCase):
    def test_bypass_is_always_an_alert(self):
        got = a.alerts([rec("2026-11-02T10:00:00+09:00", action="block", violation="tool_denied", denied=["bash"])])
        self.assertEqual([x["rule"] for x in got], ["bypass"])
        self.assertIn("bash", got[0]["detail"])

    def test_agent_denied_is_a_config_alert(self):
        got = a.alerts([rec("2026-11-02T10:00:00+09:00", action="block", violation="agent_denied", agent="dev-main")])
        self.assertEqual([x["rule"] for x in got], ["config"])
        self.assertEqual(a.RULE_NAMES["config"], "설정 확인 필요")

    def test_three_blocks_within_an_hour(self):
        times = ["2026-11-02T10:00:00+09:00", "2026-11-02T10:20:00+09:00", "2026-11-02T10:50:00+09:00",
                 "2026-11-02T10:55:00+09:00"]
        got = [x for x in a.alerts([rec(t, action="block", violation="secret") for t in times]) if x["rule"] == "repeated"]
        self.assertEqual(len(got), 1)  # one alert per burst, not one per extra block

    def test_spread_out_blocks_do_not_alert(self):
        times = ["2026-11-02T10:00:00+09:00", "2026-11-02T11:30:00+09:00", "2026-11-02T13:00:00+09:00"]
        self.assertEqual(a.alerts([rec(t, action="block", violation="secret") for t in times]), [])

    def test_secret_in_history_per_day(self):
        audit = [rec(f"2026-11-02T1{i}:00:00+09:00", action="mask", violation="secret_in_history") for i in range(5)]
        self.assertEqual([x["rule"] for x in a.alerts(audit)], ["secret_leak"])
        self.assertEqual(a.alerts(audit[:4]), [])

    def test_login_failures(self):
        events = [{"ts": "2026-11-02T10:00:00+09:00", "subject": "kim"}] * 10
        self.assertEqual([x["rule"] for x in a.alerts([], events)], ["login_attack"])
        self.assertEqual(a.alerts([], events[:9]), [])


class Archive(unittest.TestCase):
    def test_filters(self):
        r = {"user": "kim", "agent": "dev-main", "input": [{"role": "user", "content": "배포 스크립트"}], "output": "답"}
        self.assertTrue(a.archive_matches(r, user="kim", text="배포"))
        self.assertFalse(a.archive_matches(r, user="lee"))
        self.assertFalse(a.archive_matches(r, agent="dev-doc"))
        self.assertFalse(a.archive_matches(r, text="없는말"))

    def test_message_text(self):
        self.assertEqual(a.message_text({"content": "hi"}), "hi")
        self.assertEqual(a.message_text({"content": [{"type": "text", "text": "a"}, {"type": "image_url"}]}), "a\n[image_url]")
        self.assertEqual(a.message_text({"tool_calls": [{"function": {"name": "bash"}}]}), "[tool_calls: bash]")
        self.assertEqual(json.dumps(a.message_text({})), '""')


if __name__ == "__main__":
    unittest.main()
