"""Execution permits on the gate: which tool results need a permit, and the check."""
import asyncio
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from croak_core import UNREADABLE_ARGS, Denied, _load_tiers, answered_tool_calls, args_hash  # noqa: E402

# Same table as auth/tests/test_permit_core.py and croakcode's permit-parity test.
PARITY = [
    ({"command": "ls"}, "4cf29611a66934862f29acfcc817e30b905c1ab73d5e65831413eb6b454d49db"),
    ({"b": 1, "a": {"d": [2, {"z": 1, "y": 2}], "c": "x"}}, "8280fefe643f84bbeee696cffe0ba03a09974c0b6c325c8e2890d386e245b530"),
    ({"n": 1.0, "m": 2.5, "neg": -3}, "060665a8709da3f60738f77f6bbd2b6fc4bd8881b97be14e011a38ff61c918d2"),
    ({"text": "한글 \"따옴표\" \n줄바꿈 \\ /"}, "4656a21193f397daafb30fdb2cdc4571eb2d5a86c02141f01926be27586afda5"),
    ({"empty": {}, "list": [], "nul": None, "t": True}, "a3849bb2ba1ce30a15c6d237c4be53ac3ae7fb1569de03844fcef4b88d3e234d"),
]


def conversation(*calls, answered=None):
    """An OpenAI-format history with one assistant message holding `calls`."""
    answered = [c[0] for c in calls] if answered is None else answered
    return [
        {"role": "user", "content": "hi"},
        {
            "role": "assistant",
            "tool_calls": [{"id": cid, "type": "function", "function": {"name": name, "arguments": args}} for cid, name, args in calls],
        },
        *({"role": "tool", "tool_call_id": cid, "content": "result"} for cid in answered),
    ]


class Hash(unittest.TestCase):
    def test_parity_with_auth_and_croakcode(self):
        for value, expected in PARITY:
            with self.subTest(value=value):
                self.assertEqual(args_hash(value), expected)


class AnsweredCalls(unittest.TestCase):
    def test_only_calls_with_a_result_count(self):
        messages = conversation(("c1", "bash", '{"command":"ls"}'), ("c2", "read", '{"path":"a"}'), answered=["c1"])
        self.assertEqual(answered_tool_calls(messages), [{"tool": "bash", "args": PARITY[0][1]}])

    def test_argument_key_order_does_not_matter(self):
        a = answered_tool_calls(conversation(("c1", "x", '{"b":1,"a":2}')))
        b = answered_tool_calls(conversation(("c1", "x", '{"a":2,"b":1}')))
        self.assertEqual(a, b)

    def test_unreadable_arguments_never_match_a_permit(self):
        self.assertEqual(answered_tool_calls(conversation(("c1", "bash", "{not json"))), [{"tool": "bash", "args": UNREADABLE_ARGS}])

    def test_no_tools_no_calls(self):
        self.assertEqual(answered_tool_calls([{"role": "user", "content": "hi"}]), [])


class TierFlag(unittest.TestCase):
    def test_require_permits_is_parsed_and_checked(self):
        tiers = _load_tiers({"restricted": {"agents": ["*"], "require_permits": True}, "full": {"agents": ["*"]}}, {})
        self.assertTrue(tiers["restricted"].require_permits)
        self.assertFalse(tiers["full"].require_permits)
        with self.assertRaises(ValueError):
            _load_tiers({"restricted": {"agents": ["*"], "require_permits": "yes"}}, {})


try:
    import croak_guardrail as guardrail  # needs litellm
except ImportError:  # pragma: no cover - local runs without litellm
    guardrail = None


@unittest.skipIf(guardrail is None, "litellm is not installed")
class Reconcile(unittest.TestCase):
    def run_check(self, tier_flag, messages, missing, session="ses_1"):
        tier = _load_tiers({"restricted": {"agents": ["*"], "require_permits": tier_flag}}, {})["restricted"]
        seen = []

        async def post(body):
            seen.append(body)
            return missing

        asyncio.run(guardrail.check_permits(session, tier, messages, post=post))
        return seen

    def test_off_by_default(self):
        self.assertEqual(self.run_check(False, conversation(("c1", "bash", "{}")), [{"tool": "bash"}]), [])

    def test_permitted_calls_pass(self):
        seen = self.run_check(True, conversation(("c1", "bash", '{"command":"ls"}')), [])
        self.assertEqual(seen, [{"session": "ses_1", "calls": [{"tool": "bash", "args": PARITY[0][1]}]}])

    def test_unpermitted_result_is_refused(self):
        with self.assertRaises(Denied) as err:
            self.run_check(True, conversation(("c1", "bash", "{}")), [{"tool": "bash", "args": "x"}])
        self.assertEqual(err.exception.code, "unpermitted_tool")

    def test_no_session_header_is_refused(self):
        with self.assertRaises(Denied):
            self.run_check(True, conversation(("c1", "bash", "{}")), [], session=None)


if __name__ == "__main__":
    unittest.main()
