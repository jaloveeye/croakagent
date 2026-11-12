import copy
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from croak_core import (  # noqa: E402
    PII_PATTERNS,
    SECRET_PATTERNS,
    OPEN_TIER,
    Blocked,
    Denied,
    Profile,
    check_access,
    chat_tool_use,
    client_agent,
    tier_for,
    tool_names,
    apply_profile,
    find,
    load_policy,
    new_turn,
    redact,
    resolve,
    spans,
    media_parts,
    media_pii_action,
    DenyPaths,
    apply_deny_paths,
    strip_media,
)

POLICY = load_policy(
    {
        "retention_days": 90,
        "allow": {"email": ["Owner@Example.com"]},
        "profiles": {
            "default": {"pii": "mask", "secrets": "block", "store_prompt": "masked"},
            "hr-doc": {"pii": "allow", "secrets": "block", "store_prompt": "none"},
            "strict": {"pii": "block", "secrets": "block", "store_prompt": "none"},
        },
        "agents": {"dev-main": "default", "hr-doc": "hr-doc", "audit": "strict"},
        "tiers": {
            "full": {"agents": ["*"], "profiles": ["*"]},
            "standard": {"agents": ["dev-*", "title"]},
            "restricted": {"agents": ["dev-doc"], "deny_tools": ["bash", "web*", "rhwp_*"], "secrets_scope": "all"},
        },
    }
)


class DetectSecrets(unittest.TestCase):
    def test_finds_credentials(self):
        cases = {
            "aws_access_key": "key AKIAIOSFODNN7EXAMPLE here",
            "github_token": "token ghp_" + "a" * 36,
            "openai_style_key": "OPENAI_API_KEY=sk-proj-" + "b" * 30,
            "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----",
            "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            "bearer_token": "Authorization: Bearer abcdefghijklmnopqrstuvwx",
            "password_assignment": "db password: Sup3rS3cret!",
        }
        for kind, text in cases.items():
            with self.subTest(kind=kind):
                self.assertIn(kind, find(text, SECRET_PATTERNS))

    def test_short_labelled_passwords(self):
        for text in ["id: kimhj\npw:1234", "pass=abcd", "비번: 0000", "PIN: 4821", "pw = qwer", "pin_code=123456", "암호=7788"]:
            with self.subTest(text=text):
                self.assertIn("short_password", find(text, SECRET_PATTERNS), text)

    def test_short_label_lookalikes(self):
        for text in [
            "pass: true",
            "password: string",
            "def login(pw: str, user: str)",
            "pin: v1.2.3",
            "pass=${PASS}",
            "pw: ****",
            "pass: <your password>",
            "pin=12",
            "compass:1234",
            "bypass=1234",
            "pass: none",
            "테스트 통과 pass: 12건",
            "테스트 결과 pass: 120건, fail: 0건",
        ]:
            with self.subTest(text=text):
                self.assertEqual(find(text, SECRET_PATTERNS), {}, text)

    def test_password_in_sentences(self):
        for text in [
            "pass1234로 패스워드를 설정하자",
            "Qwer1234!으로 비밀번호 바꿔줘",
            "비밀번호는 qwer1234! 이야",
            "DB 비번 abc123def 로 접속해",
            "패스워드를 hello2026으로 해줘",
            "the password is Abc12345 for now",
            "암호: \"Sunny-day7\"",
        ]:
            with self.subTest(text=text):
                self.assertTrue(find(text, SECRET_PATTERNS), text)

    def test_password_talk_without_a_password(self):
        for text in [
            "비밀번호를 바꾸는 방법을 알려줘",
            "비밀번호는 12자 이상이어야 한다",
            "비밀번호는 argon2id로 저장한다",
            "sha256으로 비밀번호를 해시한다",
            "패스워드 정책 v2 문서를 정리해줘",
            "password reset flow for version 3",
            "비밀번호 확인칸과 보기 버튼을 넣자",
        ]:
            with self.subTest(text=text):
                self.assertEqual(find(text, SECRET_PATTERNS), {}, text)

    def test_korean_password_label(self):
        self.assertIn("password_assignment", find("비밀번호: qwer1234!!", SECRET_PATTERNS))

    def test_ignores_placeholders_and_references(self):
        for text in [
            "password: ********",
            "api_key: <YOUR_KEY>",
            'apiKey = "{env:CROAK_GATE_KEY}"',
            "api_key: os.environ/UPSTREAM_API_KEY",
            "password=${DB_PASSWORD}",
            "password: changeme",
            "비밀번호를 바꾸는 방법을 알려줘",
            "the secret of good code is tests",
        ]:
            with self.subTest(text=text):
                self.assertEqual(find(text, SECRET_PATTERNS), {})


class DetectPII(unittest.TestCase):
    def test_finds_korean_personal_data(self):
        cases = {
            "resident_id": "주민번호 900101-1234567",
            "mobile_phone": "연락처 010-1234-5678",
            "phone": "대표번호 02-123-4567",
            "email": "메일 alice@example.com",
            "card_number": "카드 4111 1111 1111 1111",
            "passport": "여권 M12345678",
        }
        for kind, text in cases.items():
            with self.subTest(kind=kind):
                self.assertIn(kind, find(text, PII_PATTERNS))

    def test_names_and_addresses(self):
        cases = {
            "person_name": ["성명: 홍길동", "담당자 : 김철수 과장", "Name: John Smith", "대표이사: 이영희"],
            "address": ["주소: 서울시 강남구 테헤란로 123", "서울특별시 강남구 테헤란로 123, 4층",
                        "13494 경기도 성남시 분당구 판교역로 235", "13494 판교역로 235 A동", "(삼평동 670 유스페이스1)",
                        "성남시 분당구 삼평동 670",
                        "경기도 성남시 분당구 판교역로 235", "소재지：부산광역시 해운대구 센텀중앙로 79"],
        }
        for kind, texts in cases.items():
            for text in texts:
                with self.subTest(text=text):
                    self.assertIn(kind, find(text, PII_PATTERNS), text)

    def test_name_and_address_lookalikes(self):
        for text in [
            "이름을 바꿔줘",
            "파일 이름 변경 규칙",
            "Name: Default",
            "name: report.pdf",
            "IP 주소: 10.20.30.40",
            "메일 주소: 알려줘",
            "주소창에 입력한다",
            "서울에서 회의가 있다",
            "도로명 주소 형식을 설명해줘",
            "이동 5회, 활동 3건",
            "자동 2단계로 처리",
            "(이동 3회)는 줄었다",
            "포트 13494 열기",
        ]:
            with self.subTest(text=text):
                self.assertEqual({k: v for k, v in find(text, PII_PATTERNS).items() if k in ("person_name", "address")}, {}, text)

    def test_ignores_lookalikes(self):
        for text in [
            "버전 2026-11-06 배포",
            "주문번호 1234-5678-9012-3456",  # fails the Luhn check
            "포트 4100과 4000",
            "커밋 642396a",
            "IP 10.20.30.40",
        ]:
            with self.subTest(text=text):
                self.assertEqual(find(text, PII_PATTERNS), {})

    def test_spans_point_into_the_original_text(self):
        text = "연락처 010-1234-5678, 메일 owner@example.com"
        got = spans(text, PII_PATTERNS, POLICY.allow)
        self.assertEqual([(k, text[a:b]) for k, a, b in got], [("mobile_phone", "010-1234-5678")])

    def test_redact_marks_kind(self):
        self.assertEqual(redact("010-1234-5678로 연락", PII_PATTERNS, "MASKED").text, "[MASKED:mobile_phone]로 연락")


class ResolvePolicy(unittest.TestCase):
    def test_known_and_unknown_agents(self):
        self.assertEqual(resolve(POLICY, "dev-main", []).profile.name, "default")
        self.assertEqual(resolve(POLICY, "made-up", []).profile.name, "default")
        self.assertEqual(resolve(POLICY, None, []).agent, "unknown")

    def test_looser_profile_needs_a_grant(self):
        d = resolve(POLICY, "hr-doc", [])
        self.assertEqual(d.profile.name, "default")
        self.assertTrue(d.downgraded)
        self.assertEqual(d.requested, "hr-doc")
        self.assertEqual(resolve(POLICY, "hr-doc", ["hr-doc"]).profile.name, "hr-doc")
        self.assertEqual(resolve(POLICY, "hr-doc", ["*"]).profile.name, "hr-doc")

    def test_stricter_profile_needs_no_grant(self):
        d = resolve(POLICY, "audit", [])
        self.assertEqual(d.profile.name, "strict")
        self.assertFalse(d.downgraded)

    def test_bad_policies_are_rejected(self):
        with self.assertRaises(ValueError):
            load_policy({"profiles": {"x": {}}})
        with self.assertRaises(ValueError):
            load_policy({"profiles": {"default": {"pii": "maybe"}}})
        with self.assertRaises(ValueError):
            load_policy({"profiles": {"default": {}}, "agents": {"a": "missing"}})
        with self.assertRaises(ValueError):
            load_policy({"profiles": {"default": {"pii": "mask", "colour": "red"}}})


class ApplyProfile(unittest.TestCase):
    default = POLICY.profiles["default"]

    def test_masks_pii_and_redacts_history(self):
        msgs = [
            {"role": "system", "content": "you are helpful"},
            {"role": "user", "content": "이전 질문"},
            {"role": "assistant", "content": "답"},
            {"role": "tool", "content": "cat .env\nOPENAI_API_KEY=sk-" + "c" * 30},
            {"role": "user", "content": [{"type": "text", "text": "010-1234-5678 고객에게 보낼 문구"}, {"type": "image_url", "image_url": {"url": "data:"}}]},
        ]
        counts = apply_profile(msgs, self.default)
        self.assertEqual(counts["pii"], {"mobile_phone": 1})
        self.assertEqual(counts["secrets"], {"openai_style_key": 1})
        self.assertIn("[MASKED:mobile_phone]", msgs[4]["content"][0]["text"])
        self.assertIn("[REDACTED:openai_style_key]", msgs[3]["content"])

    def test_blocks_secret_in_newest_user_message(self):
        msgs = [{"role": "user", "content": "이 키로 접속해 AKIAIOSFODNN7EXAMPLE"}]
        before = copy.deepcopy(msgs)
        with self.assertRaises(Blocked) as ctx:
            apply_profile(msgs, self.default)
        self.assertEqual(ctx.exception.found, {"aws_access_key": 1})
        self.assertEqual(msgs, before)

    def test_old_secret_does_not_lock_the_session(self):
        msgs = [
            {"role": "user", "content": "키는 AKIAIOSFODNN7EXAMPLE"},
            {"role": "assistant", "content": "키를 지워 주세요"},
            {"role": "user", "content": "알겠어, 계속해"},
        ]
        counts = apply_profile(msgs, self.default)
        self.assertEqual(counts["secrets"], {"aws_access_key": 1})

    def test_allow_keeps_pii(self):
        msgs = [{"role": "user", "content": "900101-1234567 직원 기록"}]
        counts = apply_profile(msgs, POLICY.profiles["hr-doc"])
        self.assertEqual(counts["pii"], {})
        self.assertEqual(msgs[0]["content"], "900101-1234567 직원 기록")

    def test_strict_blocks_pii(self):
        with self.assertRaises(Blocked):
            apply_profile([{"role": "user", "content": "alice@example.com"}], POLICY.profiles["strict"])

    def test_new_turn(self):
        msgs = [{"role": "system"}, {"role": "user", "content": "a"}, {"role": "assistant"}, {"role": "tool"}, {"role": "user"}]
        self.assertEqual([m["role"] for m in new_turn(msgs)], ["tool", "user"])
        self.assertEqual([m["role"] for m in new_turn(msgs[:2])], ["user"])

    def test_allow_list_keeps_listed_values_only(self):
        msgs = [
            {"role": "system", "content": "커밋 작성자는 owner@example.com 으로 한다"},
            {"role": "user", "content": "other@example.com 에게 보내"},
        ]
        counts = apply_profile(msgs, self.default, POLICY.allow)
        self.assertIn("owner@example.com", msgs[0]["content"])
        self.assertNotIn("other@example.com", msgs[1]["content"])
        self.assertEqual(counts["pii"], {"email": 1})

    def test_allow_list_applies_to_the_system_prompt_only(self):
        msgs = [
            {"role": "system", "content": "커밋 작성자는 owner@example.com 으로 한다"},
            {"role": "user", "content": "명함: owner@example.com"},
            {"role": "tool", "content": "author owner@example.com"},
        ]
        apply_profile(msgs, self.default, POLICY.allow)
        self.assertIn("owner@example.com", msgs[0]["content"])
        self.assertNotIn("owner@example.com", msgs[1]["content"])
        self.assertNotIn("owner@example.com", msgs[2]["content"])

    def test_allow_list_validation(self):
        with self.assertRaises(ValueError):
            load_policy({"profiles": {"default": {}}, "allow": {"aws_access_key": ["AKIAIOSFODNN7EXAMPLE"]}})
        with self.assertRaises(ValueError):
            load_policy({"profiles": {"default": {}}, "allow": {"email": ["not an email"]}})
        with self.assertRaises(ValueError):
            load_policy({"profiles": {"default": {}}, "allow": {"email": "owner@example.com"}})

    def test_profile_order(self):
        self.assertTrue(Profile("a", pii="allow").looser_than(self.default))
        self.assertFalse(Profile("b", pii="block").looser_than(self.default))


class Tiers(unittest.TestCase):
    def test_unknown_or_missing_tier_is_restricted(self):
        self.assertEqual(tier_for(POLICY, None).name, "restricted")
        self.assertEqual(tier_for(POLICY, "superuser").name, "restricted")
        self.assertEqual(tier_for(POLICY, "full").name, "full")

    def test_policy_without_tiers_is_open(self):
        self.assertIs(tier_for(load_policy({"profiles": {"default": {}}}), "anything"), OPEN_TIER)

    def test_agent_check(self):
        check_access(tier_for(POLICY, "standard"), "dev-main", [])
        with self.assertRaises(Denied) as ctx:
            check_access(tier_for(POLICY, "standard"), "hr-doc", [])
        self.assertEqual(ctx.exception.code, "agent_denied")
        self.assertIn("쓸 수 있는 에이전트: dev-*", ctx.exception.reason)
        self.assertNotIn("title", ctx.exception.reason)
        check_access(tier_for(POLICY, "full"), "anything", ["bash"])

    def test_tool_check_with_wildcards(self):
        restricted = tier_for(POLICY, "restricted")
        check_access(restricted, "dev-doc", ["read", "edit"])
        with self.assertRaises(Denied) as ctx:
            check_access(restricted, "dev-doc", ["read", "bash", "webfetch", "rhwp_open"])
        self.assertEqual(ctx.exception.code, "tool_denied")
        self.assertEqual(ctx.exception.detail, ["bash", "rhwp_open", "webfetch"])

    def test_tool_names(self):
        tools = [{"type": "function", "function": {"name": "bash"}}, {"name": "read"}, "junk", {"function": {}}]
        self.assertEqual(tool_names(tools), ["bash", "read"])
        self.assertEqual(tool_names(None), [])

    def test_secret_anywhere_blocks_for_scope_all(self):
        msgs = [
            {"role": "user", "content": "키는 AKIAIOSFODNN7EXAMPLE"},
            {"role": "assistant", "content": "지워 주세요"},
            {"role": "user", "content": "계속해"},
        ]
        with self.assertRaises(Blocked):
            apply_profile(copy.deepcopy(msgs), POLICY.profiles["default"], secrets_scope="all")
        self.assertEqual(apply_profile(msgs, POLICY.profiles["default"])["secrets"], {"aws_access_key": 1})

    def test_bad_tiers_are_rejected(self):
        base = {"profiles": {"default": {}}}
        with self.assertRaises(ValueError):
            load_policy({**base, "tiers": {"full": {"agents": ["*"]}}})  # no restricted tier
        with self.assertRaises(ValueError):
            load_policy({**base, "tiers": {"restricted": {"agents": "dev-doc"}}})
        with self.assertRaises(ValueError):
            load_policy({**base, "tiers": {"restricted": {"profiles": ["missing"]}}})
        with self.assertRaises(ValueError):
            load_policy({**base, "tiers": {"restricted": {"secrets_scope": "some"}}})
        with self.assertRaises(ValueError):
            load_policy({**base, "tiers": {"restricted": {"color": "red"}}})


class MediaParts(unittest.TestCase):
    def msgs(self):
        return [
            {"role": "user", "content": [
                {"type": "text", "text": "Image read successfully"},
                {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}},
                {"type": "image_url", "image_url": {"url": "https://example.com/x.png"}},
                {"type": "file", "file": {"filename": "a.pdf", "file_data": "data:application/pdf;base64,BBBB"}},
            ]},
            {"role": "user", "content": "plain"},
        ]

    def test_finds_inline_images_and_pdfs_only(self):
        found = media_parts(self.msgs())
        self.assertEqual([(m.kind, m.data, m.name, m.message_index) for m in found],
                         [("image", "AAAA", "image", 0), ("pdf", "BBBB", "a.pdf", 0)])

    def test_setters_replace_in_place(self):
        msgs = self.msgs()
        image, pdf = media_parts(msgs)
        image.set_data("CCCC")
        pdf.replace({"type": "text", "text": "masked"})
        self.assertEqual(msgs[0]["content"][1]["image_url"]["url"], "data:image/png;base64,CCCC")
        self.assertEqual(msgs[0]["content"][3], {"type": "text", "text": "masked"})

    def test_strip_media_keeps_no_data(self):
        msgs = self.msgs()
        stripped = strip_media(msgs)
        blob = json.dumps(stripped)
        self.assertNotIn("AAAA", blob)
        self.assertNotIn("BBBB", blob)
        self.assertIn("not stored", blob)
        self.assertIn("AAAA", json.dumps(msgs))  # the original is untouched


class Overrides(unittest.TestCase):
    def test_media_pii_action_defaults_to_mask(self):
        self.assertEqual(media_pii_action(None, "restricted"), "mask")
        self.assertEqual(media_pii_action({"media_pii": {"restricted": "block"}}, "restricted"), "block")
        self.assertEqual(media_pii_action({"media_pii": {"restricted": "block"}}, "standard"), "mask")
        self.assertEqual(media_pii_action({"media_pii": {"restricted": "drop table"}}, "restricted"), "mask")


class Paths(unittest.TestCase):
    deny = DenyPaths((".ssh", ".aws", ".gnupg", ".config/croak"), (".env", "*.env", "*.pem", "*.key", "id_rsa*"))

    def test_rules(self):
        self.assertEqual(self.deny.rule("/home/u/.ssh/id_rsa"), ".ssh")
        self.assertEqual(self.deny.rule("/home/u/.config/croak/session.json"), ".config/croak")
        self.assertEqual(self.deny.rule("deploy/prod.env"), "*.env")
        self.assertIsNone(self.deny.rule(".env.example"))
        self.assertIsNone(self.deny.rule("docs/ssh.md"))
        self.assertIsNone(self.deny.rule(".config/opencode/opencode.jsonc"))

    def msgs(self):
        return [
            {"role": "user", "content": "설정 확인"},
            {"role": "assistant", "content": "", "tool_calls": [
                {"id": "c1", "type": "function", "function": {"name": "read", "arguments": json.dumps({"filePath": "/home/u/.ssh/id_rsa"})}},
                {"id": "c2", "type": "function", "function": {"name": "bash", "arguments": json.dumps({"command": "cat ~/.aws/credentials"})}},
                {"id": "c3", "type": "function", "function": {"name": "grep", "arguments": json.dumps({"pattern": "password", "path": "."})}},
                {"id": "c4", "type": "function", "function": {"name": "read", "arguments": json.dumps({"filePath": "src/main.py"})}},
            ]},
            {"role": "tool", "tool_call_id": "c1", "content": "-----BEGIN OPENSSH PRIVATE KEY-----"},
            {"role": "tool", "tool_call_id": "c2", "content": "aws_secret_access_key = abc"},
            {"role": "tool", "tool_call_id": "c3", "content": "src/a.py:3: password = env\n.env:1: DB_PASSWORD=x\nREADME.md:2: hi"},
            {"role": "tool", "tool_call_id": "c4", "content": "print('ok')"},
        ]

    def test_blocked_results_and_lines(self):
        msgs = self.msgs()
        out = apply_deny_paths(msgs, self.deny)
        self.assertEqual(out["blocked"], 2)
        self.assertEqual(out["lines"], 1)
        self.assertEqual(out["fresh"], 3)
        self.assertIn("보내지 않았다", msgs[2]["content"])
        self.assertIn("보내지 않았다", msgs[3]["content"])
        self.assertNotIn("DB_PASSWORD", msgs[4]["content"])
        self.assertIn("src/a.py:3", msgs[4]["content"])
        self.assertEqual(msgs[5]["content"], "print('ok')")

    def test_read_tool_attachment(self):
        note = 'Called the Read tool with the following input: {"filePath":"/home/u/.ssh/id_ed25519.pem"}'
        msgs = [{"role": "user", "content": [{"type": "text", "text": note}, {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}}]}]
        out = apply_deny_paths(msgs, self.deny)
        self.assertEqual(out["blocked"], 1)
        self.assertNotIn("AAAA", json.dumps(msgs))

    def test_empty_lists_do_nothing(self):
        msgs = self.msgs()
        self.assertEqual(apply_deny_paths(msgs, DenyPaths())["blocked"], 0)
        self.assertIn("OPENSSH", msgs[2]["content"])

    def test_policy_validation(self):
        with self.assertRaises(ValueError):
            load_policy({"profiles": {"default": {}}, "deny_paths": {"dirs": ".ssh"}})
        with self.assertRaises(ValueError):
            load_policy({"profiles": {"default": {}}, "deny_paths": {"folders": [".ssh"]}})


if __name__ == "__main__":
    unittest.main()


class ChatKeys(unittest.TestCase):
    """Chat-only keys (croak_client: chat) for Open WebUI and the like."""

    CHAT = {"croak_client": "chat", "croak_tier": "standard"}
    LOGIN = {"croak_session": "s1", "croak_tier": "standard"}

    def test_plain_chat_is_the_chat_agent(self):
        data = {"messages": [{"role": "system", "content": "s"}, {"role": "user", "content": "hi"}]}
        self.assertEqual(client_agent(self.CHAT, "dev-main", data), "chat")
        self.assertEqual(chat_tool_use({**data, "tool_choice": "none"}), [])

    def test_any_tool_use_is_refused(self):
        cases = {
            "tools": {"tools": [{"type": "function", "function": {"name": "web_search"}}]},
            "functions": {"functions": [{"name": "f"}]},
            "tool_choice": {"tool_choice": "auto"},
            "tool_result": {"messages": [{"role": "tool", "tool_call_id": "1", "content": "x"}]},
            "tool_call": {"messages": [{"role": "assistant", "tool_calls": [{"id": "1"}]}]},
        }
        for part, extra in cases.items():
            data = {"messages": [{"role": "user", "content": "hi"}], **extra}
            with self.subTest(part=part):
                with self.assertRaises(Denied) as caught:
                    client_agent(self.CHAT, None, data)
                self.assertEqual(caught.exception.code, "chat_key_tools")
                self.assertIn(part, caught.exception.detail)

    def test_a_login_key_needs_croakcode(self):
        data = {"messages": [{"role": "user", "content": "hi"}]}
        with self.assertRaises(Denied) as caught:
            client_agent(self.LOGIN, None, data)
        self.assertEqual(caught.exception.code, "client_required")
        self.assertEqual(client_agent(self.LOGIN, "dev-main", data), "dev-main")

    def test_an_issued_key_keeps_working_without_an_agent(self):
        self.assertEqual(client_agent({"croak_tier": "full"}, None, {"messages": []}), "unknown")
