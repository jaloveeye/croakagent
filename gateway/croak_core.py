"""Policy resolution and secret/PII detection for croak-gate.

Pure Python with no LiteLLM import, so it is unit-tested on its own
(gateway/tests/test_core.py). croak_guardrail.py and croak_archive.py
adapt it to LiteLLM.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

# A password-looking word: 6-64 characters with at least one letter and one digit.
_PW_VALUE = (
    r"(?<![A-Za-z0-9])"
    r"(?!(?:argon2|bcrypt|scrypt|pbkdf2|sha\d|md5|aes\d|rsa\d|base64|utf-?8|ed25519|x509|tls1|http2)[a-z0-9-]*(?![A-Za-z0-9!@#$%^&*_+=.~-]))"
    r"(?=[A-Za-z0-9!@#$%^&*_+=.~-]*\d)(?=[A-Za-z0-9!@#$%^&*_+=.~-]*[A-Za-z])"
    r"[A-Za-z0-9!@#$%^&*_+=.~-]{6,64}(?![A-Za-z0-9!@#$%^&*_+=.~-])"
)

# Values after "password:" that are placeholders, references or types, not passwords.
_NOT_A_VALUE = (
    r"(?:\*+|x+|<[^>]*>|\$\{?[A-Za-z_]+\}?|os\.environ[^\s]*|\{env:[^}]*\}|changeme|example|your[_-]\w+"
    r"|true|false|none|null|nil|undefined|yes|no|required|optional"
    r"|string|str|number|int|integer|bool|boolean|bytes|any|object|text|varchar\(?\d*\)?)"
)

# Secrets: credentials that must never reach a model.
SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"),
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
    "slack_token": re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"),
    "openai_style_key": re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    "bearer_token": re.compile(r"(?i)\bauthorization\s*:\s*bearer\s+[A-Za-z0-9._~+/=-]{16,}"),
    # key=value style assignments; the value must look like a credential, not a placeholder.
    "password_assignment": re.compile(
        r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|비밀번호|패스워드)\b\s*[:=]\s*"
        r"(?![\"']?" + _NOT_A_VALUE + r"[\"']?(?:[\s,;)]|$))"
        r"[\"']?[^\s\"']{6,}[\"']?"
    ),
    # Short labelled passwords: "pw:1234", "비번=0000", "PIN: 4821". Only right
    # after ':' or '='; a PIN must be 4-8 digits. Words that merely contain the
    # label (compass, bypass) do not count.
    "short_password": re.compile(
        r"(?i)(?<![A-Za-z0-9_])(?:"
        r"(?:pw|pwd|pass|passwd|password|passcode|비번|암호|비밀번호|패스워드)\s*[:=]\s*[\"']?"
        r"(?!" + _NOT_A_VALUE + r"[\"']?(?:[\s,;)]|$))(?:(?![\"',;])[!-~]){4,64}(?![!-~가-힣])"
        r"|(?:pin|pin[\s_-]?code|핀번호|핀)\s*[:=]\s*[\"']?\d{4,8}(?!\d)"
        r")"
    ),
    # Korean and English sentences: "pass1234로 패스워드를 설정", "비밀번호는 qwer1234!",
    # "password is Abc12345". The value needs a letter and a digit; hash and
    # cipher names (sha256, argon2id, aes256 ...) are not passwords.
    "password_phrase": re.compile(
        r"(?i)(?:"
        r"(?:비밀번호|패스워드|비번|암호|password|passwd)\s*(?:은|는|이|가|을|를|is|:|=)?\s*[\"'“‘]?" + _PW_VALUE +
        r"|" + _PW_VALUE + r"(?=[\"'”’]?\s*(?:으로|로)\s*(?:비밀번호|패스워드|비번|암호|password|passwd))"
        r")"
    ),
}

# Personal information (Korean formats first).
PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "resident_id": re.compile(r"(?<!\d)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\s?-\s?[1-8]\d{6}(?!\d)"),
    "mobile_phone": re.compile(r"(?<!\d)01[016789][-.\s]?\d{3,4}[-.\s]?\d{4}(?!\d)"),
    "phone": re.compile(r"(?<!\d)0(?:2|[3-6][1-5]|70)[-.\s]\d{3,4}[-.\s]\d{4}(?!\d)"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "card_number": re.compile(r"(?<!\d)(?:\d{4}[-\s]?){3}\d{4}(?!\d)"),
    "passport": re.compile(r"\b[MSRODG]\d{8}\b"),
    # Names only after a label and a colon: free text ("이름을 바꿔줘") is not a name.
    "person_name": re.compile(
        r"(?i)(?<![가-힣A-Za-z])(?:성명|이름|담당자명?|대표자?|대표이사|name)\s*[:：]\s*"
        r"(?:[가-힣]{2,4}(?![가-힣])|(?-i:[A-Z][a-z]+(?:[ ][A-Z][a-z]+){1,2}))"
    ),
    # Addresses: a label followed by a value that starts in Hangul, or a road-name
    # address (시·도, 시·군·구, 로·길 and a building number) without a label.
    "address": re.compile(
        r"(?:(?:주소|소재지|거주지)\s*[:：]\s*[가-힣][^\n]{3,80}"
        # road-name address, with the 5-digit postal code in front when there is one
        r"|(?:(?<!\d)\d{5}\s*)?(?:[가-힣]{2,}(?:특별시|광역시|특별자치시|특별자치도|도|시))\s*[가-힣]{1,}(?:시|군|구)\s*"
        r"(?:[가-힣0-9]{1,}(?:구|읍|면|동)\s*)?[가-힣0-9]{1,}(?:로|길)\s*\d{1,4}(?:-\d{1,4})?[^\n,]{0,30}"
        r"|(?<!\d)\d{5}\s*[가-힣0-9]{1,}(?:로|길)\s*\d{1,4}(?:-\d{1,4})?[^\n,]{0,30}"
        # lot-number address (○○동 670): only in brackets or right after 시·군·구,
        # because many words end in 동 (이동, 활동)
        r"|\(\s*[가-힣]{1,6}(?:동|리)\s*\d{1,5}(?:-\d{1,4})?(?:번지)?(?=[\s,)])[^)\n]{0,30}\)"
        r"|[가-힣]{1,}(?:시|군|구)\s+[가-힣]{1,6}(?:동|리)\s*\d{1,5}(?:-\d{1,4})?(?:번지)?(?![가-힣0-9]))"
    ),
}


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _valid(kind: str, match: str) -> bool:
    if kind == "card_number":
        return _luhn_ok(re.sub(r"\D", "", match))
    return True


@dataclass
class Scan:
    text: str
    found: dict[str, int] = field(default_factory=dict)


def redact(
    text: str,
    patterns: dict[str, re.Pattern[str]],
    label: str,
    allow: dict[str, frozenset[str]] | None = None,
) -> Scan:
    """Replaces every match with [label:kind] and counts matches per kind.

    Values listed in `allow` for their kind (compared case-insensitively) stay.
    """
    found: dict[str, int] = {}
    for kind, pattern in patterns.items():
        keep = (allow or {}).get(kind, frozenset())

        def sub(m: re.Match[str], kind: str = kind, keep: frozenset[str] = keep) -> str:
            if not _valid(kind, m.group(0)) or m.group(0).lower() in keep:
                return m.group(0)
            found[kind] = found.get(kind, 0) + 1
            return f"[{label}:{kind}]"

        text = pattern.sub(sub, text)
    return Scan(text, found)


def find(text: str, patterns: dict[str, re.Pattern[str]]) -> dict[str, int]:
    return redact(text, patterns, "x").found


def spans(
    text: str,
    patterns: dict[str, re.Pattern[str]],
    allow: dict[str, frozenset[str]] | None = None,
) -> list[tuple[str, int, int]]:
    """(kind, start, end) of every match in the original text, for masking
    regions of an image instead of characters. Matches may overlap."""
    out = []
    for kind, pattern in patterns.items():
        keep = (allow or {}).get(kind, frozenset())
        for m in pattern.finditer(text):
            if _valid(kind, m.group(0)) and m.group(0).lower() not in keep:
                out.append((kind, m.start(), m.end()))
    return sorted(out, key=lambda x: x[1])


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

PII_ACTIONS = ("allow", "mask", "block")
SECRET_ACTIONS = ("redact", "block")
STORE_ACTIONS = ("none", "masked")

# Higher rank = stricter. Used to tell whether a profile loosens the default.
_RANK = {
    "pii": {"allow": 0, "mask": 1, "block": 2},
    "secrets": {"redact": 0, "block": 1},
    "store_prompt": {"masked": 0, "none": 1},
}


@dataclass(frozen=True)
class Profile:
    name: str
    pii: str = "mask"
    secrets: str = "block"
    store_prompt: str = "masked"

    def looser_than(self, other: "Profile") -> bool:
        return any(_RANK[k][getattr(self, k)] < _RANK[k][getattr(other, k)] for k in ("pii", "secrets"))


@dataclass(frozen=True)
class Policy:
    profiles: dict[str, Profile]
    agents: dict[str, str]
    retention_days: int = 90
    # Exact personal-data values that are never masked, per kind (lower case).
    allow: dict[str, frozenset[str]] = field(default_factory=dict)
    # User tiers from the key metadata `croak_tier`; empty means no tier checks.
    tiers: dict[str, "Tier"] = field(default_factory=dict)
    # Folders and file names whose contents never reach the model.
    deny_paths: "DenyPaths" = field(default_factory=lambda: DenyPaths())

    @property
    def default(self) -> Profile:
        return self.profiles["default"]


def load_policy(raw: dict[str, Any]) -> Policy:
    """Validates a parsed policy.yaml. Raises ValueError on any mistake."""
    profiles: dict[str, Profile] = {}
    for name, rules in (raw.get("profiles") or {}).items():
        rules = rules or {}
        unknown = set(rules) - {"pii", "secrets", "store_prompt"}
        if unknown:
            raise ValueError(f"profile {name}: unknown keys {sorted(unknown)}")
        p = Profile(name=name, **rules)
        if p.pii not in PII_ACTIONS or p.secrets not in SECRET_ACTIONS or p.store_prompt not in STORE_ACTIONS:
            raise ValueError(f"profile {name}: bad value in {rules}")
        profiles[name] = p
    if "default" not in profiles:
        raise ValueError("policy needs a 'default' profile")
    agents = {str(k): str(v) for k, v in (raw.get("agents") or {}).items()}
    for agent, profile in agents.items():
        if profile not in profiles:
            raise ValueError(f"agent {agent}: unknown profile {profile}")
    retention = int(raw.get("retention_days", 90))
    if retention < 1:
        raise ValueError("retention_days must be at least 1")
    allow: dict[str, frozenset[str]] = {}
    for kind, values in (raw.get("allow") or {}).items():
        if kind not in PII_PATTERNS:
            raise ValueError(f"allow: unknown personal-data kind {kind}; secrets cannot be allowed")
        if not isinstance(values, list) or not all(isinstance(v, str) and v.strip() for v in values):
            raise ValueError(f"allow.{kind} must be a list of exact values")
        for v in values:
            if not PII_PATTERNS[kind].fullmatch(v.strip()):
                raise ValueError(f"allow.{kind}: {v!r} is not a single {kind} value")
        allow[kind] = frozenset(v.strip().lower() for v in values)
    tiers = _load_tiers(raw.get("tiers"), profiles)
    deny_paths = _load_deny_paths(raw.get("deny_paths"))
    return Policy(profiles=profiles, agents=agents, retention_days=retention, allow=allow, tiers=tiers, deny_paths=deny_paths)


@dataclass(frozen=True)
class Decision:
    agent: str
    profile: Profile
    requested: str
    downgraded: bool


def resolve(policy: Policy, agent: str | None, granted: Iterable[str] | None) -> Decision:
    """Picks the profile for a request.

    The agent name comes from a client header and can be forged, so it may only
    tighten the rules. A profile looser than `default` applies only when the
    key's metadata grants it (`granted` contains its name or "*").
    """
    agent = (agent or "").strip() or "unknown"
    requested = policy.agents.get(agent, "default")
    profile = policy.profiles[requested]
    grants = set(granted or ())
    if profile.looser_than(policy.default) and requested not in grants and "*" not in grants:
        return Decision(agent, policy.default, requested, True)
    return Decision(agent, profile, requested, False)


# ---------------------------------------------------------------------------
# User tiers
# ---------------------------------------------------------------------------

DEFAULT_TIER = "restricted"
SECRET_SCOPES = ("new", "all")


@dataclass(frozen=True)
class Tier:
    """What one user tier may do. Patterns accept "*" and a trailing "*"."""

    name: str
    agents: tuple[str, ...] = ()
    deny_tools: tuple[str, ...] = ()
    # Looser profiles this tier may use (replaces the key's croak_profiles).
    profiles: tuple[str, ...] = ()
    # "all": a secret anywhere in the conversation blocks the request.
    secrets_scope: str = "new"
    # Every tool result must come from a call Gate signed a permit for.
    require_permits: bool = False


# Without a `tiers` section the gate behaves as before: no tier checks.
OPEN_TIER = Tier("open", agents=("*",))


def _load_tiers(raw: Any, profiles: dict[str, Profile]) -> dict[str, Tier]:
    if not raw:
        return {}
    tiers: dict[str, Tier] = {}
    for name, rules in raw.items():
        rules = rules or {}
        unknown = set(rules) - {"agents", "deny_tools", "profiles", "secrets_scope", "require_permits"}
        if unknown:
            raise ValueError(f"tier {name}: unknown keys {sorted(unknown)}")
        lists = {}
        for key in ("agents", "deny_tools", "profiles"):
            value = rules.get(key, [])
            if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
                raise ValueError(f"tier {name}: {key} must be a list of names")
            lists[key] = tuple(v.strip() for v in value)
        for profile in lists["profiles"]:
            if profile != "*" and profile not in profiles:
                raise ValueError(f"tier {name}: unknown profile {profile}")
        scope = rules.get("secrets_scope", "new")
        if scope not in SECRET_SCOPES:
            raise ValueError(f"tier {name}: secrets_scope must be one of {SECRET_SCOPES}")
        require_permits = rules.get("require_permits", False)
        if not isinstance(require_permits, bool):
            raise ValueError(f"tier {name}: require_permits must be true or false")
        tiers[str(name)] = Tier(str(name), secrets_scope=scope, require_permits=require_permits, **lists)
    if DEFAULT_TIER not in tiers:
        raise ValueError(f"tiers need a '{DEFAULT_TIER}' tier for keys without one")
    return tiers


def tier_for(policy: Policy, name: str | None) -> Tier:
    """The key's tier. A key without a known tier gets the most limited one."""
    if not policy.tiers:
        return OPEN_TIER
    return policy.tiers.get((name or "").strip()) or policy.tiers[DEFAULT_TIER]


def matches(name: str, pattern: str) -> bool:
    return pattern == "*" or (name.startswith(pattern[:-1]) if pattern.endswith("*") else name == pattern)


# ---------------------------------------------------------------------------
# Execution permits (croakcode Phase 4): which tool calls came back with a result
# ---------------------------------------------------------------------------


def _js_number(value: Any) -> Any:
    """Matches JavaScript JSON, which writes an integral float as an integer."""
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite number")
        return int(value) if value.is_integer() and abs(value) < 2**53 else value
    if isinstance(value, dict):
        return {str(k): _js_number(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_js_number(v) for v in value]
    return value


def canonical_json(value: Any) -> str:
    """Same bytes as croakcode's canonicalJson and auth/permit_core.canonical_json."""
    return json.dumps(_js_number(value), ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False)


def args_hash(args: Any) -> str:
    return hashlib.sha256(canonical_json(args).encode("utf-8")).hexdigest()


UNREADABLE_ARGS = "unreadable"


# croakcode (experimental.deferred_tools) sends most tools behind this proxy:
# tool_call {"name": <tool>, "input": <its arguments>}.
TOOL_PROXY = "tool_call"


def answered_tool_calls(messages: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Tool calls whose result the request sends back to the model.

    Each is {"tool", "args"} with the argument hash croakcode used when it
    asked for the permit. A tool_call proxy call counts as the tool it called.
    Arguments that are not JSON get UNREADABLE_ARGS, which no permit matches,
    so such a call is treated as unpermitted.
    """
    answered = {
        str(m.get("tool_call_id"))
        for m in messages
        if isinstance(m, dict) and m.get("role") == "tool" and m.get("tool_call_id")
    }
    calls: list[dict[str, str]] = []
    for message in messages:
        if not isinstance(message, dict) or message.get("role") != "assistant":
            continue
        for call in message.get("tool_calls") or []:
            if not isinstance(call, dict) or str(call.get("id")) not in answered:
                continue
            function = call.get("function") or {}
            name = str(function.get("name") or "")
            raw = function.get("arguments")
            try:
                args = json.loads(raw) if isinstance(raw, str) else raw if isinstance(raw, dict) else {}
                # croakcode's deferred-tool proxy: the permit is for the tool it
                # called, under that tool's own name and arguments.
                if name == TOOL_PROXY and isinstance(args, dict) and isinstance(args.get("name"), str) and isinstance(args.get("input"), dict):
                    name, args = args["name"], args["input"]
                digest = args_hash(args)
            except (ValueError, TypeError):
                digest = UNREADABLE_ARGS
            calls.append({"tool": name, "args": digest})
    return calls


class Denied(Exception):
    """The user's tier does not allow this agent or tool."""

    def __init__(self, code: str, reason: str, detail: list[str]):
        super().__init__(reason)
        self.code = code
        self.reason = reason
        self.detail = detail


def tool_names(tools: Any) -> list[str]:
    """Function names from an OpenAI-style `tools` list."""
    names = []
    for tool in tools or []:
        if isinstance(tool, dict):
            fn = tool.get("function") if isinstance(tool.get("function"), dict) else tool
            name = fn.get("name")
            if isinstance(name, str):
                names.append(name)
    return names


# opencode's own helpers (titles, summaries, compaction): allowed but not chosen by users.
INTERNAL_AGENTS = frozenset({"title", "summary", "compaction"})


def check_access(tier: Tier, agent: str, tools: list[str]) -> None:
    """Raises Denied when the tier does not allow the agent or any listed tool.

    The agent name is a client header and can be forged; the tool list cannot
    be dodged, because the model can only call tools the request declares.
    """
    if not any(matches(agent, p) for p in tier.agents):
        usable = [a for a in tier.agents if a not in INTERNAL_AGENTS]
        hint = f" 쓸 수 있는 에이전트: {', '.join(usable)}. opencode에서 Tab으로 바꾼다." if usable else ""
        raise Denied("agent_denied", f"{tier.name} 등급은 '{agent}' 에이전트를 쓸 수 없다.{hint}", [agent])
    denied = sorted({t for t in tools if any(matches(t, p) for p in tier.deny_tools)})
    if denied:
        raise Denied("tool_denied", f"{tier.name} 등급은 이 도구를 쓸 수 없다: {', '.join(denied)}. opencode 설정에서 끈다.", denied)


# ---------------------------------------------------------------------------
# Applying a profile to chat messages
# ---------------------------------------------------------------------------


class Blocked(Exception):
    def __init__(self, reason: str, found: dict[str, int]):
        super().__init__(reason)
        self.reason = reason
        self.found = found


def _texts(message: dict[str, Any]) -> list[tuple[Callable[[], str], Callable[[str], None]]]:
    """Getter/setter pairs for every text in a message (string or content parts)."""
    content = message.get("content")
    if isinstance(content, str):
        return [(lambda: message["content"], lambda v: message.__setitem__("content", v))]
    out = []
    if isinstance(content, list):
        for part in content:
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                out.append((lambda p=part: p["text"], lambda v, p=part: p.__setitem__("text", v)))
    return out


def _last_user_index(messages: list[dict[str, Any]]) -> int:
    for i in range(len(messages) - 1, -1, -1):
        if messages[i].get("role") == "user":
            return i
    return -1


def apply_profile(
    messages: list[dict[str, Any]],
    profile: Profile,
    allow: dict[str, frozenset[str]] | None = None,
    secrets_scope: str = "new",
) -> dict[str, dict[str, int]]:
    """Masks or redacts messages in place and returns counts per kind.

    Raises Blocked when the user's newest message breaks a `block` rule. Older
    messages and tool results are only redacted: blocking on them would lock a
    session forever once a secret slipped into its history. With
    secrets_scope "all" a secret anywhere blocks the request.
    """
    if secrets_scope == "all" and profile.secrets == "block":
        hit: dict[str, int] = {}
        for message in messages:
            for get, _ in _texts(message):
                for k, n in find(get(), SECRET_PATTERNS).items():
                    hit[k] = hit.get(k, 0) + n
        if hit:
            raise Blocked("대화에 비밀정보가 남아 있어 요청을 보내지 않았다. 새 세션에서 비밀정보 없이 다시 시작한다.", hit)
    last_user = _last_user_index(messages)
    secrets: dict[str, int] = {}
    pii: dict[str, int] = {}
    for i, message in enumerate(messages):
        newest = i == last_user
        # The allow list exists for instructions such as the commit author in
        # AGENTS.md, which reach the model in the system prompt. Everywhere else
        # (user text, tool results, attachments) listed values are masked too.
        keep = allow if message.get("role") == "system" else None
        for get, set_ in _texts(message):
            text = get()
            if newest and profile.secrets == "block":
                hit = find(text, SECRET_PATTERNS)
                if hit:
                    raise Blocked("비밀정보가 들어 있어 요청을 보내지 않았다. 키와 비밀번호를 지우고 다시 보낸다.", hit)
            if newest and profile.pii == "block":
                hit = redact(text, PII_PATTERNS, "x", keep).found
                if hit:
                    raise Blocked("이 에이전트는 개인정보를 받지 않는다. 개인정보를 지우고 다시 보낸다.", hit)
            scan = redact(text, SECRET_PATTERNS, "REDACTED")
            for k, n in scan.found.items():
                secrets[k] = secrets.get(k, 0) + n
            text = scan.text
            if profile.pii != "allow":
                scan = redact(text, PII_PATTERNS, "MASKED", keep)
                for k, n in scan.found.items():
                    pii[k] = pii.get(k, 0) + n
                text = scan.text
            if text != get():
                set_(text)
    return {"secrets": secrets, "pii": pii}


def new_turn(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Messages after the last assistant message: what this request adds."""
    for i in range(len(messages) - 1, -1, -1):
        if messages[i].get("role") == "assistant":
            return messages[i + 1 :]
    return [m for m in messages if m.get("role") != "system"]


# ---------------------------------------------------------------------------
# Images and documents in chat messages
# ---------------------------------------------------------------------------

_DATA_URL = re.compile(r"^data:([\w.+/-]+);base64,(.*)$", re.S)


@dataclass
class Media:
    """One inline image or PDF in a message, with a setter that replaces the part."""

    kind: str  # "image" | "pdf"
    data: str  # base64
    name: str
    message_index: int
    replace: Callable[[dict[str, Any]], None]
    set_data: Callable[[str], None]


def media_parts(messages: list[dict[str, Any]]) -> list[Media]:
    """Inline images (image_url data URLs) and PDFs (file parts) in the messages."""
    out: list[Media] = []
    for i, message in enumerate(messages):
        content = message.get("content")
        if not isinstance(content, list):
            continue
        for j, part in enumerate(content):
            if not isinstance(part, dict):
                continue

            def replace(new: dict[str, Any], content: list = content, j: int = j) -> None:
                content[j] = new

            if part.get("type") == "image_url" and isinstance(part.get("image_url"), dict):
                m = _DATA_URL.match(str(part["image_url"].get("url", "")))
                if m and m.group(1).startswith("image/"):
                    holder = part["image_url"]
                    out.append(Media("image", m.group(2), "image", i, replace,
                                     lambda b64, h=holder: h.__setitem__("url", f"data:image/png;base64,{b64}")))
            elif part.get("type") == "file" and isinstance(part.get("file"), dict):
                m = _DATA_URL.match(str(part["file"].get("file_data", "")))
                if m and m.group(1) == "application/pdf":
                    holder = part["file"]
                    out.append(Media("pdf", m.group(2), str(holder.get("filename") or "document.pdf"), i, replace,
                                     lambda b64, h=holder: h.__setitem__("file_data", f"data:application/pdf;base64,{b64}")))
    return out


def strip_media(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """A copy without inline data, for the archive: each image or PDF becomes a
    short placeholder with its hash."""
    import copy
    import hashlib

    out = copy.deepcopy(messages)
    for media in media_parts(out):
        digest = hashlib.sha256(media.data.encode("ascii", "ignore")).hexdigest()[:16]
        media.replace({"type": "text", "text": f"[{media.kind} {media.name} sha256:{digest} not stored]"})
    return out


# ---------------------------------------------------------------------------
# Settings the admin console may change (settings/policy-overrides.json)
# ---------------------------------------------------------------------------

MEDIA_PII_ACTIONS = ("mask", "block")


def media_pii_action(overrides: dict[str, Any] | None, tier: str) -> str:
    """How personal data in attachments is handled for a tier: "mask" (default) or "block"."""
    value = ((overrides or {}).get("media_pii") or {}).get(tier, "mask")
    return value if value in MEDIA_PII_ACTIONS else "mask"


# ---------------------------------------------------------------------------
# Blocked paths: keys, certificates and secret files
# ---------------------------------------------------------------------------

import fnmatch  # noqa: E402


@dataclass(frozen=True)
class DenyPaths:
    """Folders (whole path segments) and file-name globs. Same lists as the
    opencode plugin plugins/secret-paths.mjs."""

    dirs: tuple[str, ...] = ()
    files: tuple[str, ...] = ()

    def rule(self, value: Any) -> str | None:
        if not isinstance(value, str) or not value.strip():
            return None
        segs = [s for s in value.strip().replace("\\", "/").split("/") if s]
        for d in self.dirs:
            parts = d.split("/")
            for i in range(len(segs) - len(parts) + 1):
                if segs[i:i + len(parts)] == parts:
                    return d
        base = segs[-1] if segs else ""
        for glob in self.files:
            if fnmatch.fnmatchcase(base, glob):
                return glob
        return None


def _load_deny_paths(raw: Any) -> DenyPaths:
    if not raw:
        return DenyPaths()
    if not isinstance(raw, dict) or set(raw) - {"dirs", "files"}:
        raise ValueError("deny_paths takes dirs and files")
    out = {}
    for key in ("dirs", "files"):
        values = raw.get(key) or []
        if not isinstance(values, list) or not all(isinstance(v, str) and v.strip() for v in values):
            raise ValueError(f"deny_paths.{key} must be a list of names")
        out[key] = tuple(v.strip() for v in values)
    return DenyPaths(**out)


_SHELL_SPLIT = re.compile(r"[\s\"'`;|&<>()=,]+")
_PATH_ARGS = ("filePath", "path", "file", "include", "pattern", "directory")
_READ_TOOL_NOTE = re.compile(r"Called the Read tool with the following input: (\{.*?\})", re.S)


def denied_call(deny: DenyPaths, tool: str, args: Any) -> str | None:
    """The rule a tool call breaks: path arguments, or path-like words of a bash command."""
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except ValueError:
            return None
    if not isinstance(args, dict):
        return None
    if tool == "bash":
        for word in _SHELL_SPLIT.split(str(args.get("command") or "")):
            if word and not word.startswith("-") and (rule := deny.rule(word)):
                return rule
        return None
    for key in _PATH_ARGS:
        if rule := deny.rule(args.get(key)):
            return rule
    return None


def filter_lines(deny: DenyPaths, text: str) -> tuple[str, int]:
    """Drops lines that start with a blocked path (grep, glob and list output)."""
    removed = 0
    kept = []
    for line in text.split("\n"):
        first = re.split(r"[:\s]", line.strip(), maxsplit=1)[0] if line.strip() else ""
        if first and deny.rule(first):
            removed += 1
            continue
        kept.append(line)
    if removed:
        kept.append(f"[croak] 키, 인증서, 비밀 파일의 줄 {removed}개를 뺐다.")
    return "\n".join(kept), removed


def apply_deny_paths(messages: list[dict[str, Any]], deny: DenyPaths) -> dict[str, Any]:
    """Keeps blocked files out of the request, in place.

    - a tool result whose call targets a blocked path is replaced,
    - lines naming blocked files are dropped from other tool results,
    - an attachment opencode read from a blocked path is replaced.
    Returns {"blocked": n, "lines": n, "fresh": n, "rules": [...]}.
    """
    out = {"blocked": 0, "lines": 0, "fresh": 0, "rules": []}
    if not deny.dirs and not deny.files:
        return out
    last_assistant = max((i for i, m in enumerate(messages) if m.get("role") == "assistant"), default=-1)
    calls: dict[str, str] = {}
    for message in messages:
        for call in message.get("tool_calls") or []:
            fn = call.get("function") or {}
            if rule := denied_call(deny, str(fn.get("name") or ""), fn.get("arguments")):
                calls[str(call.get("id"))] = rule

    def hit(i: int, rule: str) -> None:
        out["blocked"] += 1
        out["rules"].append(rule)
        if i > last_assistant:
            out["fresh"] += 1

    for i, message in enumerate(messages):
        role = message.get("role")
        if role == "tool":
            rule = calls.get(str(message.get("tool_call_id")))
            if rule:
                message["content"] = f"[croak] 키, 인증서, 비밀 파일({rule})의 내용이라 보내지 않았다."
                hit(i, rule)
                continue
            for get, set_ in _texts(message):
                text, n = filter_lines(deny, get())
                if n:
                    set_(text)
                    out["lines"] += n
                    if i > last_assistant:
                        out["fresh"] += 1
        elif role == "user" and isinstance(message.get("content"), list):
            # opencode puts files read by its Read tool into a user message,
            # after a note with the call's input.
            for part in message["content"]:
                if isinstance(part, dict) and part.get("type") == "text":
                    m = _READ_TOOL_NOTE.search(part.get("text") or "")
                    if m and (rule := denied_call(deny, "read", m.group(1))):
                        message["content"] = [{"type": "text", "text": f"[croak] 키, 인증서, 비밀 파일({rule})이라 첨부를 보내지 않았다."}]
                        hit(i, rule)
                        break
    return out
