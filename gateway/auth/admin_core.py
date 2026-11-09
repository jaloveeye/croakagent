"""Reading croak-gate's JSONL records and turning them into statistics and alerts.

    $CROAK_DATA/audit/YYYY-MM-DD.jsonl    guardrail decisions (no message text)
    $CROAK_DATA/usage/YYYY-MM-DD.jsonl    tokens per successful call
    $CROAK_DATA/archive/YYYY-MM-DD.jsonl  masked prompts and answers

Pure functions over lists of dicts, so they are unit-tested without the web app.
"""
from __future__ import annotations

import json
import os
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta
from typing import Any, Iterable, Iterator
from zoneinfo import ZoneInfo

DATA_DIR = os.environ.get("CROAK_DATA", "/data")

# Alert thresholds (docs/auth.md).
BLOCKS_PER_HOUR = 3
SECRETS_IN_HISTORY_PER_DAY = 5
LOGIN_FAILURES_PER_DAY = 10
BYPASS = ("tool_denied",)  # declared a tool the tier forbids
CONFIG = ("agent_denied",)  # usually an opencode setup that does not fit the tier

VIOLATION_NAMES = {
    "secret": "비밀정보 거부",
    "pii": "개인정보 거부",
    "agent_denied": "허용되지 않은 에이전트",
    "tool_denied": "금지 도구",
    "secret_in_history": "도구 결과와 첨부의 비밀정보",
    "downgraded": "권한 없는 정책 요청",
    "foreign_session": "다른 계정의 대화",
    "path_blocked": "키, 인증서, 비밀 파일 접근",
}


def days(start: date, end: date) -> list[date]:
    return [start + timedelta(days=i) for i in range((end - start).days + 1)]


def read(kind: str, start: date, end: date, data_dir: str | None = None) -> Iterator[dict[str, Any]]:
    """Records of one kind between two dates, oldest first. Broken lines are skipped."""
    base = os.path.join(data_dir or DATA_DIR, kind)
    for day in days(start, end):
        path = os.path.join(base, f"{day.isoformat()}.jsonl")
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        try:
                            yield json.loads(line)
                        except ValueError:
                            continue
        except FileNotFoundError:
            continue


KST = ZoneInfo("Asia/Seoul")


def kst_day(ts: Any) -> str:
    """The Korean calendar day of an ISO timestamp (files are named in UTC)."""
    try:
        t = datetime.fromisoformat(str(ts))
    except ValueError:
        return str(ts)[:10]
    return (t.astimezone(KST) if t.tzinfo else t).date().isoformat()


def kst_time(ts: Any) -> str:
    """MM-DD HH:MM:SS in Korean time."""
    try:
        t = datetime.fromisoformat(str(ts))
    except ValueError:
        return str(ts)
    return (t.astimezone(KST) if t.tzinfo else t).strftime("%m-%d %H:%M:%S")


def _day(record: dict[str, Any]) -> str:
    return kst_day(record.get("ts", ""))


def read_kst(kind: str, start: date, end: date, data_dir: str | None = None) -> list[dict[str, Any]]:
    """Records whose Korean day is within [start, end]. Reads one extra file each side."""
    lo, hi = start.isoformat(), end.isoformat()
    return [r for r in read(kind, start - timedelta(days=1), end + timedelta(days=1), data_dir) if lo <= _day(r) <= hi]


def _who(record: dict[str, Any]) -> str:
    return str(record.get("user") or record.get("key_alias") or "unknown")


def _tokens(record: dict[str, Any]) -> int:
    usage = record.get("usage") or {}
    total = usage.get("total_tokens")
    if isinstance(total, int):
        return total
    return sum(v for k, v in usage.items() if k in ("prompt_tokens", "completion_tokens") and isinstance(v, int))


def stats(audit: Iterable[dict], usage: Iterable[dict]) -> dict[str, Any]:
    """Requests and blocks from the audit log; tokens from the usage log."""
    per_day: dict[str, Counter] = defaultdict(Counter)
    per_user: dict[str, Counter] = defaultdict(Counter)
    per_agent: dict[str, Counter] = defaultdict(Counter)
    per_model: dict[str, Counter] = defaultdict(Counter)
    for r in audit:
        if r.get("action") in (None, "archive_error"):
            continue
        blocked = r.get("action") == "block" or r.get("action") == "error"
        for table, key in ((per_day, _day(r)), (per_user, _who(r)), (per_agent, str(r.get("agent") or "unknown")),
                           (per_model, str(r.get("model") or "-"))):
            table[key]["requests"] += 1
            if blocked:
                table[key]["blocked"] += 1
            if r.get("violation"):
                table[key]["violations"] += 1
    for r in usage:
        n = _tokens(r)
        for table, key in ((per_day, _day(r)), (per_user, _who(r)), (per_agent, str(r.get("agent") or "unknown")),
                           (per_model, str(r.get("model") or "-"))):
            table[key]["tokens"] += n

    def rows(table: dict[str, Counter], sort_by_key: bool = False) -> list[dict[str, Any]]:
        out = [{"key": k, **{f: v.get(f, 0) for f in ("requests", "blocked", "violations", "tokens")}} for k, v in table.items()]
        return sorted(out, key=lambda x: x["key"]) if sort_by_key else sorted(out, key=lambda x: (-x["requests"], x["key"]))

    totals = Counter()
    for v in per_day.values():
        totals.update(v)
    return {
        "totals": {f: totals.get(f, 0) for f in ("requests", "blocked", "violations", "tokens")},
        "days": rows(per_day, sort_by_key=True),
        "users": rows(per_user),
        "agents": rows(per_agent),
        "models": rows(per_model),
    }


def violations(audit: Iterable[dict]) -> list[dict[str, Any]]:
    return [r for r in audit if r.get("violation")]


def _ts(record: dict[str, Any]) -> datetime | None:
    try:
        return datetime.fromisoformat(str(record.get("ts")))
    except ValueError:
        return None


def alerts(audit: Iterable[dict], login_failures: Iterable[dict] = ()) -> list[dict[str, Any]]:
    """Alert rules from docs/auth.md. Each alert names the user and the evidence."""
    out: list[dict[str, Any]] = []
    blocks: dict[str, list[datetime]] = defaultdict(list)
    history: Counter = Counter()
    for r in audit:
        who = _who(r)
        code = r.get("violation")
        if code in CONFIG:
            out.append({"rule": "config", "user": who, "day": _day(r), "ts": r.get("ts"),
                        "detail": f"등급에 없는 에이전트 {r.get('agent')}"})
        if code == "path_blocked":
            # The opencode plugin blocks these locally; reaching the gate means it is missing or off.
            out.append({"rule": "config", "user": who, "day": _day(r), "ts": r.get("ts"),
                        "detail": f"키, 인증서, 비밀 파일을 읽음 ({', '.join((r.get('paths') or {}).get('rules') or [])}). opencode 플러그인 확인"})
        if code == "foreign_session":
            out.append({"rule": "foreign_session", "user": who, "day": _day(r), "ts": r.get("ts"),
                        "detail": f"{', '.join(r.get('denied') or [])}의 세션으로 요청"})
        if code in BYPASS:
            out.append({"rule": "bypass", "user": who, "day": _day(r), "ts": r.get("ts"),
                        "detail": f"{VIOLATION_NAMES[code]}: {', '.join(r.get('denied') or [])} (에이전트 {r.get('agent')})"})
        if r.get("action") == "block" and (t := _ts(r)):
            blocks[who].append(t)
        if code == "secret_in_history":
            history[(who, _day(r))] += 1
    for who, times in blocks.items():
        times.sort()
        start = 0
        flagged_until: datetime | None = None
        for end, t in enumerate(times):
            while t - times[start] > timedelta(hours=1):
                start += 1
            if end - start + 1 >= BLOCKS_PER_HOUR and (flagged_until is None or t > flagged_until):
                out.append({"rule": "repeated", "user": who, "day": t.date().isoformat(), "ts": t.isoformat(),
                            "detail": f"1시간 안에 거부 {end - start + 1}회"})
                flagged_until = times[start] + timedelta(hours=1)
    for (who, day), n in history.items():
        if n >= SECRETS_IN_HISTORY_PER_DAY:
            out.append({"rule": "secret_leak", "user": who, "day": day, "ts": day, "detail": f"이전 대화에서 비밀정보 {n}회"})
    failures: Counter = Counter()
    for e in login_failures:
        failures[(str(e.get("subject") or "unknown"), kst_day(e.get("ts")))] += 1
    for (who, day), n in failures.items():
        if n >= LOGIN_FAILURES_PER_DAY:
            out.append({"rule": "login_attack", "user": who, "day": day, "ts": day, "detail": f"로그인 실패 {n}회"})
    return sorted(out, key=lambda a: str(a["ts"]), reverse=True)


RULE_NAMES = {
    "bypass": "우회 시도",
    "config": "설정 확인 필요",
    "foreign_session": "다른 계정의 대화",
    "repeated": "반복 위반",
    "secret_leak": "비밀정보 유출 의심",
    "login_attack": "로그인 공격 의심",
}


def archive_matches(record: dict[str, Any], user: str = "", agent: str = "", text: str = "") -> bool:
    if user and _who(record) != user:
        return False
    if agent and record.get("agent") != agent:
        return False
    if text:
        blob = json.dumps(record.get("input"), ensure_ascii=False) + str(record.get("output") or "")
        return text.lower() in blob.lower()
    return True


def message_text(message: dict[str, Any]) -> str:
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for p in content:
            if isinstance(p, dict):
                parts.append(p.get("text") if isinstance(p.get("text"), str) else f"[{p.get('type', 'part')}]")
        return "\n".join(parts)
    calls = message.get("tool_calls")
    if calls:
        return "[tool_calls: " + ", ".join(str((c.get("function") or {}).get("name")) for c in calls if isinstance(c, dict)) + "]"
    return ""
