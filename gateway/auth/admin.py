"""Admin console at /admin for the `admin` and `auditor` roles.

    /admin              alerts and today's numbers
    /admin/prompts      masked prompt archive (every view is recorded)
    /admin/stats        requests, blocks and tokens by day, user, agent, model
    /admin/violations   alerts and violation records
    /admin/events       admin audit trail (logins, account changes, archive views)
    /admin/users        accounts (admin only)

Server-rendered HTML without JavaScript. Every form carries a per-session
CSRF token; the session cookie is HttpOnly, Secure, SameSite=Strict, ends
after 30 idle minutes or 8 hours.
"""
from __future__ import annotations

import html
import json
import os
import secrets
from datetime import date, datetime, timedelta
from typing import Any, Callable

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

import admin_core as ac
import auth_core as core
import auth_db as db
import yaml
from app import CSP, POLICY_PATH, STYLE, authenticate, client_ip, end_session, hasher, now, revoke_chat_key, revoke_chat_keys

router = APIRouter()
COOKIE = "croak_admin"
IDLE = timedelta(minutes=30)
ABSOLUTE = timedelta(hours=8)
MAX_ROWS = 200
h = html.escape

ADMIN_STYLE = STYLE + """
main{max-width:1100px}body{display:block;padding:24px 16px}main{margin:0 auto}
nav{display:flex;flex-wrap:wrap;gap:12px;align-items:center;margin-bottom:20px;font-size:14px}
nav a{color:inherit;text-decoration:none;padding:4px 8px;border-radius:6px}nav a.on{background:#2f8a3a;color:#fff}
nav .me{margin-left:auto;color:#5b6b5d}nav form{display:inline}nav button{margin:0;width:auto;padding:4px 10px;font-size:13px}
table{border-collapse:collapse;width:100%;font-size:13px;margin:8px 0 20px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #dfe6df;vertical-align:top}
th{font-weight:600;color:#5b6b5d}td.n{text-align:right;font-variant-numeric:tabular-nums}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin:12px 0 20px}.card{flex:1 1 140px;border:1px solid #dfe6df;border-radius:10px;padding:12px}
.card b{display:block;font-size:22px}a.card,a.alert{display:block;color:inherit;text-decoration:none}a.card:hover{border-color:#2f8a3a}a.alert:hover{text-decoration:underline}.alert{background:#fdecea;color:#8a1c12;border-radius:8px;padding:8px 12px;margin:6px 0;font-size:14px}
.ok{background:#e9f6ea;color:#1f5f28;border-radius:8px;padding:8px 12px;font-size:14px}
form.inline{display:flex;flex-wrap:wrap;gap:8px;align-items:end;margin:8px 0}form.inline label{margin:0;font-size:12px}
form.inline input,form.inline select{width:auto;padding:6px;font-size:14px}form.inline button{width:auto;margin:0;padding:7px 12px;font-size:14px}
details{border-bottom:1px solid #dfe6df;padding:6px 0}summary{cursor:pointer;font-size:13px}
pre{white-space:pre-wrap;word-break:break-word;background:#f4f6f4;border-radius:6px;padding:8px;font-size:12px;margin:4px 0}
.bar{display:inline-block;height:8px;background:#2f8a3a;border-radius:4px;vertical-align:middle}
.tag{display:inline-block;padding:1px 6px;border-radius:4px;background:#eef2ee;font-size:12px}
.pw{display:inline-flex;align-items:center;gap:2px}.pw input{width:12em}
button.eye{width:auto;margin:0;padding:5px 7px;background:transparent;color:inherit;border:1px solid #c5d0c6;font-size:14px;line-height:1}
@media (prefers-color-scheme: dark){th,td,details,.card{border-color:#3a4a3c}pre{background:#121a13}.tag{background:#24342a}.alert{background:#4a1d18;color:#ffd9d4}.ok{background:#1d3a22;color:#cdeccf}}
"""

NAV = [
    ("/admin", "대시보드", None),
    ("/admin/prompts", "프롬프트 기록", None),
    ("/admin/stats", "통계", None),
    ("/admin/violations", "위반", None),
    ("/admin/events", "관리 감사", None),
    ("/admin/policy", "정책", None),
    ("/admin/users", "사용자", "admin"),
    ("/admin/chat-keys", "대화 전용 키", "admin"),
]


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------


class Ctx:
    def __init__(self, user: dict, csrf: str):
        self.user = user
        self.csrf = csrf

    @property
    def name(self) -> str:
        return self.user["username"]

    def has(self, role: str) -> bool:
        return role in (self.user["roles"] or [])


def _session(request: Request, conn) -> Ctx | None:
    token = request.cookies.get(COOKIE, "")
    if not token:
        return None
    row = conn.execute("SELECT * FROM admin_sessions WHERE id_hash = %s AND ended_at IS NULL", (core.token_hash(token),)).fetchone()
    t = now()
    if not row or t - row["last_seen"] > IDLE or t - row["created_at"] > ABSOLUTE:
        return None
    user = db.user_by_id(conn, row["user_id"])
    if not user or user["disabled"] or not set(user["roles"] or []) & {"admin", "auditor"}:
        return None
    conn.execute("UPDATE admin_sessions SET last_seen = %s WHERE id_hash = %s", (t, row["id_hash"]))
    return Ctx(user, row["csrf"])


def _guarded(request: Request, role: str | None, render: Callable[[Any, Ctx], HTMLResponse | RedirectResponse]):
    with db.connect() as conn:
        ctx = _session(request, conn)
        if not ctx:
            return RedirectResponse("/admin/login", status_code=303)
        if role and not ctx.has(role):
            return layout(ctx, "권한 없음", "<h1>권한 없음</h1><p>이 화면은 관리자만 볼 수 있습니다.</p>", status=403)
        return render(conn, ctx)


def _csrf_ok(ctx: Ctx, token: str) -> bool:
    return bool(token) and secrets.compare_digest(ctx.csrf, token)


def layout(ctx: Ctx | None, title: str, body: str, active: str = "", status: int = 200) -> HTMLResponse:
    nav = ""
    if ctx:
        links = "".join(
            f"<a href='{href}' class='{'on' if href == active else ''}'>{label}</a>"
            for href, label, role in NAV
            if not role or ctx.has(role)
        )
        roles = ", ".join({"admin": "관리자", "auditor": "보안 담당"}.get(r, r) for r in ctx.user["roles"] or [])
        nav = (
            f"<nav>{links}<span class='me'>{h(ctx.name)} ({h(roles)})</span>"
            f"<form method='post' action='/admin/logout'><input type='hidden' name='csrf' value='{h(ctx.csrf)}'>"
            f"<button type='submit'>로그아웃</button></form></nav>"
        )
    nonce = secrets.token_urlsafe(16)
    response = HTMLResponse(
        "<!doctype html><html lang='ko'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{h(title)} · croak 관리</title><style>{ADMIN_STYLE}</style></head><body><main>{nav}{body}</main>"
        f"<script nonce='{nonce}'>{PAGE_SCRIPT}</script></body></html>",
        status_code=status,
    )
    response.headers["Content-Security-Policy"] = CSP.replace("default-src 'none';", f"default-src 'none'; script-src 'nonce-{nonce}';")
    return response


# Show/hide buttons for password fields, and a mismatch hint before submit.
# The server checks the confirmation itself; this only saves a round trip.
PAGE_SCRIPT = """
document.querySelectorAll('button.eye').forEach((b) => b.addEventListener('click', () => {
  const input = b.previousElementSibling;
  const show = input.type === 'password';
  input.type = show ? 'text' : 'password';
  b.setAttribute('aria-pressed', String(show));
  b.setAttribute('aria-label', show ? '비밀번호 숨기기' : '비밀번호 보기');
  b.textContent = show ? '🙈' : '👁';
}));
document.querySelectorAll('form').forEach((f) => f.addEventListener('submit', (e) => {
  const pw = f.querySelector('input[name=password]');
  const again = f.querySelector('input[name=password_confirm]');
  if (pw && again && pw.value !== again.value) {
    e.preventDefault();
    again.setCustomValidity('두 비밀번호가 다릅니다.');
    again.reportValidity();
    again.addEventListener('input', () => again.setCustomValidity(''), { once: true });
  }
}));
"""


def pw_field(name: str, placeholder: str, required: bool = True) -> str:
    """A password input with a show/hide button right after it."""
    req = " required minlength='12'" if required else ""
    return (
        f"<span class='pw'><input type='password' name='{name}' placeholder='{h(placeholder)}' autocomplete='new-password'{req}>"
        "<button type='button' class='eye' aria-label='비밀번호 보기' aria-pressed='false'>👁</button></span>"
    )


def _today() -> date:
    return now().astimezone(core.KST).date()


def _date(value: str, default: date) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError:
        return default


def _span(value: str) -> int:
    return 30 if value == "30" else 7


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------


@router.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse("/admin", status_code=303)


def _login_page(error: str = "", username: str = "", status: int = 200) -> HTMLResponse:
    err = f"<p class='alert'>{h(error)}</p>" if error else ""
    return layout(
        None,
        "관리 로그인",
        f"""<h1>croak 관리</h1><p class='muted'>관리자와 보안 담당 계정으로 로그인합니다.</p>{err}
<form method='post' action='/admin/login' style='max-width:360px'>
<label for='u'>아이디</label><input id='u' name='username' autocomplete='username' value='{h(username)}' required autofocus>
<label for='p'>비밀번호</label><input id='p' name='password' type='password' autocomplete='current-password' required>
<button type='submit'>로그인</button></form>""",
        status=status,
    )


@router.get("/admin/login")
def admin_login_page() -> HTMLResponse:
    return _login_page()


@router.post("/admin/login")
def admin_login(request: Request, username: str = Form(""), password: str = Form("")):
    # SameSite=Strict cookies and Origin checks guard the other forms; this one
    # creates the session, so it checks the Origin header directly.
    origin = request.headers.get("origin")
    if origin and origin.rstrip("/") != f"{request.url.scheme}://{request.url.netloc}":
        return _login_page("다른 사이트에서 보낸 요청이라 거부했습니다.", status=400)
    username = username.strip().lower()
    ip = client_ip(request)
    with db.connect() as conn:
        user, error, status = authenticate(conn, username, password, ip, now())
        if not user:
            return _login_page(error, username, status)
        if not set(user["roles"] or []) & {"admin", "auditor"}:
            db.event(conn, "admin_login_denied", subject=username, ip=ip)
            return _login_page("관리 권한이 없는 계정입니다.", username, 403)
        token = secrets.token_urlsafe(32)
        conn.execute(
            "INSERT INTO admin_sessions (id_hash, user_id, csrf) VALUES (%s, %s, %s)",
            (core.token_hash(token), user["id"], secrets.token_urlsafe(24)),
        )
        db.event(conn, "admin_login", actor=username, ip=ip)
    response = RedirectResponse("/admin", status_code=303)
    response.set_cookie(COOKIE, token, httponly=True, secure=True, samesite="strict", path="/", max_age=int(ABSOLUTE.total_seconds()))
    return response


@router.post("/admin/logout")
def admin_logout(request: Request, csrf: str = Form("")):
    with db.connect() as conn:
        ctx = _session(request, conn)
        if ctx and _csrf_ok(ctx, csrf):
            conn.execute("UPDATE admin_sessions SET ended_at = now() WHERE id_hash = %s",
                         (core.token_hash(request.cookies.get(COOKIE, "")),))
            db.event(conn, "admin_logout", actor=ctx.name, ip=client_ip(request))
    response = RedirectResponse("/admin/login", status_code=303)
    response.delete_cookie(COOKIE, path="/")
    return response


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------


def _alerts_html(alerts: list[dict]) -> str:
    if not alerts:
        return "<p class='ok'>경보가 없습니다.</p>"
    return "".join(
        f"<a class='alert' href='/admin/violations?user={h(a['user'])}&day={h(str(a['day']))}'>"
        f"<b>{h(ac.RULE_NAMES.get(a['rule'], a['rule']))}</b> · {h(a['user'])} · {h(str(a['day']))} · {h(a['detail'])}</a>"
        for a in alerts[:50]
    )


def _login_failures(conn, start: date, end: date) -> list[dict]:
    lo = datetime.combine(start, datetime.min.time(), core.KST)
    hi = datetime.combine(end + timedelta(days=1), datetime.min.time(), core.KST)
    rows = conn.execute("SELECT ts, subject FROM events WHERE kind = 'login_failed' AND ts >= %s AND ts < %s", (lo, hi)).fetchall()
    return [{"ts": r["ts"].isoformat(), "subject": r["subject"]} for r in rows]


def _cards(totals: dict, links: dict[str, str] | None = None) -> str:
    """Number cards. With links, each card opens the matching list."""
    items = [("요청", totals["requests"]), ("거부", totals["blocked"]), ("위반", totals["violations"]), ("토큰", totals["tokens"])]
    out = []
    for label, value in items:
        inner = f"{label}<b>{value:,}</b>"
        href = (links or {}).get(label)
        out.append(f"<a class='card' href='{h(href)}'>{inner}</a>" if href else f"<div class='card'>{inner}</div>")
    return "<div class='cards'>" + "".join(out) + "</div>"


@router.get("/admin")
def dashboard(request: Request):
    def render(conn, ctx: Ctx):
        today = _today()
        week = today - timedelta(days=6)
        audit = ac.read_kst("audit", week, today)
        alerts = ac.alerts(audit, _login_failures(conn, week, today))
        today_stats = ac.stats([r for r in audit if ac.kst_day(r.get("ts")) == today.isoformat()],
                               ac.read_kst("usage", today, today))
        open_sessions = conn.execute("SELECT count(*) AS n FROM sessions WHERE ended_at IS NULL AND expires_at > now()").fetchone()["n"]
        body = (
            f"<h1>대시보드</h1><h2>경보 (최근 7일)</h2>{_alerts_html(alerts)}"
            f"<h2>오늘 ({today.isoformat()})</h2>"
            + _cards(today_stats["totals"], {
                "요청": f"/admin/prompts?day={today.isoformat()}",
                "거부": f"/admin/violations?day={today.isoformat()}&only=block",
                "위반": f"/admin/violations?day={today.isoformat()}",
                "토큰": "/admin/stats",
            })
            + f"<p class='muted'>로그인 중인 세션 {open_sessions}개</p>"
        )
        return layout(ctx, "대시보드", body, "/admin")

    return _guarded(request, None, render)


@router.get("/admin/prompts")
def prompts(request: Request, day: str = "", user: str = "", agent: str = "", q: str = ""):
    def render(conn, ctx: Ctx):
        d = _date(day, _today())
        rows = [r for r in ac.read_kst("archive", d, d) if ac.archive_matches(r, user.strip(), agent.strip(), q.strip())]
        rows.reverse()
        shown = rows[:MAX_ROWS]
        db.event(conn, "archive_viewed", actor=ctx.name, ip=client_ip(request),
                 day=d.isoformat(), user=user or None, agent=agent or None, query=bool(q), shown=len(shown))
        items = []
        for r in shown:
            usage = r.get("usage") or {}
            messages = "".join(
                f"<div class='muted'>{h(str(m.get('role')))}</div><pre>{h(ac.message_text(m))}</pre>" for m in r.get("input") or []
            )
            media_html = "".join(
                f"<div class='muted'>이미지 {h(str(m.get('name')))} sha256:{h(str(m.get('sha256')))}에서 읽은 글자 (원본은 저장하지 않음)</div>"
                f"<pre>{h(str(m.get('text') or ''))}</pre>"
                for m in r.get("media_text") or []
            )
            items.append(
                f"<details><summary>{h(str(r.get('ts', ''))[11:19])} UTC · <b>{h(str(r.get('user') or '-'))}</b> · "
                f"<span class='tag'>{h(str(r.get('agent')))}</span> · {h(str(r.get('model')))} · "
                f"토큰 {usage.get('total_tokens') or '-'} · {r.get('duration_ms', '-')}ms</summary>"
                f"{messages}{media_html}<div class='muted'>답변</div><pre>{h(str(r.get('output') or ''))}</pre></details>"
            )
        more = f"<p class='muted'>최근 {MAX_ROWS}건만 보입니다. 조건을 좁히세요.</p>" if len(rows) > MAX_ROWS else ""
        body = (
            "<h1>프롬프트 기록</h1><p class='muted'>개인정보와 비밀정보를 가린 뒤의 기록입니다. 이 화면을 연 기록은 관리 감사에 남습니다.</p>"
            f"<form class='inline' method='get'><label>날짜<br><input type='date' name='day' value='{d.isoformat()}'></label>"
            f"<label>사용자<br><input name='user' value='{h(user)}'></label><label>에이전트<br><input name='agent' value='{h(agent)}'></label>"
            f"<label>내용 검색<br><input name='q' value='{h(q)}'></label><button type='submit'>찾기</button></form>"
            f"<p>{len(rows)}건</p>{''.join(items) or '<p class=muted>기록이 없습니다.</p>'}{more}"
        )
        return layout(ctx, "프롬프트 기록", body, "/admin/prompts")

    return _guarded(request, None, render)


def _table(title: str, rows: list[dict], key_label: str) -> str:
    peak = max([r["requests"] for r in rows] or [1]) or 1
    body = "".join(
        f"<tr><td>{h(str(r['key']))}</td><td class='n'>{r['requests']:,} <span class='bar' style='width:{int(60 * r['requests'] / peak)}px'></span></td>"
        f"<td class='n'>{r['blocked']:,}</td><td class='n'>{r['violations']:,}</td><td class='n'>{r['tokens']:,}</td></tr>"
        for r in rows
    )
    return (f"<h2>{title}</h2><table><tr><th>{key_label}</th><th>요청</th><th>거부</th><th>위반</th><th>토큰</th></tr>"
            f"{body or '<tr><td colspan=5>없음</td></tr>'}</table>")


@router.get("/admin/stats")
def stats_page(request: Request, span: str = "7"):
    def render(conn, ctx: Ctx):
        n = _span(span)
        end = _today()
        start = end - timedelta(days=n - 1)
        s = ac.stats(ac.read_kst("audit", start, end), ac.read_kst("usage", start, end))
        switch = " · ".join(f"<a href='?span={v}'>{v}일</a>" if v != n else f"<b>{v}일</b>" for v in (7, 30))
        body = (
            f"<h1>통계</h1><p>{start.isoformat()} ~ {end.isoformat()} · {switch}</p>{_cards(s['totals'])}"
            + _table("날짜별", s["days"], "날짜")
            + _table("사용자별", s["users"], "사용자")
            + _table("에이전트별", s["agents"], "에이전트")
            + _table("모델별", s["models"], "모델")
        )
        return layout(ctx, "통계", body, "/admin/stats")

    return _guarded(request, None, render)


@router.get("/admin/violations")
def violations_page(request: Request, span: str = "7", day: str = "", only: str = "", user: str = ""):
    def render(conn, ctx: Ctx):
        n = _span(span)
        end = _today()
        start = end - timedelta(days=n - 1)
        if day:
            start = end = _date(day, end)
        audit = ac.read_kst("audit", start, end)
        alerts = [a for a in ac.alerts(audit, _login_failures(conn, start, end)) if not user or a["user"] == user]
        if only == "block":
            picked = [r for r in audit if r.get("action") in ("block", "error")]
        else:
            picked = ac.violations(audit)
        if user:
            picked = [r for r in picked if str(r.get("user") or r.get("key_alias") or "") == user]
        found = list(reversed(picked))[:MAX_ROWS]
        rows = "".join(
            f"<tr><td>{h(ac.kst_time(r.get('ts')))}</td><td>{h(str(r.get('user') or r.get('key_alias') or '-'))}</td>"
            f"<td>{h(str(r.get('tier') or '-'))}</td><td>{h(str(r.get('agent') or '-'))}</td>"
            f"<td><span class='tag'>{h(ac.VIOLATION_NAMES.get(r.get('violation'), r.get('violation') or r.get('error') or '-'))}</span></td>"
            f"<td>{h(r.get('action', ''))}</td><td>{h(json.dumps(r.get('denied') or r.get('found') or r.get('fresh_secrets') or r.get('secrets') or {}, ensure_ascii=False))}</td></tr>"
            for r in found
        )
        switch = " · ".join(f"<a href='?span={v}'>{v}일</a>" if (v != n or day) else f"<b>{v}일</b>" for v in (7, 30))
        filters = [f for f in (f"날짜 {start.isoformat()}" if day else "", "거부만" if only == "block" else "",
                               f"사용자 {user}" if user else "") if f]
        shown = f" · 조건: {h(', '.join(filters))} · <a href='/admin/violations'>조건 지우기</a>" if filters else ""
        title = "거부된 요청" if only == "block" else "위반 기록"
        body = (
            f"<h1>위반</h1><p>{start.isoformat()} ~ {end.isoformat()} · {switch}{shown}</p><h2>경보</h2>{_alerts_html(alerts)}"
            f"<h2>{title}</h2><p class='muted'>시각은 한국 시간입니다. 메시지 본문은 감사 기록에 남지 않습니다. 찾은 항목의 종류와 개수만 보입니다.</p>"
            "<table><tr><th>시각</th><th>사용자</th><th>등급</th><th>에이전트</th><th>위반</th><th>처리</th><th>내용</th></tr>"
            f"{rows or '<tr><td colspan=7>없음</td></tr>'}</table>"
        )
        return layout(ctx, "위반", body, "/admin/violations")

    return _guarded(request, None, render)


EVENT_NAMES = {
    "login_ok": "opencode 로그인", "login_failed": "로그인 실패", "login_locked": "잠긴 계정 로그인 시도",
    "login_blocked_ip": "IP 차단", "session_started": "세션 시작", "session_ended": "세션 종료",
    "token_refreshed": "토큰 갱신", "code_rejected": "확인 코드 거부", "admin_login": "관리 로그인",
    "admin_logout": "관리 로그아웃", "admin_login_denied": "관리 권한 없는 로그인", "archive_viewed": "프롬프트 기록 열람",
    "user_created": "사용자 생성", "password_changed": "비밀번호 변경", "tier_changed": "등급 변경",
    "roles_changed": "관리 권한 변경", "user_locked": "계정 잠금", "user_unlocked": "잠금 해제",
    "policy_changed": "정책 변경",
}


@router.get("/admin/events")
def events_page(request: Request, span: str = "7", kind: str = ""):
    def render(conn, ctx: Ctx):
        n = _span(span)
        since = now() - timedelta(days=n)
        rows = conn.execute(
            "SELECT * FROM events WHERE ts > %s AND (%s = '' OR kind = %s) ORDER BY ts DESC LIMIT 500", (since, kind, kind)
        ).fetchall()
        options = "".join(f"<option value='{k}' {'selected' if k == kind else ''}>{v}</option>" for k, v in EVENT_NAMES.items())
        body = (
            "<h1>관리 감사</h1><p class='muted'>로그인, 계정 변경, 프롬프트 기록 열람을 남깁니다. 이 화면에서는 지울 수 없습니다.</p>"
            f"<form class='inline' method='get'><label>기간<br><select name='span'><option value='7'>7일</option>"
            f"<option value='30' {'selected' if n == 30 else ''}>30일</option></select></label>"
            f"<label>종류<br><select name='kind'><option value=''>전체</option>{options}</select></label><button type='submit'>보기</button></form>"
            "<table><tr><th>시각 (KST)</th><th>종류</th><th>누가</th><th>대상</th><th>IP</th><th>내용</th></tr>"
            + "".join(
                f"<tr><td>{h(r['ts'].astimezone(core.KST).strftime('%m-%d %H:%M:%S'))}</td><td>{h(EVENT_NAMES.get(r['kind'], r['kind']))}</td>"
                f"<td>{h(r['actor'] or '-')}</td><td>{h(r['subject'] or '-')}</td><td>{h(r['ip'] or '-')}</td>"
                f"<td>{h(json.dumps(r['detail'], ensure_ascii=False) if r['detail'] else '')}</td></tr>"
                for r in rows
            )
            + "</table>"
        )
        return layout(ctx, "관리 감사", body, "/admin/events")

    return _guarded(request, None, render)


# ---------------------------------------------------------------------------
# Users (admin only)
# ---------------------------------------------------------------------------

TIER_NAMES = {"full": "전체", "standard": "일반", "restricted": "제한"}


def _users_page(conn, ctx: Ctx, message: str = "", error: str = "", status: int = 200) -> HTMLResponse:
    users = conn.execute(
        """SELECT u.*, count(s.id) FILTER (WHERE s.ended_at IS NULL AND s.expires_at > now()) AS open
             FROM users u LEFT JOIN sessions s ON s.user_id = u.id GROUP BY u.id ORDER BY u.username"""
    ).fetchall()
    tier_opts = lambda cur: "".join(f"<option value='{t}' {'selected' if t == cur else ''}>{TIER_NAMES[t]}</option>" for t in core.TIERS)
    csrf = f"<input type='hidden' name='csrf' value='{h(ctx.csrf)}'>"
    rows = []
    for u in users:
        name = h(u["username"])
        roles = set(u["roles"] or [])
        role_boxes = "".join(
            f"<label><input type='checkbox' name='roles' value='{r}' {'checked' if r in roles else ''} style='width:auto'> {label}</label>"
            for r, label in (("admin", "관리자"), ("auditor", "보안 담당"))
        )
        lock = "unlock" if u["disabled"] else "lock"
        rows.append(
            f"<tr><td><b>{name}</b>{' <span class=tag>잠김</span>' if u['disabled'] else ''}</td>"
            f"<td><form class='inline' method='post' action='/admin/users/{name}/tier'>{csrf}<select name='tier'>{tier_opts(u['tier'])}</select><button>바꾸기</button></form></td>"
            f"<td><form class='inline' method='post' action='/admin/users/{name}/roles'>{csrf}{role_boxes}<button>바꾸기</button></form></td>"
            f"<td class='n'>{u['open']}</td>"
            f"<td><form class='inline' method='post' action='/admin/users/{name}/revoke'>{csrf}<button>세션 끝내기</button></form>"
            f"<form class='inline' method='post' action='/admin/users/{name}/{lock}'>{csrf}<button>{'잠금 해제' if u['disabled'] else '잠그기'}</button></form>"
            f"<form class='inline' method='post' action='/admin/users/{name}/password'>{csrf}{pw_field('password', '새 비밀번호 12자 이상')}{pw_field('password_confirm', '한 번 더')}<button>비밀번호 바꾸기</button></form></td></tr>"
        )
    note = (f"<p class='ok'>{h(message)}</p>" if message else "") + (f"<p class='alert'>{h(error)}</p>" if error else "")
    body = (
        f"<h1>사용자</h1>{note}<h2>새 사용자</h2>"
        f"<form class='inline' method='post' action='/admin/users'>{csrf}"
        "<label>아이디<br><input name='username' required pattern='[a-z][a-z0-9._-]{1,31}'></label>"
        f"<label>처음 비밀번호<br>{pw_field('password', '12자 이상')}</label>"
        f"<label>비밀번호 확인<br>{pw_field('password_confirm', '한 번 더')}</label>"
        f"<label>등급<br><select name='tier'>{tier_opts('standard')}</select></label>"
        "<label><input type='checkbox' name='roles' value='admin' style='width:auto'> 관리자</label>"
        "<label><input type='checkbox' name='roles' value='auditor' style='width:auto'> 보안 담당</label><button>만들기</button></form>"
        "<p class='muted'>등급, 관리 권한, 비밀번호를 바꾸거나 잠그면 그 사용자의 로그인 세션이 모두 끝나고 대화 전용 키도 모두 폐기됩니다. 다시 로그인하면 바뀐 권한이 적용됩니다.</p>"
        "<h2>목록</h2><table><tr><th>아이디</th><th>등급</th><th>관리 권한</th><th>세션</th><th>조치</th></tr>"
        + "".join(rows)
        + "</table>"
    )
    return layout(ctx, "사용자", body, "/admin/users", status)


@router.get("/admin/users")
def users_page(request: Request):
    return _guarded(request, "admin", lambda conn, ctx: _users_page(conn, ctx))


def _end_all(conn, user: dict, reason: str, actor: str) -> int:
    """Ends the user's opencode sessions and revokes their chat keys, which carry the old tier and roles.

    Admin sessions re-check the account on every request."""
    sessions = conn.execute("SELECT * FROM sessions WHERE user_id = %s AND ended_at IS NULL", (user["id"],)).fetchall()
    for s in sessions:
        end_session(conn, s, reason, actor=actor)
    revoke_chat_keys(conn, user["id"], reason, actor=actor)
    return len(sessions)


@router.post("/admin/users")
async def create_user(request: Request):
    form = await request.form()

    def render(conn, ctx: Ctx):
        if not _csrf_ok(ctx, str(form.get("csrf", ""))):
            return _users_page(conn, ctx, error="페이지가 만료됐습니다. 다시 시도하세요.", status=400)
        username = str(form.get("username", "")).strip().lower()
        password = str(form.get("password", ""))
        if password != str(form.get("password_confirm", "")):
            return _users_page(conn, ctx, error="두 비밀번호가 다릅니다.", status=400)
        tier = str(form.get("tier", ""))
        roles = sorted({r for r in form.getlist("roles") if r in core.ROLES})
        if not core.valid_username(username):
            return _users_page(conn, ctx, error="아이디는 소문자로 시작하고 소문자, 숫자, . _ - 만 씁니다 (2-32자).", status=400)
        if tier not in core.TIERS:
            return _users_page(conn, ctx, error="등급이 올바르지 않습니다.", status=400)
        if problem := core.password_problem(password, username):
            return _users_page(conn, ctx, error=problem, status=400)
        if db.user_by_name(conn, username):
            return _users_page(conn, ctx, error=f"이미 있는 아이디입니다: {username}", status=400)
        conn.execute("INSERT INTO users (username, password_hash, tier, roles) VALUES (%s, %s, %s, %s)",
                     (username, hasher.hash(password), tier, roles))
        db.event(conn, "user_created", actor=ctx.name, subject=username, ip=client_ip(request), tier=tier, roles=roles)
        return _users_page(conn, ctx, message=f"{username} 사용자를 만들었습니다.")

    return _guarded(request, "admin", render)


@router.post("/admin/users/{username}/{action}")
async def user_action(request: Request, username: str, action: str):
    form = await request.form()

    def render(conn, ctx: Ctx):
        if not _csrf_ok(ctx, str(form.get("csrf", ""))):
            return _users_page(conn, ctx, error="페이지가 만료됐습니다. 다시 시도하세요.", status=400)
        user = db.user_by_name(conn, username)
        if not user:
            return _users_page(conn, ctx, error=f"없는 사용자입니다: {username}", status=404)
        ip = client_ip(request)
        self_target = user["id"] == ctx.user["id"]
        if action == "tier":
            tier = str(form.get("tier", ""))
            if tier not in core.TIERS:
                return _users_page(conn, ctx, error="등급이 올바르지 않습니다.", status=400)
            conn.execute("UPDATE users SET tier = %s WHERE id = %s", (tier, user["id"]))
            n = _end_all(conn, user, "tier_changed", ctx.name)
            db.event(conn, "tier_changed", actor=ctx.name, subject=username, ip=ip, tier=tier)
            return _users_page(conn, ctx, message=f"{username}: 등급을 {TIER_NAMES[tier]}(으)로 바꿨습니다. 세션 {n}개를 끝냈습니다.")
        if action == "roles":
            roles = sorted({r for r in form.getlist("roles") if r in core.ROLES})
            if self_target and "admin" not in roles:
                return _users_page(conn, ctx, error="자기 자신의 관리자 권한은 뺄 수 없습니다.", status=400)
            conn.execute("UPDATE users SET roles = %s WHERE id = %s", (roles, user["id"]))
            n = _end_all(conn, user, "roles_changed", ctx.name) if not self_target else 0
            db.event(conn, "roles_changed", actor=ctx.name, subject=username, ip=ip, roles=roles)
            return _users_page(conn, ctx, message=f"{username}: 관리 권한을 바꿨습니다. 세션 {n}개를 끝냈습니다.")
        if action in ("lock", "unlock"):
            if self_target:
                return _users_page(conn, ctx, error="자기 자신은 잠글 수 없습니다.", status=400)
            conn.execute("UPDATE users SET disabled = %s, failed = 0, last_failed = NULL WHERE id = %s", (action == "lock", user["id"]))
            n = _end_all(conn, user, "locked", ctx.name) if action == "lock" else 0
            db.event(conn, f"user_{action}ed", actor=ctx.name, subject=username, ip=ip)
            return _users_page(conn, ctx, message=f"{username}: {'잠갔습니다' if action == 'lock' else '잠금을 풀었습니다'}." + (f" 세션 {n}개를 끝냈습니다." if n else ""))
        if action == "revoke":
            n = _end_all(conn, user, "revoked", ctx.name)
            return _users_page(conn, ctx, message=f"{username}: 세션 {n}개를 끝냈습니다.")
        if action == "password":
            password = str(form.get("password", ""))
            if password != str(form.get("password_confirm", "")):
                return _users_page(conn, ctx, error=f"{username}: 두 비밀번호가 다릅니다.", status=400)
            if problem := core.password_problem(password, username):
                return _users_page(conn, ctx, error=problem, status=400)
            conn.execute("UPDATE users SET password_hash = %s, failed = 0, last_failed = NULL WHERE id = %s",
                         (hasher.hash(password), user["id"]))
            n = _end_all(conn, user, "password_changed", ctx.name) if not self_target else 0
            db.event(conn, "password_changed", actor=ctx.name, subject=username, ip=ip)
            return _users_page(conn, ctx, message=f"{username}: 비밀번호를 바꿨습니다. 세션 {n}개를 끝냈습니다.")
        return _users_page(conn, ctx, error="알 수 없는 조치입니다.", status=400)

    return _guarded(request, "admin", render)


# ---------------------------------------------------------------------------
# Chat-only keys (admin): every open key, and revoking one
# ---------------------------------------------------------------------------


def _chat_keys_page(conn, ctx: Ctx, message: str = "", error: str = "", status: int = 200) -> HTMLResponse:
    keys = conn.execute(
        """SELECT k.*, u.username FROM chat_keys k JOIN users u ON u.id = k.user_id
            WHERE k.revoked_at IS NULL AND k.expires_at > now() ORDER BY u.username, k.id"""
    ).fetchall()
    csrf = f"<input type='hidden' name='csrf' value='{h(ctx.csrf)}'>"
    rows = "".join(
        f"<tr><td>{h(k['username'])}</td><td>{h(k['name'])}</td>"
        f"<td>{k['created_at'].astimezone(core.KST):%Y-%m-%d %H:%M}</td><td>{k['expires_at'].astimezone(core.KST):%Y-%m-%d %H:%M}</td>"
        f"<td><form class='inline' method='post' action='/admin/chat-keys/{k['id']}/revoke'>{csrf}<button>폐기</button></form></td></tr>"
        for k in keys
    )
    note = (f"<p class='ok'>{h(message)}</p>" if message else "") + (f"<p class='alert'>{h(error)}</p>" if error else "")
    body = (
        f"<h1>대화 전용 키</h1>{note}"
        "<p class='muted'>사용자가 croakcode의 /chatkey로 만든 키입니다. Open WebUI 같은 대화 프로그램에 씁니다. "
        "게이트는 이 키로 오는 도구 사용을 거부합니다.</p>"
        "<table><tr><th>사용자</th><th>이름</th><th>만든 때</th><th>만료</th><th>조치</th></tr>"
        + (rows or "<tr><td colspan='5'>열린 키가 없습니다.</td></tr>")
        + "</table>"
    )
    return layout(ctx, "대화 전용 키", body, "/admin/chat-keys", status)


@router.get("/admin/chat-keys")
def chat_keys_page(request: Request):
    return _guarded(request, "admin", lambda conn, ctx: _chat_keys_page(conn, ctx))


@router.post("/admin/chat-keys/{key_id}/revoke")
async def chat_key_revoke(request: Request, key_id: int):
    form = await request.form()

    def render(conn, ctx: Ctx):
        if not _csrf_ok(ctx, str(form.get("csrf", ""))):
            return _chat_keys_page(conn, ctx, error="페이지가 만료됐습니다. 다시 시도하세요.", status=400)
        row = conn.execute("SELECT * FROM chat_keys WHERE id = %s AND revoked_at IS NULL", (key_id,)).fetchone()
        if not row:
            return _chat_keys_page(conn, ctx, error="없거나 이미 폐기된 키입니다.", status=404)
        revoke_chat_key(conn, row, "revoked_by_admin", actor=ctx.name)
        return _chat_keys_page(conn, ctx, message=f"키 '{row['name']}'를 폐기했습니다.")

    return _guarded(request, "admin", render)


# ---------------------------------------------------------------------------
# Policy settings (admin changes, auditor views)
# ---------------------------------------------------------------------------

OVERRIDES_PATH = os.environ.get("CROAK_OVERRIDES", "/settings/policy-overrides.json")
MEDIA_PII_NAMES = {"mask": "가리기", "block": "거부"}


def _load_overrides() -> dict:
    try:
        with open(OVERRIDES_PATH, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_overrides(data: dict) -> None:
    """Atomic write; the gate reloads the file when its time changes."""
    tmp = f"{OVERRIDES_PATH}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, OVERRIDES_PATH)


def _policy_tiers() -> list[str]:
    try:
        with open(POLICY_PATH, encoding="utf-8") as f:
            return list(((yaml.safe_load(f) or {}).get("tiers") or {}).keys()) or list(core.TIERS)
    except OSError:
        return list(core.TIERS)


def _policy_page(ctx: Ctx, message: str = "", error: str = "", status: int = 200) -> HTMLResponse:
    overrides = _load_overrides()
    current = overrides.get("media_pii") or {}
    editable = ctx.has("admin")
    rows = []
    for tier in _policy_tiers():
        value = current.get(tier, "mask")
        if editable:
            cell = "".join(
                f"<label style='display:inline;margin-right:16px'><input type='radio' name='media_pii_{h(tier)}' value='{v}' "
                f"{'checked' if v == value else ''} style='width:auto'> {label}</label>"
                for v, label in MEDIA_PII_NAMES.items()
            )
        else:
            cell = MEDIA_PII_NAMES.get(value, value)
        rows.append(f"<tr><td><b>{h(TIER_NAMES.get(tier, tier))}</b> ({h(tier)})</td><td>{cell}</td></tr>")
    note = (f"<p class='ok'>{h(message)}</p>" if message else "") + (f"<p class='alert'>{h(error)}</p>" if error else "")
    changed = ""
    if overrides.get("updated_at"):
        changed = f"<p class='muted'>마지막 변경: {h(str(overrides.get('updated_by')))}, {h(str(overrides.get('updated_at')))}</p>"
    table = "<table><tr><th>등급</th><th>첨부(이미지, PDF)의 개인정보</th></tr>" + "".join(rows) + "</table>"
    form = (
        f"<form method='post' action='/admin/policy'><input type='hidden' name='csrf' value='{h(ctx.csrf)}'>{table}"
        "<button type='submit' style='width:auto'>저장</button></form>"
        if editable else table + "<p class='muted'>보안 담당은 보기만 할 수 있습니다.</p>"
    )
    body = (
        f"<h1>정책</h1>{note}"
        "<p class='muted'>가리기: 개인정보 위에 검은 상자를 칠하고 보낸다. 거부: 이번 요청에서 새로 들어온 첨부에 개인정보가 있으면 요청을 보내지 않는다. "
        "이미 대화에 있던 첨부는 계속 가리기로 처리한다. 저장하면 다음 요청부터 바로 적용된다.</p>"
        f"{form}{changed}"
        "<p class='muted'>나머지 규칙(에이전트, 도구, 비밀정보)은 Git의 policy.yaml에서 바꾸고 배포한다.</p>"
    )
    return layout(ctx, "정책", body, "/admin/policy", status)


@router.get("/admin/policy")
def policy_page(request: Request):
    return _guarded(request, None, lambda conn, ctx: _policy_page(ctx))


@router.post("/admin/policy")
async def policy_save(request: Request):
    form = await request.form()

    def render(conn, ctx: Ctx):
        if not _csrf_ok(ctx, str(form.get("csrf", ""))):
            return _policy_page(ctx, error="페이지가 만료됐습니다. 다시 시도하세요.", status=400)
        overrides = _load_overrides()
        before = dict(overrides.get("media_pii") or {})
        after = {}
        for tier in _policy_tiers():
            value = str(form.get(f"media_pii_{tier}", before.get(tier, "mask")))
            if value not in MEDIA_PII_NAMES:
                return _policy_page(ctx, error=f"{tier}: 값이 올바르지 않습니다.", status=400)
            after[tier] = value
        changes = {t: [before.get(t, "mask"), v] for t, v in after.items() if before.get(t, "mask") != v}
        if not changes:
            return _policy_page(ctx, message="바뀐 것이 없습니다.")
        overrides["media_pii"] = after
        overrides["updated_by"] = ctx.name
        overrides["updated_at"] = now().astimezone(core.KST).strftime("%Y-%m-%d %H:%M:%S")
        _write_overrides(overrides)
        db.event(conn, "policy_changed", actor=ctx.name, ip=client_ip(request), media_pii=changes)
        summary = ", ".join(f"{TIER_NAMES.get(t, t)} {MEDIA_PII_NAMES[a]}→{MEDIA_PII_NAMES[b]}" for t, (a, b) in changes.items())
        return _policy_page(ctx, message=f"저장했습니다: {summary}")

    return _guarded(request, "admin", render)
