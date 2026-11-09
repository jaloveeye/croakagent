"""croak-auth: login page, one-time codes, tokens and logout.

    GET  /auth/login?challenge=...   login form (opened by opencode /login)
    POST /auth/login                 checks the password, shows a one-time code
    POST /auth/token                 code + PKCE verifier -> tokens; or refresh
    POST /auth/logout                ends the session and deletes its gate key
    GET  /auth/me                    who the access token belongs to
    GET  /auth/health                liveness

Sessions end at the first Sunday 00:00 (Korea) after login. Access tokens are
croak-gate keys that live 24 hours at most.
"""
from __future__ import annotations

import hashlib
import html
import os
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse

import auth_core as core
import auth_db as db
import gate_keys
import yaml

POLICY_PATH = os.environ.get("CROAK_POLICY", "/app/policy.yaml")

PUBLIC_URL = os.environ.get("AUTH_PUBLIC_URL", "")  # set by docker-compose from CROAK_PUBLIC_URL
# HMAC key for the login form's CSRF token, derived from the master key so the
# server .env needs no new secret.
SECRET = hashlib.sha256(b"croak-auth-csrf:" + os.environ.get("LITELLM_MASTER_KEY", "").encode()).digest()
IP_LIMIT = 20  # failed logins per IP per lock window
SWEEP_SECONDS = 300

CSP = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"

hasher = PasswordHasher()
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


def now() -> datetime:
    return datetime.now(timezone.utc)


def client_ip(request: Request) -> str:
    # Caddy sets X-Forwarded-For; the last entry is the address it saw.
    forwarded = request.headers.get("x-forwarded-for", "")
    return forwarded.split(",")[-1].strip() or (request.client.host if request.client else "")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    # A page may set its own policy (the code page allows one nonce script).
    if "content-security-policy" not in response.headers:
        response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Frame-Options"] = "DENY"
    # same-origin, not no-referrer: with no-referrer browsers send "Origin: null"
    # on form posts, and the admin login checks Origin.
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.on_event("startup")
def startup() -> None:
    db.ensure_database()
    threading.Thread(target=_sweep_forever, daemon=True).start()


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

STYLE = """
body{font-family:system-ui,'Malgun Gothic',sans-serif;background:#f4f6f4;color:#1b2a1d;display:flex;justify-content:center;padding:48px 16px;margin:0}
main{background:#fff;border-radius:12px;box-shadow:0 2px 12px #0001;padding:32px;max-width:380px;width:100%}
h1{font-size:20px;margin:0 0 4px}p{line-height:1.5}.muted{color:#5b6b5d;font-size:14px}
label{display:block;font-size:14px;margin:16px 0 4px}input{width:100%;box-sizing:border-box;padding:10px;border:1px solid #c5d0c6;border-radius:8px;font-size:16px}
button{margin-top:20px;width:100%;padding:12px;border:0;border-radius:8px;background:#2f8a3a;color:#fff;font-size:16px;cursor:pointer}
.error{background:#fdecea;color:#8a1c12;padding:10px;border-radius:8px;font-size:14px}
.code{font:600 28px/1.4 ui-monospace,monospace;letter-spacing:2px;text-align:center;background:#eef6ee;border-radius:8px;padding:16px;user-select:all;margin:16px 0}
@media (prefers-color-scheme: dark){body{background:#121a13;color:#e2ece3}main{background:#1b251c}input{background:#121a13;color:#e2ece3;border-color:#3a4a3c}.code{background:#24342a}.muted{color:#9fb0a1}}
"""


def page(title: str, body: str, status: int = 200) -> HTMLResponse:
    return HTMLResponse(
        f"<!doctype html><html lang='ko'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{html.escape(title)}</title><style>{STYLE}</style></head><body><main>{body}</main></body></html>",
        status_code=status,
    )


def login_form(challenge: str, error: str = "", username: str = "", status: int = 200) -> HTMLResponse:
    nonce = secrets.token_urlsafe(16)
    err = f"<p class='error'>{html.escape(error)}</p>" if error else ""
    response = page(
        "croak 로그인",
        f"""<h1>croak 로그인</h1><p class='muted'>opencode에서 쓸 계정으로 로그인합니다.</p>{err}
<form method='post' action='/auth/login'>
<input type='hidden' name='challenge' value='{html.escape(challenge)}'>
<input type='hidden' name='csrf' value='{html.escape(core.sign(SECRET, nonce))}'>
<label for='u'>아이디</label><input id='u' name='username' autocomplete='username' value='{html.escape(username)}' required autofocus>
<label for='p'>비밀번호</label><input id='p' name='password' type='password' autocomplete='current-password' required>
<button type='submit'>로그인</button></form>""",
        status,
    )
    response.set_cookie("croak_csrf", nonce, httponly=True, secure=True, samesite="strict", path="/auth", max_age=1800)
    return response


def valid_challenge(challenge: str) -> bool:
    return len(challenge or "") == 43 and all(ch.isalnum() or ch in "-_" for ch in challenge)


@app.get("/auth/login")
def login_page(challenge: str = "") -> HTMLResponse:
    if not valid_challenge(challenge):
        return page("잘못된 로그인 주소", "<h1>잘못된 로그인 주소</h1><p>opencode에서 <b>/login</b>을 다시 실행하세요.</p>", 400)
    return login_form(challenge)


@app.post("/auth/login")
def login_submit(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    challenge: str = Form(""),
    csrf: str = Form(""),
) -> HTMLResponse:
    if not valid_challenge(challenge):
        return page("잘못된 로그인 주소", "<h1>잘못된 로그인 주소</h1><p>opencode에서 <b>/login</b>을 다시 실행하세요.</p>", 400)
    nonce = request.cookies.get("croak_csrf", "")
    if not nonce or core.unsign(SECRET, csrf) != nonce:
        return login_form(challenge, "페이지가 만료됐습니다. 다시 로그인하세요.", status=400)

    ip = client_ip(request)
    username = username.strip().lower()
    t = now()
    with db.connect() as conn:
        user, error, status = authenticate(conn, username, password, ip, t)
        if not user:
            return login_form(challenge, error, username, status)
        code = core.new_code()
        conn.execute(
            "INSERT INTO auth_codes (code_hash, user_id, challenge, expires_at) VALUES (%s, %s, %s, %s)",
            (core.token_hash(core.normalize_code(code)), user["id"], challenge, t + core.CODE_LIFETIME),
        )
        db.event(conn, "login_ok", actor=username, ip=ip)

    nonce = secrets.token_urlsafe(16)
    response = page(
        "확인 코드",
        f"""<h1>로그인했습니다</h1><p>아래 확인 코드를 opencode 입력창에 붙여 넣으세요.</p>
<div class='code' id='code'>{html.escape(code)}</div>
<button type='button' id='copy' data-code='{html.escape(code)}'>코드 복사</button>
<p class='muted'>코드는 5분 동안 한 번만 쓸 수 있습니다. 다른 사람이나 다른 프로그램에 알려 주지 마세요.</p>
<script nonce='{nonce}'>
document.getElementById('copy').addEventListener('click', async (e) => {{
  const b = e.currentTarget;
  try {{ await navigator.clipboard.writeText(b.dataset.code); b.textContent = '복사했습니다'; }}
  catch {{ b.textContent = '복사하지 못했습니다. 코드를 직접 선택하세요'; }}
}});
</script>""",
    )
    response.headers["Content-Security-Policy"] = CSP.replace("default-src 'none';", f"default-src 'none'; script-src 'nonce-{nonce}';")
    response.delete_cookie("croak_csrf", path="/auth")
    return response


DUMMY_HASH = hasher.hash(secrets.token_urlsafe(16))


def authenticate(conn, username: str, password: str, ip: str, t: datetime) -> tuple[dict | None, str, int]:
    """Checks a password with the IP and account lockouts.

    Returns (user, "", 200) on success, otherwise (None, message, status).
    Unknown users, disabled users and wrong passwords get the same answer.
    """
    if db.failed_from_ip(conn, ip, t - core.LOCK_FOR) >= IP_LIMIT:
        db.event(conn, "login_blocked_ip", subject=username, ip=ip)
        return None, "로그인 시도가 너무 많습니다. 15분 뒤에 다시 시도하세요.", 429
    user = db.user_by_name(conn, username)
    if user and core.locked(user["failed"], user["last_failed"], t):
        db.event(conn, "login_locked", subject=username, ip=ip)
        return None, "로그인 시도가 너무 많아 계정이 잠시 잠겼습니다. 15분 뒤에 다시 시도하세요.", 429
    ok = False
    if user and not user["disabled"]:
        try:
            ok = hasher.verify(user["password_hash"], password)
        except VerificationError:
            ok = False
    else:
        # Same cost for unknown users, so timing does not reveal accounts.
        try:
            hasher.verify(DUMMY_HASH, password)
        except VerificationError:
            pass
    if not ok:
        if user:
            conn.execute("UPDATE users SET failed = failed + 1, last_failed = %s WHERE id = %s", (t, user["id"]))
        db.event(conn, "login_failed", subject=username, ip=ip, known=bool(user))
        return None, "로그인 정보가 맞지 않습니다.", 401
    conn.execute("UPDATE users SET failed = 0, last_failed = NULL WHERE id = %s", (user["id"],))
    if hasher.check_needs_rehash(user["password_hash"]):
        conn.execute("UPDATE users SET password_hash = %s WHERE id = %s", (hasher.hash(password), user["id"]))
    return user, "", 200


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse({"error": code, "message": message}, status_code=status)


def _issue_access(conn, session: dict, user: dict, t: datetime) -> tuple[str, datetime]:
    """Replaces the session's gate key with a new one."""
    if session.get("key_alias"):
        gate_keys.delete(session["key_alias"])
    seq = session["seq"] + 1
    alias = f"croak-{session['id']}-{seq}"
    expires = core.access_end(t, session["expires_at"])
    key = gate_keys.issue(alias, user, session["id"], expires, t)
    conn.execute(
        "UPDATE sessions SET access_hash = %s, key_alias = %s, seq = %s, access_expires_at = %s, key_deleted = false WHERE id = %s",
        (core.token_hash(key), alias, seq, expires, session["id"]),
    )
    return key, expires


def _token_body(key: str, access_expires: datetime, refresh: str, session: dict, user: dict) -> dict:
    return {
        "access_token": key,
        "access_expires_at": access_expires.astimezone(core.KST).isoformat(),
        "refresh_token": refresh,
        "session_expires_at": session["expires_at"].astimezone(core.KST).isoformat(),
        "user": {"username": user["username"], "tier": user["tier"], "roles": list(user["roles"] or [])},
    }


def end_session(conn, session: dict, reason: str, actor: str | None = None) -> None:
    if session.get("ended_at") is None:
        conn.execute("UPDATE sessions SET ended_at = now(), end_reason = %s WHERE id = %s", (reason, session["id"]))
    deleted = not session.get("key_alias") or gate_keys.delete(session["key_alias"])
    conn.execute("UPDATE sessions SET key_deleted = %s WHERE id = %s", (deleted, session["id"]))
    user = db.user_by_id(conn, session["user_id"])
    db.event(conn, "session_ended", actor=actor, subject=user["username"] if user else None, session=session["id"], reason=reason)


@app.post("/auth/token")
async def token(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        return _error(400, "invalid_request", "JSON body required")
    grant = body.get("grant_type")
    ip = client_ip(request)
    t = now()
    with db.connect() as conn:
        if grant == "authorization_code":
            code_hash = core.token_hash(core.normalize_code(str(body.get("code", ""))))
            row = conn.execute(
                "UPDATE auth_codes SET used_at = %s WHERE code_hash = %s AND used_at IS NULL RETURNING *", (t, code_hash)
            ).fetchone()
            if not row or row["expires_at"] <= t:
                db.event(conn, "code_rejected", ip=ip, reason="unknown_or_expired")
                return _error(400, "invalid_grant", "확인 코드가 맞지 않거나 만료됐습니다. /login을 다시 실행하세요.")
            user = db.user_by_id(conn, row["user_id"])
            if not core.pkce_ok(str(body.get("code_verifier", "")), row["challenge"]):
                db.event(conn, "code_rejected", subject=user["username"], ip=ip, reason="pkce_mismatch")
                return _error(400, "invalid_grant", "이 확인 코드는 다른 로그인 요청에서 만들어졌습니다. /login을 다시 실행하세요.")
            if user["disabled"]:
                return _error(403, "account_disabled", "잠긴 계정입니다. 관리자에게 문의하세요.")
            refresh = core.new_token()
            session = conn.execute(
                "INSERT INTO sessions (id, user_id, refresh_hash, expires_at) VALUES (%s, %s, %s, %s) RETURNING *",
                (secrets.token_hex(8), user["id"], core.token_hash(refresh), core.session_end(t)),
            ).fetchone()
            key, access_expires = _issue_access(conn, session, user, t)
            db.event(conn, "session_started", actor=user["username"], ip=ip, session=session["id"],
                     expires=session["expires_at"].astimezone(core.KST).isoformat())
            return JSONResponse(_token_body(key, access_expires, refresh, session, user))

        if grant == "refresh_token":
            session = conn.execute(
                "SELECT * FROM sessions WHERE refresh_hash = %s", (core.token_hash(str(body.get("refresh_token", ""))),)
            ).fetchone()
            if not session or session["ended_at"] is not None:
                return _error(401, "session_ended", "로그인이 끝났습니다. /login으로 다시 로그인하세요.")
            user = db.user_by_id(conn, session["user_id"])
            if session["expires_at"] <= t:
                end_session(conn, session, "expired")
                return _error(401, "session_expired", "이번 주 로그인이 끝났습니다. /login으로 다시 로그인하세요.")
            if user["disabled"]:
                end_session(conn, session, "disabled")
                return _error(401, "account_disabled", "잠긴 계정입니다. 관리자에게 문의하세요.")
            refresh = core.new_token()
            conn.execute("UPDATE sessions SET refresh_hash = %s WHERE id = %s", (core.token_hash(refresh), session["id"]))
            key, access_expires = _issue_access(conn, session, user, t)
            db.event(conn, "token_refreshed", actor=user["username"], ip=ip, session=session["id"])
            return JSONResponse(_token_body(key, access_expires, refresh, session, user))

    return _error(400, "unsupported_grant_type", "grant_type must be authorization_code or refresh_token")


@app.post("/auth/logout")
async def logout(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        body = {}
    refresh = str(body.get("refresh_token", ""))
    with db.connect() as conn:
        session = conn.execute("SELECT * FROM sessions WHERE refresh_hash = %s", (core.token_hash(refresh),)).fetchone()
        if session:
            user = db.user_by_id(conn, session["user_id"])
            end_session(conn, session, "logout", actor=user["username"] if user else None)
    # Same answer either way: logging out twice is not an error.
    return JSONResponse({"ok": True})


@app.get("/auth/me")
def me(request: Request) -> JSONResponse:
    auth = request.headers.get("authorization", "")
    key = auth[7:] if auth.lower().startswith("bearer ") else ""
    t = now()
    with db.connect() as conn:
        session = conn.execute("SELECT * FROM sessions WHERE access_hash = %s", (core.token_hash(key),)).fetchone() if key else None
        if not session or session["ended_at"] is not None or session["access_expires_at"] <= t:
            return _error(401, "not_logged_in", "로그인하지 않았습니다. /login으로 로그인하세요.")
        user = db.user_by_id(conn, session["user_id"])
        return JSONResponse(
            {
                "username": user["username"],
                "tier": user["tier"],
                "rules": tier_rules(user["tier"]),
                "roles": list(user["roles"] or []),
                "session_expires_at": session["expires_at"].astimezone(core.KST).isoformat(),
                "access_expires_at": session["access_expires_at"].astimezone(core.KST).isoformat(),
            }
        )


def tier_rules(tier: str) -> dict:
    """What the gate allows this tier, from the same policy.yaml (for /whoami)."""
    try:
        with open(POLICY_PATH, encoding="utf-8") as f:
            tiers = (yaml.safe_load(f) or {}).get("tiers") or {}
    except OSError:
        return {}
    rules = tiers.get(tier) or tiers.get("restricted") or {}
    return {
        "agents": list(rules.get("agents") or []),
        "deny_tools": list(rules.get("deny_tools") or []),
        "secrets_scope": rules.get("secrets_scope", "new"),
    }


@app.get("/auth/health")
def health() -> dict:
    return {"ok": True}


# ---------------------------------------------------------------------------
# Expiry sweep
# ---------------------------------------------------------------------------


def sweep(t: datetime | None = None) -> int:
    """Ends sessions past Sunday 00:00 and retries gate keys that were not deleted."""
    t = t or now()
    count = 0
    with db.connect() as conn:
        for session in conn.execute("SELECT * FROM sessions WHERE ended_at IS NULL AND expires_at <= %s", (t,)).fetchall():
            end_session(conn, session, "expired")
            count += 1
        for session in conn.execute("SELECT * FROM sessions WHERE ended_at IS NOT NULL AND NOT key_deleted").fetchall():
            if session.get("key_alias") and gate_keys.delete(session["key_alias"]):
                conn.execute("UPDATE sessions SET key_deleted = true WHERE id = %s", (session["id"],))
        conn.execute("DELETE FROM auth_codes WHERE expires_at < %s", (t - timedelta(days=1),))
    return count


def _sweep_forever() -> None:
    while True:
        try:
            sweep()
        except Exception as error:  # keep sweeping; the next run retries
            print(f"croak-auth sweep failed: {type(error).__name__}", flush=True)
        time.sleep(SWEEP_SECONDS)


# Admin console (/admin). Imported last: admin.py uses the helpers above.
import admin  # noqa: E402

app.include_router(admin.router)
