"""Pure helpers for croak-auth: session lifetime, PKCE, codes and tokens.

No database or web framework here, so it is unit-tested on its own
(gateway/auth/tests/test_auth_core.py).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

KST = ZoneInfo("Asia/Seoul")
ACCESS_LIFETIME = timedelta(hours=24)
CODE_LIFETIME = timedelta(minutes=5)
MIN_PASSWORD = 12
LOCK_AFTER = 5
LOCK_FOR = timedelta(minutes=15)

# Chat-only keys (Open WebUI and the like on the user's own PC).
CHAT_KEY_DEFAULT_DAYS = 30
CHAT_KEY_MAX_DAYS = 90
CHAT_KEY_LIMIT = 5

TIERS = ("full", "standard", "restricted")
ROLES = ("admin", "auditor")

# Unambiguous characters: no 0/O, 1/I/L.
_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
_USERNAME = re.compile(r"^[a-z][a-z0-9._-]{1,31}$")
_VERIFIER = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")


def session_end(now: datetime) -> datetime:
    """The first Sunday 00:00 in Korea after `now`; a week later on Sundays."""
    local = now.astimezone(KST)
    days = (6 - local.weekday()) % 7 or 7
    return (local + timedelta(days=days)).replace(hour=0, minute=0, second=0, microsecond=0)


def access_end(now: datetime, session_expires: datetime) -> datetime:
    """Access tokens live 24 hours but never outlive the session."""
    return min(now + ACCESS_LIFETIME, session_expires)


def pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def valid_verifier(verifier: str) -> bool:
    return bool(_VERIFIER.fullmatch(verifier or ""))


def pkce_ok(verifier: str, challenge: str) -> bool:
    return valid_verifier(verifier) and hmac.compare_digest(pkce_challenge(verifier), challenge or "")


def new_code() -> str:
    """A 12-character one-time code shown as XXXX-XXXX-XXXX."""
    raw = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(12))
    return f"{raw[:4]}-{raw[4:8]}-{raw[8:]}"


def normalize_code(code: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", (code or "").upper())


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    """Tokens and codes carry 60+ bits of randomness, so a plain SHA-256 is enough."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def valid_username(name: str) -> bool:
    return bool(_USERNAME.fullmatch(name or ""))


def password_problem(password: str, username: str = "") -> str | None:
    if len(password) < MIN_PASSWORD:
        return f"비밀번호는 {MIN_PASSWORD}자 이상이어야 한다."
    if username and username.lower() in password.lower():
        return "비밀번호에 아이디를 넣을 수 없다."
    return None


def sign(secret: bytes, value: str) -> str:
    mac = hmac.new(secret, value.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{value}.{mac}"


def unsign(secret: bytes, signed: str) -> str | None:
    value, _, mac = (signed or "").rpartition(".")
    if not value:
        return None
    expected = hmac.new(secret, value.encode("utf-8"), hashlib.sha256).hexdigest()
    return value if hmac.compare_digest(expected, mac) else None


def locked(failed: int, last_failed: datetime | None, now: datetime) -> bool:
    return failed >= LOCK_AFTER and last_failed is not None and now - last_failed < LOCK_FOR


def chat_key_name(name: object) -> str | None:
    """A chat key's label as the user typed it, trimmed; None when it is not usable."""
    if not isinstance(name, str):
        return None
    name = name.strip()
    if not 1 <= len(name) <= 40 or any(ord(ch) < 32 or ord(ch) == 127 for ch in name):
        return None
    return name


def chat_key_days(days: object) -> int | None:
    """Days a new chat key lives: the default when not given, None when out of range."""
    if days is None or days == "":
        return CHAT_KEY_DEFAULT_DAYS
    if isinstance(days, bool):
        return None
    try:
        value = int(days)
    except (TypeError, ValueError):
        return None
    if isinstance(days, float) and days != value:
        return None
    return value if 1 <= value <= CHAT_KEY_MAX_DAYS else None


def chat_key_alias(username: str, key_id: int) -> str:
    return f"croak-chat-{username}-{key_id}"
