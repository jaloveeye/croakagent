"""Issues and deletes croak-gate (LiteLLM) virtual keys for login sessions.

Each access token is a LiteLLM key with a unique alias croak-<session>-<seq>,
so it can be deleted by alias without storing the key itself.
"""
from __future__ import annotations

import os
from datetime import datetime

import httpx

GATE_URL = os.environ.get("GATE_URL", "http://gate:4000")


def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {os.environ['LITELLM_MASTER_KEY']}"}


def issue(alias: str, user: dict, session_id: str, expires: datetime, now: datetime) -> str:
    seconds = max(60, int((expires - now).total_seconds()))
    body = {
        "key_alias": alias,
        "user_id": user["username"],
        "duration": f"{seconds}s",
        "metadata": {
            "croak_user": user["username"],
            "croak_tier": user["tier"],
            "croak_roles": list(user["roles"] or []),
            "croak_session": session_id,
        },
    }
    r = httpx.post(f"{GATE_URL}/key/generate", json=body, headers=_headers(), timeout=15)
    r.raise_for_status()
    return r.json()["key"]


def issue_chat(alias: str, user: dict, key_id: int, expires: datetime, now: datetime) -> str:
    """A chat-only key. The guardrail reads croak_client and refuses tools with it."""
    seconds = max(60, int((expires - now).total_seconds()))
    body = {
        "key_alias": alias,
        "user_id": user["username"],
        "duration": f"{seconds}s",
        "metadata": {
            "croak_user": user["username"],
            "croak_tier": user["tier"],
            "croak_roles": list(user["roles"] or []),
            "croak_client": "chat",
            "croak_chat_key": key_id,
        },
    }
    r = httpx.post(f"{GATE_URL}/key/generate", json=body, headers=_headers(), timeout=15)
    r.raise_for_status()
    return r.json()["key"]


def delete(alias: str) -> bool:
    """Deletes the key by alias. A key that is already gone counts as deleted."""
    r = httpx.post(f"{GATE_URL}/key/delete", json={"key_aliases": [alias]}, headers=_headers(), timeout=15)
    if r.status_code < 300:
        return True
    text = r.text.lower()
    return r.status_code in (400, 404) and ("not found" in text or "does not exist" in text)
