"""Execution permits: Gate's side of croakcode Phase 4 Task 9.

croakcode asks for a permit right before it runs a tool. Gate signs a token
bound to that one call with Ed25519; croakcode verifies it with Gate's public
key. Gate also keeps every permit so the guardrail can check, on each model
request, that every tool result in the conversation came from a permitted
call (reconciliation). That check is what stops a tampered client.

Token: base64url(payload JSON) "." base64url(signature). The signature covers
the ASCII bytes of the first segment. Protocol:
croakcode docs/superpowers/architecture/2026-11-09-execution-permit-protocol.md
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import secrets
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

AUDIENCE = "croakcode"
# croakcode accepts at most 60 s; Gate issues 30 s so clock skew still fits.
TTL_MS = 30_000
HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def _normalize(value: Any) -> Any:
    """Matches JavaScript JSON: an integral float is written as an integer."""
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite number")
        return int(value) if value.is_integer() and abs(value) < 2**53 else value
    if isinstance(value, dict):
        return {str(k): _normalize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize(v) for v in value]
    return value


def canonical_json(value: Any) -> str:
    """Object keys sorted at every level, no spaces; same bytes as croakcode's canonicalJson."""
    return json.dumps(_normalize(value), ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False)


def args_hash(args: Any) -> str:
    return hashlib.sha256(canonical_json(args).encode("utf-8")).hexdigest()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sign_token(payload: dict[str, Any], key: Ed25519PrivateKey) -> str:
    segment = b64url(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    return f"{segment}.{b64url(key.sign(segment.encode('ascii')))}"


def load_private_key(path: str) -> Ed25519PrivateKey | None:
    """The signing key from a PEM (PKCS#8) file; None when missing or not Ed25519."""
    try:
        with open(path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
    except (OSError, ValueError, TypeError):
        return None
    return key if isinstance(key, Ed25519PrivateKey) else None


def public_key_b64(key: Ed25519PrivateKey) -> str:
    """The value croakcode takes in CROAKCODE_GATE_PERMIT_PUBLIC_KEY."""
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def matches(name: str, pattern: str) -> bool:
    """Same rule as the gate's croak_core.matches: "*" and a trailing "*"."""
    if pattern == "*":
        return True
    if pattern.endswith("*"):
        return name.startswith(pattern[:-1])
    return name == pattern


def tool_denied(tool: str, deny_tools: list[str]) -> bool:
    return any(matches(tool, p) for p in deny_tools)


def parse_request(body: Any) -> dict[str, Any]:
    """Validates a permit request; raises ValueError with the bad field."""
    if not isinstance(body, dict):
        raise ValueError("body")
    out: dict[str, Any] = {}
    for key in ("sid", "pid", "rid", "tool"):
        value = body.get(key)
        if not isinstance(value, str) or not value.strip() or len(value) > 200:
            raise ValueError(key)
        out[key] = value
    if not isinstance(body.get("args"), str) or not HASH_RE.match(body["args"]):
        raise ValueError("args")
    out["args"] = body["args"]
    rev = body.get("rev")
    if isinstance(rev, bool) or not isinstance(rev, int) or rev < 0:
        raise ValueError("rev")
    out["rev"] = rev
    return out


def payload(request: dict[str, Any], now_ms: int) -> dict[str, Any]:
    return {
        "aud": AUDIENCE,
        **request,
        "iat": now_ms,
        "exp": now_ms + TTL_MS,
        "nonce": secrets.token_urlsafe(16),
    }
