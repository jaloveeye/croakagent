"""LiteLLM pre-call guardrail for croak-gate.

Registered in config.yaml as `croak_guardrail.CroakGuardrail`. For every chat
request it:

1. reads the agent name from the `x-croak-agent` header (set by the opencode
   plugin plugins/gate-identity.mjs),
2. reads the user's tier from the key metadata `croak_tier` (set by
   croak-auth at login) and rejects agents and tools the tier does not allow,
3. picks a profile from policy.yaml, honouring looser profiles only when the
   tier (or the key's legacy `croak_profiles`) grants them,
4. masks personal data and redacts secrets, or rejects the request,
5. reads the text in inline images and PDFs through the croak-ocr service
   (CROAK_OCR_URL) and masks what the same rules find: black boxes on images,
   masked text in place of PDFs,
6. writes one audit record without any message text. Rejections and secrets
   found in the history carry a `violation` code for detection.

Any unexpected error rejects the request: a request that could not be
checked is never forwarded.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import httpx  # noqa: E402
import yaml  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from litellm.integrations.custom_guardrail import CustomGuardrail  # noqa: E402

import croak_models  # noqa: E402
import croak_store  # noqa: E402
from croak_core import CHAT_AGENT, SECRET_PATTERNS, Blocked, client_agent, apply_deny_paths, answered_tool_calls, find, media_parts, media_pii_action, new_turn, Denied, Policy, apply_profile, check_access, load_policy, resolve, tier_for, tool_names  # noqa: E402

POLICY_PATH = os.environ.get("CROAK_POLICY", os.path.join(os.path.dirname(os.path.abspath(__file__)), "policy.yaml"))
AGENT_HEADER = "x-croak-agent"
SECRET_KINDS = frozenset(SECRET_PATTERNS)
SESSION_HEADER = "x-croak-session"
# croakcode sends the agent run id, so the gate's records join its audit by run.
RUN_HEADER = "x-croak-run"
# The model registry (croak_models.py): reasoning levels and what to record per alias.
MODELS_PATH = os.environ.get("CROAK_MODELS", "/app/gateway/models.yaml")
OCR_URL = os.environ.get("CROAK_OCR_URL", "").rstrip("/")
# croak-auth keeps the execution permits; the gate asks it on an internal route.
AUTH_INTERNAL_URL = os.environ.get("CROAK_AUTH_INTERNAL_URL", "http://auth:8000").rstrip("/")


def internal_token() -> str:
    """Shared with croak-auth: derived from the master key both services hold."""
    import hashlib

    return hashlib.sha256(b"croak-internal:" + os.environ.get("LITELLM_MASTER_KEY", "").encode()).hexdigest()


async def check_permits(session: str | None, tier: Any, messages: list[dict[str, Any]], post: Any = None) -> None:
    """Refuses a request that sends back a tool result Gate never permitted.

    A tampered client can skip croakcode's permit check and run tools anyway;
    this is where its results stop. Any failure to check raises, and the hook
    turns that into a refusal (fail closed).
    """
    if not getattr(tier, "require_permits", False):
        return
    calls = answered_tool_calls(messages)
    if not calls:
        return
    if not session:
        raise Denied("unpermitted_tool", "세션 머리글이 없어 도구 결과의 실행 허가를 확인할 수 없다.", [c["tool"] for c in calls])
    if post is None:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(
                f"{AUTH_INTERNAL_URL}/internal/permits/check",
                json={"session": session, "calls": calls},
                headers={"x-croak-internal": internal_token()},
            )
            r.raise_for_status()
            missing = r.json().get("missing") or []
    else:
        missing = await post({"session": session, "calls": calls})
    if missing:
        tools = sorted({str(m.get("tool")) for m in missing})
        raise Denied(
            "unpermitted_tool",
            f"실행 허가 없이 실행한 도구의 결과가 있다: {', '.join(tools)}. croakcode의 실행 허가 설정을 켜고 새 세션에서 다시 시작한다.",
            tools,
        )
# Written by the admin console; read-only here.
OVERRIDES_PATH = os.environ.get("CROAK_OVERRIDES", "/app/settings/policy-overrides.json")
_overrides: dict[str, Any] = {}
_overrides_mtime: float | None = None


def current_overrides() -> dict[str, Any]:
    """Admin console settings, reloaded when the file changes. Missing file: none."""
    global _overrides, _overrides_mtime
    try:
        mtime = os.path.getmtime(OVERRIDES_PATH)
    except OSError:
        _overrides, _overrides_mtime = {}, None
        return _overrides
    if mtime != _overrides_mtime:
        with open(OVERRIDES_PATH, encoding="utf-8") as f:
            loaded = json.load(f)
        _overrides = loaded if isinstance(loaded, dict) else {}
        _overrides_mtime = mtime
    return _overrides

_policy: Policy | None = None
_policy_mtime: float | None = None


def current_policy() -> Policy:
    """Loads policy.yaml, reloading when the file changes."""
    global _policy, _policy_mtime
    mtime = os.path.getmtime(POLICY_PATH)
    if _policy is None or mtime != _policy_mtime:
        with open(POLICY_PATH, encoding="utf-8") as f:
            _policy = load_policy(yaml.safe_load(f) or {})
        _policy_mtime = mtime
    return _policy


def request_headers(data: dict[str, Any]) -> dict[str, str]:
    raw = (data.get("proxy_server_request") or {}).get("headers") or (data.get("metadata") or {}).get("headers") or {}
    return {str(k).lower(): str(v) for k, v in raw.items()}


def check_session_owner(session: str | None, who: dict[str, Any]) -> None:
    """One opencode session belongs to the account that started it.

    After a logout and a login as someone else in the same session, opencode
    would resend the previous user's conversation under the new account.
    """
    owner = who.get("user") or who.get("key_alias")
    if not session or not owner:
        return
    first = croak_store.claim_session(str(session), str(owner))
    if first != owner:
        raise Denied(
            "foreign_session",
            "이 대화는 다른 계정이 시작한 세션이다. 새 세션을 열고 다시 시작한다.",
            [first],
        )


async def inspect_media(messages: list[dict[str, Any]], profile: Any, scope: str, pii_action: str = "mask") -> dict[str, Any]:
    """Checks inline images and PDFs with croak-ocr and masks them in place.

    Attachments reach the model as the result of opencode's Read tool, so a
    secret in them is masked like a secret in any tool result, not blocked.
    Only the "all" secrets scope (restricted tier) blocks, and a "block" PII
    profile blocks personal data in the newest user message. The admin console
    can set a tier to block personal data in new attachments (pii_action).
    Attachments already in the history are masked, so a setting change does
    not lock running sessions.
    """
    result: dict[str, Any] = {"secrets": {}, "pii": {}, "fresh": {}, "images": 0, "pdfs": 0, "unscanned": 0, "ms": 0, "texts": []}
    parts = media_parts(messages)
    if not parts:
        return result
    if not OCR_URL:
        result["unscanned"] = len(parts)
        return result
    last_assistant = max((i for i, m in enumerate(messages) if m.get("role") == "assistant"), default=-1)
    last_user = max((i for i, m in enumerate(messages) if m.get("role") == "user"), default=-1)
    mask_pii = profile.pii != "allow"
    async with httpx.AsyncClient(timeout=60) as client:
        for media in parts:
            r = await client.post(f"{OCR_URL}/inspect", json={
                "kind": media.kind, "data": media.data, "mask_secrets": True, "mask_pii": mask_pii,
                "allow": {},  # attachments never get the system-prompt allow list
            })
            if r.status_code == 422:  # not a readable image or PDF: do not forward what was not checked
                media.replace({"type": "text", "text": f"[croak] {media.name}을 읽지 못해 보내지 않았다."})
                result["unscanned"] += 1
                continue
            r.raise_for_status()
            out = r.json()
            result["images" if media.kind == "image" else "pdfs"] += 1
            result["ms"] += int(out.get("ms") or 0)
            secrets, pii = out.get("secrets") or {}, out.get("pii") or {}
            if secrets and scope == "all" and profile.secrets == "block":
                raise Blocked("첨부한 이미지나 문서에 비밀정보가 있어 요청을 보내지 않았다. 새 세션에서 비밀정보 없이 다시 시작한다.", secrets)
            if pii and profile.pii == "block" and media.message_index == last_user:
                raise Blocked("이 에이전트는 개인정보를 받지 않는다. 첨부에서 개인정보를 지우고 다시 보낸다.", pii)
            if pii and pii_action == "block" and media.message_index > last_assistant:
                raise Blocked("이 등급은 개인정보가 보이는 이미지나 문서를 쓸 수 없다. 개인정보가 없는 첨부로 다시 보낸다.", pii)
            for key, found in (("secrets", secrets), ("pii", pii)):
                for k, n in found.items():
                    result[key][k] = result[key].get(k, 0) + n
            if secrets and media.message_index > last_assistant:
                for k, n in secrets.items():
                    result["fresh"][k] = result["fresh"].get(k, 0) + n
            if media.kind == "image":
                if out.get("image"):
                    media.set_data(out["image"])
                result["texts"].append({"name": media.name, "sha256": str(out.get("sha256", ""))[:16], "text": out.get("text", "")})
            elif secrets or (pii and mask_pii):
                media.replace({"type": "text", "text": f"[croak] {media.name}의 텍스트다. 비밀정보와 개인정보를 가렸다.\n{out.get('text', '')}"})
    return result


def fresh_secrets(messages: list[dict[str, Any]]) -> dict[str, int]:
    """Secrets in the messages this request adds (after the last assistant message)."""
    found: dict[str, int] = {}
    for message in new_turn(messages):
        content = message.get("content")
        if isinstance(content, str):
            texts = [content]
        elif isinstance(content, list):
            texts = [p["text"] for p in content if isinstance(p, dict) and isinstance(p.get("text"), str)]
        else:
            texts = []
        for text in texts:
            for kind, n in find(text, SECRET_PATTERNS).items():
                found[kind] = found.get(kind, 0) + n
    return found


def key_metadata(user_api_key_dict: Any) -> dict[str, Any]:
    metadata = getattr(user_api_key_dict, "metadata", None)
    return metadata if isinstance(metadata, dict) else {}


def caller(user_api_key_dict: Any) -> dict[str, Any]:
    """Who sent the request. The key itself is never recorded."""
    metadata = key_metadata(user_api_key_dict)
    return {
        "user": metadata.get("croak_user") or getattr(user_api_key_dict, "user_id", None),
        "key_alias": getattr(user_api_key_dict, "key_alias", None),
        "team_id": getattr(user_api_key_dict, "team_id", None),
    }


def granted_profiles(user_api_key_dict: Any) -> list[str]:
    """Legacy per-key grants from issue-key.sh."""
    granted = key_metadata(user_api_key_dict).get("croak_profiles") or []
    return [str(g) for g in granted] if isinstance(granted, list) else []


class CroakGuardrail(CustomGuardrail):
    async def async_pre_call_hook(self, user_api_key_dict, cache, data: dict, call_type):  # type: ignore[override]
        messages = data.get("messages")
        if not isinstance(messages, list):
            return data
        headers = request_headers(data)
        who = caller(user_api_key_dict)
        base = {"model": data.get("model"), "session": headers.get(SESSION_HEADER), **who}
        try:
            policy = current_policy()
            croak_store.purge(policy.retention_days)
            meta = key_metadata(user_api_key_dict)
            tier = tier_for(policy, meta.get("croak_tier"))
            base.update(tier=tier.name)
            agent = client_agent(meta, headers.get(AGENT_HEADER), data)
            chat_key = agent == CHAT_AGENT and meta.get("croak_client") == "chat"
            base.update(agent=agent, **({"client": "chat"} if chat_key else {}))
            # A chat-only key sends no tools (client_agent refused them) and is
            # not one of the tier's croakcode agents.
            if not chat_key:
                check_access(tier, agent, tool_names(data.get("tools")))
            check_session_owner(headers.get(SESSION_HEADER), who)
            await check_permits(headers.get(SESSION_HEADER), tier, messages)
            served = croak_models.apply_level(croak_models.current_models(MODELS_PATH).get(str(data.get("model"))), data)
            base.update(served, run=headers.get(RUN_HEADER))
            decision = resolve(policy, agent, [*tier.profiles, *granted_profiles(user_api_key_dict)])
            base.update(profile=decision.profile.name, requested=decision.requested, downgraded=decision.downgraded)
            paths = apply_deny_paths(messages, policy.deny_paths)  # before anything reads the text
            fresh = fresh_secrets(messages)  # before apply_profile redacts them
            media = await inspect_media(messages, decision.profile, tier.secrets_scope,
                                        media_pii_action(current_overrides(), tier.name))
            counts = apply_profile(messages, decision.profile, policy.allow, tier.secrets_scope)
            for key in ("secrets", "pii"):
                for k, n in media[key].items():
                    counts[key][k] = counts[key].get(k, 0) + n
            for k, n in media["fresh"].items():
                fresh[k] = fresh.get(k, 0) + n
        except Denied as denied:
            croak_store.append("audit", {**base, "action": "block", "violation": denied.code, "denied": denied.detail})
            raise HTTPException(status_code=403, detail={"error": f"[croak] {denied.reason}", "violation": denied.code})
        except croak_models.UnknownLevel as unknown:
            croak_store.append("audit", {**base, "action": "block", "violation": "reasoning_level"})
            raise HTTPException(status_code=400, detail={"error": f"[croak] {unknown}", "violation": "reasoning_level"})
        except Blocked as blocked:
            code = "secret" if any(k in blocked.found for k in SECRET_KINDS) else "pii"
            croak_store.append("audit", {**base, "action": "block", "violation": code, "found": blocked.found})
            raise HTTPException(status_code=400, detail={"error": f"[croak] {blocked.reason}", "found": blocked.found})
        except Exception as error:  # fail closed
            croak_store.append("audit", {**base, "action": "error", "error": type(error).__name__})
            raise HTTPException(
                status_code=500,
                detail={"error": "[croak] 요청을 검사하지 못해 보내지 않았다. 관리자에게 알린다."},
            )
        action = "mask" if counts["pii"] or counts["secrets"] else "pass"
        record = {**base, "action": action, "pii": counts["pii"], "secrets": counts["secrets"]}
        if paths["blocked"] or paths["lines"]:
            record["paths"] = {k: paths[k] for k in ("blocked", "lines", "rules")}
        if media["images"] or media["pdfs"] or media["unscanned"]:
            record["media"] = {k: media[k] for k in ("images", "pdfs", "unscanned", "ms")}
        # Every request resends the whole conversation, so a secret already in
        # the history is redacted each time but counted as a violation only in
        # the request that brought it in.
        if fresh:
            record["violation"] = "secret_in_history"
            record["fresh_secrets"] = fresh
        elif paths["fresh"]:
            record["violation"] = "path_blocked"
        elif decision.downgraded:
            record["violation"] = "downgraded"
        croak_store.append("audit", record)
        metadata = data.setdefault("metadata", {})
        metadata["croak"] = {
            "agent": decision.agent,
            "tier": tier.name,
            "profile": decision.profile.name,
            "pii": decision.profile.pii,
            "store_prompt": decision.profile.store_prompt,
            "session": headers.get(SESSION_HEADER),
            "client": base.get("client"),
            # Which model served the request and how hard it thought (croak_models.apply_level).
            **{k: base.get(k) for k in ("alias", "served_model", "engine", "reasoning", "run")},
            # Masked text read from images, for the archive (which keeps no image data).
            "media_text": media["texts"],
            **who,
        }
        return data
