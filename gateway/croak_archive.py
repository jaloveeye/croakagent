"""Prompt archive for croak-gate.

Registered in config.yaml as the callback `croak_archive.archive_logger`.
After a successful call it writes the token usage of every request to the
usage log, and stores what the request added (the messages after the last
assistant message) and the answer, but only when the guardrail's profile says
`store_prompt: masked`. The messages were already masked by the
guardrail; the answer is masked here with the same profile.
"""
from __future__ import annotations

import os
import sys
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from litellm.integrations.custom_logger import CustomLogger  # noqa: E402

import croak_store  # noqa: E402
from croak_core import PII_PATTERNS, SECRET_PATTERNS, new_turn, redact, strip_media  # noqa: E402


def _answer_text(kwargs: dict[str, Any], response: Any) -> str:
    response = kwargs.get("complete_streaming_response") or response
    try:
        choice = response.choices[0]
        message = getattr(choice, "message", None)
        text = getattr(message, "content", None) or ""
        calls = getattr(message, "tool_calls", None) or []
        names = [getattr(getattr(c, "function", None), "name", "") for c in calls]
        return text + (f"\n[tool_calls: {', '.join(n for n in names if n)}]" if names else "")
    except Exception:
        return ""


def _mask(text: str, pii: str, allow: dict | None = None) -> str:
    text = redact(text, SECRET_PATTERNS, "REDACTED").text
    return text if pii == "allow" else redact(text, PII_PATTERNS, "MASKED", allow).text


def _usage(response: Any) -> dict[str, Any]:
    usage = getattr(response, "usage", None)
    if usage is None:
        return {}
    return {k: getattr(usage, k, None) for k in ("prompt_tokens", "completion_tokens", "total_tokens")}


class CroakArchive(CustomLogger):
    async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):  # type: ignore[override]
        try:
            metadata = (kwargs.get("litellm_params") or {}).get("metadata") or {}
            croak = metadata.get("croak")
            if not croak:
                return
            common = {
                **croak,
                "model": kwargs.get("model"),
                "duration_ms": int((end_time - start_time).total_seconds() * 1000),
                "usage": _usage(kwargs.get("complete_streaming_response") or response_obj),
            }
            croak_store.append("usage", {k: common.get(k) for k in ("user", "tier", "agent", "model", "session", "duration_ms", "usage")})
            if croak.get("store_prompt") != "masked":
                return
            messages = kwargs.get("messages") or []
            croak_store.append(
                "archive",
                {
                    **common,
                    # Images and PDFs are not stored; their masked OCR text is.
                    "input": strip_media(new_turn(messages)),
                    # The allow list covers the system prompt only, not answers.
                    "output": _mask(_answer_text(kwargs, response_obj), croak.get("pii", "mask")),
                },
            )
        except Exception as error:
            # The answer already reached the user; record the failure instead of raising.
            croak_store.append("audit", {"action": "archive_error", "error": type(error).__name__})


archive_logger = CroakArchive()
