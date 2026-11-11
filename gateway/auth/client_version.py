"""Enforce the minimum client version from the public release manifest."""
from __future__ import annotations

import json
import re
from pathlib import Path

# Development builds sort before the corresponding release.
VERSION = re.compile(r"^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})(-dev\.[0-9a-f]+)?$")


def version(value: object, *, release: bool = False) -> tuple[int, int, int, int] | None:
    if not isinstance(value, str) or len(value) > 100:
        return None
    match = VERSION.fullmatch(value)
    if not match or (release and match[4]):
        return None
    return (int(match[1]), int(match[2]), int(match[3]), 0 if match[4] else 1)


def check(manifest_path: str | Path, client: str | None) -> tuple[int, dict]:
    try:
        with open(manifest_path, encoding="utf-8") as source:
            data = json.load(source)
        if not isinstance(data, dict) or data.get("product") != "croakcode":
            raise ValueError("invalid product")
        minimum = version(data.get("minimum"), release=True)
        latest = version(data.get("latest"), release=True)
        if minimum is None or latest is None or minimum > latest:
            raise ValueError("invalid versions")
    except (OSError, ValueError, TypeError):
        return 503, {"error": "version_policy_unavailable", "message": "업데이트 정책을 확인할 수 없습니다."}
    received = version(client)
    if received is None or received < minimum:
        return 426, {"error": "upgrade_required", "message": "croakcode upgrade를 실행해 업데이트하세요.", "minimum": data["minimum"]}
    return 200, {"ok": True}
