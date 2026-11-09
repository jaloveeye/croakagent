"""Append-only JSONL files for audit events and the prompt archive.

    $CROAK_DATA/audit/YYYY-MM-DD.jsonl    every guardrail decision, no message text
    $CROAK_DATA/usage/YYYY-MM-DD.jsonl    tokens per successful call
    $CROAK_DATA/archive/YYYY-MM-DD.jsonl  masked prompts and answers, per profile
    $CROAK_DATA/sessions/<sha256>.json    who started each opencode session

Files are 0600 in 0700 directories. The container runs as root, so set
CROAK_DATA_UID/CROAK_DATA_GID to the server account that reads them; files
and directories are then owned by it. Days older than the policy's
retention_days are deleted, checked at most once an hour.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import threading
import time
from typing import Any

DATA_DIR = os.environ.get("CROAK_DATA", "/data")


def _owner() -> tuple[int, int] | None:
    uid, gid = os.environ.get("CROAK_DATA_UID"), os.environ.get("CROAK_DATA_GID")
    if not uid:
        return None
    return int(uid), int(gid or uid)


def _own(path: str) -> None:
    owner = _owner()
    if owner and hasattr(os, "chown"):
        os.chown(path, *owner)


_lock = threading.Lock()
_last_purge = 0.0


def _today(now: dt.datetime) -> str:
    return now.astimezone().strftime("%Y-%m-%d")


def append(kind: str, record: dict[str, Any], now: dt.datetime | None = None) -> None:
    now = now or dt.datetime.now(dt.timezone.utc)
    directory = os.path.join(DATA_DIR, kind)
    path = os.path.join(directory, f"{_today(now)}.jsonl")
    line = json.dumps({"ts": now.isoformat(), **record}, ensure_ascii=False) + "\n"
    with _lock:
        if not os.path.isdir(directory):
            os.makedirs(directory, mode=0o700, exist_ok=True)
            _own(directory)
        new = not os.path.exists(path)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        if new:
            _own(path)
        try:
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)


def claim_session(session_id: str, owner: str) -> str:
    """Records who started an opencode session and returns that owner.

    The first request of a session claims it (an exclusive create, so two
    racing requests cannot both win). Later requests get the stored owner.
    File names are hashes, so client-chosen ids never become paths.
    """
    directory = os.path.join(DATA_DIR, "sessions")
    path = os.path.join(directory, hashlib.sha256(session_id.encode("utf-8")).hexdigest() + ".json")
    with _lock:
        if not os.path.isdir(directory):
            os.makedirs(directory, mode=0o700, exist_ok=True)
            _own(directory)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        with open(path, encoding="utf-8") as f:
            return str(json.load(f).get("owner", ""))
    _own(path)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"owner": owner, "ts": dt.datetime.now(dt.timezone.utc).isoformat()}, f)
    return owner


def purge(retention_days: int, now: float | None = None, force: bool = False) -> list[str]:
    """Deletes day files older than retention_days. Returns the deleted paths."""
    global _last_purge
    now = now or time.time()
    if not force and now - _last_purge < 3600:
        return []
    _last_purge = now
    cutoff = dt.date.fromtimestamp(now) - dt.timedelta(days=retention_days)
    deleted = []
    for kind in ("audit", "usage", "archive"):
        directory = os.path.join(DATA_DIR, kind)
        if not os.path.isdir(directory):
            continue
        for name in os.listdir(directory):
            try:
                day = dt.date.fromisoformat(name.removesuffix(".jsonl"))
            except ValueError:
                continue
            if day < cutoff:
                path = os.path.join(directory, name)
                os.remove(path)
                deleted.append(path)
    # Session owners: by last change, like the day files.
    directory = os.path.join(DATA_DIR, "sessions")
    if os.path.isdir(directory):
        limit = now - retention_days * 86400
        for name in os.listdir(directory):
            path = os.path.join(directory, name)
            if name.endswith(".json") and os.path.getmtime(path) < limit:
                os.remove(path)
                deleted.append(path)
    return deleted
