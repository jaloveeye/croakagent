"""Postgres storage for croak-auth.

Tokens and codes are stored only as SHA-256 hashes; passwords as argon2id.
The `events` table is the admin audit trail: the service only inserts into it.
"""
from __future__ import annotations

import json
import os
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Iterator

import psycopg
from psycopg.rows import dict_row

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  tier TEXT NOT NULL,
  roles TEXT[] NOT NULL DEFAULT '{}',
  disabled BOOLEAN NOT NULL DEFAULT false,
  failed INT NOT NULL DEFAULT 0,
  last_failed TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS auth_codes (
  code_hash TEXT PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users ON DELETE CASCADE,
  challenge TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users ON DELETE CASCADE,
  refresh_hash TEXT UNIQUE NOT NULL,
  access_hash TEXT,
  key_alias TEXT,
  seq INT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  access_expires_at TIMESTAMPTZ,
  ended_at TIMESTAMPTZ,
  end_reason TEXT,
  key_deleted BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS sessions_access ON sessions (access_hash);
CREATE INDEX IF NOT EXISTS sessions_open ON sessions (expires_at) WHERE ended_at IS NULL;
CREATE TABLE IF NOT EXISTS events (
  id BIGSERIAL PRIMARY KEY,
  ts TIMESTAMPTZ NOT NULL DEFAULT now(),
  kind TEXT NOT NULL,
  actor TEXT,
  subject TEXT,
  ip TEXT,
  detail JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS events_ts ON events (ts);
CREATE TABLE IF NOT EXISTS admin_sessions (
  id_hash TEXT PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users ON DELETE CASCADE,
  csrf TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
  ended_at TIMESTAMPTZ
);
"""

DSN = os.environ.get("AUTH_DATABASE_URL", "")


def ensure_database(dsn: str = DSN) -> None:
    """Creates the auth database next to the gate's one, then the tables."""
    info = psycopg.conninfo.conninfo_to_dict(dsn)
    name = info["dbname"]
    admin = psycopg.conninfo.make_conninfo(dsn, dbname=os.environ.get("AUTH_ADMIN_DB", "postgres"))
    with psycopg.connect(admin, autocommit=True) as conn:
        if not conn.execute("SELECT 1 FROM pg_database WHERE datname = %s", (name,)).fetchone():
            conn.execute(psycopg.sql.SQL("CREATE DATABASE {}").format(psycopg.sql.Identifier(name)))
    with connect(dsn) as conn:
        conn.execute(SCHEMA)


@contextmanager
def connect(dsn: str = DSN) -> Iterator[psycopg.Connection]:
    with psycopg.connect(dsn, row_factory=dict_row) as conn:
        yield conn


def event(conn: psycopg.Connection, kind: str, *, actor: str | None = None, subject: str | None = None,
          ip: str | None = None, **detail: Any) -> None:
    conn.execute(
        "INSERT INTO events (kind, actor, subject, ip, detail) VALUES (%s, %s, %s, %s, %s)",
        (kind, actor, subject, ip, json.dumps(detail, ensure_ascii=False, default=str)),
    )


def user_by_name(conn: psycopg.Connection, username: str) -> dict | None:
    return conn.execute("SELECT * FROM users WHERE username = %s", (username,)).fetchone()


def user_by_id(conn: psycopg.Connection, user_id: int) -> dict | None:
    return conn.execute("SELECT * FROM users WHERE id = %s", (user_id,)).fetchone()


def failed_from_ip(conn: psycopg.Connection, ip: str, since: datetime) -> int:
    row = conn.execute(
        "SELECT count(*) AS n FROM events WHERE kind = 'login_failed' AND ip = %s AND ts > %s", (ip, since)
    ).fetchone()
    return int(row["n"])
