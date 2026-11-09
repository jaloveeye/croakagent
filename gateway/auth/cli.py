"""Account administration for croak-auth, run on the server.

    docker compose exec auth python cli.py create-user alice --tier full --role admin --role auditor
    docker compose exec auth python cli.py set-password alice
    docker compose exec auth python cli.py set-tier alice standard
    docker compose exec auth python cli.py set-roles alice admin auditor
    docker compose exec auth python cli.py lock alice        # also ends every session
    docker compose exec auth python cli.py unlock alice
    docker compose exec auth python cli.py revoke alice      # ends every session
    docker compose exec auth python cli.py sweep             # end expired sessions now
    docker compose exec auth python cli.py list

Passwords are typed at a hidden prompt (use `exec -it`), never passed as arguments.
"""
from __future__ import annotations

import argparse
import getpass
import sys

from argon2 import PasswordHasher

import auth_core as core
import auth_db as db

hasher = PasswordHasher()
ACTOR = "cli"


def ask_password(username: str) -> str:
    first = getpass.getpass(f"{username} 비밀번호: ")
    problem = core.password_problem(first, username)
    if problem:
        sys.exit(problem)
    if getpass.getpass("한 번 더: ") != first:
        sys.exit("두 비밀번호가 다르다.")
    return first


def need_user(conn, username: str) -> dict:
    user = db.user_by_name(conn, username)
    if not user:
        sys.exit(f"사용자가 없다: {username}")
    return user


def end_all(conn, user: dict, reason: str) -> int:
    from app import end_session

    sessions = conn.execute("SELECT * FROM sessions WHERE user_id = %s AND ended_at IS NULL", (user["id"],)).fetchall()
    for session in sessions:
        end_session(conn, session, reason, actor=ACTOR)
    return len(sessions)


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="cli.py")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create-user")
    c.add_argument("username")
    c.add_argument("--tier", choices=core.TIERS, default="restricted")
    c.add_argument("--role", action="append", choices=core.ROLES, default=[])
    for name in ("set-password", "lock", "unlock", "revoke"):
        sub.add_parser(name).add_argument("username")
    t = sub.add_parser("set-tier")
    t.add_argument("username")
    t.add_argument("tier", choices=core.TIERS)
    r = sub.add_parser("set-roles")
    r.add_argument("username")
    r.add_argument("roles", nargs="*", choices=core.ROLES)
    sub.add_parser("list")
    sub.add_parser("sweep")
    args = p.parse_args(argv)

    db.ensure_database()
    with db.connect() as conn:
        if args.cmd == "create-user":
            if not core.valid_username(args.username):
                sys.exit("아이디는 소문자로 시작하고 소문자, 숫자, . _ - 만 쓴다 (2-32자).")
            if db.user_by_name(conn, args.username):
                sys.exit(f"이미 있는 사용자다: {args.username}")
            password = ask_password(args.username)
            roles = sorted(set(args.role))
            conn.execute(
                "INSERT INTO users (username, password_hash, tier, roles) VALUES (%s, %s, %s, %s)",
                (args.username, hasher.hash(password), args.tier, roles),
            )
            db.event(conn, "user_created", actor=ACTOR, subject=args.username, tier=args.tier, roles=roles)
            print(f"만들었다: {args.username} ({args.tier}, {', '.join(roles) or '관리 권한 없음'})")
        elif args.cmd == "set-password":
            user = need_user(conn, args.username)
            password = ask_password(args.username)
            conn.execute("UPDATE users SET password_hash = %s, failed = 0, last_failed = NULL WHERE id = %s",
                         (hasher.hash(password), user["id"]))
            ended = end_all(conn, user, "password_changed")
            db.event(conn, "password_changed", actor=ACTOR, subject=args.username)
            print(f"비밀번호를 바꿨다. 세션 {ended}개를 끝냈다.")
        elif args.cmd == "set-tier":
            user = need_user(conn, args.username)
            conn.execute("UPDATE users SET tier = %s WHERE id = %s", (args.tier, user["id"]))
            ended = end_all(conn, user, "tier_changed")
            db.event(conn, "tier_changed", actor=ACTOR, subject=args.username, tier=args.tier)
            print(f"등급을 {args.tier}로 바꿨다. 세션 {ended}개를 끝냈다. 다시 로그인하면 적용된다.")
        elif args.cmd == "set-roles":
            user = need_user(conn, args.username)
            roles = sorted(set(args.roles))
            conn.execute("UPDATE users SET roles = %s WHERE id = %s", (roles, user["id"]))
            ended = end_all(conn, user, "roles_changed")
            db.event(conn, "roles_changed", actor=ACTOR, subject=args.username, roles=roles)
            print(f"관리 권한을 [{', '.join(roles)}]로 바꿨다. 세션 {ended}개를 끝냈다.")
        elif args.cmd in ("lock", "unlock"):
            user = need_user(conn, args.username)
            conn.execute("UPDATE users SET disabled = %s, failed = 0, last_failed = NULL WHERE id = %s",
                         (args.cmd == "lock", user["id"]))
            ended = end_all(conn, user, "locked") if args.cmd == "lock" else 0
            db.event(conn, f"user_{args.cmd}ed", actor=ACTOR, subject=args.username)
            print(f"{args.cmd}: {args.username}" + (f", 세션 {ended}개를 끝냈다." if ended else ""))
        elif args.cmd == "revoke":
            user = need_user(conn, args.username)
            print(f"세션 {end_all(conn, user, 'revoked')}개를 끝냈다.")
        elif args.cmd == "sweep":
            from app import sweep

            print(f"만료 세션 {sweep()}개를 끝냈다.")
        elif args.cmd == "list":
            rows = conn.execute(
                """SELECT u.username, u.tier, u.roles, u.disabled,
                          count(s.id) FILTER (WHERE s.ended_at IS NULL) AS open
                     FROM users u LEFT JOIN sessions s ON s.user_id = u.id
                    GROUP BY u.id ORDER BY u.username"""
            ).fetchall()
            for row in rows:
                flag = " (잠김)" if row["disabled"] else ""
                print(f"{row['username']:<20} {row['tier']:<11} {','.join(row['roles']) or '-':<16} 세션 {row['open']}{flag}")


if __name__ == "__main__":
    main()
