"""End-to-end test of croakcode execution permits (stdlib + cryptography).

    python3 tests/e2e_permits.py <work-dir> [croakcode-opencode-dir]

Starts the stack like tests/e2e.py, with a permit signing key and a policy
whose restricted tier requires permits. Checks issuing at croak-auth, the
token signature, and the guardrail's reconciliation of tool results. With
a croakcode checkout it also runs croakcode's real permit client (PT-07).
Everything lives in <work-dir>; the stack is removed at the end.
"""
import base64
import hashlib
import json
import os
import re
import secrets
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
from croak_core import args_hash  # noqa: E402

WORK = os.path.abspath(sys.argv[1])
CROAKCODE = os.path.abspath(sys.argv[2]) if len(sys.argv) > 2 else ""
PORT, TLS_PORT = 4198, 8498
MASTER = "sk-test-" + secrets.token_hex(16)
USER, PASSWORD = "e2e-permit", "correct horse battery staple"

os.makedirs(WORK, exist_ok=True)
DATA, RECORDS, SETTINGS, SECRETS, DOWNLOADS = (os.path.join(WORK, d) for d in ("data", "records", "settings", "secrets", "downloads"))
for d in (DATA, RECORDS, SETTINGS, DOWNLOADS):
    os.makedirs(d, exist_ok=True)
    os.chmod(d, 0o777)
with open(os.path.join(DOWNLOADS, "manifest.json"), "w") as f:
    json.dump({"product": "croakcode", "latest": "1.0.0", "minimum": "1.0.0"}, f)
CERTS = os.path.join(WORK, "certs")
ENV = os.path.join(WORK, "test.env")
with open(ENV, "w") as f:
    f.write(
        f"POSTGRES_PASSWORD={secrets.token_hex(12)}\nLITELLM_MASTER_KEY={MASTER}\n"
        f"UPSTREAM_API_BASE=http://mock:8000/v1\nUPSTREAM_API_KEY=unused\nUPSTREAM_API_KEY_QWEN=unused\nCROAK_GATE_PORT={PORT}\n"
        f"CROAK_DATA_UID={os.getuid()}\nCROAK_DATA_GID={os.getgid()}\n"
        f"CROAK_TLS_PORT={TLS_PORT}\nCROAK_CERTS={CERTS}\nCROAK_SETTINGS={SETTINGS}\nCROAK_SECRETS={SECRETS}\n"
        f"CROAK_PUBLIC_URL=https://127.0.0.1:{TLS_PORT}\n"
    )
os.chmod(ENV, 0o600)
subprocess.run([os.path.join(HERE, "tls", "make-certs.sh"), "--out", CERTS, "127.0.0.1", "localhost"],
               env={**os.environ, "CROAK_CA_DIR": os.path.join(WORK, "ca")}, check=True, capture_output=True)
made = subprocess.run([os.path.join(HERE, "make-permit-key.sh")], env={**os.environ, "CROAK_SECRETS": SECRETS},
                      check=True, capture_output=True, text=True)
PUBLIC = made.stdout.strip().split("=", 1)[1]

# This test's policy: the test policy with permits required for the restricted tier.
with open(os.path.join(HERE, "tests", "policy.test.yaml"), encoding="utf-8") as f:
    policy = f.read()
policy = policy.replace("secrets_scope: all}", "secrets_scope: all, require_permits: true}")
assert "require_permits: true" in policy
POLICY = os.path.join(WORK, "policy.permits.yaml")
with open(POLICY, "w", encoding="utf-8") as f:
    f.write(policy)
OVERRIDE = os.path.join(WORK, "compose.permits.yml")
with open(OVERRIDE, "w") as f:
    f.write(f"services:\n  gate:\n    volumes:\n      - {POLICY}:/app/gateway/policy.yaml:ro\n"
            f"  auth:\n    volumes:\n      - {POLICY}:/app/policy.yaml:ro\n")

COMPOSE = ["docker", "compose", "-f", "docker-compose.yml", "-f", "tests/compose.test.yml", "-f", OVERRIDE,
           "--env-file", ENV, "-p", "croak-permit-test"]
ENVIRON = {**os.environ, "CROAK_TEST_RECORDS": RECORDS, "CROAK_TEST_DATA": DATA, "CROAK_TEST_DOWNLOADS": DOWNLOADS}


def compose(*args, check=True, **kw):
    return subprocess.run(COMPOSE + list(args), cwd=HERE, env=ENVIRON, check=check, capture_output=True, text=True, **kw)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def tls(method, path, body=None, headers=None, form=False, raw=None):
    data, hdrs = None, {"x-croak-client-version": "1.0.0", **(headers or {})}
    if raw is not None:
        data, hdrs["content-type"] = raw, "application/json"
    elif body is not None:
        data = urllib.parse.urlencode(body).encode() if form else json.dumps(body).encode()
        hdrs["content-type"] = "application/x-www-form-urlencoded" if form else "application/json"
    req = urllib.request.Request(f"https://127.0.0.1:{TLS_PORT}{path}", data=data, headers=hdrs, method=method)
    ctx = ssl.create_default_context(cafile=os.path.join(CERTS, "ca.crt"))
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), NoRedirect())
    try:
        with opener.open(req, timeout=60) as r:
            return r.status, r.headers, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode()


def login():
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    _, headers, text = tls("GET", f"/auth/login?challenge={challenge}")
    cookie = headers.get("set-cookie", "").split(";")[0]
    csrf = re.search(r"name='csrf' value='([^']+)'", text).group(1)
    _, _, text = tls("POST", "/auth/login", {"username": USER, "password": PASSWORD, "challenge": challenge, "csrf": csrf},
                     {"cookie": cookie}, form=True)
    code = (re.search(r"class='code' id='code'>([A-Z0-9-]+)<", text) or re.search(r"class='code'>([A-Z0-9-]+)<", text)).group(1)
    status, _, text = tls("POST", "/auth/token", {"grant_type": "authorization_code", "code": code, "code_verifier": verifier})
    if status != 200:
        raise SystemExit(f"login failed: {status} {text[:300]}\n" + compose("logs", "auth", check=False).stdout[-2000:])
    return json.loads(text)


def unb64url(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


failures = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -- {detail}"))
    if not ok:
        failures.append(name)


try:
    compose("up", "-d", "--build")
    # Token issuing creates a gate key, so the gate must be up before login.
    for _ in range(120):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/health/liveliness", timeout=2):
                break
        except Exception:
            time.sleep(2)
    else:
        raise SystemExit("gate did not become healthy:\n" + compose("logs", "gate", check=False).stdout[-3000:])
    for _ in range(120):
        try:
            if tls("GET", "/auth/health")[0] == 200:
                break
        except (urllib.error.URLError, ConnectionError, ssl.SSLError):
            pass  # the proxy is not up yet
        time.sleep(2)
    else:
        raise SystemExit("auth did not become healthy:\n" + compose("logs", "auth", check=False).stdout[-3000:])
    created = compose("exec", "-T", "auth", "python", "cli.py", "create-user", USER, "--tier", "restricted",
                      check=False, input=f"{PASSWORD}\n{PASSWORD}\n")
    check("cli creates a restricted user", created.returncode == 0, created.stderr[-300:])
    tokens = login()
    access = tokens.get("access_token", "")
    check("login gives an access token", bool(access), json.dumps(tokens)[:200])
    auth = {"authorization": f"Bearer {access}"}
    sid = "ses_e2e_permit_0000000000001"
    read_args = {"filePath": "/work/a.txt"}
    request = {"sid": sid, "pid": "apr_e2e", "rid": "run_e2e", "tool": "read", "args": args_hash(read_args), "rev": 0}

    # 1. Issuing.
    status, _, text = tls("POST", "/v1/execution-permits", request, auth)
    check("permit issued for a permitted tool", status == 200 and "token" in text, f"{status} {text[:200]}")
    token = json.loads(text).get("token", "") if status == 200 else ""
    segment, _, signature = token.partition(".")
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(PUBLIC)).verify(unb64url(signature), segment.encode("ascii"))
        signed = True
    except Exception:
        signed = False
    check("permit signature verifies with the published key", signed)
    payload = json.loads(unb64url(segment)) if segment else {}
    check("permit binds the call", {k: payload.get(k) for k in request} == request and payload.get("aud") == "croakcode"
          and payload.get("exp", 0) - payload.get("iat", 0) == 30_000, json.dumps(payload)[:300])
    rows = compose("exec", "-T", "db", "psql", "-U", "croak", "-d", "croak_auth", "-tAc",
                   f"SELECT count(*) FROM execution_permits WHERE session_id = '{sid}' AND tool = 'read'").stdout.strip()
    check("permit recorded", rows == "1", rows)

    status, _, text = tls("POST", "/v1/execution-permits", {**request, "tool": "bash"}, auth)
    check("tier-denied tool gets no permit", status == 403 and "tool_denied" in text, f"{status} {text[:200]}")
    status, _, _ = tls("POST", "/v1/execution-permits", request, {"authorization": "Bearer nope"})
    check("unknown token gets no permit", status == 401, str(status))
    status, _, _ = tls("POST", "/v1/execution-permits", {**request, "args": "not-a-hash"}, auth)
    check("malformed request refused", status == 400, str(status))
    foreign = "ses_e2e_foreign_000000000001"
    os.makedirs(os.path.join(DATA, "sessions"), exist_ok=True)
    with open(os.path.join(DATA, "sessions", hashlib.sha256(foreign.encode()).hexdigest() + ".json"), "w") as f:
        json.dump({"owner": "someone-else"}, f)
    status, _, text = tls("POST", "/v1/execution-permits", {**request, "sid": foreign}, auth)
    check("another account's session gets no permit", status == 403 and "foreign_session" in text, f"{status} {text[:200]}")
    status, _, _ = tls("POST", "/internal/permits/check", {"session": sid, "calls": []}, auth)
    check("internal check is not reachable from outside", status == 404, str(status))

    # 2. Reconciliation at the gate.
    def chat_with_result(args, session=sid):
        messages = [
            {"role": "user", "content": "read the file"},
            {"role": "assistant", "content": None, "tool_calls": [
                {"id": "call_1", "type": "function", "function": {"name": "read", "arguments": json.dumps(args)}}]},
            {"role": "tool", "tool_call_id": "call_1", "content": "file body"},
        ]
        return tls("POST", "/v1/chat/completions", {"model": "default", "messages": messages},
                   {**auth, "x-croak-agent": "dev-safe", "x-croak-session": session})

    status, _, text = chat_with_result({"filePath": "/work/a.txt"})
    check("a permitted tool result reaches the model", status == 200, f"{status} {text[:200]}")
    status, _, text = chat_with_result({"filePath": "/etc/shadow"})
    check("an unpermitted tool result is refused", status == 403 and "unpermitted_tool" in text, f"{status} {text[:300]}")
    status, _, text = chat_with_result({"filePath": "/work/a.txt"}, session="ses_e2e_other_00000000000001")
    check("a permit does not carry over to another session", status == 403 and "unpermitted_tool" in text, f"{status} {text[:200]}")
    blob = ""
    for root, _, files in os.walk(os.path.join(DATA, "audit")):
        for name in files:
            with open(os.path.join(root, name)) as f:
                blob += f.read()
    check("refusal is audited", '"violation": "unpermitted_tool"' in blob or '"violation":"unpermitted_tool"' in blob, blob[-300:])

    # 3. Guardrail unit tests where litellm is installed (the gate image).
    cid = compose("ps", "-q", "gate").stdout.strip()
    subprocess.run(["docker", "cp", os.path.join(HERE, "tests", "test_permits.py"), f"{cid}:/tmp/test_permits.py"], check=True)
    unit = subprocess.run(["docker", "exec", "-w", "/tmp", "-e", "PYTHONPATH=/app/gateway", cid, "python", "-m", "unittest", "-v", "test_permits"],
                          capture_output=True, text=True)
    ran = re.search(r"Ran (\d+) test", unit.stderr)
    skipped = "skipped" in unit.stderr and "Reconcile" in unit.stderr and "litellm" in unit.stderr
    check("guardrail unit tests pass inside the gate image", unit.returncode == 0 and ran and not skipped, unit.stderr[-600:])

    # 4. PT-07: croakcode's real permit client against this gate.
    if CROAKCODE:
        cfg = os.path.join(WORK, "croak-config")
        os.makedirs(cfg, exist_ok=True)
        with open(os.path.join(cfg, "session.json"), "w") as f:
            json.dump({k: tokens[k] for k in ("access_token", "access_expires_at", "refresh_token", "session_expires_at") if k in tokens}, f)
        os.chmod(os.path.join(cfg, "session.json"), 0o600)
        live = subprocess.run(
            ["bun", "run", "script/permit-live-check.ts", sid, "read", json.dumps(read_args)],
            cwd=CROAKCODE, capture_output=True, text=True, timeout=120,
            env={**os.environ, "CROAKCODE_GATE_PERMIT_URL": f"https://127.0.0.1:{TLS_PORT}", "CROAKCODE_GATE_PERMIT_PUBLIC_KEY": PUBLIC,
                 "CROAK_CONFIG_DIR": cfg, "CROAKCODE_DEV_CLIENT_VERSION": "1.0.0", "CROAKCODE_CLIENT_VERSION": "1.0.0", "NODE_EXTRA_CA_CERTS": os.path.join(CERTS, "ca.crt")},
        )
        out = (live.stdout.strip().splitlines() or [""])[-1]
        check("PT-07: croakcode client gets and verifies a real permit", live.returncode == 0 and '"ok":true' in out, out + live.stderr[-300:])

        # 5. PT-08: a whole croakcode turn under require_permits. The mock model
        # calls todowrite through croakcode's tool_call proxy; the result must
        # reach the model past the gate's check.
        project = os.path.join(WORK, "pt08")
        os.makedirs(project, exist_ok=True)
        env = {**os.environ, "LITELLM_BASE_URL": f"https://127.0.0.1:{TLS_PORT}/v1", "CROAK_AUTH_URL": f"https://127.0.0.1:{TLS_PORT}",
               "CROAKCODE_GATE_PERMIT_URL": f"https://127.0.0.1:{TLS_PORT}", "CROAKCODE_GATE_PERMIT_PUBLIC_KEY": PUBLIC,
               "CROAKCODE_EXECUTION_PERMIT": "required", "CROAK_CONFIG_DIR": cfg, "NODE_EXTRA_CA_CERTS": os.path.join(CERTS, "ca.crt"),
               "CROAKCODE_DEV_CLIENT_VERSION": "1.0.0",
               "CROAKCODE_CONFIG_DIR": os.path.join(CROAKCODE, "..", "..", ".croakcode")}

        def turn(prompt, *more):
            done = subprocess.run(
                ["bun", "run", "--conditions=browser", "src/index.ts", "run", "--format", "json", "--dir", project,
                 "-m", "litellm-head/qwen3.8-27b-nvfp4", "--agent", "dev-safe", *more, prompt],
                cwd=CROAKCODE, capture_output=True, text=True, timeout=180, env=env, stdin=subprocess.DEVNULL,
            )
            events = [json.loads(line) for line in done.stdout.splitlines() if line.startswith("{")]
            texts = [e["part"].get("text", "") for e in events if e.get("type") == "text"]
            errors = [json.dumps(e.get("error"), ensure_ascii=False)[:300] for e in events if e.get("type") == "error"]
            return texts, errors, events, done.stderr[-400:]

        texts, errors, events, stderr = turn('CALL_TOOL tool_call {"name":"todowrite","input":{"todos":[{"content":"x","status":"pending","priority":"low"}]}}')
        session_id = next((e.get("sessionID") for e in events if e.get("sessionID")), "")
        check("PT-08: a tool_call result reaches the model under require_permits",
              not errors and any(t.startswith("SEEN:") for t in texts), json.dumps({"texts": texts, "errors": errors, "stderr": stderr}, ensure_ascii=False))
        rows = compose("exec", "-T", "db", "psql", "-U", "croak", "-d", "croak_auth", "-tAc",
                       f"SELECT count(*) FROM execution_permits WHERE session_id = '{session_id}' AND tool = 'todowrite'").stdout.strip()
        check("PT-08: the permit is for the tool tool_call called", rows == "1", rows)

        # 6. PT-09: login alone turns permits on. No permit settings in the
        # environment; the token answer says the tier requires permits and
        # carries the key, and croakcode follows it.
        check("PT-09: the token answer carries the tier's permit settings",
              tokens.get("execution_permits") == {"required": True, "public_key": PUBLIC}, json.dumps(tokens.get("execution_permits")))
        login_cfg = os.path.join(WORK, "croak-config-login")
        os.makedirs(login_cfg, exist_ok=True)
        with open(os.path.join(login_cfg, "session.json"), "w") as f:
            keep = ("access_token", "access_expires_at", "refresh_token", "session_expires_at", "execution_permits")
            json.dump({**{k: tokens[k] for k in keep if k in tokens}, "auth_url": f"https://127.0.0.1:{TLS_PORT}"}, f)
        os.chmod(os.path.join(login_cfg, "session.json"), 0o600)
        env = {k: v for k, v in env.items() if not k.startswith("CROAKCODE_EXECUTION_PERMIT") and not k.startswith("CROAKCODE_GATE_PERMIT")}
        env["CROAK_CONFIG_DIR"] = login_cfg
        texts, errors, events, stderr = turn('CALL_TOOL tool_call {"name":"todowrite","input":{"todos":[{"content":"y","status":"pending","priority":"low"}]}}')
        session_id = next((e.get("sessionID") for e in events if e.get("sessionID")), "")
        check("PT-09: with login only, a tool result reaches the model under require_permits",
              not errors and any(t.startswith("SEEN:") for t in texts), json.dumps({"texts": texts, "errors": errors, "stderr": stderr}, ensure_ascii=False))
        rows = compose("exec", "-T", "db", "psql", "-U", "croak", "-d", "croak_auth", "-tAc",
                       f"SELECT count(*) FROM execution_permits WHERE session_id = '{session_id}' AND tool = 'todowrite'").stdout.strip()
        check("PT-09: croakcode asked for the permit on its own", rows == "1", rows)

        # 7. PT-10: a core tool called directly (not through tool_call). In use,
        # read and bash results were refused although their permits existed.
        with open(os.path.join(project, "hello.txt"), "w") as f:
            f.write("hello\n")
        texts, errors, events, stderr = turn('CALL_TOOL read {"filePath":"' + os.path.join(project, "hello.txt") + '"}')
        session_id = next((e.get("sessionID") for e in events if e.get("sessionID")), "")
        rows = compose("exec", "-T", "db", "psql", "-U", "croak", "-d", "croak_auth", "-tAc",
                       f"SELECT count(*) FROM execution_permits WHERE session_id = '{session_id}' AND tool = 'read'").stdout.strip()
        check("PT-10: croakcode asked for a permit for read", rows == "1", rows)
        read_session = session_id
        check("PT-10: a read result reaches the model under require_permits",
              not errors and any(t.startswith("SEEN:") for t in texts), json.dumps({"texts": texts, "errors": errors, "stderr": stderr}, ensure_ascii=False))

        # 8. PT-11: a call a policy plugin refuses before its permit (a key
        # file path) sends croakcode's fixed "never ran" text, which the gate
        # lets through. In use, such refused calls made the gate refuse the
        # whole session.
        os.makedirs(os.path.join(project, ".ssh"), exist_ok=True)
        with open(os.path.join(project, ".ssh", "id_rsa"), "w") as f:
            f.write("fake\n")
        texts, errors, events, stderr = turn('CALL_TOOL read {"filePath":"' + os.path.join(project, ".ssh", "id_rsa") + '"}')
        check("PT-11: a call that never ran does not block the session",
              not errors and any(t.startswith("SEEN: [croak]") for t in texts), json.dumps({"texts": texts, "errors": errors, "stderr": stderr}, ensure_ascii=False))

        # 9. PT-12: tool_search (croakcode's deferred-tool finder) asks for a
        # permit too. In use, its results were refused.
        texts, errors, events, stderr = turn('CALL_TOOL tool_search {"query":"todo"}')
        check("PT-12: a tool_search result reaches the model under require_permits",
              not errors and any(t.startswith("SEEN:") for t in texts), json.dumps({"texts": texts, "errors": errors, "stderr": stderr}, ensure_ascii=False))

        # 10. PT-13: a forked session copies its parent's tool calls under a
        # new session id. A permit does not carry over to another session, so
        # croakcode asks again for each copied call under the fork's own id.
        texts, errors, events, stderr = turn("fork and go on", "--session", read_session, "--fork")
        forked = next((e.get("sessionID") for e in events if e.get("sessionID")), "")
        check("PT-13: the fork is a new session", bool(forked) and forked != read_session, f"{read_session} {forked}")
        check("PT-13: a forked session's copied tool results pass",
              not errors and bool(texts), json.dumps({"texts": texts, "errors": errors, "stderr": stderr}, ensure_ascii=False))
        rows = compose("exec", "-T", "db", "psql", "-U", "croak", "-d", "croak_auth", "-tAc",
                       f"SELECT count(*) FROM execution_permits WHERE session_id = '{forked}' AND tool = 'read'").stdout.strip()
        check("PT-13: the fork asked for its own permit for the copied read", rows == "1", rows)
finally:
    if os.environ.get("KEEP") != "1":
        compose("down", "-v", check=False)

print(f"\n{len(failures)} failed" if failures else "\nall passed")
sys.exit(1 if failures else 0)
