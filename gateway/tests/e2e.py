"""End-to-end test of croak-gate against a mock upstream (stdlib only).

    python3 tests/e2e.py <work-dir>

Starts the stack with docker compose, issues two virtual keys, sends requests
and checks what the mock upstream received, the audit log and the archive.
Everything it creates lives in <work-dir>; the stack is removed at the end.
"""
import base64
import glob
import hashlib
import re
import json
import os
import secrets
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = os.path.abspath(sys.argv[1])
PORT = 4199
TLS_PORT = 8499
PHONE = "010-1234-5678"
AWS = "AKIAIOSFODNN7EXAMPLE"
SK = "sk-" + "t" * 32
MASTER = "sk-test-" + secrets.token_hex(16)

os.makedirs(WORK, exist_ok=True)
RECORDS = os.path.join(WORK, "records")
DATA = os.path.join(WORK, "data")
SETTINGS = os.path.join(WORK, "settings")
for d in (RECORDS, DATA, SETTINGS):
    os.makedirs(d, exist_ok=True)
    os.chmod(d, 0o777)  # the containers write here as other users
ENV = os.path.join(WORK, "test.env")
with open(ENV, "w") as f:
    f.write(
        f"POSTGRES_PASSWORD={secrets.token_hex(12)}\nLITELLM_MASTER_KEY={MASTER}\n"
        f"UPSTREAM_API_BASE=http://mock:8000/v1\nUPSTREAM_API_KEY=unused\nUPSTREAM_API_KEY_QWEN=unused\nCROAK_GATE_PORT={PORT}\n"
        f"CROAK_DATA_UID={os.getuid()}\nCROAK_DATA_GID={os.getgid()}\n"
        f"CROAK_TLS_PORT={TLS_PORT}\nCROAK_CERTS={os.path.join(WORK, 'certs')}\nCROAK_SETTINGS={os.path.join(WORK, 'settings')}\n"
        f"CROAK_PUBLIC_URL=https://127.0.0.1:{TLS_PORT}\n"
    )
os.chmod(ENV, 0o600)
CERTS = os.path.join(WORK, "certs")
subprocess.run(
    [os.path.join(HERE, "tls", "make-certs.sh"), "--out", CERTS, "127.0.0.1", "localhost"],
    env={**os.environ, "CROAK_CA_DIR": os.path.join(WORK, "ca")},
    check=True,
    capture_output=True,
)
COMPOSE = ["docker", "compose", "-f", "docker-compose.yml", "-f", "tests/compose.test.yml", "--env-file", ENV, "-p", "croak-test"]
ENVIRON = {**os.environ, "CROAK_TEST_RECORDS": RECORDS, "CROAK_TEST_DATA": DATA}


def compose(*args, check=True):
    return subprocess.run(COMPOSE + list(args), cwd=HERE, env=ENVIRON, check=check, capture_output=True, text=True)


def call(path, body, key, headers=None, base=None, context=None):
    req = urllib.request.Request(
        f"{base or f'http://127.0.0.1:{PORT}'}{path}",
        data=json.dumps(body).encode(),
        headers={"content-type": "application/json", "authorization": f"Bearer {key}", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=60, context=context) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def chat(key, messages, agent=None, stream=False):
    headers = {"x-croak-agent": agent, "x-croak-session": f"ses_{key[-8:]}"} if agent else {}
    return call("/v1/chat/completions", {"model": "default", "messages": messages, "stream": stream}, key, headers)


def records():
    return sorted(glob.glob(os.path.join(RECORDS, "req-*.json")), key=lambda p: int(p.rsplit("-", 1)[1].split(".")[0]))


def last_record():
    with open(records()[-1]) as f:
        return json.load(f)


def lines(kind):
    out = []
    for p in sorted(glob.glob(os.path.join(DATA, kind, "*.jsonl"))):
        with open(p) as f:
            out += [json.loads(l) for l in f if l.strip()]
    return out


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # return 3xx responses as they are


def tls(method, path, body=None, headers=None, form=False):
    """Request through the HTTPS front. Returns (status, headers, text)."""
    data = None
    hdrs = dict(headers or {})
    if body is not None:
        if form:
            data = urllib.parse.urlencode(body).encode()
            hdrs["content-type"] = "application/x-www-form-urlencoded"
        else:
            data = json.dumps(body).encode()
            hdrs["content-type"] = "application/json"
    req = urllib.request.Request(f"https://127.0.0.1:{TLS_PORT}{path}", data=data, headers=hdrs, method=method)
    ctx = ssl.create_default_context(cafile=os.path.join(CERTS, "ca.crt"))
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), NoRedirect())
    try:
        with opener.open(req, timeout=60) as r:
            return r.status, r.headers, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode()


def pkce():
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


LAST_PAGE = {"text": "", "csp": ""}


def browser_login(username, password, challenge):
    """What the user does in the browser: open the page, submit the form. Returns (status, code)."""
    status, headers, text = tls("GET", f"/auth/login?challenge={challenge}")
    cookie = headers.get("set-cookie", "").split(";")[0]
    csrf = re.search(r"name='csrf' value='([^']+)'", text).group(1)
    status, headers_out, text = tls(
        "POST", "/auth/login",
        {"username": username, "password": password, "challenge": challenge, "csrf": csrf},
        {"cookie": cookie}, form=True,
    )
    LAST_PAGE.update(text=text, csp=headers_out.get("content-security-policy", "") if headers_out else "")
    m = re.search(r"class='code' id='code'>([A-Z0-9-]+)<", text) or re.search(r"class='code'>([A-Z0-9-]+)<", text)
    return status, m.group(1) if m else None


def psql(sql):
    return compose("exec", "-T", "db", "psql", "-U", "croak", "-d", "croak_auth", "-tAc", sql).stdout.strip()


failures = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -- {detail}"))
    if not ok:
        failures.append(name)


try:
    compose("up", "-d", "--build")  # auth bakes its code into the image
    for _ in range(120):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/health/liveliness", timeout=2):
                break
        except Exception:
            time.sleep(2)
    else:
        raise SystemExit("gate did not become healthy:\n" + compose("logs", "gate", check=False).stdout[-3000:])

    def issue(alias, metadata):
        return json.loads(call("/key/generate", {"key_alias": alias, "metadata": metadata}, MASTER)[1])["key"]

    plain = issue("e2e-plain", {"croak_tier": "standard", "croak_user": "e2e-standard"})
    granted = issue("e2e-granted", {"croak_tier": "full", "croak_user": "e2e-full"})
    untiered = issue("e2e-untiered", {})

    # 1. Personal data is masked before it leaves the gate.
    status, body = chat(plain, [{"role": "user", "content": f"고객 연락처 {PHONE}로 안내 문자를 써줘"}], agent="dev-main")
    sent = json.dumps(last_record(), ensure_ascii=False)
    check("pii masked upstream", status == 200 and PHONE not in sent and "[MASKED:mobile_phone]" in sent, f"{status} {sent[:300]}")

    # 2. A key in the newest user message blocks the request before the upstream.
    before = len(records())
    status, body = chat(plain, [{"role": "user", "content": f"이 키로 접속해 {AWS}"}], agent="dev-main")
    check("secret blocked", status == 400 and "[croak]" in body and len(records()) == before, f"{status} {body[:300]}")

    # 3. A key in tool output (history) is redacted, not blocked.
    status, body = chat(
        plain,
        [
            {"role": "user", "content": ".env 확인"},
            {"role": "assistant", "content": "읽겠다"},
            {"role": "tool", "tool_call_id": "c1", "content": f"OPENAI_API_KEY={SK}"},
            {"role": "user", "content": "계속해"},
        ],
        agent="dev-main",
    )
    sent = json.dumps(last_record(), ensure_ascii=False)
    check("history secret redacted", status == 200 and SK not in sent and "[REDACTED:" in sent, f"{status} {sent[:300]}")

    # 4. A looser profile without a grant falls back to default.
    status, body = chat(plain, [{"role": "user", "content": f"직원 연락처 {PHONE}"}], agent="hr-doc")
    sent = json.dumps(last_record(), ensure_ascii=False)
    downgraded = [a for a in lines("audit") if a.get("agent") == "hr-doc" and a.get("downgraded")]
    check("ungranted profile downgraded", status == 200 and PHONE not in sent and downgraded, f"{status} {sent[:200]}")

    # 5. With a grant the looser profile applies and nothing is archived.
    # (Archive records are written after the response, so check by profile, not by count.)
    status, body = chat(granted, [{"role": "user", "content": f"직원 연락처 {PHONE}"}], agent="hr-doc")
    sent = json.dumps(last_record(), ensure_ascii=False)
    time.sleep(2)
    check("granted profile keeps pii", status == 200 and PHONE in sent, f"{status} {sent[:200]}")
    hr_archived = [a for a in lines("archive") if a.get("profile") == "hr-doc"]
    hr_audited = [a for a in lines("audit") if a.get("profile") == "hr-doc"]
    check("store_prompt none not archived", hr_audited and not hr_archived, f"audit {len(hr_audited)} archive {len(hr_archived)}")

    # 6. Streaming works and is archived (masked).
    status, body = chat(plain, [{"role": "user", "content": f"스트림 시험 {PHONE}"}], agent="dev-main", stream=True)
    time.sleep(2)
    arch = lines("archive")
    check("stream ok", status == 200 and "ECHO" in body, body[:200])
    check("stream archived", any("스트림 시험" in json.dumps(a, ensure_ascii=False) for a in arch), json.dumps(arch[-1:], ensure_ascii=False)[:300])

    # 6b. Allowed values (policy allow list) pass unmasked; others are masked.
    status, _ = chat(plain, [{"role": "system", "content": "커밋 작성자 owner@example.com"}, {"role": "user", "content": "other@example.com 에게"}], agent="dev-main")
    sent = json.dumps(last_record(), ensure_ascii=False)
    check("allow list", status == 200 and "owner@example.com" in sent and "other@example.com" not in sent, sent[:300])

    # 7. No header -> default profile, agent recorded as unknown.
    status, _ = chat(granted, [{"role": "user", "content": "헤더 없음"}])
    check("no header uses default", status == 200 and any(a.get("agent") == "unknown" for a in lines("audit")))

    # 7a. Model registry: a reasoning level becomes the model's own parameters,
    # and the records name the alias, served model, engine, level and run.
    def leveled(level=None, run=None):
        body = {"model": "croak", "messages": [{"role": "user", "content": "추론 수준 시험"}]}
        if level is not None:
            body["reasoning_effort"] = level
        headers = {"x-croak-agent": "dev-main", "x-croak-session": f"ses_{plain[-8:]}", **({"x-croak-run": run} if run else {})}
        return call("/v1/chat/completions", body, plain, headers)
    status, _ = leveled("low", "run_e2e_low")
    sent = last_record()
    check("reasoning level becomes the model's parameters",
          status == 200 and sent.get("chat_template_kwargs") == {"enable_thinking": True, "reasoning_effort": "low"} and "reasoning_effort" not in sent,
          json.dumps(sent, ensure_ascii=False)[:300])
    status, _ = leveled()
    sent = last_record()
    check("the model's default level applies", status == 200 and sent.get("chat_template_kwargs") == {"enable_thinking": False},
          json.dumps(sent, ensure_ascii=False)[:300])
    before = len(records())
    status, body = leveled("max")
    check("an unknown reasoning level is refused", status == 400 and "reasoning_level" in body and len(records()) == before, f"{status} {body[:200]}")
    usage = []
    for _ in range(20):  # the usage line is written after the response
        usage = [u for u in lines("usage") if u.get("run") == "run_e2e_low"]
        if usage:
            break
        time.sleep(0.25)
    check("usage names alias, served model, engine, level and run",
          bool(usage) and {k: usage[-1].get(k) for k in ("alias", "served_model", "engine", "reasoning")}
          == {"alias": "croak", "served_model": "example-model", "engine": "unknown", "reasoning": "low"},
          json.dumps(usage[-1:], ensure_ascii=False)[:300])

    # 7b. Tiers: agents and tools by the key's croak_tier; no tier means restricted.
    def tiered(key, agent, tools=(), messages=None):
        body = {"model": "default", "messages": messages or [{"role": "user", "content": "등급 시험"}]}
        if tools:
            body["tools"] = [{"type": "function", "function": {"name": t, "parameters": {"type": "object"}}} for t in tools]
        return call("/v1/chat/completions", body, key, {"x-croak-agent": agent, "x-croak-session": f"ses_tier_{key[-8:]}"})

    def violations(code):
        return [a for a in lines("audit") if a.get("violation") == code]

    status, _ = tiered(plain, "dev-main", ["bash", "read"])
    check("standard may use bash", status == 200, str(status))
    status, body = tiered(untiered, "dev-main")
    check("untiered key is restricted (agent denied)", status == 403 and "agent_denied" in body, f"{status} {body[:200]}")
    status, body = tiered(untiered, "dev-doc", ["read", "bash"])
    check("restricted tool denied", status == 403 and "tool_denied" in body, f"{status} {body[:200]}")
    status, _ = tiered(untiered, "dev-doc", ["read", "edit"])
    check("restricted allowed agent and tools", status == 200, str(status))
    history = [
        {"role": "user", "content": "설정 확인"},
        {"role": "tool", "tool_call_id": "c1", "content": f"OPENAI_API_KEY={SK}"},
        {"role": "user", "content": "계속해"},
    ]
    status, _ = tiered(untiered, "dev-doc", messages=history)
    check("restricted blocks a secret anywhere", status == 400, str(status))
    status, _ = tiered(plain, "dev-main", messages=history)
    check("standard redacts a secret in history", status == 200, str(status))
    before = len(violations("secret_in_history"))
    later = history[:2] + [{"role": "assistant", "content": "확인했습니다"}, {"role": "user", "content": "다음 작업"}]
    status, _ = tiered(plain, "dev-main", messages=later)
    sent = json.dumps(last_record(), ensure_ascii=False)
    check("an old secret is redacted but not counted again", status == 200 and SK not in sent
          and len(violations("secret_in_history")) == before, f"{status} {len(violations('secret_in_history'))} vs {before}")
    check("violations recorded", violations("agent_denied") and violations("tool_denied") and violations("secret")
          and violations("secret_in_history") and violations("downgraded"),
          str({c: len(violations(c)) for c in ("agent_denied", "tool_denied", "secret", "secret_in_history", "downgraded")}))
    denied = violations("tool_denied")[-1]
    check("audit names user and tier", denied.get("tier") == "restricted" and denied.get("denied") == ["bash"]
          and violations("secret_in_history")[-1].get("user") == "e2e-standard", json.dumps(denied, ensure_ascii=False)[:300])

    # 7c. A session belongs to the account that started it.
    status, _ = tiered(plain, "dev-main", messages=[{"role": "user", "content": "내 세션"}])
    def in_session(key, sid):
        return call("/v1/chat/completions", {"model": "default", "messages": [{"role": "user", "content": "이어서"}]}, key,
                    {"x-croak-agent": "dev-main", "x-croak-session": sid})
    first, _ = in_session(plain, "ses_owned")
    other, body = in_session(granted, "ses_owned")
    again, _ = in_session(plain, "ses_owned")
    check("another account cannot continue a session", first == 200 and other == 403 and "foreign_session" in body and again == 200,
          f"{first} {other} {again} {body[:150]}")
    check("foreign session recorded with the owner", any(v.get("denied") == ["e2e-standard"] for v in violations("foreign_session")))

    # 7d. Images and PDFs: OCR'd, masked, never stored.
    fixtures = os.path.join(HERE, "tests", "fixtures")
    png = base64.b64encode(open(os.path.join(fixtures, "secret.png"), "rb").read()).decode()
    pdf = base64.b64encode(open(os.path.join(fixtures, "secret.pdf"), "rb").read()).decode()

    def with_media(key, agent, part, sid):
        content = [{"type": "text", "text": "Image read successfully"}, part, {"type": "text", "text": "요약해줘"}]
        return call("/v1/chat/completions", {"model": "default", "messages": [{"role": "user", "content": content}]}, key,
                    {"x-croak-agent": agent, "x-croak-session": sid})

    status, _ = with_media(granted, "dev-main", {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{png}"}}, "ses_media_img")
    sent = last_record()["messages"][0]["content"][1]["image_url"]["url"]
    audit_img = lines("audit")[-1]
    check("image with a password is masked, not blocked", status == 200 and sent.startswith("data:image/png;base64,") and png not in sent
          and audit_img.get("media", {}).get("images") == 1 and "password_assignment" in audit_img.get("secrets", {})
          and audit_img.get("violation") == "secret_in_history", json.dumps(audit_img, ensure_ascii=False)[:300])

    status, _ = with_media(granted, "dev-main", {"type": "file", "file": {"filename": "secret.pdf", "file_data": f"data:application/pdf;base64,{pdf}"}}, "ses_media_pdf")
    part = last_record()["messages"][0]["content"][1]
    check("pdf becomes masked text", status == 200 and part.get("type") == "text" and "[REDACTED:aws_access_key]" in part.get("text", "")
          and AWS not in json.dumps(last_record()) and "[MASKED:mobile_phone]" in part.get("text", ""), json.dumps(part, ensure_ascii=False)[:300])

    status, body = with_media(untiered, "dev-doc", {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{png}"}}, "ses_media_r")
    check("restricted tier blocks a secret in an image", status == 400 and "첨부" in body, f"{status} {body[:200]}")

    time.sleep(2)
    archived = [a for a in lines("archive") if a.get("session") in ("ses_media_img", "ses_media_pdf")]
    blob = json.dumps(archived, ensure_ascii=False)
    check("archive keeps masked OCR text, not the image", archived and png[:200] not in blob and pdf[:200] not in blob
          and "not stored" in blob and "[REDACTED:" in blob, blob[:300])

    # 7e. Keys, certificates and secret files never reach the model.
    leak = [
        {"role": "user", "content": "ssh 설정 보여줘"},
        {"role": "assistant", "content": "", "tool_calls": [
            {"id": "r1", "type": "function", "function": {"name": "read", "arguments": json.dumps({"filePath": "/home/u/.ssh/config"})}}]},
        {"role": "tool", "tool_call_id": "r1", "content": "Host internal-db\n  User deploy\n  HostName 10.9.8.7"},
    ]
    status, _ = call("/v1/chat/completions", {"model": "default", "messages": leak}, plain,
                     {"x-croak-agent": "dev-main", "x-croak-session": "ses_paths"})
    sent = json.dumps(last_record(), ensure_ascii=False)
    audit_paths = lines("audit")[-1]
    check("a tool result from ~/.ssh is not forwarded", status == 200 and "internal-db" not in sent and "보내지 않았다" in sent
          and audit_paths.get("violation") == "path_blocked", json.dumps(audit_paths, ensure_ascii=False)[:300])

    # 8. HTTPS front: trusted with the internal CA only, API reachable, admin routes hidden.
    tls_base = f"https://127.0.0.1:{TLS_PORT}"
    trusted = ssl.create_default_context(cafile=os.path.join(CERTS, "ca.crt"))
    status, body = call("/v1/chat/completions", {"model": "default", "messages": [{"role": "user", "content": "tls"}]}, plain, {"x-croak-agent": "dev-main"}, base=tls_base, context=trusted)
    check("https api with internal ca", status == 200 and "ECHO" in body, f"{status} {body[:200]}")
    try:
        call("/v1/models", {}, plain, base=tls_base, context=ssl.create_default_context())
        check("https rejected without internal ca", False, "connected")
    except urllib.error.URLError as e:
        check("https rejected without internal ca", isinstance(e.reason, ssl.SSLCertVerificationError), repr(e.reason))
    status, _ = call("/key/generate", {"key_alias": "via-tls"}, MASTER, base=tls_base, context=trusted)
    check("admin routes hidden behind tls", status == 404, str(status))


    # 10. Login: browser code + PKCE -> gate key, refresh, logout, lockout, Sunday expiry.
    USER, PASSWORD = "e2e-user", "correct horse battery staple"
    for _ in range(60):
        if tls("GET", "/auth/health")[0] == 200:
            break
        time.sleep(2)
    created = subprocess.run(
        COMPOSE + ["exec", "-T", "auth", "python", "cli.py", "create-user", USER, "--tier", "standard", "--role", "auditor"],
        cwd=HERE, env=ENVIRON, input=f"{PASSWORD}\n{PASSWORD}\n", capture_output=True, text=True,
    )
    check("cli creates user", created.returncode == 0, created.stderr[-300:])

    verifier, challenge = pkce()
    status, code = browser_login(USER, "wrong password!!", challenge)
    check("wrong password refused", status == 401 and code is None, str(status))
    status, _, text = tls("POST", "/auth/login", {"username": USER, "password": PASSWORD, "challenge": challenge, "csrf": "x.y"}, form=True)
    check("login form needs csrf", status == 400 and "class='code'" not in text, str(status))

    status, code = browser_login(USER, PASSWORD, challenge)
    check("browser shows code", status == 200 and code, str(status))
    page_html, page_csp = LAST_PAGE["text"], LAST_PAGE["csp"]
    nonce = re.search(r"<script nonce='([^']+)'>", page_html)
    check("copy button runs only with the page nonce", "코드 복사" in page_html and nonce
          and f"script-src 'nonce-{nonce.group(1)}'" in page_csp and "unsafe-inline' ; script" not in page_csp, page_csp)
    status, hdrs, _ = tls("GET", f"/auth/login?challenge={challenge}")
    check("other pages allow no scripts", "script-src" not in hdrs.get("content-security-policy", "x"), hdrs.get("content-security-policy", ""))
    other_verifier, _ = pkce()
    status, _, text = tls("POST", "/auth/token", {"grant_type": "authorization_code", "code": code, "code_verifier": other_verifier})
    check("code needs matching pkce", status == 400, f"{status} {text[:200]}")
    status, _, text = tls("POST", "/auth/token", {"grant_type": "authorization_code", "code": code, "code_verifier": verifier})
    check("code is single use", status == 400, f"{status} {text[:200]}")

    verifier, challenge = pkce()
    _, code = browser_login(USER, PASSWORD, challenge)
    status, _, text = tls("POST", "/auth/token", {"grant_type": "authorization_code", "code": code.lower(), "code_verifier": verifier})
    tokens = json.loads(text) if status == 200 else {}
    check("code -> tokens", status == 200 and tokens.get("user", {}).get("tier") == "standard", f"{status} {text[:200]}")
    access, refresh = tokens.get("access_token", ""), tokens.get("refresh_token", "")

    def gate_ok(key):
        st, _, body = tls("POST", "/v1/chat/completions", {"model": "default", "messages": [{"role": "user", "content": "login"}]},
                          {"authorization": f"Bearer {key}", "x-croak-agent": "dev-main"})
        return st, body

    check("access token works at the gate", gate_ok(access)[0] == 200)
    status, _, text = tls("GET", "/auth/me", headers={"authorization": f"Bearer {access}"})
    me = json.loads(text) if status == 200 else {}
    check("me", me.get("username") == USER and me.get("roles") == ["auditor"], text[:200])
    check("me shows tier rules", "dev-main" in me.get("rules", {}).get("agents", []), text[:300])
    # 15a. The model list for clients: names and levels, never the served model.
    status, _, text = tls("GET", "/v1/croak/models", headers={"authorization": f"Bearer {access}"})
    listed = json.loads(text).get("models", []) if status == 200 else []
    check("model list shows the listed aliases with their levels",
          [m.get("id") for m in listed] == ["croak"] and listed[0].get("levels") == ["none", "low", "high"]
          and listed[0].get("display") == "사내 모델" and "served_model" not in text and "engine" not in text, f"{status} {text[:300]}")
    status, _, _ = tls("GET", "/v1/croak/models")
    check("model list needs a login", status == 401, str(status))
    ends = tokens.get("session_expires_at", "")
    check("session ends on Sunday 00:00 KST", ends.endswith("T00:00:00+09:00") and time.strptime(ends[:10], "%Y-%m-%d").tm_wday == 6, ends)

    status, _, text = tls("POST", "/auth/token", {"grant_type": "refresh_token", "refresh_token": refresh})
    renewed = json.loads(text) if status == 200 else {}
    check("refresh issues a new key", status == 200 and renewed.get("access_token") not in ("", access), f"{status} {text[:200]}")
    check("old key stops working", gate_ok(access)[0] in (400, 401, 403))
    check("new key works", gate_ok(renewed.get("access_token", ""))[0] == 200)
    status, _, _ = tls("POST", "/auth/token", {"grant_type": "refresh_token", "refresh_token": refresh})
    check("old refresh token rotated out", status == 401, str(status))

    tls("POST", "/auth/logout", {"refresh_token": renewed.get("refresh_token", "")})
    check("logout kills the key", gate_ok(renewed.get("access_token", ""))[0] in (400, 401, 403))
    status, _, _ = tls("POST", "/auth/token", {"grant_type": "refresh_token", "refresh_token": renewed.get("refresh_token", "")})
    check("logout kills the refresh token", status == 401, str(status))

    # Sunday expiry: pretend the session's Sunday has passed.
    verifier, challenge = pkce()
    _, code = browser_login(USER, PASSWORD, challenge)
    _, _, text = tls("POST", "/auth/token", {"grant_type": "authorization_code", "code": code, "code_verifier": verifier})
    weekly = json.loads(text)
    issued_code = code
    psql("UPDATE sessions SET expires_at = now() - interval '1 second' WHERE ended_at IS NULL")
    swept = compose("exec", "-T", "auth", "python", "cli.py", "sweep", check=False)
    check("sweep ends expired session", "1" in swept.stdout, swept.stdout + swept.stderr[-200:])
    check("expired session key rejected", gate_ok(weekly["access_token"])[0] in (400, 401, 403))
    status, _, text = tls("POST", "/auth/token", {"grant_type": "refresh_token", "refresh_token": weekly["refresh_token"]})
    check("expired session cannot refresh", status == 401, f"{status} {text[:200]}")

    # Lockout after five failures, even with the right password next.
    verifier, challenge = pkce()
    for _ in range(5):
        browser_login(USER, "wrong password!!", challenge)
    status, code = browser_login(USER, PASSWORD, challenge)
    check("locked after 5 failures", status == 429 and code is None, str(status))
    unknown_status, _ = browser_login("nobody", PASSWORD, challenge)
    check("unknown user gets the same answer", unknown_status == 401, str(unknown_status))

    events = psql("SELECT string_agg(kind || ' ' || detail::text, E'\\n') FROM events")
    stored = psql("SELECT string_agg(password_hash, '') FROM users")
    leaks = [t for t in (PASSWORD, access, refresh, issued_code) if t and t in events + stored]
    check("no passwords or tokens stored in clear", stored.startswith("$argon2id$") and not leaks, str(len(leaks)))
    logs = compose("logs", "auth", "proxy", check=False).stdout
    check("no tokens in service logs", access not in logs and refresh not in logs and PASSWORD not in logs)


    # 11. Admin console: roles, CSRF, archive view audit, stats, alerts, account changes.
    def make_user(name, *args):
        r = subprocess.run(COMPOSE + ["exec", "-T", "auth", "python", "cli.py", "create-user", name, *args],
                           cwd=HERE, env=ENVIRON, input=f"{PASSWORD}\n{PASSWORD}\n", capture_output=True, text=True)
        return r.returncode == 0

    check("cli creates admin users", make_user("e2e-admin", "--tier", "full", "--role", "admin")
          and make_user("e2e-audit", "--tier", "standard", "--role", "auditor") and make_user("e2e-member", "--tier", "standard"))

    def admin_login(name, origin=None):
        headers = {"origin": origin} if origin else {}
        status, headers, text = tls("POST", "/admin/login", {"username": name, "password": PASSWORD}, headers, form=True)
        return status, headers.get("set-cookie", ""), text

    status, cookie, _ = admin_login("e2e-member")
    check("member cannot open admin", status == 403 and not cookie, str(status))
    status, cookie, _ = admin_login("e2e-admin", origin="https://evil.example")
    check("admin login rejects foreign origin", status == 400 and not cookie, str(status))
    status, headers, _ = tls("GET", "/admin/login")
    check("pages keep Origin for same-site forms", headers.get("referrer-policy") == "same-origin", headers.get("referrer-policy", ""))
    status, cookie, _ = admin_login("e2e-admin", origin=f"https://127.0.0.1:{TLS_PORT}")
    flags = cookie.lower()
    check("admin session cookie is locked down", status == 303 and "httponly" in flags and "secure" in flags and "samesite=strict" in flags, cookie[:120])
    admin = {"cookie": cookie.split(";")[0]}
    _, audit_cookie, _ = admin_login("e2e-audit")
    auditor = {"cookie": audit_cookie.split(";")[0]}

    status, headers, _ = tls("GET", "/admin")
    check("admin pages need a session", status == 303 and headers.get("location") == "/admin/login", str(status))
    status, headers, _ = tls("GET", "/")
    check("root goes to the console", status == 303 and headers.get("location") == "/admin", str(status))
    status, _, text = tls("GET", "/admin", headers=admin)
    check("dashboard shows bypass alert", status == 200 and "우회 시도" in text, f"{status} {text[-300:]}")
    check("dashboard numbers link to lists", "only=block" in text and "href='/admin/violations?user=" in text, text[-400:])
    status, _, text = tls("GET", "/admin/violations?only=block&user=e2e-standard", headers=admin)
    check("violations filter by block and user", status == 200 and "거부된 요청" in text and "e2e-standard" in text
          and "<td>e2e-full</td>" not in text, str(status))
    status, _, text = tls("GET", "/admin/prompts", headers=auditor)
    check("auditor reads masked archive", status == 200 and "[MASKED:mobile_phone]" in text and PHONE not in text, f"{status}")
    viewed = psql("SELECT count(*) FROM events WHERE kind = 'archive_viewed' AND actor = 'e2e-audit'")
    check("archive view is recorded", viewed == "1", viewed)
    status, _, text = tls("GET", "/admin/stats", headers=auditor)
    check("stats by user", status == 200 and "e2e-standard" in text and "사용자별" in text, str(status))
    status, _, text = tls("GET", "/admin/violations", headers=auditor)
    check("violations listed", status == 200 and "금지 도구" in text and "비밀정보 거부" in text, str(status))
    status, _, _ = tls("GET", "/admin/users", headers=auditor)
    check("auditor cannot manage users", status == 403, str(status))

    status, _, text = tls("GET", "/admin/users", headers=admin)
    csrf = re.search(r"name='csrf' value='([^']+)'", text).group(1)
    status, _, text = tls("POST", "/admin/users", {"username": "e2e-new", "password": PASSWORD, "tier": "restricted"}, admin, form=True)
    check("forms need csrf", status == 400 and psql("SELECT count(*) FROM users WHERE username = 'e2e-new'") == "0", str(status))
    status, _, text = tls("POST", "/admin/users", {"username": "e2e-new", "password": PASSWORD, "password_confirm": PASSWORD + "x",
                                                  "tier": "restricted", "csrf": csrf}, admin, form=True)
    check("password confirmation must match", status == 400 and "두 비밀번호가 다릅니다" in text
          and psql("SELECT count(*) FROM users WHERE username = 'e2e-new'") == "0", str(status))
    status, hdrs, page_html = tls("GET", "/admin/users", headers=admin)
    nonce = re.search(r"<script nonce='([^']+)'>", page_html)
    check("eye buttons with a nonce script", page_html.count("class='eye'") >= 2 and nonce
          and f"'nonce-{nonce.group(1)}'" in hdrs.get("content-security-policy", ""), hdrs.get("content-security-policy", ""))
    status, _, text = tls("POST", "/admin/users", {"username": "e2e-new", "password": PASSWORD, "password_confirm": PASSWORD,
                                                  "tier": "restricted", "csrf": csrf}, admin, form=True)
    check("admin creates user", status == 200 and psql("SELECT tier FROM users WHERE username = 'e2e-new'") == "restricted", str(status))
    status, _, _ = tls("POST", "/admin/users/e2e-admin/lock", {"csrf": csrf}, admin, form=True)
    check("admin cannot lock self", status == 400 and psql("SELECT disabled FROM users WHERE username = 'e2e-admin'") == "f", str(status))

    # Locking a user ends their opencode session and its gate key.
    verifier, challenge = pkce()
    _, code = browser_login("e2e-new", PASSWORD, challenge)
    _, _, text = tls("POST", "/auth/token", {"grant_type": "authorization_code", "code": code, "code_verifier": verifier})
    new_key = json.loads(text)["access_token"]
    st, _, _ = tls("POST", "/v1/chat/completions", {"model": "default", "messages": [{"role": "user", "content": "x"}]},
                   {"authorization": f"Bearer {new_key}", "x-croak-agent": "dev-doc"})
    check("new restricted user works with dev-doc", st == 200, str(st))
    tls("POST", "/admin/users/e2e-new/lock", {"csrf": csrf}, admin, form=True)
    st, _, _ = tls("POST", "/v1/chat/completions", {"model": "default", "messages": [{"role": "user", "content": "x"}]},
                   {"authorization": f"Bearer {new_key}", "x-croak-agent": "dev-doc"})
    check("lock kills the user's key", st in (400, 401, 403), str(st))
    changes = psql("SELECT string_agg(kind, ',' ORDER BY id) FROM events WHERE actor = 'e2e-admin'")
    check("admin actions recorded", "user_created" in changes and "user_locked" in changes, changes)

    # Policy page: an admin switches attachment PII to block; it applies at once.
    pii_png = base64.b64encode(open(os.path.join(HERE, "tests", "fixtures", "pii.png"), "rb").read()).decode()
    img_part = {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{pii_png}"}}
    status, _ = with_media(plain, "dev-main", img_part, "ses_policy_1")
    check("attachment pii masked by default", status == 200 and lines("audit")[-1].get("pii", {}).get("mobile_phone") == 1, str(status))
    status, _, _ = tls("POST", "/admin/policy", {"csrf": csrf, "media_pii_standard": "block"}, auditor, form=True)
    check("auditor cannot change policy", status == 403, str(status))
    status, _, text = tls("POST", "/admin/policy", {"csrf": csrf, "media_pii_standard": "block", "media_pii_full": "mask",
                                                    "media_pii_restricted": "mask"}, admin, form=True)
    check("admin switches standard to block", status == 200 and "저장했습니다" in text, f"{status} {text[-300:]}")
    status, body = with_media(plain, "dev-main", img_part, "ses_policy_2")
    check("blocked tier rejects a new attachment with pii", status == 400 and "개인정보" in body, f"{status} {body[:200]}")
    old_turn = [{"role": "user", "content": [{"type": "text", "text": "Image read successfully"}, img_part]},
                {"role": "assistant", "content": "봤습니다"}, {"role": "user", "content": "계속"}]
    status, _ = call("/v1/chat/completions", {"model": "default", "messages": old_turn}, plain,
                     {"x-croak-agent": "dev-main", "x-croak-session": "ses_policy_3"})
    check("an attachment already in the history is still masked, not blocked", status == 200, str(status))
    status, body = with_media(granted, "dev-main", img_part, "ses_policy_4")
    check("other tiers keep masking", status == 200, str(status))
    changed = psql("SELECT count(*) FROM events WHERE kind = 'policy_changed' AND actor = 'e2e-admin'")
    check("policy change recorded", changed == "1", changed)

    tls("POST", "/admin/logout", {"csrf": csrf}, admin, form=True)
    status, _, _ = tls("GET", "/admin", headers=admin)
    check("admin logout ends the session", status == 303, str(status))

    # 9. Nothing raw anywhere in the gate's files, and no API key either.
    blob = ""
    for p in glob.glob(os.path.join(DATA, "*", "*.jsonl")):
        with open(p) as f:
            blob += f.read()
    check("no raw pii in audit/archive", PHONE not in blob)
    check("no secrets in audit/archive", AWS not in blob and SK not in blob and plain not in blob and granted not in blob and MASTER not in blob)
    modes = {oct(os.stat(p).st_mode & 0o777) for p in glob.glob(os.path.join(DATA, "*", "*.jsonl"))}
    check("files are 0600", modes == {"0o600"}, str(modes))
finally:
    if os.environ.get("KEEP") != "1":
        compose("down", "-v", check=False)

print(f"\n{len(failures)} failed" if failures else "\nall passed")
sys.exit(1 if failures else 0)
