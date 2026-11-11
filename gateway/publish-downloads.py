#!/usr/bin/env python3
"""Validate a staged release and publish it on the gate host."""
# The gate host may run an older Python (3.8): keep annotations lazy.
from __future__ import annotations

import base64
import io
import hashlib
import html
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import zipfile

TARGETS = {"linux-x64", "linux-arm64", "darwin-x64", "darwin-arm64", "windows-x64"}
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
GATE = re.compile(r"https://[A-Za-z0-9.-]+(:[0-9]{1,5})?")
PLACEHOLDER = "__CROAK_GATE__"
# Installers that carry the gate's address once published, so a user types none.
SCRIPTS = ("install.sh", "install.ps1", "croakcode-setup-windows.cmd")


def gate_url(downloads: Path) -> str | None:
    """The gate's public address from the server .env next to the downloads folder."""
    try:
        for line in (downloads.parent / ".env").read_text(encoding="utf-8").splitlines():
            if line.startswith("CROAK_PUBLIC_URL="):
                value = line.split("=", 1)[1].strip().strip('"').strip("'").rstrip("/")
                return value if GATE.fullmatch(value) else None
    except OSError:
        return None
    return None


def ca_fingerprint(pem: str) -> str:
    body = re.search(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", pem, re.S)
    if not body:
        raise ValueError("invalid CA certificate")
    return hashlib.sha256(base64.b64decode("".join(body.group(1).split()))).hexdigest()


def rendered(stage: Path, gate: str | None) -> dict[str, bytes]:
    """The installers as published: the gate's address filled in, the macOS one zipped."""
    out: dict[str, bytes] = {}
    for name in SCRIPTS:
        if (stage / name).is_file():
            text = (stage / name).read_text(encoding="utf-8")
            out[name] = (text.replace(PLACEHOLDER, gate) if gate else text).encode("utf-8")
    setup = stage / "croakcode-setup.sh"
    if setup.is_file():
        text = setup.read_text(encoding="utf-8")
        body = (text.replace(PLACEHOLDER, gate) if gate else text).encode("utf-8")
        out["croakcode-setup-linux.sh"] = body
        # A zip keeps the executable bit, so Finder can open the .command file.
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            info = zipfile.ZipInfo("croakcode-setup.command", date_time=(2026, 1, 1, 0, 0, 0))
            info.external_attr = (0o100755 << 16)
            archive.writestr(info, body)
        out["croakcode-setup-macos.zip"] = buffer.getvalue()
    return out


def page(version: str, gate: str, fingerprint: str, files: dict[str, bytes]) -> str:
    """The download page at /download/: one click or one command per operating system."""
    e = html.escape
    unix = f"curl -fsSLk --proto '=https' {gate}/download/install.sh | bash"
    windows = (f"curl.exe -fsSLk --proto =https {gate}/download/install.ps1 -o $env:TEMP\\croak-install.ps1; "
               "powershell -NoProfile -ExecutionPolicy Bypass -File $env:TEMP\\croak-install.ps1")

    def command(text: str) -> str:
        return (f'<div class="cmd"><code>{e(text)}</code>'
                f'<button type="button" data-copy="{e(text, quote=True)}">복사</button></div>')

    def link(name: str, label: str) -> str:
        return f'<a class="dl" href="{e(name, quote=True)}" download>{e(label)}</a>' if name in files else ""

    return f"""<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>croakcode 설치</title>
<style>
:root {{ --bg:#f5f7f4; --card:#fff; --ink:#18231c; --muted:#5d6b62; --line:#d6ded8; --accent:#2f7d4f; color-scheme: light; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#101612; --card:#18211b; --ink:#e4ebe6; --muted:#9aaa9f; --line:#2c3a31; --accent:#6cc690; color-scheme: dark; }} }}
body {{ margin:0; background:var(--bg); color:var(--ink); font:15px/1.6 system-ui,"Apple SD Gothic Neo","Malgun Gothic",sans-serif; }}
main {{ max-width:760px; margin:0 auto; padding:32px 16px 48px; }}
h1 {{ margin:0 0 4px; font-size:1.7rem; }} h2 {{ font-size:1.15rem; margin:0 0 8px; }}
.muted {{ color:var(--muted); }} section {{ background:var(--card); border:1px solid var(--line); border-radius:10px; padding:16px 18px; margin-top:16px; }}
.os {{ display:grid; gap:14px; }} .os h3 {{ margin:0 0 4px; font-size:1rem; }} .os p {{ margin:4px 0 8px; }}
a.dl {{ display:inline-block; background:var(--accent); color:var(--bg); text-decoration:none; font-weight:600; padding:7px 14px; border-radius:7px; }}
.cmd {{ display:flex; gap:8px; align-items:flex-start; margin:6px 0 2px; }}
.cmd code {{ flex:1; min-width:0; overflow-x:auto; white-space:pre; background:var(--bg); border:1px solid var(--line); border-radius:6px; padding:8px 10px; font:13px/1.5 ui-monospace,Menlo,Consolas,monospace; }}
.cmd button {{ border:1px solid var(--line); background:var(--card); color:var(--ink); border-radius:6px; padding:7px 10px; cursor:pointer; }}
.fp {{ font:12px ui-monospace,Menlo,Consolas,monospace; word-break:break-all; }}
</style></head><body><main>
<h1>croakcode 설치</h1>
<p class="muted">버전 {e(version)} · 게이트 {e(gate)}</p>

<section><h2>내려받아 실행</h2><div class="os">
<div><h3>Windows (x64)</h3><p>내려받은 파일을 더블클릭한다. "Windows의 PC 보호" 창이 뜨면 "추가 정보"를 누르고 "실행"을 누른다.</p>{link("croakcode-setup-windows.cmd", "Windows용 설치 파일")}</div>
<div><h3>macOS</h3><p>zip을 풀고 croakcode-setup.command를 오른쪽 클릭한 뒤 "열기"를 누른다. 처음 한 번만 이렇게 연다.</p>{link("croakcode-setup-macos.zip", "macOS용 설치 파일")}</div>
<div><h3>Linux, WSL</h3><p>내려받은 폴더의 터미널에서 <code>bash croakcode-setup-linux.sh</code>를 실행한다.</p>{link("croakcode-setup-linux.sh", "Linux용 설치 파일")}</div>
</div></section>

<section><h2>터미널로 설치</h2>
<h3>Linux, WSL, macOS</h3>{command(unix)}
<h3>Windows (PowerShell)</h3>{command(windows)}
</section>

<section><h2>설치한 뒤</h2><p>새 터미널을 열고 프로젝트 폴더에서 <code>croakcode</code>를 실행한다. <code>/login</code>을 입력해 로그인한다.</p></section>

<section><h2>인증서</h2>
<p>처음 설치할 때 이 게이트의 인증서를 믿고 저장한다. 그 뒤 설치와 업데이트는 저장한 인증서로만 확인한다. 설치 화면에 뜨는 지문이 아래 값과 같은지 비교할 수 있다.</p>
<p class="fp">{e(fingerprint)}</p></section>
</main>
<script>
document.querySelectorAll("button[data-copy]").forEach((button) => {{
  button.addEventListener("click", async () => {{
    try {{ await navigator.clipboard.writeText(button.dataset.copy); button.textContent = "복사함"; }}
    catch {{ const range = document.createRange(); range.selectNodeContents(button.previousElementSibling); getSelection().removeAllRanges(); getSelection().addRange(range); button.textContent = "선택함"; }}
    setTimeout(() => (button.textContent = "복사"), 1500);
  }});
}});
</script>
</body></html>
"""


def publish(stage: Path, downloads: Path, gate: str | None = None) -> None:
    manifest = json.loads((stage / "manifest.json").read_text(encoding="utf-8"))
    version = manifest["latest"]
    minimum = manifest["minimum"]
    if manifest.get("product") != "croakcode" or not VERSION.fullmatch(version) or not VERSION.fullmatch(minimum):
        raise ValueError("invalid release manifest")
    if tuple(map(int, minimum.split('.'))) > tuple(map(int, version.split('.'))):
        raise ValueError("minimum exceeds latest")
    files = manifest["files"]
    if set(files) != TARGETS:
        raise ValueError("release must contain all five targets")
    for target, info in files.items():
        extension = "zip" if target.startswith("windows") else "tar.gz"
        name = f"croakcode-{version}-{target}.{extension}"
        if info["file"] != name:
            raise ValueError("invalid archive name")
        path = stage / name
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        if path.stat().st_size != info["size"] or digest.hexdigest() != info["sha256"]:
            raise ValueError(f"archive failed verification: {name}")
    downloads.mkdir(parents=True, exist_ok=True)
    versions = downloads / "versions"
    versions.mkdir(exist_ok=True)
    destination = versions / version
    if destination.exists():
        raise ValueError("release version already exists")
    # A temporary directory in the destination filesystem permits atomic rename.
    temporary = Path(tempfile.mkdtemp(prefix=".release-", dir=versions))
    linked = []
    committed = False
    try:
        for name in ["manifest.json", "SHA256SUMS", *(item["file"] for item in files.values())]:
            shutil.copyfile(stage / name, temporary / name)
            (temporary / name).chmod(0o644)
        os.rename(temporary, destination)
        # Publish archives first; manifest is the final commit point.
        for item in files.values():
            source = destination / item["file"]
            target = downloads / item["file"]
            os.link(source, target)
            linked.append(target)
        gate = gate or gate_url(downloads)
        ca = stage / "ca.crt"
        extra = rendered(stage, gate)
        if gate and ca.is_file():
            extra["index.html"] = page(version, gate, ca_fingerprint(ca.read_text(encoding="utf-8")), extra).encode("utf-8")
        for name in ("SHA256SUMS", "ca.crt", *extra, "manifest.json"):
            source = stage / name
            if name not in extra and not source.is_file():
                continue
            temp = downloads / ("." + name + ".new")
            if name in extra:
                temp.write_bytes(extra[name])
            else:
                shutil.copyfile(source, temp)
            temp.chmod(0o644)
            os.replace(temp, downloads / name)
            if name == "manifest.json":
                committed = True
        releases = sorted((p for p in versions.iterdir() if p.is_dir() and VERSION.fullmatch(p.name)),
                          key=lambda p: tuple(map(int, p.name.split('.'))), reverse=True)
        for old in [p for p in releases if p != destination][2:]:
            for archive in old.glob("croakcode-*.tar.gz"):
                (downloads / archive.name).unlink(missing_ok=True)
            for archive in old.glob("croakcode-*.zip"):
                (downloads / archive.name).unlink(missing_ok=True)
            shutil.rmtree(old)
    except Exception:
        if not committed:
            for target in linked:
                target.unlink(missing_ok=True)
            if destination.exists():
                shutil.rmtree(destination)
        raise
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: publish-downloads.py STAGING_DIR DOWNLOADS_DIR")
    try:
        publish(Path(sys.argv[1]), Path(sys.argv[2]))
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        sys.exit(f"error: {exc}")
