#!/usr/bin/env python3
"""Validate a staged release and publish it on the gate host."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile

TARGETS = {"linux-x64", "linux-arm64", "darwin-x64", "darwin-arm64", "windows-x64"}
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")


def publish(stage: Path, downloads: Path) -> None:
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
        for name in ("SHA256SUMS", "ca.crt", "install.sh", "install.ps1", "manifest.json"):
            source = stage / name
            if not source.is_file():
                continue
            temp = downloads / ("." + name + ".new")
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
