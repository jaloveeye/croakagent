#!/usr/bin/env bash
# Upload a packaged release. Run this from an administrator's machine.
# CROAK_GATE_HOST=user@host ./upload-release.sh RELEASE_DIR CA_CERT [INSTALLER_DIR]
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
host="${CROAK_GATE_HOST:?set CROAK_GATE_HOST}"
dir="${CROAK_DIR:-croak}"
[[ "$dir" =~ ^[A-Za-z0-9._/-]+$ && "$dir" != /* && "$dir" != *..* ]] || { echo "invalid CROAK_DIR" >&2; exit 1; }
[[ $# -ge 2 && $# -le 3 ]] || { echo "usage: $0 RELEASE_DIR CA_CERT [INSTALLER_DIR]" >&2; exit 1; }
release="$1"
ca="$2"
[[ -d "$release" && -f "$ca" ]] || { echo "release directory or CA certificate missing" >&2; exit 1; }
# The staging directory is outside the publicly served tree.
stage="$(ssh -o BatchMode=yes "$host" "mkdir -p ~/$dir && mktemp -d ~/$dir/.download-stage.XXXXXXXX")"
cleanup() { ssh -o BatchMode=yes "$host" "rm -rf -- '$stage'" || true; }
trap cleanup EXIT
scp -q "$release"/manifest.json "$release"/SHA256SUMS "$release"/croakcode-*.tar.gz "$release"/croakcode-*.zip "$host:$stage/"
scp -q "$ca" "$host:$stage/ca.crt"
if [[ $# == 3 ]]; then
  scp -q "$3/install.sh" "$3/install.ps1" "$host:$stage/"
fi
scp -q "$here/publish-downloads.py" "$host:$stage/publish-downloads.py"
ssh -o BatchMode=yes "$host" "flock -n ~/$dir/.publish-downloads.lock python3 '$stage/publish-downloads.py' '$stage' ~/$dir/downloads"
echo "Release published."
