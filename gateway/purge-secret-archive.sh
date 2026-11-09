#!/usr/bin/env bash
# Deletes prompt-archive records that still contain secrets under the current
# detection rules (records stored before a rule existed). Runs on the server
# with its croak_core.py. Deleted records are not backed up: a backup would
# keep the secret. Audit records carry no message text and are left alone.
#
#   bash purge-secret-archive.sh            list what would be deleted
#   bash purge-secret-archive.sh --apply    delete it
set -euo pipefail
HOST="${CROAK_GATE_HOST:?set CROAK_GATE_HOST, e.g. user@gate.example.internal}"
DIR="${CROAK_DIR:-croak}"
APPLY=0
[[ "${1:-}" == "--apply" ]] && APPLY=1

ssh -o BatchMode=yes "$HOST" APPLY="$APPLY" DIR="$DIR" 'bash -s' <<'REMOTE'
set -euo pipefail
cd ~/"$DIR"
python3 - <<'PY'
import glob, json, os, sys
sys.path.insert(0, ".")
from croak_core import SECRET_PATTERNS, find

apply = os.environ["APPLY"] == "1"
removed = kept = 0
for path in sorted(glob.glob("data/archive/*.jsonl")):
    with open(path, encoding="utf-8") as f:
        lines = f.read().splitlines(keepends=True)
    out = []
    for line in lines:
        try:
            record = json.loads(line)
        except ValueError:
            out.append(line)
            continue
        text = json.dumps(record.get("input"), ensure_ascii=False) + "\n" + str(record.get("output") or "")
        hit = find(text, SECRET_PATTERNS)
        if hit:
            removed += 1
            print(f"  {os.path.basename(path)} {str(record.get('ts', ''))[11:19]} {record.get('user')} {hit}")
        else:
            out.append(line)
            kept += 1
    if apply and len(out) != len(lines):
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.writelines(out)
        os.replace(tmp, path)
print(("deleted" if apply else "would delete"), removed, "records; kept", kept)
PY
REMOTE
