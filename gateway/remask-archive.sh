#!/usr/bin/env bash
# Masks the prompt archive again with the current rules, for records stored
# before a rule existed. Records are kept; only their text changes:
# secrets become [REDACTED:kind], personal data [MASKED:kind] (unless the
# record's profile allowed personal data). The system-prompt allow list does
# not apply: the archive holds no system prompt. Prints counts only.
#
#   bash remask-archive.sh            show how many records would change
#   bash remask-archive.sh --apply    rewrite them
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
from croak_core import PII_PATTERNS, SECRET_PATTERNS, redact

apply = os.environ["APPLY"] == "1"
totals = {"secrets": {}, "pii": {}}


def mask(text, keep_pii):
    scan = redact(text, SECRET_PATTERNS, "REDACTED")
    for k, n in scan.found.items():
        totals["secrets"][k] = totals["secrets"].get(k, 0) + n
    text = scan.text
    if not keep_pii:
        scan = redact(text, PII_PATTERNS, "MASKED")
        for k, n in scan.found.items():
            totals["pii"][k] = totals["pii"].get(k, 0) + n
        text = scan.text
    return text


def walk(value, keep_pii):
    if isinstance(value, str):
        return mask(value, keep_pii)
    if isinstance(value, list):
        return [walk(v, keep_pii) for v in value]
    if isinstance(value, dict):
        return {k: (walk(v, keep_pii) if k in ("content", "text", "input", "output", "media_text") or isinstance(v, (list, dict)) else v)
                for k, v in value.items()}
    return value


changed = records = 0
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
        records += 1
        keep_pii = record.get("pii") == "allow"
        new = dict(record)
        for key in ("input", "output", "media_text"):
            if key in new:
                new[key] = walk(new[key], keep_pii)
        if new != record:
            changed += 1
            line = json.dumps(new, ensure_ascii=False) + "\n"
        out.append(line)
    if apply and out != lines:
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.writelines(out)
        os.replace(tmp, path)
print(("masked" if apply else "would mask"), changed, "of", records, "records")
print("found:", json.dumps(totals, ensure_ascii=False))
PY
REMOTE
