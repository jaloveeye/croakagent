#!/usr/bin/env bash
# Sets the user tier of an existing croak-gate key, found by its alias.
# Keys issued before tiers existed have none and count as `restricted`.
# Runs the update on the server with the master key from its .env; no key is
# printed or copied.
#
#   bash set-key-tier.sh <key-alias> <tier> [user]
#   bash set-key-tier.sh alice-opencode full alice
set -euo pipefail
ALIAS="${1:?usage: set-key-tier.sh <key-alias> <tier> [user]}"
TIER="${2:?usage: set-key-tier.sh <key-alias> <tier> [user]}"
USER_NAME="${3:-}"
HOST="${CROAK_GATE_HOST:?set CROAK_GATE_HOST, e.g. user@gate.example.internal}"
DIR="${CROAK_DIR:-croak}"
case "$TIER" in full|standard|restricted) ;; *) echo "error: tier must be full, standard or restricted" >&2; exit 2 ;; esac

ssh -o BatchMode=yes "$HOST" ALIAS="$ALIAS" TIER="$TIER" USER_NAME="$USER_NAME" DIR="$DIR" 'bash -s' <<'REMOTE'
set -euo pipefail
cd ~/"$DIR" && set -a && . ./.env && set +a
python3 - <<'PY'
import json, os, urllib.parse, urllib.request
base = f"http://127.0.0.1:{os.environ.get('CROAK_GATE_PORT', '4100')}"
auth = {"Authorization": f"Bearer {os.environ['LITELLM_MASTER_KEY']}", "content-type": "application/json"}
alias = os.environ["ALIAS"]
def call(path, body=None):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode() if body is not None else None, headers=auth)
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r)
listed = call("/key/list?" + urllib.parse.urlencode({"key_alias": alias, "return_full_object": "true"}))
keys = [k for k in listed.get("keys", []) if isinstance(k, dict) and k.get("key_alias") == alias]
if len(keys) != 1:
    raise SystemExit(f"error: expected one key with alias {alias}, found {len(keys)}")
metadata = dict(keys[0].get("metadata") or {})
metadata["croak_tier"] = os.environ["TIER"]
if os.environ.get("USER_NAME"):
    metadata["croak_user"] = os.environ["USER_NAME"]
call("/key/update", {"key": keys[0]["token"], "metadata": metadata})
print(f"{alias}: tier {metadata['croak_tier']}" + (f", user {metadata['croak_user']}" if metadata.get("croak_user") else ""))
PY
REMOTE
