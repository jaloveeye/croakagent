#!/usr/bin/env bash
# Run on your PC (WSL). Issues a croak-gate virtual key and stores it, mode 600, in
#   ~/.config/croak/key   the key alone; opencode reads it with
#                                     "apiKey": "{file:~/.config/croak/key}"
#   ~/.config/croak/env   CROAK_GATE_KEY=... for shells and scripts
# The key is never printed.
#
#   bash issue-key.sh <key-alias> [profiles] [tier]
#     profiles: comma-separated profile names from policy.yaml, or "*" for all (default)
#     tier:     user tier from policy.yaml (full, standard, restricted); default full
#
#   bash issue-key.sh alice-opencode
#   bash issue-key.sh teammate-opencode default standard
#
# Users who log in with /login get their key from croak-auth instead.
set -euo pipefail
ALIAS="${1:?usage: issue-key.sh <key-alias> [profiles]}"
PROFILES="${2:-*}"
TIER="${3:-full}"
HOST="${CROAK_GATE_HOST:?set CROAK_GATE_HOST, e.g. user@gate.example.internal}"
DIR="${CROAK_DIR:-croak}"
OUT_DIR="${CROAK_GATE_CONFIG:-$HOME/.config/croak}"

BODY="$(python3 -c 'import json,sys; print(json.dumps({"key_alias": sys.argv[1], "metadata": {"croak_tier": sys.argv[3], "croak_profiles": [p.strip() for p in sys.argv[2].split(",") if p.strip()]}}))' "$ALIAS" "$PROFILES" "$TIER")"

# The request runs on the server with the master key from its .env; only the new key comes back.
key="$(printf '%s' "$BODY" | ssh -o BatchMode=yes "$HOST" "cd ~/$DIR && set -a && . ./.env && set +a && curl -fsS -X POST http://127.0.0.1:\$CROAK_GATE_PORT/key/generate -H \"Authorization: Bearer \$LITELLM_MASTER_KEY\" -H 'content-type: application/json' --data-binary @-" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["key"])')"
[[ "$key" == sk-* ]] || { echo "error: key generation failed" >&2; exit 1; }

umask 077
mkdir -p "$OUT_DIR"
printf '%s\n' "$key" > "$OUT_DIR/key"
printf 'CROAK_GATE_KEY=%s\n' "$key" > "$OUT_DIR/env"
chmod 600 "$OUT_DIR/key" "$OUT_DIR/env"
echo "issued key '$ALIAS' (tier: $TIER, profiles: $PROFILES); stored in $OUT_DIR/key and $OUT_DIR/env"
