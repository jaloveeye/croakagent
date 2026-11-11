#!/usr/bin/env bash
# Deploys croak-gate to the server: test, diff, confirm, back up, upload,
# start, health check, and roll back on failure.
#
#   ./deploy.sh            deploy to $CROAK_GATE_HOST (default user@gate.example.internal), asking first
#   ./deploy.sh --diff     show the difference only
#   ./deploy.sh --yes      deploy without asking (the difference is still shown)
#   ./deploy.sh --yes --no-start   upload only
#   CROAK_POLICY_FILE=local/policy.yaml ./deploy.sh   upload a production policy kept outside the repository
#   CROAK_MODELS_FILE=local/models.yaml ./deploy.sh   generate config.yaml from a production model registry
#
# The server keeps its own .env (mode 600); it is never uploaded or printed.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST="${CROAK_GATE_HOST:?set CROAK_GATE_HOST, e.g. user@gate.example.internal}"
DIR="${CROAK_DIR:-croak}"
PORT="${CROAK_GATE_PORT:-4100}"
TLS_PORT="${CROAK_TLS_PORT:-8443}"
SERVER_IP="${HOST#*@}"
# Made by tls/make-certs.sh. The CA private key is never uploaded.
CERTS="${CROAK_CERTS_DIR:-$HOME/.config/croak/ca/server}"
# The policy uploaded as policy.yaml. The repository copy holds placeholder
# addresses; keep the production one outside the repository (local/ is ignored).
POLICY="${CROAK_POLICY_FILE:-policy.yaml}"
# The model registry uploaded as models.yaml; config.yaml is generated from it
# (make_config.py). The production registry names the real models: keep it in local/.
MODELS="${CROAK_MODELS_FILE:-models.yaml}"
CONFIG="$(mktemp)"
trap 'rm -f "$CONFIG"' EXIT
FILES=(docker-compose.yml Caddyfile config.yaml models.yaml policy.yaml croak_core.py croak_models.py croak_store.py croak_guardrail.py croak_archive.py
  make-permit-key.sh
  auth/Dockerfile auth/requirements.txt auth/auth_core.py auth/auth_db.py auth/gate_keys.py auth/permit_core.py auth/app.py
  auth/cli.py auth/admin.py auth/admin_core.py ocr/Dockerfile ocr/requirements.txt ocr/ocr_service.py)

die() { echo "error: $*" >&2; exit 1; }
# The local source of a deployed file.
src() {
  case "$1" in
    policy.yaml) echo "$POLICY" ;;
    models.yaml) echo "$MODELS" ;;
    config.yaml) echo "$CONFIG" ;;
    *) echo "$1" ;;
  esac
}
# -n: never read local stdin, so the confirmation prompt keeps its input.
remote() { ssh -n -o BatchMode=yes "$HOST" "$@"; }
MODE="${1:-}"
# --no-start: upload only, without restarting the stack.
NO_START=0
for arg in "$@"; do [[ "$arg" == "--no-start" ]] && NO_START=1; done

cd "$HERE"
echo "== local tests"
python3 -m unittest -q tests/test_core.py tests/test_store.py
python3 -m unittest -q auth/tests/test_auth_core.py auth/tests/test_admin_core.py
python3 check_policy.py "$POLICY"
python3 -m unittest -q tests/test_models.py
python3 make_config.py "$MODELS" config.base.yaml -o "$CONFIG"

echo "== server checks ($HOST:~/$DIR)"
remote "mkdir -p ~/$DIR/data ~/$DIR/backups ~/$DIR/settings && chmod 700 ~/$DIR/data ~/$DIR/backups ~/$DIR/settings"
mode="$(remote "stat -c %a ~/$DIR/.env 2>/dev/null || echo missing")"
[[ "$mode" == "600" ]] || die "~/$DIR/.env on the server is '$mode'. Create it from .env.example with mode 600 first."

for f in server.crt server.key ca.crt; do
  [[ -f "$CERTS/$f" ]] || die "$CERTS/$f is missing. Run tls/make-certs.sh first."
done

echo "== difference"
changed=0
local_cert="$(sha256sum "$CERTS/server.crt" | cut -d' ' -f1)"
remote_cert="$(remote "sha256sum ~/$DIR/certs/server.crt 2>/dev/null | cut -d' ' -f1" || true)"
certs_changed=0
if [[ "$local_cert" != "$remote_cert" ]]; then
  echo "server certificate: new ($(openssl x509 -in "$CERTS/server.crt" -noout -enddate))"
  certs_changed=1
  changed=1
fi
# Files are bind-mounted one by one, so `compose up` does not notice new
# content. Restart the services whose files changed.
restart=()
for f in "${FILES[@]}"; do
  if ! remote "cat ~/$DIR/$f 2>/dev/null" | diff -u --label "server/$f" --label "local/$f" - "$(src "$f")"; then
    changed=1
    case "$f" in
      Caddyfile) restart+=(proxy) ;;
      croak_core.py) restart+=(gate ocr) ;;
      config.yaml|models.yaml|croak_*.py) restart+=(gate) ;;
      policy.yaml) restart+=(gate auth) ;;
    esac
  fi
done
[[ "$certs_changed" == 1 ]] && restart+=(proxy)
mapfile -t restart < <(printf '%s\n' "${restart[@]}" | sort -u | sed '/^$/d')
[[ "$changed" == 1 ]] || { echo "no changes"; exit 0; }
[[ "$MODE" == "--diff" ]] && exit 0

if [[ "$MODE" != "--yes" ]]; then
  answer=""
  read -r -p "Deploy these changes to $HOST? [y/N] " answer || true
  [[ "$answer" == "y" || "$answer" == "Y" ]] || die "cancelled"
fi

stamp="$(date +%Y%m%d-%H%M%S)"
echo "== backup to ~/$DIR/backups/$stamp"
remote "mkdir -p ~/$DIR/backups/$stamp/auth ~/$DIR/backups/$stamp/ocr && cd ~/$DIR && for f in ${FILES[*]}; do [ -f \$f ] && cp -p \$f backups/$stamp/\$f; done; [ -d certs ] && cp -rp certs backups/$stamp/; true"

echo "== upload"
remote "mkdir -p ~/$DIR/auth ~/$DIR/ocr"
for f in "${FILES[@]}"; do
  from="$(src "$f")"
  [[ "$from" == /* ]] || from="$HERE/$from"
  scp -q "$from" "$HOST:$DIR/$f"
done
if [[ "$certs_changed" == 1 ]]; then
  remote "mkdir -p ~/$DIR/certs && chmod 700 ~/$DIR/certs"
  scp -q "$CERTS/server.crt" "$CERTS/server.key" "$CERTS/ca.crt" "$HOST:$DIR/certs/"
  remote "chmod 600 ~/$DIR/certs/server.key && chmod 644 ~/$DIR/certs/server.crt ~/$DIR/certs/ca.crt"
fi

if [[ "$NO_START" == 1 ]]; then
  echo "== uploaded; not started (--no-start)"
  exit 0
fi

echo "== start"
remote "cd ~/$DIR && docker compose up -d --build --remove-orphans"
if [[ ${#restart[@]} -gt 0 ]]; then
  echo "== restart ${restart[*]} (changed files)"
  remote "cd ~/$DIR && docker compose restart ${restart[*]}"
fi
for _ in $(seq 1 60); do
  if remote "curl -fs http://127.0.0.1:$PORT/health/liveliness >/dev/null && curl -fs --cacert ~/$DIR/certs/ca.crt https://$SERVER_IP:$TLS_PORT/health/liveliness >/dev/null && curl -fs --cacert ~/$DIR/certs/ca.crt https://$SERVER_IP:$TLS_PORT/auth/health >/dev/null"; then
    echo "healthy on :$PORT and https://$SERVER_IP:$TLS_PORT"
    exit 0
  fi
  sleep 3
done

echo "== health check failed; rolling back to backups/$stamp" >&2
remote "cd ~/$DIR && docker compose ps -a && docker compose logs --tail 60 auth proxy gate" 2>&1 | sed -E "s/sk-[A-Za-z0-9_-]+/sk-***/g" >&2 || true
remote "cd ~/$DIR && cp -p backups/$stamp/* . 2>/dev/null; cp -p backups/$stamp/auth/* auth/ 2>/dev/null; cp -p backups/$stamp/ocr/* ocr/ 2>/dev/null; [ -d backups/$stamp/certs ] && cp -p backups/$stamp/certs/* certs/; docker compose up -d --remove-orphans; docker compose restart gate proxy"
die "deploy failed and was rolled back"
