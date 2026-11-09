#!/usr/bin/env bash
# Creates the internal certificate authority (once) and issues a server
# certificate signed by it.
#
#   ./make-certs.sh [--out DIR] NAME...
#
# NAME is an IP address or DNS name; the default is gate.example.internal gate.
# The CA lives in $CROAK_CA_DIR (default ~/.config/croak/ca), mode
# 700. Its private key never leaves this machine: only server.crt, server.key
# and ca.crt are deployed. Running again reuses the CA and issues a new server
# certificate valid for 397 days.
set -euo pipefail
umask 077

CA_DIR="${CROAK_CA_DIR:-$HOME/.config/croak/ca}"
OUT="$CA_DIR/server"
if [[ "${1:-}" == "--out" ]]; then
  OUT="$2"
  shift 2
fi
NAMES=("$@")
[[ ${#NAMES[@]} -gt 0 ]] || { echo "usage: make-certs.sh [--out DIR] NAME..." >&2; exit 2; }

mkdir -p "$CA_DIR" "$OUT"
chmod 700 "$CA_DIR" "$OUT"

if [[ ! -f "$CA_DIR/ca.key" ]]; then
  echo "== creating the internal CA in $CA_DIR (valid 10 years)"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$CA_DIR/ca.key" -out "$CA_DIR/ca.crt" -days 3650 \
    -subj "/O=croak/CN=Croak internal CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
  chmod 600 "$CA_DIR/ca.key"
  chmod 644 "$CA_DIR/ca.crt"
fi

san=""
for n in "${NAMES[@]}"; do
  if [[ "$n" =~ ^[0-9.]+$ || "$n" == *:* ]]; then san+="IP:$n,"; else san+="DNS:$n,"; fi
done
san="${san%,}"

echo "== issuing the server certificate for ${NAMES[*]} (valid 397 days)"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$OUT/server.key" -out "$OUT/server.csr" -subj "/O=croak/CN=${NAMES[0]}" 2>/dev/null
openssl x509 -req -in "$OUT/server.csr" -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" \
  -set_serial "0x$(openssl rand -hex 16)" -days 397 -sha256 -out "$OUT/server.crt" \
  -extfile <(printf 'subjectAltName=%s\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' "$san") 2>/dev/null
rm -f "$OUT/server.csr"
cp "$CA_DIR/ca.crt" "$OUT/ca.crt"
chmod 600 "$OUT/server.key"
chmod 644 "$OUT/server.crt" "$OUT/ca.crt"
openssl verify -CAfile "$CA_DIR/ca.crt" "$OUT/server.crt" >/dev/null
echo "server.crt, server.key, ca.crt -> $OUT"
