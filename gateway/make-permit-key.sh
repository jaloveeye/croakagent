#!/usr/bin/env bash
# Creates the Ed25519 key that signs croakcode execution permits and prints
# the public key for croakcode's CROAKCODE_GATE_PERMIT_PUBLIC_KEY.
#   ./make-permit-key.sh            # creates ./secrets/permit-signing.pem once
#   ./make-permit-key.sh --public   # prints the public key of the existing key
# The private key never leaves the server. Rotating it means every client
# needs the new public key.
set -euo pipefail
cd "$(dirname "$0")"
dir="${CROAK_SECRETS:-./secrets}"
key="$dir/permit-signing.pem"
umask 077
if [[ "${1:-}" != "--public" ]]; then
  if [[ -e "$key" ]]; then
    echo "already exists: $key (use --public to print its public key)" >&2
    exit 1
  fi
  mkdir -p "$dir"
  openssl genpkey -algorithm ed25519 -out "$key"
  chmod 600 "$key"
  # croak-auth runs as CROAK_DATA_UID; it must be able to read the key.
  if [[ -n "${CROAK_DATA_UID:-}" ]]; then chown "${CROAK_DATA_UID}:${CROAK_DATA_GID:-$CROAK_DATA_UID}" "$key"; fi
  echo "created $key" >&2
fi
printf 'CROAKCODE_GATE_PERMIT_PUBLIC_KEY=%s\n' "$(openssl pkey -in "$key" -pubout -outform DER | tail -c 32 | base64)"
