#!/usr/bin/env bash
set -euo pipefail
mkdir -p .local/keys
if [[ -e .local/keys/private.pem || -e .local/keys/public.pem ]]; then
  echo 'Keys already exist; refusing to overwrite.' >&2
  exit 1
fi
umask 077
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out .local/keys/private.pem
openssl pkey -in .local/keys/private.pem -pubout -out .local/keys/public.pem
echo 'Local keys created. Do not commit private keys.'
