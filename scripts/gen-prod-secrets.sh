#!/usr/bin/env bash
set -euo pipefail

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

openssl genpkey -algorithm ED25519 -out "${TMP_DIR}/jwt_private.pem" >/dev/null 2>&1
openssl pkey -in "${TMP_DIR}/jwt_private.pem" -pubout -out "${TMP_DIR}/jwt_public.pem" >/dev/null 2>&1

POW_HEX="$(openssl rand -hex 32)"
COOLDOWN_HEX="$(openssl rand -hex 32)"

echo "=================================================================="
echo "  SECRETOS DE PRODUCCIÓN LISTOS PARA PEGAR EN RENDER"
echo "=================================================================="
echo ""
echo "POW_SECRET_HEX=${POW_HEX}"
echo "COOLDOWN_SECRET_HEX=${COOLDOWN_HEX}"
echo ""
echo "JWT_PRIVATE_KEY_PEM:"
cat "${TMP_DIR}/jwt_private.pem"
echo ""
echo "JWT_PUBLIC_KEY_PEM:"
cat "${TMP_DIR}/jwt_public.pem"
echo "=================================================================="
