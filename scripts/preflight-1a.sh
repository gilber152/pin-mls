#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ERRORS=0

check_file() {
  if [[ ! -s "${ROOT_DIR}/$1" ]]; then
    echo "  [FAIL] Falta o está vacío: $1" >&2
    ERRORS=$((ERRORS + 1))
  fi
}

echo "==> [Preflight 1A] Verificando archivos del Backend + Infra..."
FILES=(
  "Makefile"
  "backend/package.json"
  "backend/tsconfig.json"
  "backend/Dockerfile"
  "backend/docker-compose.yml"
  "backend/sql/migrate.sh"
  "backend/sql/migrations/001_init.sql"
  "backend/src/app.ts"
  "backend/src/server.ts"
  "backend/src/worker.ts"
  "backend/src/config/env.ts"
  "backend/src/infra/db.ts"
  "backend/src/infra/runMigrations.ts"
  "backend/src/infra/redis.ts"
  "backend/src/infra/crypto.ts"
  "backend/src/infra/deviceCert.ts"
  "backend/src/infra/revocationManifest.ts"
  "backend/src/infra/linkSession.ts"
  "backend/src/infra/keyPackageGrant.ts"
  "backend/src/infra/pow.ts"
  "backend/src/infra/push/queue.ts"
  "backend/src/plugins/authTypes.ts"
  "backend/src/plugins/rawBody.ts"
  "backend/src/plugins/jwtAuth.ts"
  "backend/src/plugins/ed25519Auth.ts"
  "backend/src/modules/pow/routes.ts"
  "backend/src/modules/auth/routes.ts"
  "backend/src/modules/identities/routes.ts"
  "backend/src/modules/identities/revoke.routes.ts"
  "backend/src/modules/keypackages/routes.ts"
  "backend/src/modules/keypackages/selfClaim.routes.ts"
  "backend/src/modules/invites/routes.ts"
  "backend/src/modules/mls/routes.ts"
  "backend/src/modules/sync/routes.ts"
  "backend/src/modules/link/routes.ts"
  "backend/src/modules/safe/routes.ts"
  "backend/src/modules/ws/presence.ts"
  "backend/src/modules/ws/auth.ts"
  "backend/src/modules/ws/ack.ts"
  "backend/src/modules/ws/gateway.ts"
  "backend/scripts/smoke-e2e.mjs"
)

for f in "${FILES[@]}"; do
  check_file "$f"
done

if ! grep -q "on('smessage'" "${ROOT_DIR}/backend/src/modules/ws/gateway.ts"; then
  echo "  [FAIL] ws/gateway.ts no escucha 'smessage'" >&2
  ERRORS=$((ERRORS + 1))
fi

if ! grep -q "127.0.0.1:3000:3000" "${ROOT_DIR}/backend/docker-compose.yml"; then
  echo "  [FAIL] docker-compose.yml debe enlazar API a 127.0.0.1:3000 sin TLS" >&2
  ERRORS=$((ERRORS + 1))
fi

if [[ "${ERRORS}" -gt 0 ]]; then
  echo "PREFLIGHT 1A FALLIDO (${ERRORS} errores)" >&2
  exit 1
fi
echo "PREFLIGHT 1A EXITOSO (${#FILES[@]} archivos verificados)."
