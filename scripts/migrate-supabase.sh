#!/usr/bin/env bash
set -euo pipefail

if [ -z "${DATABASE_URL:-}" ]; then
  echo "ERROR: Exporta DATABASE_URL de Supabase antes de ejecutar este script."
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}/backend"

if [ ! -f "dist/infra/runMigrations.js" ]; then
  npm run build
fi

echo "==> Aplicando migraciones SQL en Supabase..."
node dist/infra/runMigrations.js
echo "OK: Migraciones aplicadas correctamente en Supabase."
