#!/usr/bin/env bash
set -euo pipefail

if [ -z "${DATABASE_URL:-}" ]; then
  echo "ERROR: Exporta DATABASE_URL de Supabase antes de ejecutar este script."
  echo 'Ejemplo: export DATABASE_URL="postgresql://postgres.<ref>:<pass>@aws-0-us-east-1.pooler.supabase.com:5432/postgres?sslmode=require"'
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

echo "==> Aplicando migraciones SQL en Supabase..."
chmod +x backend/sql/migrate.sh
./backend/sql/migrate.sh
echo "OK: Migraciones aplicadas correctamente en Supabase."
