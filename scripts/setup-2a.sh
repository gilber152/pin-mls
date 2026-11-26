#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

# shellcheck disable=SC1091
source "${HOME}/.cargo/env"

echo "==> [1/5] Compilando Backend (GET /v1/devices + limpieza de revocación)..."
(cd backend && npm run typecheck && npm run build)

echo "==> [2/5] Reconstruyendo y reiniciando contenedor API en Docker..."
(cd backend && docker compose up --build -d api)
for i in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:3000/readyz >/dev/null 2>&1; then
    echo "  + API lista en http://127.0.0.1:3000/readyz"
    break
  fi
  sleep 2
done

echo "==> [3/5] Ejecutando pruebas E2E (smoke-2a.mjs)..."
(cd backend && API_URL=http://127.0.0.1:3000 node scripts/smoke-2a.mjs)

echo "==> [4/5] Ejecutando tests Rust (pin-core + bloque2a_tests + interop)..."
cargo test -p pin-core -- --nocapture
node backend/scripts/verify-rust-interop.mjs target/interop_vectors.json

echo "==> [5/5] Recompilando pin-web-wasm y cliente Web Vite..."
wasm-pack build crates/pin-web-wasm --target web --release --out-dir ../../web/src/wasm
(cd web && npm run build)

echo ""
echo "=================================================================="
echo "  BLOQUE 2A COMPILADO Y VERIFICADO EN VERDE"
echo "=================================================================="
echo "Recarga tu navegador en el puerto 5173 (o ejecuta: cd web && npm run dev)"
echo "para probar multidispositivo LinkQr y revocación en vivo (WS 4001)."
