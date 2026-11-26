#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

# shellcheck disable=SC1091
source "${HOME}/.cargo/env"

echo "==> [1/4] Compilando y ejecutando tests Rust (OpenMLS 0.9 TreeKEM + PCS + Interop)..."
cargo test -p pin-core -- --nocapture

echo "==> [2/4] Verificando interoperabilidad Rust <-> Node.js (6 fronteras)..."
node backend/scripts/verify-rust-interop.mjs target/interop_vectors.json

echo "==> [3/4] Compilando pin-web-wasm con OpenMLS 0.9 para wasm32-unknown-unknown..."
wasm-pack build crates/pin-web-wasm --target web --release --out-dir ../../web/src/wasm

echo "==> [4/4] Verificando TypeScript y empaquetando cliente Web Vite..."
(cd web && npm run build)

echo ""
echo "=================================================================="
echo "  BLOQUE 2B (OPENMLS 0.9 RFC 9420) COMPILADO Y VERIFICADO EN VERDE"
echo "=================================================================="
echo "Recarga tus pestañas en el puerto 5173 (o ejecuta: cd web && npm run dev)."
echo "Nota: tus cuentas previas se migran automáticamente a OpenMLS RFC 9420,"
echo "pero los chats de prueba previos deben abrirse de nuevo bajo TreeKEM."
