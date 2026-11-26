#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

echo "==> [1/5] Verificando Rust, target wasm32 y wasm-pack..."
if ! command -v rustup >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
fi
# shellcheck disable=SC1091
source "${HOME}/.cargo/env"
rustup target add wasm32-unknown-unknown

if ! command -v wasm-pack >/dev/null 2>&1; then
  curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
fi

echo "==> [2/5] Configurando ALLOWED_WEB_ORIGINS para Codespaces (puerto 5173)..."
if [[ -n "${CODESPACE_NAME:-}" && -f backend/.env ]]; then
  CS_ORIGIN="https://${CODESPACE_NAME}-5173.app.github.dev"
  if ! grep -q "${CS_ORIGIN}" backend/.env; then
    sed -i "s|^ALLOWED_WEB_ORIGINS=.*|&,${CS_ORIGIN}|" backend/.env
    echo "  + Añadido origen permitido: ${CS_ORIGIN}"
    (cd backend && docker compose up -d api)
  else
    echo "  = Origen ${CS_ORIGIN} ya presente en backend/.env"
  fi
fi

echo "==> [3/5] Ejecutando tests Rust (pin-core) y verificando interoperabilidad contra Node.js..."
cargo test -p pin-core -- --nocapture
(cd backend && npm run build)
node backend/scripts/verify-rust-interop.mjs target/interop_vectors.json

echo "==> [4/5] Compilando pin-web-wasm hacia web/src/wasm..."
wasm-pack build crates/pin-web-wasm --target web --release --out-dir ../../web/src/wasm

echo "==> [5/5] Instalando dependencias de web/ y verificando build TypeScript..."
(cd web && npm install && npm run build)

echo ""
echo "=================================================================="
echo "  BLOQUE 1B/1C COMPILADO Y VERIFICADO EN VERDE"
echo "=================================================================="
echo "Para iniciar el chat Web en vivo ejecuta:"
echo "  cd web && npm run dev"
echo "Luego abre la pestaña 'Puertos' -> puerto 5173 -> hazlo Público y ábrelo."
