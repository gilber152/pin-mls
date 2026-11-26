#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

export PATH="${HOME}/.cargo/bin:${PATH}"
if [ -f "${HOME}/.cargo/env" ]; then
  # shellcheck disable=SC1091
  source "${HOME}/.cargo/env"
fi

echo "==> [1/3] Ejecutando tests Rust de pin-mobile-ffi (SQLCipher AES-256 + OpenMLS 0.9.2)..."
cargo test -p pin-mobile-ffi -- --nocapture

echo "==> [2/3] Compilando librería cdylib pin-mobile-ffi para generar bindings Kotlin..."
cargo build -p pin-mobile-ffi --release

LIB_PATH="target/release/libpin_mobile_ffi.so"
if [ ! -f "${LIB_PATH}" ]; then
  LIB_PATH="target/release/libpin_mobile_ffi.dylib"
fi

echo "==> [3/3] Generando bindings Kotlin con uniffi-bindgen en android/app/src/main/java/..."
mkdir -p android/app/src/main/java
cargo run -p pin-mobile-ffi --bin uniffi-bindgen -- generate \
  --library "${LIB_PATH}" \
  --language kotlin \
  --out-dir android/app/src/main/java

echo ""
echo "=================================================================="
echo "  BLOQUE 3 (PIN-MOBILE-FFI + SQLCIPHER + ANDROID) VERIFICADO"
echo "=================================================================="
echo "Bindings Kotlin generados en: android/app/src/main/java/uniffi/pin_mobile_ffi/"
echo "Para compilar los .so de Android (arm64-v8a / x86_64) cuando tengas Android NDK:"
echo "  ./scripts/build-android-jni.sh"
