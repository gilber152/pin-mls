#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

if ! command -v cargo-ndk >/dev/null 2>&1; then
  echo "Instala cargo-ndk primero: cargo install cargo-ndk"
  exit 1
fi

rustup target add aarch64-linux-android x86_64-linux-android

mkdir -p android/app/src/main/jniLibs
cargo ndk -t arm64-v8a -t x86_64 -o android/app/src/main/jniLibs build -p pin-mobile-ffi --release

echo "OK: librerías nativas Android (.so) generadas en android/app/src/main/jniLibs/"
