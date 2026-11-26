# PIN-MLS — Bloque 3 (`pin-mobile-ffi` UniFFI + SQLCipher + Android Jetpack Compose)

Agrega la capa nativa móvil en Rust (**`crates/pin-mobile-ffi`**) con **UniFFI 0.28** y base de datos cifrada **SQLCipher AES-256** (`rusqlite` con `bundled-sqlcipher`), más el proyecto **Android** en Kotlin + Jetpack Compose + Android Keystore.

## Qué incluye este bloque
- **`crates/pin-mobile-ffi`**: expone `PinMobileClient` (UniFFI Object) sobre `pin-core` (OpenMLS 0.9.2 RFC 9420) persistiendo identidad, árbol TreeKEM, grupos y mensajes en SQLCipher AES-256. Incluye el binario `uniffi-bindgen` integrado.
- **`crates/pin-mobile-ffi/tests/mobile_ffi_sqlcipher_tests.rs`**: prueba integral que verifica rechazo de clave incorrecta en SQLCipher + handshake OpenMLS + cierre/reapertura de base de datos cifrada + mensajería E2EE.
- **`android/`**: proyecto Gradle Kotlin DSL con `VaultKeyManager` (Android Keystore AES-256-GCM), `PinApiClient` (OkHttp3 + WebSocket `4001`), `PinViewModel` y `MainActivity` (Jetpack Compose Material 3).
- **`scripts/setup-3.sh`** y **`scripts/build-android-jni.sh`**.

## Instalación y verificación en Codespaces

```bash
cd /workspaces/pin-mls
unzip -o pin-mls-bloque3.zip -d .
rm -f pin-mls-bloque3.zip
chmod +x scripts/setup-3.sh scripts/build-android-jni.sh
./scripts/setup-3.sh
```
