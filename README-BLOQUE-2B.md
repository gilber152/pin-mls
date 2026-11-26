# PIN-MLS — Bloque 2B (Motor OpenMLS 0.9 · RFC 9420 TreeKEM)

Reemplaza el cifrado grupal temporal en el cliente Web por el estándar real **RFC 9420 (OpenMLS 0.9)** con Forward Secrecy, Post-Compromise Security (TreeKEM), persistencia `MemoryStorage` serializada en IndexedDB y recuperación automática de conflictos `409 EPOCH_CONFLICT`.

## Qué incluye este bloque
- **`.cargo/config.toml` + `Cargo.toml`**: fija `openmls = "0.9"` (`features = ["js"]`), `openmls_rust_crypto = "0.6"`, `openmls_basic_credential = "0.6"`, `openmls_memory_storage = "0.6"` (`features = ["persistence"]`) y `tls_codec = "0.5"`, con soporte `wasm32-unknown-unknown`.
- **`crates/pin-core/src/mls_engine.rs`**: ciphersuite RFC 9420 `0x0003` (`MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`), `PURE_CIPHERTEXT_WIRE_FORMAT_POLICY`, extensión `ratchet_tree` en Welcome, `KeyPackage` `last_resort`, `add_members`, `remove_members` por `device_id`, `merge_pending_commit` y `clear_pending_commit`.
- **`crates/pin-core/tests/openmls_engine_tests.rs`**: 3 suites reales (handshake + persistencia JSON + multidispositivo/revocación PCS + recuperación 409).
- **`crates/pin-web-wasm` + `web/`**: runtime OpenMLS persistido en IndexedDB (`vaultSchemaVersion: 2`), con migración automática de identidades previas.

## Instalación en Codespaces

```bash
cd /workspaces/pin-mls/pin-mls
unzip -o pin-mls-bloque2b.zip -d .
rm -f pin-mls-bloque2b.zip
chmod +x scripts/setup-2b.sh
./scripts/setup-2b.sh
```
