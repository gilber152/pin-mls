# PIN-MLS — Bloque 2A v2 (Multidispositivo LinkQr + Revocación en vivo WS 4001)

Se descomprime encima de tu carpeta `pin-mls/` (donde ya tienes los Bloques 1A y 1B/1C).

## Qué agrega este bloque
- **Backend (`GET /v1/devices`)**: lista tus dispositivos activos/revocados, presencia en vivo en Redis y el `revocationSeqNum` acumulativo; además limpia `group_members` y `welcome_deliveries` al revocar.
- **Rust Core & WASM**: `LinkBundle` cifrado (`X25519 + XChaCha20-Poly1305`), `Welcome` multi-destinatario (`PINW2`), `Commit` cifrado de rotación de época (`add`/`remove`/`rekey`) y `revmanifest-v1` desde navegador.
- **Cliente Web**: botón **Vincular a un PIN existente (LinkQr)** en onboarding y modal **Dispositivos** para autorizar otro navegador, sincronizar chats vía `POST /v1/keypackages/self-claim` y revocarlo en vivo con expulsión inmediata **WebSocket `4001`** y rotación de clave de época.

## Instalación en Codespaces

```bash
cd /workspaces/pin-mls/pin-mls
unzip -o pin-mls-bloque2a-v2.zip -d .
rm -f pin-mls-bloque2a-v2.zip
chmod +x scripts/setup-2a.sh
./scripts/setup-2a.sh
```

## Corrección incluida en v2
- `web/src/net/api.ts`: tipo discriminado `{ status: 'waiting' } | { status: 'expired' } | { status: 'ready'; bundleWire: Uint8Array }` en `pollLinkSessionOnce` para compilar `tsc --noEmit` sin errores.
