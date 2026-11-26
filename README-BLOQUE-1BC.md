# PIN-MLS — Bloque 1B/1C (pin-core + Interop Rust↔Node + pin-web-wasm + Cliente Web)

Este paquete se descomprime encima de tu carpeta `pin-mls/` existente (donde ya corriste el Bloque 1A).

## Pasos dentro de la terminal del Codespace

```bash
cd /workspaces/pin-mls/pin-mls
unzip -o ~/pin-mls-bloque1bc.zip -d .
chmod +x scripts/setup-1bc.sh
./scripts/setup-1bc.sh
```

Cuando termine en verde, levanta la interfaz Web:

```bash
cd web && npm run dev
```

Abre la pestaña **Puertos** del Codespace, marca el puerto **5173** como **Public** y ábrelo en dos ventanas del navegador (una normal y otra de incógnito) para probar el chat E2EE en tiempo real.
