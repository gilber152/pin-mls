# PIN-MLS — Bloque 4A (Despliegue en Render + Supabase)

Configuración lista para desplegar el backend Fastify 5 + WebSockets (`/v1/ws`), Redis y el cliente Web (WASM + OpenMLS 0.9.2) en **Render**, usando **Supabase** como PostgreSQL 16 gestionado, sin necesidad de dominio propio ni VPS.

## Paso a paso

1. **Descomprimir y subir al repositorio Git:**
   ```bash
   cd /workspaces/pin-mls
   unzip -o pin-mls-bloque4a-render-supabase.zip -d .
   rm -f pin-mls-bloque4a-render-supabase.zip
   chmod +x scripts/gen-prod-secrets.sh scripts/migrate-supabase.sh
   git add . && git commit -m "chore: agregar Bloque 4A (Render + Supabase)" && git push
   ```

2. **Crear base de datos en Supabase y aplicar migraciones:**
   - Crea un proyecto en Supabase y copia la cadena **Session Pooler URI** (con `?sslmode=require`).
   - En tu terminal de Codespaces:
     ```bash
     export DATABASE_URL="postgresql://postgres.<REF>:<PASS>@...pooler.supabase.com:5432/postgres?sslmode=require"
     ./scripts/migrate-supabase.sh
     ```

3. **Generar secretos Ed25519 y hex:**
   ```bash
   ./scripts/gen-prod-secrets.sh
   ```

4. **Desplegar en Render usando Blueprint (`render.yaml`):**
   - En Render: **New + → Blueprint** y conecta tu repositorio de GitHub.
   - Completa las variables marcadas `sync: false`:
     - En `pin-mls-api`: `DATABASE_URL`, `JWT_PRIVATE_KEY_PEM`, `JWT_PUBLIC_KEY_PEM` y `CORS_ORIGIN` (la URL `https://pin-mls-web.onrender.com` que genere Render).
     - En `pin-mls-web`: `VITE_API_BASE_URL` (la URL `https://pin-mls-api.onrender.com` que genere Render).

5. **Verificar en vivo:**
   - Abre `https://pin-mls-api.onrender.com/readyz` y confirma `{"status":"ok"}`.
   - Abre `https://pin-mls-web.onrender.com` en dos pestañas (normal e incógnito) y prueba el chat E2EE OpenMLS.
   - Para conectar tu app Android del Bloque 3, actualiza `API_BASE_URL` en `android/app/build.gradle.kts` con la URL HTTPS de `pin-mls-api`.
