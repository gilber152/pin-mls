# PIN-MLS — Bloque 1A v3 (Backend + PostgreSQL 16 + Redis 7 + E2E)

Versión corregida y lista para subir sin errores a un VPS con Docker, GitHub Codespaces, Render, Railway o conectado a Supabase PostgreSQL.

## Correcciones incluidas en v3
- `backend/src/modules/ws/auth.ts`: narrowing estricto de `typeof raw === 'string'` (cero errores TS).
- `backend/src/infra/pow.ts` y `backend/scripts/smoke-e2e.mjs`: Argon2id con `timeCost: 2` (compatible con `argon2 ^0.41.1` y alineado con Rust `pin-core`).
- `backend/src/infra/db.ts` y `backend/src/infra/runMigrations.ts`: detección automática de TLS para bases gestionadas (Supabase, Render externa, Neon o `DATABASE_SSL=true`) y `PG_POOL_MAX` configurable.
- `backend/src/infra/redis.ts`: soporte para `rediss://` y `?family=0` (Railway IPv6) en BullMQ.

## Despliegue rápido en VPS / Codespaces

Descomprime directamente en la raíz del proyecto (evita crear una subcarpeta duplicada `pin-mls/pin-mls/`):

```bash
mkdir -p ~/pin-mls
unzip -o ~/pin-mls-bloque1a-v3.zip -d ~/pin-mls
cd ~/pin-mls
chmod +x scripts/*.sh backend/sql/migrate.sh
make test-1a
```
