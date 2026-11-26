SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

API_URL ?= http://127.0.0.1:3000
FORCE ?= 0

.PHONY: help preflight env backend-install backend-build docker-up docker-down docker-logs smoke-e2e test-1a clean

help: ## Muestra comandos disponibles del Bloque 1A
	@awk 'BEGIN {FS = ":.*## "; printf "\nUso: make <objetivo>\n\n"} \
	  /^[a-zA-Z0-9_-]+:.*## / { printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

preflight: ## Verifica estructura e invariantes del Bloque 1A
	@chmod +x scripts/*.sh backend/sql/migrate.sh
	@./scripts/preflight-1a.sh

env: ## Genera backend/.env efímero con claves Ed25519 (usa FORCE=1 para regenerar)
	@if [ -f backend/.env ] && [ "$(FORCE)" != "1" ]; then \
	  echo "==> backend/.env ya existe (usa 'make env FORCE=1' para sobrescribir)."; \
	  exit 0; \
	fi
	@echo "==> Generando backend/.env efímero..."
	@TMP_DIR="$$(mktemp -d)"; \
	trap 'rm -rf "$$TMP_DIR"' EXIT; \
	openssl genpkey -algorithm ED25519 -out "$$TMP_DIR/jwt_priv.pem" >/dev/null 2>&1; \
	openssl pkey -in "$$TMP_DIR/jwt_priv.pem" -pubout -out "$$TMP_DIR/jwt_pub.pem" >/dev/null 2>&1; \
	JWT_PRIV_ESC="$$(awk '{printf "%s\\n", $$0}' "$$TMP_DIR/jwt_priv.pem")"; \
	JWT_PUB_ESC="$$(awk '{printf "%s\\n", $$0}' "$$TMP_DIR/jwt_pub.pem")"; \
	POW_SECRET="$$(openssl rand -hex 32)"; \
	COOLDOWN_PEPPER="$$(openssl rand -hex 32)"; \
	{ \
	  echo "NODE_ENV=development"; \
	  echo "HOST=0.0.0.0"; \
	  echo "PORT=3000"; \
	  echo "LOG_LEVEL=info"; \
	  echo "DATABASE_URL=postgres://pinmls:pinmls_dev@postgres:5432/pinmls"; \
	  echo "REDIS_URL=redis://redis:6379/0"; \
	  echo "ALLOWED_WEB_ORIGINS=http://localhost:5173,http://127.0.0.1:5173"; \
	  echo "JWT_KEY_ID=dev-ed25519-1"; \
	  echo "JWT_PRIVATE_KEY_PEM=\"$$JWT_PRIV_ESC\""; \
	  echo "JWT_PUBLIC_KEY_PEM=\"$$JWT_PUB_ESC\""; \
	  echo "POW_HMAC_SECRET_HEX=$$POW_SECRET"; \
	  echo "COOLDOWN_PEPPER_HEX=$$COOLDOWN_PEPPER"; \
	  echo "POW_DIFFICULTY_REGISTER=10"; \
	  echo "POW_DIFFICULTY_INVITE=10"; \
	  echo "POW_DIFFICULTY_SAFE=10"; \
	  echo "PUSH_MODE=mock"; \
	} > backend/.env; \
	chmod 600 backend/.env
	@echo "==> backend/.env generado."

backend-install: ## Instala dependencias npm de backend/
	@cd backend && if [ -f package-lock.json ]; then npm ci; else npm install; fi

backend-build: backend-install ## Ejecuta typecheck estricto y compila backend/dist
	@cd backend && npm run typecheck && npm run build

docker-up: env ## Levanta PostgreSQL 16, Redis 7, Migrator, API (127.0.0.1:3000) y Worker
	@cd backend && docker compose up --build -d
	@echo "==> Esperando a $(API_URL)/readyz..."
	@for i in $$(seq 1 40); do \
	  if curl -fsS "$(API_URL)/readyz" >/dev/null 2>&1; then \
	    echo "==> API lista en $(API_URL)"; \
	    exit 0; \
	  fi; \
	  sleep 2; \
	done; \
	echo "ERROR: $(API_URL)/readyz no respondió en 80s" >&2; \
	(cd backend && docker compose ps -a && docker compose logs --tail=100 migrator api worker); \
	exit 1

docker-down: ## Detiene y elimina contenedores y volúmenes de desarrollo
	@cd backend && docker compose down -v --remove-orphans

docker-logs: ## Muestra logs en vivo de API y Worker
	@cd backend && docker compose logs -f api worker

smoke-e2e: backend-install ## Ejecuta los 11 flujos E2E reales contra Docker
	@cd backend && API_URL="$(API_URL)" node scripts/smoke-e2e.mjs

test-1a: preflight backend-build docker-up smoke-e2e ## Ejecuta toda la validación del Bloque 1A
	@echo "==> BLOQUE 1A VERIFICADO EN VERDE."

clean: ## Limpia artefactos de compilación locales
	@rm -rf backend/dist
