#!/usr/bin/env sh
set -eu
exec node /app/dist/infra/runMigrations.js
