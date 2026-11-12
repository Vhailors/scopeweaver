#!/usr/bin/env bash
set -euo pipefail
cd /home/devuser/Documents/Projects/scopeweaver-provider-scr93
scratch=/tmp/scopeweaver-provider-scr93
proof=$PWD/evidence/provider-scr93/automatic
mkdir -p "$proof"
(cd adapters/agent && HUSKY=0 npm ci && npm test && npm run check) > "$scratch/adapter-node.log" 2>&1
printf 'PASS adapter npm ci, npm test, npm run check\n' > "$proof/adapter-gate-summary.txt"
database=scopeweaver_adapter_scr93
docker exec scopeweaver-provider-scr93-test createdb -U scopeweaver_test "$database"
trap 'docker exec scopeweaver-provider-scr93-test dropdb --force -U scopeweaver_test "$database" >/dev/null' EXIT
export ARTEX_PG_DSN="postgres://scopeweaver_test@/$database?host=$scratch/socket&sslmode=disable"
SCOPEWEAVER_ADAPTER_E2E=1 go test ./server -run '^TestAgentAdapterE2E$' -count=1 -v > "$scratch/adapter-http.log" 2>&1
printf 'PASS existing adapter real backend/PostgreSQL gate\n' >> "$proof/adapter-gate-summary.txt"
cat "$proof/adapter-gate-summary.txt"
