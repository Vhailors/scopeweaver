#!/usr/bin/env bash
set -euo pipefail
cd /home/devuser/Documents/Projects/scopeweaver-provider-scr93
scratch=/tmp/scopeweaver-provider-scr93
proof=$PWD/evidence/provider-scr93/automatic
mkdir -p "$proof"
(cd web && HUSKY=0 npm ci && npm test && NEXT_TELEMETRY_DISABLED=1 npm run build:static) > "$scratch/frontend.log" 2>&1
printf 'PASS frontend npm ci, npm test, npm run build:static (Node >=22)\n' > "$proof/frontend-gate-summary.txt"
cat "$proof/frontend-gate-summary.txt"
