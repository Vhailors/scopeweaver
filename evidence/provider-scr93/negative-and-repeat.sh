#!/usr/bin/env bash
set -euo pipefail
cd /home/devuser/Documents/Projects/scopeweaver-provider-scr93
scratch=/tmp/scopeweaver-provider-scr93
proof=$PWD/evidence/provider-scr93
mkdir -p "$proof"
export ARTEX_PG_DSN="postgres://scopeweaver_test@/scopeweaver_provider_scr93?host=$scratch/socket&sslmode=disable"
export SCOPEWEAVER_PROVIDER_E2E=1
cp db/provider.go "$scratch/provider-negative-backup.go"
trap 'cp "$scratch/provider-negative-backup.go" db/provider.go' EXIT
python3 - <<'PY'
from pathlib import Path
p=Path('db/provider.go')
s=p.read_text()
before='WHERE token_hash=$1 AND company_id=$2 AND revoked_at'
after='WHERE token_hash=$1 AND ($2::bigint > 0) AND revoked_at'
assert s.count(before)==1
p.write_text(s.replace(before,after))
PY
set +e
go test ./server -run '^TestProviderCompanyContractPG$' -count=1 -v > "$scratch/negative-control.log" 2>&1
negative=$?
set -e
cp "$scratch/provider-negative-backup.go" db/provider.go
trap - EXIT
if [ "$negative" -eq 0 ]; then
 printf 'FAIL negative control unexpectedly passed\n' > "$proof/negative-control-summary.txt"
 exit 1
fi
# Require the intended transport-level security failure, not a build or fixture error.
if ! grep -q 'expected HTTP 403, got 200 (body suppressed)' "$scratch/negative-control.log"; then
 printf 'FAIL negative control did not reach the wrong-company refusal assertion\n' > "$proof/negative-control-summary.txt"
 exit 1
fi
printf 'PASS negative control: removing the grant company predicate caused the real HTTP journey to fail at expected HTTP 403, got 200; response body was suppressed. Restored provider enforcement.\n' > "$proof/negative-control-summary.txt"
SCOPEWEAVER_PROVIDER_EVIDENCE="$proof/provider-http-transcript.json" go test ./server -run '^TestProviderCompanyContractPG$' -count=1 -v > "$scratch/restored-control.log" 2>&1
printf 'PASS restored positive control\n' >> "$proof/negative-control-summary.txt"
go test ./server -run '^TestProviderCompanyContractPG$' -count=10 -v > "$scratch/ten-journeys.log" 2>&1
python3 - <<'PY'
from pathlib import Path
lines=Path('/tmp/scopeweaver-provider-scr93/ten-journeys.log').read_text().splitlines()
passes=[s for s in lines if s.startswith('--- PASS: TestProviderCompanyContractPG ')]
assert len(passes)==10
proof=Path('evidence/provider-scr93/ten-journeys-summary.txt')
out=['PASS ten consecutive real HTTP/PostgreSQL journeys, no retries.']
for line in lines:
 if line.startswith('--- PASS: TestProviderCompanyContractPG ') or 'Deletion reconciliation: provider assets=' in line:
  out.append(line.strip())
proof.write_text('\n'.join(out)+'\n')
PY
cat "$proof/negative-control-summary.txt" "$proof/ten-journeys-summary.txt"
