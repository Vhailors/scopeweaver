#!/usr/bin/env bash
set -euo pipefail
cd /home/devuser/Documents/Projects/scopeweaver-provider-scr93
scratch=/tmp/scopeweaver-provider-scr93
proof=$PWD/evidence/provider-scr93/automatic
mkdir -p "$proof"
export ARTEX_PG_DSN="postgres://scopeweaver_test@/scopeweaver_provider_scr93?host=$scratch/socket&sslmode=disable"
export SCOPEWEAVER_PROVIDER_E2E=1
unset SCOPEWEAVER_PROVIDER_EVIDENCE
cp db/provider.go "$scratch/automatic-company-backup.go"
cp db/provider_redaction.go "$scratch/automatic-redaction-backup.go"
restore() {
 cp "$scratch/automatic-company-backup.go" db/provider.go
 cp "$scratch/automatic-redaction-backup.go" db/provider_redaction.go
}
trap restore EXIT
python3 - <<'PY'
from pathlib import Path
p=Path('db/provider.go');s=p.read_text()
before='WHERE token_hash=$1 AND company_id=$2 AND revoked_at'
after='WHERE token_hash=$1 AND ($2::bigint > 0) AND revoked_at'
assert s.count(before)==1
p.write_text(s.replace(before,after))
PY
set +e
go test ./server -run '^TestProviderCompanyContractPG$' -count=1 -v > "$scratch/automatic-company-negative.log" 2>&1
company=$?
set -e
restore
if [ "$company" -eq 0 ] || ! grep -q 'expected HTTP 403, got 200 (body suppressed)' "$scratch/automatic-company-negative.log"; then
 printf 'FAIL company negative control did not reach the intended refusal assertion\n' > "$proof/negative-controls-summary.txt"
 exit 1
fi
printf 'PASS company negative control: disabling the grant company predicate produced HTTP 200 instead of required HTTP 403. No response body was printed.\n' > "$proof/negative-controls-summary.txt"
python3 - <<'PY'
from pathlib import Path
p=Path('db/provider_redaction.go');s=p.read_text()
before='func ProviderPayload(family string, raw []byte, detail bool) ([]byte, error) {'
assert s.count(before)==1
p.write_text(s.replace(before,before+'\n if family != "" { return ProviderCanonicalJSON(raw) }'))
PY
set +e
go test ./server -run '^TestProviderCompanyContractPG$' -count=1 -v > "$scratch/automatic-redaction-negative.log" 2>&1
redaction=$?
set -e
restore
if [ "$redaction" -eq 0 ] || ! grep -q 'source content escaped provider redaction boundary' "$scratch/automatic-redaction-negative.log"; then
 printf 'FAIL redaction negative control did not reach the source disclosure assertion\n' >> "$proof/negative-controls-summary.txt"
 exit 1
fi
printf 'PASS redaction negative control: bypassing the serializer made the real HTTP journey detect forbidden source content; its response body was suppressed.\n' >> "$proof/negative-controls-summary.txt"
SCOPEWEAVER_PROVIDER_EVIDENCE="$proof/provider-http-transcript.json" go test ./server -run '^TestProviderCompanyContractPG$' -count=1 -v > "$scratch/automatic-restored.log" 2>&1
printf 'PASS restored positive control, with sanitized actual API evidence\n' >> "$proof/negative-controls-summary.txt"
go test ./server -run '^TestProviderCompanyContractPG$' -count=10 -v > "$scratch/automatic-ten.log" 2>&1
python3 - <<'PY'
from pathlib import Path
lines=Path('/tmp/scopeweaver-provider-scr93/automatic-ten.log').read_text().splitlines()
passes=[s for s in lines if s.startswith('--- PASS: TestProviderCompanyContractPG ')]
assert len(passes)==10
out=['PASS ten consecutive revised real HTTP/PostgreSQL journeys, no retries.']
for s in lines:
 if s.startswith('--- PASS: TestProviderCompanyContractPG ') or 'Deletion reconciliation: provider assets=' in s:out.append(s.strip())
Path('evidence/provider-scr93/automatic/ten-journeys-summary.txt').write_text('\n'.join(out)+'\n')
PY
cmp -s "$scratch/automatic-company-backup.go" db/provider.go
cmp -s "$scratch/automatic-redaction-backup.go" db/provider_redaction.go
trap - EXIT
cat "$proof/negative-controls-summary.txt" "$proof/ten-journeys-summary.txt"
