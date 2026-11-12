#!/usr/bin/env bash
set -euo pipefail
cd /home/devuser/Documents/Projects/scopeweaver-provider-scr93
scratch=/tmp/scopeweaver-provider-scr93
proof=/home/devuser/Documents/Projects/scopeweaver-provider-scr93/evidence/provider-scr93/automatic
mkdir -p "$proof"
export PGHOST="$scratch/socket" PGUSER=scopeweaver_test
cat > "$scratch/init.go" <<'GO'
package main
import("os";"github.com/Autumn-27/artex/db")
func main(){d,e:=db.Open(os.Getenv("ARTEX_PG_DSN"));if e!=nil{panic("isolated database initialization failed")};defer d.Close();if d.EnsureLLMUsageTable()!=nil||d.EnsureLLMRecordsTable()!=nil{panic("supplementary schema failed")}}
GO
go build -o "$scratch/init" "$scratch/init.go"
i=0
status=0
: > "$proof/backend-gate-summary.txt"
while IFS= read -r package; do
 i=$((i+1))
 database="scopeweaver_provider_gate_$i"
 docker exec scopeweaver-provider-scr93-test createdb -U scopeweaver_test "$database"
 export ARTEX_PG_DSN="postgres://scopeweaver_test@/$database?host=$scratch/socket&sslmode=disable"
 "$scratch/init" > "$scratch/init-$i.log" 2>&1
 if go test -p 1 "$package" -count=1 > "$scratch/gate-$i.log" 2>&1; then
  printf 'PASS %s\n' "$package" >> "$proof/backend-gate-summary.txt"
 else
  printf 'FAIL %s (private diagnostic log gate-%s.log)\n' "$package" "$i" >> "$proof/backend-gate-summary.txt"
  status=1
 fi
 docker exec scopeweaver-provider-scr93-test dropdb --force -U scopeweaver_test "$database"
done < <(go list ./...)
for script in *.sh; do bash -n "$script"; done
sh -n start.sh
printf 'PASS shell syntax\n' >> "$proof/backend-gate-summary.txt"
cat "$proof/backend-gate-summary.txt"
exit "$status"
