package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/locale"
)

func TestSecurityCatalogStatusAndEligibility(t *testing.T) {
	f := newCatalogFixture(t, "")
	command := f.m.Command
	f.m.Enabled = false
	f.save(t)
	path := fmt.Sprintf("/api/mcp/%d/refresh", f.m.ID)
	for _, tc := range []struct {
		enabled bool
		command string
		status  string
	}{
		{false, command, "disabled"},
		{true, "", "not_configured"},
		{true, command, "not_discovered"},
	} {
		t.Run(tc.status, func(t *testing.T) {
			// Given disabled, unconfigured, and configured-but-unrefreshed rows.
			f.m.Enabled, f.m.Command = tc.enabled, tc.command
			f.save(t)
			status, err := f.s.m.pg.MCPProviderStatus(f.m)
			if err != nil {
				t.Fatal(err)
			}
			if status.Status != tc.status || status.Configured != (tc.command != "") ||
				status.Enabled != tc.enabled || status.Callable || status.Provenance != "unverified" || status.Cache != nil {
				t.Fatalf("status contract: %+v", status)
			}
			// When an ineligible row is explicitly refreshed, or a generic
			// connection helper is asked to connect a tagged row.
			if !tc.enabled || tc.command == "" {
				rec := f.call(t, t.Context(), "POST", path, nil, true, locale.En)
				if rec.Code != 409 {
					t.Fatalf("ineligible refresh: %d %s", rec.Code, rec.Body.String())
				}
			}
			if _, err := connectMCP(t.Context(), f.m); err == nil {
				t.Fatal("generic connector accepted a tagged row")
			}
			// Then metadata reads and rejected requests launch nothing.
			if rows := f.records(t); len(rows) != 0 {
				t.Fatalf("ineligible/passive operation launched fixture: %+v", rows)
			}
		})
	}
	// Given valid but independently unmeasured catalog metadata.
	if err := f.s.m.pg.SaveMCPCatalog(t.Context(), f.m, db.MCPCatalog{Available: true}); err != nil {
		t.Fatal(err)
	}
	status, err := f.s.m.pg.MCPProviderStatus(f.m)
	if err != nil || status.Cache == nil || status.Cache.ExecutableSHA256 != "" || status.Provenance != "unverified" {
		t.Fatalf("unmeasured SHA misrepresented: %+v %v", status, err)
	}
	// When config changes after a successful cache publication.
	f.m.Name += "-renamed"
	f.save(t)
	status, err = f.s.m.pg.MCPProviderStatus(f.m)
	if err != nil || status.Status != "stale" || status.Callable {
		t.Fatalf("old cache presented as current: %+v %v", status, err)
	}
	t.Log("disabled/not_configured/not_discovered/configured/stale distinguished; unmeasured provenance=unverified; launches=0")
}

func TestSecurityCatalogMalformed(t *testing.T) {
	for _, lang := range locale.Languages() {
		t.Run(string(lang), func(t *testing.T) {
			// Given the real fixture's malformed response containing a canary.
			f := newCatalogFixture(t, "malformed")
			f.save(t)
			// When explicit authenticated refresh consumes that response.
			rec := f.call(t, t.Context(), "POST", fmt.Sprintf("/api/mcp/%d/refresh", f.m.ID), nil, true, lang)
			status, err := f.s.m.pg.MCPProviderStatus(f.m)
			// Then error text is fixed/localized and no malformed metadata is cached.
			if rec.Code != 502 || strings.Contains(rec.Body.String(), "scopeweaver-secret-canary-01") ||
				err != nil || status.Status != "unavailable" || status.Cache == nil || len(status.Cache.Tools) != 0 {
				t.Fatalf("malformed contract: HTTP %d %+v %v %s", rec.Code, status, err, rec.Body.String())
			}
			counts := map[string]int{}
			for _, row := range f.records(t) {
				counts[fmt.Sprint(row["event"])]++
				counts[fmt.Sprint(row["method"])]++
				if row["method"] == "tools/call" {
					t.Fatal("malformed provider caused tools/call")
				}
			}
			if counts["start"] != 1 || counts["initialize"] != 1 || counts["tools/list"] != 1 {
				t.Fatalf("malformed IPC evidence is incomplete: %v", counts)
			}
			t.Logf("malformed lang=%s HTTP %d status=%s body=%s; tools/call=0", lang, rec.Code, status.Status, rec.Body.String())
		})
	}
}

func TestSecurityCatalogHungCancellation(t *testing.T) {
	// Given the hung fixture and an event subscription before refresh starts.
	f := newCatalogFixture(t, "hung")
	f.save(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- f.call(t, ctx, "POST", fmt.Sprintf("/api/mcp/%d/refresh", f.m.ID), nil, true, locale.En)
	}()
	awaitCatalogEvent(t, f, "tools/list")
	// When cancellation happens at the exact pending tools/list event.
	cancel()
	wait, stop := context.WithTimeout(t.Context(), 20*time.Second)
	defer stop()
	select {
	case rec := <-done:
		if rec.Code != 502 || strings.Contains(rec.Body.String(), "scopeweaver-secret-canary-01") {
			t.Fatalf("hung cancellation: %d %s", rec.Code, rec.Body.String())
		}
	case <-wait.Done():
		t.Fatal("hung provider not reaped on cancellation")
	}
	var count int
	if err := f.s.m.pg.QueryRow(`SELECT count(*) FROM mcp_catalog_cache WHERE server_id=$1`, f.m.ID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("cancelled refresh published metadata: rows=%d err=%v", count, err)
	}
	t.Log("tools/list event -> cancellation -> refresh joined; cache_rows=0; tools/call=0")
}

func TestSecurityCatalogBoundedMetadata(t *testing.T) {
	for _, mode := range []string{"oversized", "too_many", "duplicate", "paged", "missing_tools", "null"} {
		t.Run(mode, func(t *testing.T) {
			// Given a real fixture response mutated at the wire boundary.
			f := newCatalogFixture(t, mode)
			f.save(t)
			// When explicit refresh receives excessive/incomplete metadata.
			rec := f.call(t, t.Context(), "POST", fmt.Sprintf("/api/mcp/%d/refresh", f.m.ID), nil, true, locale.En)
			status, err := f.s.m.pg.MCPProviderStatus(f.m)
			// Then success cannot be claimed and no tool metadata survives.
			if rec.Code != 502 || err != nil || status.Status != "unavailable" || status.Cache == nil || len(status.Cache.Tools) != 0 {
				t.Fatalf("bounded metadata: HTTP %d %+v %v", rec.Code, status, err)
			}
			t.Logf("wire mode=%s HTTP %d status=%s cached_tools=0", mode, rec.Code, status.Status)
		})
	}
}

func TestSecurityCatalogReportsSetting(t *testing.T) {
	f := newCatalogFixture(t, "")
	if _, err := f.s.m.pg.Exec(`DELETE FROM settings WHERE key=$1`, db.SettingSecurityReportsEnabled); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := f.s.m.pg.Exec(`DELETE FROM settings WHERE key=$1`, db.SettingSecurityReportsEnabled); err != nil {
			t.Errorf("setting cleanup: %v", err)
		}
	})
	if f.s.m.pg.SecurityReportsEnabled() {
		t.Fatal("missing feature flag must default off")
	}
	for _, enabled := range []bool{true, false} {
		rec := f.call(t, t.Context(), "PUT", "/api/settings", map[string]bool{"security_reports_enabled": enabled}, true, locale.En)
		if rec.Code != 200 {
			t.Fatalf("toggle setting: %d %s", rec.Code, rec.Body.String())
		}
		rec = f.call(t, t.Context(), "PUT", "/api/settings", map[string]any{}, true, locale.En)
		var payload struct {
			Enabled bool `json:"security_reports_enabled"`
		}
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &payload) != nil || payload.Enabled != enabled {
			t.Fatalf("omitted flag lost saved value: %d %s", rec.Code, rec.Body.String())
		}
		// Schema initialization/restart cannot resurrect or clear an operator toggle.
		other, err := db.Open(os.Getenv("ARTEX_PG_DSN"))
		if err != nil {
			t.Fatal(err)
		}
		preserved := other.SecurityReportsEnabled()
		if err := other.Close(); err != nil {
			t.Fatal(err)
		}
		if preserved != enabled {
			t.Fatalf("restart lost security_reports_enabled=%t", enabled)
		}
	}
	t.Log("security_reports_enabled: absent=false; explicit true/false survives omitted field and database restart")
}
