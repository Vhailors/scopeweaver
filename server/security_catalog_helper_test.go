package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/locale"
	actool "github.com/Autumn-27/norma/tool"
)

func TestSecurityCatalogHelperFeatureAndBindings(t *testing.T) {
	f := newCatalogFixture(t, "")
	f.save(t)
	if err := f.s.seedSecurityCatalog(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, err := f.s.m.pg.Exec(`DELETE FROM settings WHERE key=$1`, db.SettingSecurityReportsEnabled)
		if err != nil {
			t.Error(err)
		}
	})
	a, err := f.s.m.pg.GetAgentByKey("auto")
	if err != nil || a == nil {
		t.Fatalf("agent: %v", err)
	}
	if err := f.s.m.pg.SetAgentVisibilityKind(a.ID, "mcp", []int64{f.m.ID}); err != nil {
		t.Fatal(err)
	}
	if err := f.s.m.pg.SaveMCPCatalog(t.Context(), f.m, db.MCPCatalog{Available: true,
		Tools: []db.MCPTool{{Name: "unexpected_operation", Description: "scopeweaver-secret-canary-01"}}}); err != nil {
		t.Fatal(err)
	}
	for _, producer := range []string{"yeepforge", "adstrike", "confirmesc"} {
		dir := filepath.Join(f.s.skillDir, producer)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"),
			[]byte(fmt.Sprintf("---\nname: %s\ndescription: Fixture\n---\nFixture.\n", producer)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.s.m.pg.ToggleSkillVisibility(a.ID, "yeepforge", true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.s.m.pg.ToggleSkillVisibility(a.ID, "yeepforge", false); err != nil {
			t.Error(err)
		}
	})
	oldTrafficBinding := agent.FindingTrafficBindingEnabled
	t.Cleanup(func() { agent.FindingTrafficBindingEnabled = oldTrafficBinding })
	wireAgentAugment(f.s.m.pg, f.s.skillDir, f.s.hostTools)
	wireTools(f.s.m.pg, nil, f.s.knownToolLanguages())
	tools, _, cleanup := agent.AugmentTools(t.Context(), "auto", nil)
	defer cleanup()
	var helper actool.CoreTool
	for _, tool := range tools {
		if tool.Name() == "security_catalog" {
			helper = tool
		}
	}
	if helper == nil {
		t.Fatal("host helper missing from real bound assembly")
	}
	for _, lang := range locale.Languages() {
		ctx := locale.WithLang(t.Context(), lang)
		if err := f.s.m.pg.SetBool(db.SettingSecurityReportsEnabled, false); err != nil {
			t.Fatal(err)
		}
		res, err := helper.Call(ctx, json.RawMessage(`{}`), nil)
		want, ok := locale.Raw(lang, "security.catalog.disabled")
		if err != nil || !res.IsError || !ok || res.Flatten() != want {
			t.Fatalf("disabled lang=%s result=%+v err=%v", lang, res, err)
		}
	}
	if err := f.s.m.pg.SetBool(db.SettingSecurityReportsEnabled, true); err != nil {
		t.Fatal(err)
	}
	res, err := helper.Call(t.Context(), json.RawMessage(`{}`), nil)
	var result struct {
		Catalog []catalogProfile `json:"catalog"`
	}
	if err != nil || res.IsError || json.Unmarshal([]byte(res.Flatten()), &result) != nil ||
		len(result.Catalog) != 3 || result.Catalog[0].Skill != "yeepforge" ||
		result.Catalog[1].Skill != "" || result.Catalog[2].Skill != "" ||
		len(result.Catalog[0].Statuses) != 1 || result.Catalog[0].Statuses[0].Status != "discovered" ||
		strings.Contains(res.Flatten(), "unexpected_operation") || strings.Contains(res.Flatten(), "scopeweaver-secret-canary-01") {
		t.Fatalf("curated bound catalog: %+v err=%v", res, err)
	}
	for _, input := range []string{`{"producer":"unknown"}`, `{"agent":"worker"}`, `{"task_id":1}`} {
		res, err := helper.Call(t.Context(), json.RawMessage(input), nil)
		if err != nil || !res.IsError {
			t.Fatalf("caller-selected identity accepted: %s %+v %v", input, res, err)
		}
	}
	if err := f.s.m.pg.RemoveAgentFromTool("auto", "security_catalog"); err != nil {
		t.Fatal(err)
	}
	if err := f.s.seedSecurityCatalog(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.s.m.pg.AddAgentToToolBinding("auto", []string{"security_catalog"}); err != nil {
			t.Error(err)
		}
	})
	res, err = helper.Call(t.Context(), json.RawMessage(`{}`), nil)
	if err != nil || !res.IsError {
		t.Fatal("retained helper handle ignored revoked binding")
	}
	tools, _, cleanup2 := agent.AugmentTools(t.Context(), "auto", nil)
	defer cleanup2()
	for _, tool := range tools {
		if tool.Name() == "security_catalog" {
			t.Fatal("ToolResolve ignored revoked binding")
		}
	}
	if len(f.records(t)) != 0 {
		t.Fatal("helper launched a provider")
	}
	t.Log("helper off=en/ko/zh-Hans fixed errors; on=3 curated profiles; visible skill only; cached statuses; bindings live; starts=0")
}

func TestSecurityCatalogFeatureToggleDuringRefresh(t *testing.T) {
	f := newCatalogFixture(t, "barrier")
	f.save(t)
	if err := f.s.seedSecurityCatalog(); err != nil {
		t.Fatal(err)
	}
	if err := f.s.m.pg.SetBool(db.SettingSecurityReportsEnabled, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := f.s.m.pg.Exec(`DELETE FROM settings WHERE key=$1`, db.SettingSecurityReportsEnabled); err != nil {
			t.Error(err)
		}
	})
	helper := f.s.toolSecurityCatalog("auto")
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- f.call(t, t.Context(), "POST", fmt.Sprintf("/api/mcp/%d/refresh", f.m.ID), nil, true, locale.En)
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	select {
	case <-f.listed:
	case <-ctx.Done():
		t.Fatal("refresh barrier missing")
	}
	if rec := f.call(t, t.Context(), "PUT", "/api/settings", map[string]bool{"security_reports_enabled": false}, true, locale.En); rec.Code != 200 {
		t.Fatal("feature toggle failed")
	}
	res, err := helper.Call(t.Context(), json.RawMessage(`{}`), nil)
	if err != nil || !res.IsError || res.Flatten() != locale.T(locale.En, "security.catalog.disabled") {
		t.Fatalf("pre-toggle helper remained usable: %+v %v", res, err)
	}
	close(f.release)
	select {
	case rec := <-done:
		if rec.Code != 200 {
			t.Fatalf("provider eligibility is independent of report helper flag: %d %s", rec.Code, rec.Body.String())
		}
	case <-ctx.Done():
		t.Fatal("refresh did not close")
	}
	status, err := f.s.m.pg.MCPProviderStatus(f.m)
	if err != nil || status.Status != "discovered" || status.Callable {
		t.Fatalf("retained cached status: %+v %v", status, err)
	}
	t.Log("tools/list barrier -> feature off: helper disabled; explicit provider refresh HTTP 200; cached metadata readable; callable=false")
}

func TestSecurityCatalogMeasuredProgramDigest(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "provider.mjs")
	raw := []byte("synthetic provider script bytes\n")
	if err := os.WriteFile(script, raw, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	want := hex.EncodeToString(sum[:])
	for _, interpreter := range []string{"node", "python3", "python3.12"} {
		if got := catalogProgramDigest(filepath.Join(dir, interpreter), []string{script}); got != want {
			t.Fatalf("%s measured %s, want script %s", interpreter, got, want)
		}
	}
	for _, args := range [][]string{nil, {"-e", "inline code"}, {"-m", "provider"}, {"missing-script"}} {
		if got := catalogProgramDigest(filepath.Join(dir, "node"), args); got != "" {
			t.Fatalf("ambiguous runtime reported digest: %v %s", args, got)
		}
	}
	if got := catalogProgramDigest(script, nil); got != want {
		t.Fatalf("direct executable bytes not measured: %s", got)
	}
}
