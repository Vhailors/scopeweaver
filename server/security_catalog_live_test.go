package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/locale"
)

func TestSecurityCatalogReportsLiveServers(t *testing.T) {
	f := newCatalogFixture(t, "")
	pg := f.s.m.pg
	if err := pg.SetBool(db.SettingSecurityReportsEnabled, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pg.Exec(`DELETE FROM settings WHERE key=$1`, db.SettingSecurityReportsEnabled); err != nil {
			t.Error(err)
		}
	})
	if err := f.s.seedSecurityCatalog(); err != nil {
		t.Fatal(err)
	}
	a, err := pg.GetAgentByKey("auto")
	if err != nil || a == nil {
		t.Fatalf("auto agent: %v", err)
	}
	live := &db.MCPServer{Name: "live-probe", Transport: "stdio", Command: "/usr/bin/true",
		Args: json.RawMessage(`[]`), Env: json.RawMessage(`{}`)}
	rec := f.call(t, t.Context(), "POST", "/api/mcp", live, true, locale.En)
	if rec.Code != 200 {
		t.Fatalf("save disabled generic server: %d %s", rec.Code, rec.Body.String())
	}
	var saved struct{ ID int64 }
	if err := json.Unmarshal(rec.Body.Bytes(), &saved); err != nil || saved.ID == 0 {
		t.Fatalf("save id: %v %s", err, rec.Body.String())
	}
	t.Cleanup(func() {
		if err := pg.DeleteMCP(saved.ID); err != nil {
			t.Errorf("delete live server: %v", err)
		}
	})
	if _, err := pg.Exec(`UPDATE mcp_servers SET enabled=true WHERE id=$1`, saved.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.Exec(`INSERT INTO mcp_tools_cache(server_id, tool_name) VALUES($1, 'probe_tool')`, saved.ID); err != nil {
		t.Fatal(err)
	}
	if err := pg.SetAgentVisibilityKind(a.ID, "mcp", []int64{saved.ID}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(f.s.skillDir, "live-probe")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	body := "---\nname: live-probe\ndescription: Fixture\nmcps:\n  - live-probe\n---\nFixture.\n"
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := pg.ToggleSkillVisibility(a.ID, "live-probe", true); err != nil {
		t.Fatal(err)
	}
	res, err := f.s.toolSecurityCatalog("auto").Call(t.Context(), json.RawMessage(`{}`), nil)
	if err != nil || res.IsError {
		t.Fatalf("helper: %+v %v", res, err)
	}
	var result struct {
		Catalog     []catalogProfile    `json:"catalog"`
		LiveServers []catalogLiveServer `json:"live_servers"`
	}
	if err := json.Unmarshal([]byte(res.Flatten()), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.LiveServers) != 1 {
		t.Fatalf("live_servers entries: %+v", result.LiveServers)
	}
	got := result.LiveServers[0]
	if got.Server != "live-probe" || got.Skill != "live-probe" || !got.Callable || !got.Enabled || got.Tools != 1 {
		t.Fatalf("live server entry: %+v", got)
	}
	for _, profile := range result.Catalog {
		for _, status := range profile.Statuses {
			if status.Callable {
				t.Fatalf("catalog provider became callable: %+v", status)
			}
		}
	}
}
