package server

import (
	"encoding/json"
	"fmt"
	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/locale"
	"slices"
	"testing"
)

func TestSecuritySkillContextHelperMetadata(t *testing.T) {
	f := securityContextFixture(t)
	pg := f.s.m.pg
	row, err := pg.GetTool("security_catalog")
	if err != nil || row == nil || !slices.Equal(row.Agents, catalogHelperAgents) {
		t.Fatalf("seed bindings: %+v %v", row, err)
	}
	for _, lang := range locale.Languages() {
		current := translatedStoredTool(row, f.s.knownToolLanguages(), lang)
		stock := f.s.toolSecurityCatalog("auto", lang)
		var schema map[string]any
		if json.Unmarshal(current.Schema, &schema) != nil || current.Description != stock.Description() {
			t.Fatalf("localized metadata: %s", lang)
		}
		props := schema["properties"].(map[string]any)
		if props["producer"].(map[string]any)["description"] != stock.InputSchema()["properties"].(map[string]any)["producer"].(map[string]any)["description"] {
			t.Fatalf("localized parameter: %s", lang)
		}
	}
	row.Enabled, row.Agents, row.Description = false, []string{"worker"}, "CUSTOM_CATALOG_METADATA"
	bindings, err := json.Marshal(row.Agents)
	if err != nil {
		t.Fatal(err)
	}
	if err := pg.UpdateTool(row.Key, row.Description, row.Schema, bindings, row.Enabled); err != nil {
		t.Fatal(err)
	}
	if err := f.s.seedSecurityCatalog(); err != nil {
		t.Fatal(err)
	}
	after, err := pg.GetTool(row.Key)
	if err != nil || after.Enabled || after.Description != row.Description || !slices.Equal(after.Agents, row.Agents) {
		t.Fatal("insert-if-absent seed overwrote operator metadata")
	}
	t.Cleanup(func() {
		raw, err := json.Marshal(f.s.toolSecurityCatalog("").InputSchema())
		if err == nil {
			bindings, _ := json.Marshal(catalogHelperAgents)
			err = pg.UpsertToolForce(row.Key, f.s.toolSecurityCatalog("").Description(), raw, bindings)
		}
		if err != nil {
			t.Error(err)
		}
	})
	for _, key := range catalogHelperAgents {
		tools, _, cleanup := agent.AugmentTools(t.Context(), key, nil)
		cleanup()
		if securityContextTool(tools, row.Key) != nil {
			t.Fatal("disabled helper survived authoritative resolution")
		}
	}
	t.Log("security_catalog stock metadata translated en/ko/zh-Hans; seed preserves description/enabled/bindings; disabled helper absent")
}

func TestSecuritySkillContextLiveBoundaries(t *testing.T) {
	f := securityContextFixture(t)
	pg := f.s.m.pg
	a, err := pg.GetAgentByKey("worker")
	if err != nil || a == nil {
		t.Fatalf("agent: %v", err)
	}
	if err := pg.SetBool(db.SettingSecurityReportsEnabled, true); err != nil {
		t.Fatal(err)
	}
	if err := pg.SetAgentSkillVisibility(a.ID, []string{"yeepforge"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := pg.SetAgentSkillVisibility(a.ID, nil); err != nil {
			t.Error(err)
		}
		if _, err := pg.Exec(`UPDATE agents SET enabled=true WHERE id=$1`, a.ID); err != nil {
			t.Error(err)
		}
	})
	tools, _, cleanup := agent.AugmentTools(t.Context(), a.Key, nil)
	defer cleanup()
	helper := securityContextTool(tools, "security_catalog")
	if helper == nil {
		t.Fatal("bound helper absent")
	}
	assertSkill := func(want string) {
		t.Helper()
		res, err := helper.Call(t.Context(), json.RawMessage(`{"producer":"yeepforge"}`), nil)
		var result struct {
			Catalog []catalogProfile `json:"catalog"`
		}
		if err != nil || res.IsError || json.Unmarshal([]byte(res.Flatten()), &result) != nil ||
			len(result.Catalog) != 1 || result.Catalog[0].Skill != want {
			t.Fatalf("live helper identifier want=%q result=%+v err=%v", want, res, err)
		}
	}
	assertSkill("yeepforge")
	if err := pg.ToggleSkillVisibility(a.ID, "yeepforge", false); err != nil {
		t.Fatal(err)
	}
	assertSkill("")
	if err := pg.ToggleSkillVisibility(a.ID, "yeepforge", true); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.Exec(`UPDATE mcp_servers SET enabled=false WHERE id=$1`, f.m.ID); err != nil {
		t.Fatal(err)
	}
	assertSkill("yeepforge") // supplied-report applicability is independent of provider eligibility
	for _, input := range []string{`{"agent_key":"auto"}`, `{"task_id":1}`, `{"source_task_ids":[1]}`} {
		res, err := helper.Call(t.Context(), json.RawMessage(input), nil)
		if err != nil || !res.IsError {
			t.Fatal("caller-selected identity or task accepted")
		}
	}
	if _, err := pg.Exec(`DELETE FROM tools WHERE key='security_catalog'`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.s.seedSecurityCatalog(); err != nil {
			t.Error(err)
		}
	})
	tools, def, cleanup2 := agent.AugmentTools(t.Context(), a.Key, nil)
	defer cleanup2()
	if securityContextTool(tools, "security_catalog") != nil || def.Callable("security_catalog") {
		t.Fatal("missing helper metadata granted exposure")
	}
	res, err := helper.Call(t.Context(), json.RawMessage(`{}`), nil)
	if err != nil || !res.IsError {
		t.Fatal("retained helper ignored missing binding row")
	}
	if _, err := pg.Exec(`UPDATE agents SET enabled=false WHERE id=$1`, a.ID); err != nil {
		t.Fatal(err)
	}
	_, def, cleanup3 := agent.AugmentTools(t.Context(), a.Key, nil)
	defer cleanup3()
	if len(def.ReportSkills) != 0 {
		t.Fatal("disabled agent received report identifiers")
	}
	if len(f.records(t)) != 0 {
		t.Fatal("live helper/assembly launched a provider")
	}
	t.Log("retained helper follows current skills; provider disabled does not revoke report skill; identity/task rejected; missing helper row and disabled agent grant nothing; starts=0")
}

func TestSecuritySkillContextChildBindings(t *testing.T) {
	f := securityContextFixture(t)
	pg := f.s.m.pg
	if err := pg.SetBool(db.SettingSecurityReportsEnabled, true); err != nil {
		t.Fatal(err)
	}
	parent, err := pg.CreateTaskWithOptions("parent context", "CONTEXT_GOAL", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := pg.DeleteTask(parent.ID); err != nil {
			t.Error(err)
		}
	})
	auto, err := pg.GetAgentByKey("auto")
	if err != nil || auto == nil {
		t.Fatalf("auto: %v", err)
	}
	worker, err := pg.GetAgentByKey("worker")
	if err != nil || worker == nil {
		t.Fatalf("worker: %v", err)
	}
	if err := pg.SetAgentSkillVisibility(auto.ID, []string{"yeepforge", "adstrike"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, id := range []int64{auto.ID, worker.ID} {
			if err := pg.SetAgentSkillVisibility(id, nil); err != nil {
				t.Error(err)
			}
		}
	})
	for _, direct := range []bool{false, true} {
		t.Run(fmt.Sprintf("direct_source=%t", direct), func(t *testing.T) {
			var sources []int64
			if direct {
				sources = []int64{parent.ID}
			}
			child, err := pg.CreateTaskWithOptions("child context", "CONTEXT_GOAL", db.TaskCreateOptions{SourceTaskIDs: sources})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := pg.DeleteTask(child.ID); err != nil {
					t.Error(err)
				}
			})
			if err := pg.SetParentRef(child.ID, fmt.Sprint(parent.ID)); err != nil {
				t.Fatal(err)
			}
			for _, visible := range [][]string{nil, {"confirmesc"}} {
				if err := pg.SetAgentSkillVisibility(worker.ID, visible); err != nil {
					t.Fatal(err)
				}
				ctx := agent.WithRunInfo(t.Context(), agent.RunInfo{TaskID: child.ID, ExplorationID: child.ExplorationID})
				_, def, cleanup := agent.AugmentTools(ctx, "worker", nil)
				cleanup()
				if !slices.Equal(def.ReportSkills, visible) {
					t.Fatal("child inherited parent/source capabilities")
				}
			}
		})
	}
	if len(f.records(t)) != 0 {
		t.Fatal("child context launched tagged provider")
	}
	t.Log("parent_ref and explicit source_task_ids do not inherit skills; child worker uses its own bindings; starts=0")
}
