package server

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

func securityContextFixture(t *testing.T) *catalogFixture {
	t.Helper()
	f := newCatalogFixture(t, "")
	f.save(t)
	if err := f.s.m.pg.SaveMCPCatalog(t.Context(), f.m, db.MCPCatalog{Available: true,
		Tools: []db.MCPTool{{Name: "unexpected_operation"}}}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"yeepforge", "adstrike", "confirmesc"} {
		body, err := os.ReadFile(filepath.Join("..", "skills", name, "SKILL.md"))
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(f.s.skillDir, name)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.s.seedSecurityCatalog(); err != nil {
		t.Fatal(err)
	}
	old := agent.FindingTrafficBindingEnabled
	t.Cleanup(func() { agent.FindingTrafficBindingEnabled = old })
	wireAgentAugment(f.s.m.pg, f.s.skillDir, f.s.hostTools)
	wireTools(f.s.m.pg, nil, f.s.knownToolLanguages())
	t.Cleanup(func() {
		if _, err := f.s.m.pg.Exec(`DELETE FROM settings WHERE key=$1`, db.SettingSecurityReportsEnabled); err != nil {
			t.Error(err)
		}
	})
	return f
}

func securityContextTool(tools []actool.CoreTool, name string) actool.CoreTool {
	for _, tool := range tools {
		if tool.Name() == name {
			return tool
		}
	}
	return nil
}

func TestSecuritySkillContextVisibility(t *testing.T) {
	f := securityContextFixture(t)
	pg := f.s.m.pg
	names := []string{"yeepforge", "adstrike", "confirmesc"}
	for _, key := range catalogHelperAgents {
		t.Run(key, func(t *testing.T) {
			a, err := pg.GetAgentByKey(key)
			if err != nil || a == nil {
				t.Fatalf("agent: %v", err)
			}
			if err := pg.SetAgentVisibilityKind(a.ID, "mcp", []int64{f.m.ID}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := pg.SetAgentSkillVisibility(a.ID, nil); err != nil {
					t.Error(err)
				}
			})
			cases := []struct {
				name    string
				visible []string
				want    []string
				feature bool
			}{
				{"default_off", nil, nil, true},
				{"all", names, names, true},
				{"feature_off", names, nil, false},
			}
			for _, name := range names {
				cases = append(cases, struct {
					name          string
					visible, want []string
					feature       bool
				}{"only_" + name, []string{name}, []string{name}, true})
				cases = append(cases, struct {
					name          string
					visible, want []string
					feature       bool
				}{"disabled_" + name, slices.DeleteFunc(slices.Clone(names), func(n string) bool { return n == name }),
					slices.DeleteFunc(slices.Clone(names), func(n string) bool { return n == name }), true})
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					if err := pg.SetAgentSkillVisibility(a.ID, tc.visible); err != nil {
						t.Fatal(err)
					}
					if err := pg.SetBool(db.SettingSecurityReportsEnabled, tc.feature); err != nil {
						t.Fatal(err)
					}
					tools, def, cleanup := agent.AugmentTools(t.Context(), key, nil)
					defer cleanup()
					if !slices.Equal(def.ReportSkills, tc.want) {
						t.Fatalf("identifiers=%v want=%v", def.ReportSkills, tc.want)
					}
					for _, tool := range tools {
						if strings.HasPrefix(tool.Name(), "mcp__") {
							t.Fatal("tagged native tool exposed")
						}
					}
					if len(def.Deferred) != 0 || len(def.GlobalNames) != 0 {
						t.Fatal("report skill granted deferred native capability")
					}
					helper := securityContextTool(tools, "security_catalog")
					if helper == nil {
						t.Fatal("seeded bound helper missing")
					}
					res, err := helper.Call(t.Context(), json.RawMessage(`{}`), nil)
					if err != nil || res.IsError != !tc.feature {
						t.Fatalf("helper: %+v %v", res, err)
					}
					if !tc.feature {
						return
					}
					var result struct {
						Catalog []catalogProfile `json:"catalog"`
					}
					if err := json.Unmarshal([]byte(res.Flatten()), &result); err != nil {
						t.Fatal(err)
					}
					for _, profile := range result.Catalog {
						want := ""
						if slices.Contains(tc.want, profile.Producer) {
							want = profile.Producer
						}
						if profile.Skill != want {
							t.Fatalf("helper identifier=%q want=%q", profile.Skill, want)
						}
					}
				})
			}
			for _, name := range names {
				t.Run("missing_"+name, func(t *testing.T) {
					if err := pg.SetAgentSkillVisibility(a.ID, []string{name}); err != nil {
						t.Fatal(err)
					}
					file := filepath.Join(f.s.skillDir, name, "SKILL.md")
					if err := os.Rename(file, file+".held"); err != nil {
						t.Fatal(err)
					}
					defer func() {
						if err := os.Rename(file+".held", file); err != nil {
							t.Error(err)
						}
					}()
					_, def, cleanup := agent.AugmentTools(t.Context(), key, nil)
					defer cleanup()
					if len(def.ReportSkills) != 0 {
						t.Fatal("missing registry entry recommended")
					}
					res, err := f.s.toolSecurityCatalog(key).Call(t.Context(), json.RawMessage(fmt.Sprintf(`{"producer":%q}`, name)), nil)
					if err != nil || res.IsError {
						t.Fatalf("helper: %+v %v", res, err)
					}
					var result struct {
						Catalog []catalogProfile `json:"catalog"`
					}
					if json.Unmarshal([]byte(res.Flatten()), &result) != nil || len(result.Catalog) != 1 || result.Catalog[0].Skill != "" {
						t.Fatal("helper recommended missing skill")
					}
				})
			}
		})
	}
	if len(f.records(t)) != 0 {
		t.Fatal("assembly/helper launched tagged provider")
	}
	t.Log("five roles: actual supplied skill registry; opt-in/disabled/missing/feature-off identifiers; native tools=0; tagged starts=0")
}
