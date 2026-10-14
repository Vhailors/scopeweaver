package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/assessment"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/jackc/pgx/v5"
)

func TestSecuritySkillContextFinalRegistry(t *testing.T) {
	oldAugment, oldResolve := ToolAugment, ToolResolve
	t.Cleanup(func() { ToolAugment, ToolResolve = oldAugment, oldResolve })
	names := []string{"yeepforge", "adstrike", "confirmesc"}
	for _, tc := range []struct {
		name   string
		skill  bool
		helper bool
	}{
		{"visible", true, true},
		{"helper_hidden", true, false},
		{"skill_hidden", false, true},
		{"both_hidden", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ToolAugment = func(context.Context, string) ([]actool.CoreTool, DeferredInfo, func()) {
				return []actool.CoreTool{
					actool.Build(actool.Spec{Name: "Skill"}),
					actool.Build(actool.Spec{Name: "security_catalog"}),
				}, DeferredInfo{ReportSkills: slices.Clone(names)}, func() {}
			}
			ToolResolve = func(_ context.Context, _ string, tools []actool.CoreTool) []actool.CoreTool {
				return slices.DeleteFunc(tools, func(tool actool.CoreTool) bool {
					return tool.Name() == "Skill" && !tc.skill || tool.Name() == "security_catalog" && !tc.helper
				})
			}
			tools, def, cleanup := AugmentTools(t.Context(), "worker", nil)
			defer cleanup()
			want := names
			if !tc.skill {
				want = nil
			}
			if !slices.Equal(def.ReportSkills, want) {
				t.Fatalf("final identifiers=%v want=%v", def.ReportSkills, want)
			}
			system, boundary := deferredSystem("CUSTOM_CONTEXT_SENTINEL", def)
			if system[0] != "CUSTOM_CONTEXT_SENTINEL" {
				t.Fatal("custom prompt changed")
			}
			if tc.skill {
				if len(system) != 2 || boundary != 2 {
					t.Fatal("report block cache boundary missing")
				}
				body := strings.SplitN(strings.TrimPrefix(system[1], "<available-report-skills>\n"), "\n</available-report-skills>", 2)
				var metadata struct {
					Skills []string `json:"skills"`
					Helper string   `json:"catalog_helper"`
				}
				if len(body) != 2 || json.Unmarshal([]byte(body[0]), &metadata) != nil || !slices.Equal(metadata.Skills, names) {
					t.Fatal("machine report identifiers missing")
				}
				wantHelper := ""
				if tc.helper {
					wantHelper = "security_catalog"
				}
				if metadata.Helper != wantHelper {
					t.Fatal("hidden helper recommended")
				}
			} else if len(system) != 1 || boundary != 0 {
				t.Fatal("hidden skills rendered report context")
			}
			provider := &plannerCatalogProvider{}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			if _, _, err := captureRun(ctx, agentcore.Options{Provider: provider, SystemPrompt: system,
				DynamicBoundary: boundary, Tools: tools, MaxTurns: 2, NonStreaming: true}, "CONTEXT_INPUT", nil); err != nil {
				t.Fatal(err)
			}
			if len(provider.requests) != 1 || !slices.Equal(provider.requests[0].System, system) {
				t.Fatal("real provider request lost assembled segments")
			}
			t.Logf("final registry skill=%t helper=%t provider requests=1", tc.skill, tc.helper)
		})
	}
}

func TestSecuritySkillContextDirectSources(t *testing.T) {
	parsed, err := pgx.ParseConfig(os.Getenv("ARTEX_PG_DSN"))
	if err != nil || !strings.HasPrefix(parsed.Database, "scopeweaver_test_") {
		t.Fatal("requires an owned disposable PostgreSQL DSN; skips are not evidence")
	}
	pg, err := db.Open(os.Getenv("ARTEX_PG_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := pg.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := pg.SetBool(db.SettingSecurityReportsEnabled, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pg.Exec(`DELETE FROM settings WHERE key=$1`, db.SettingSecurityReportsEnabled); err != nil {
			t.Error(err)
		}
	})
	makeTask := func(source []int64) *db.Task {
		t.Helper()
		task, err := pg.CreateTaskWithOptions("report context fixture", "CONTEXT_GOAL", db.TaskCreateOptions{SourceTaskIDs: source})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := pg.DeleteTask(task.ID); err != nil {
				t.Error(err)
			}
		})
		return task
	}
	grand := makeTask(nil)
	parent := makeTask([]int64{grand.ID})
	parentOnly := makeTask(nil)
	direct := makeTask([]int64{parent.ID})
	for _, child := range []*db.Task{parentOnly, direct} {
		if err := pg.SetParentRef(child.ID, fmt.Sprint(parent.ID)); err != nil {
			t.Fatal(err)
		}
	}
	importReport := func(task *db.Task, producer string, body string) *db.Node {
		t.Helper()
		report, err := assessment.Parse(producer, []byte(body), time.Unix(0, 0).UTC())
		if err != nil {
			t.Fatal(err)
		}
		node, _, err := pg.Exploration(task.ExplorationID).ImportAssessment(t.Context(), task.ID, report)
		if err != nil {
			t.Fatal(err)
		}
		return node
	}
	grandNode := importReport(grand, "adstrike", `{"schema_version":"2.0","findings":[]}`)
	parentNode := importReport(parent, "yeepforge", `{"tool":"YeepForge","findings":[]}`)
	for _, tc := range []struct {
		name    string
		task    *db.Task
		node    *db.Node
		allowed bool
	}{
		{"parent_ref_grants_nothing", parentOnly, parentNode, false},
		{"explicit_direct_source", direct, parentNode, true},
		{"no_transitive_source", direct, grandNode, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tsx := NewToolSet(pg.Exploration(tc.task.ExplorationID), "worker")
			provider := &plannerCatalogProvider{replies: [][]llm.ContentBlock{{
				{Type: llm.BlockToolUse, ID: "source_detail", Name: "node_detail",
					Input: json.RawMessage(fmt.Sprintf(`{"id":%d}`, tc.node.ID))},
			}}}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			if _, _, err := captureRun(ctx, agentcore.Options{Provider: provider,
				Tools: []actool.CoreTool{tsx.NodeDetailTool()}, MaxTurns: 3, NonStreaming: true}, "CONTEXT_INPUT", nil); err != nil {
				t.Fatal(err)
			}
			if len(provider.requests) != 2 {
				t.Fatal("node detail did not reach actual provider")
			}
			results := 0
			for _, msg := range provider.requests[1].Messages {
				for _, block := range msg.Content {
					if block.Type != llm.BlockToolResult || block.ToolUseID != "source_detail" {
						continue
					}
					results++
					if block.IsError != !tc.allowed {
						t.Fatal("source boundary bypassed")
					}
					if tc.allowed {
						var node db.Node
						if len(block.Content) != 1 || json.Unmarshal([]byte(block.Content[0].Text), &node) != nil ||
							node.ID != tc.node.ID || !node.Inherited || node.SourceTaskID != parent.ID {
							t.Fatal("direct report provenance lost")
						}
						var report assessment.Report
						if json.Unmarshal(node.Payload, &report) != nil || report.AssessmentID == "" || report.Import.ValidationStatus != "producer_reported" {
							t.Fatal("sanitized report identifiers lost")
						}
					}
				}
			}
			if results != 1 {
				t.Fatal("source tool result missing")
			}
			t.Logf("task=%d source node=%d allowed=%t provider requests=2", tc.task.ID, tc.node.ID, tc.allowed)
		})
	}
}
