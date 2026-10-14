package server

import (
	"fmt"
	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
	"path/filepath"
	"slices"
	"testing"
)

func TestSecuritySkillContextProviderRequests(t *testing.T) {
	f := securityContextFixture(t)
	pg := f.s.m.pg
	oldPrompt := agent.PromptOverride
	t.Cleanup(func() { agent.PromptOverride = oldPrompt })
	agent.PromptOverride = func(key string) (string, bool) {
		a, err := pg.GetAgentByKey(key)
		if err != nil || a == nil {
			return "", false
		}
		body, err := pg.CurrentPrompt(a.ID)
		return body, err == nil && body != ""
	}
	names := []string{"yeepforge", "adstrike", "confirmesc"}
	for _, streaming := range []bool{false, true} {
		for i, key := range catalogHelperAgents {
			t.Run(fmt.Sprintf("%s/stream=%t", key, streaming), func(t *testing.T) {
				a, err := pg.GetAgentByKey(key)
				if err != nil || a == nil {
					t.Fatalf("agent: %v", err)
				}
				custom := "CUSTOM_CONTEXT_" + key
				if _, err := pg.SavePrompt(a.ID, custom, "fixture", "operator"); err != nil {
					t.Fatal(err)
				}
				seedPrompts(pg)
				task, err := pg.CreateTaskWithOptions("context fixture", "CONTEXT_GOAL", db.TaskCreateOptions{})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := pg.DeleteTask(task.ID); err != nil {
						t.Error(err)
					}
					if err := pg.SetAgentSkillVisibility(a.ID, nil); err != nil {
						t.Error(err)
					}
				})
				ts := pg.Exploration(task.ExplorationID)
				id, err := ts.AddIntent(map[string]any{"summary": "CONTEXT_INTENT"}, 1, nil, "fixture")
				if err != nil {
					t.Fatal(err)
				}
				intent, err := ts.GetNode(id)
				if err != nil {
					t.Fatal(err)
				}
				if err := pg.SetAgentVisibilityKind(a.ID, "mcp", []int64{f.m.ID}); err != nil {
					t.Fatal(err)
				}
				if err := pg.SetBool(db.SettingSecurityReportsEnabled, true); err != nil {
					t.Fatal(err)
				}
				if err := pg.SetAgentSkillVisibility(a.ID, names); err != nil {
					t.Fatal(err)
				}
				dir := t.TempDir()
				store := transcript.NewStore(filepath.Join(dir, "transcripts"))
				loaded := names[i%len(names)]
				provider := &securityContextProvider{load: loaded}
				runSecurityContextRole(t, pg, key, task, intent, provider, dir, store, streaming)
				if len(provider.requests) < 2 {
					t.Fatal("real Skill dispatch did not complete")
				}
				for _, req := range provider.requests {
					assertSecurityContextRequest(t, req, names, true, custom)
				}
				last := provider.requests[len(provider.requests)-1]
				results := 0
				for _, msg := range last.Messages {
					for _, block := range msg.Content {
						if block.Type == llm.BlockToolResult && block.ToolUseID == "context_skill" {
							if block.IsError {
								t.Fatal("visible supplied skill failed to load")
							}
							results++
						}
					}
				}
				if results != 1 {
					t.Fatal("Skill tool result not captured")
				}
				// Reconstruct the real role and registry from a persisted transcript.
				want := slices.DeleteFunc(slices.Clone(names), func(n string) bool { return n == loaded })
				if err := pg.SetAgentSkillVisibility(a.ID, want); err != nil {
					t.Fatal(err)
				}
				provider.requests = nil
				runSecurityContextRole(t, pg, key, task, intent, provider, dir, store, streaming)
				if len(provider.requests) == 0 {
					t.Fatal("resume did not reach provider")
				}
				for _, req := range provider.requests {
					assertSecurityContextRequest(t, req, want, true, custom)
				}
				results = 0
				for _, msg := range provider.requests[0].Messages {
					for _, block := range msg.Content {
						if block.Type == llm.BlockToolResult && block.ToolUseID == "context_skill" {
							results++
						}
					}
				}
				wantHistory := 1
				if key == "planner" {
					// Plan creates a fresh round, not a resumed Session. Its
					// append-only history still preserves the generic Skill pair.
					wantHistory = 0
					records, err := store.Load(store.MainPath(fmt.Sprintf("exp%d-planner", task.ExplorationID)))
					if err != nil {
						t.Fatal(err)
					}
					messages, _ := transcript.Messages(records)
					persisted := 0
					for _, msg := range messages {
						for _, block := range msg.Content {
							if block.Type == llm.BlockToolResult && block.ToolUseID == "context_skill" {
								persisted++
							}
						}
					}
					if persisted != 1 {
						t.Fatal("planner lost persisted generic Skill history")
					}
				}
				if results != wantHistory {
					t.Fatal("generic Skill history lost on resume")
				}
				// Revoke the helper independently: report skills remain visible.
				if err := pg.RemoveAgentFromTool(key, "security_catalog"); err != nil {
					t.Fatal(err)
				}
				provider.requests = nil
				runSecurityContextRole(t, pg, key, task, intent, provider, dir, store, streaming)
				for _, req := range provider.requests {
					assertSecurityContextRequest(t, req, want, false, custom)
				}
				if err := pg.AddAgentToToolBinding(key, []string{"security_catalog"}); err != nil {
					t.Fatal(err)
				}
				if err := pg.SetBool(db.SettingSecurityReportsEnabled, false); err != nil {
					t.Fatal(err)
				}
				provider.requests = nil
				runSecurityContextRole(t, pg, key, task, intent, provider, dir, store, streaming)
				for _, req := range provider.requests {
					assertSecurityContextRequest(t, req, nil, true, custom)
				}
				stored, err := pg.CurrentPrompt(a.ID)
				if err != nil || stored != custom {
					t.Fatal("context wiring rewrote customized prompt")
				}
				t.Logf("role=%s stream=%t fresh/load/resume-or-wake/revoked-helper/feature-off; visible identifiers only; replayed Skill results=%d", key, streaming, wantHistory)
			})
		}
	}
	if len(f.records(t)) != 0 {
		t.Fatal("role execution launched tagged provider")
	}
	t.Log("actual role entrypoints and provider requests: native schemas=0; tagged starts=0; no engine loop")
}
