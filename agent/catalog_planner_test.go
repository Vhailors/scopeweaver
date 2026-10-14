package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

type plannerCatalogProvider struct {
	requests  []llm.CompletionRequest
	replies   [][]llm.ContentBlock
	tokens    int
	summaries int
}

func (p *plannerCatalogProvider) Complete(_ context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.requests = append(p.requests, req)
	if req.Thinking == "disabled" && len(req.Tools) == 0 {
		p.summaries++
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("fixture-summary")}}, "end_turn", llm.Usage{}, nil
	}
	blocks, stop := []llm.ContentBlock{llm.TextBlock("fixture-complete")}, "end_turn"
	if len(p.replies) > 0 {
		blocks, p.replies, stop = p.replies[0], p.replies[1:], "tool_use"
	}
	return llm.Message{Role: llm.RoleAssistant, Content: blocks}, stop, llm.Usage{InputTokens: p.tokens}, nil
}

func (p *plannerCatalogProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		msg, stop, usage, err := p.Complete(ctx, req)
		if err != nil {
			yield(llm.StreamEvent{}, err)
			return
		}
		if !yield(llm.StreamEvent{Type: llm.SEMessageStart, Usage: usage}, nil) {
			return
		}
		for _, block := range msg.Content {
			if block.Type == llm.BlockToolUse {
				if !yield(llm.StreamEvent{Type: llm.SEToolUseStart, ToolID: block.ID, ToolName: block.Name}, nil) ||
					!yield(llm.StreamEvent{Type: llm.SEToolInputJSON, Text: string(block.Input)}, nil) {
					return
				}
			} else if !yield(llm.StreamEvent{Type: llm.SETextDelta, Text: block.Text}, nil) {
				return
			}
		}
		if yield(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: stop}, nil) {
			yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
		}
	}
}

func TestDeferredPlannerWakes(t *testing.T) {
	for _, scenario := range []struct {
		streaming bool
		tagged    bool
	}{{false, true}, {true, true}, {false, false}} {
		t.Run(fmt.Sprintf("stream=%t/tagged=%t", scenario.streaming, scenario.tagged), func(t *testing.T) {
			// Given the real planner, SQL birth ledger and one append-only file,
			// each Plan creates a fresh Session exactly as production does.
			d := testDB(t)
			defer d.Close()
			task, err := d.CreateTaskWithOptions("planner fixture", "local protocol fixture", db.TaskCreateOptions{})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := d.DeleteTask(task.ID); err != nil {
					t.Error(err)
				}
			}()
			session := fmt.Sprintf("exp%d-planner", task.ExplorationID)
			label := fmt.Sprintf("PlannerFixture%d", task.ID)
			name := "mcp__" + label + "__unexpected_operation"
			if scenario.tagged {
				id, err := d.SaveMCP(&db.MCPServer{Name: label, Transport: "stdio", ProviderKind: "yeepforge"})
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := d.DeleteMCP(id); err != nil {
						t.Error(err)
					}
				}()
			}
			defer func() {
				if _, err := d.Exec(`DELETE FROM mcp_catalog_native_uses WHERE session_id=$1`, session); err != nil {
					t.Error(err)
				}
			}()
			augment, resolve := ToolAugment, ToolResolve
			defer func() { ToolAugment, ToolResolve = augment, resolve }()
			ToolResolve = nil
			ToolAugment = func(context.Context, string) ([]actool.CoreTool, DeferredInfo, func()) {
				return nil, DeferredInfo{CatalogUse: d.RecordCatalogNativeUse, CatalogUseIDs: d.CatalogNativeUseIDs}, func() {}
			}
			dir := t.TempDir()
			markerDir := filepath.Join(dir, "tasks", fmt.Sprint(task.ID))
			if err := os.MkdirAll(markerDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(markerDir, "planner-ls-control"), []byte("fixture"), 0o600); err != nil {
				t.Fatal(err)
			}
			store := transcript.NewStore(filepath.Join(dir, "transcripts"))
			provider := &plannerCatalogProvider{}
			planner := NewPlanner(provider, "fixture", dir, store, 100000, 20)
			planner.SetNonStreaming(func() bool { return !scenario.streaming })
			use := func(name, id string) llm.ContentBlock {
				return llm.ContentBlock{Type: llm.BlockToolUse, ID: id, Name: name, Input: json.RawMessage(`{}`)}
			}
			pair := func(wake int, req llm.CompletionRequest, name, id string, want int) {
				t.Helper()
				uses, results, output := 0, 0, ""
				for _, msg := range req.Messages {
					for _, b := range msg.Content {
						if b.Type == llm.BlockToolUse && b.ID == id && b.Name == name {
							uses++
						}
						if b.Type == llm.BlockToolResult && b.ToolUseID == id {
							results++
							for _, c := range b.Content {
								output += c.Text
							}
						}
					}
				}
				if uses != want || results != want {
					t.Errorf("wake %d %s/%s pair=%d/%d want=%d", wake, name, id, uses, results, want)
				}
				if name == "LS" && want == 1 && !strings.Contains(output, "planner-ls-control") {
					t.Errorf("wake %d lost the executed directory listing: %s", wake, output)
				}
				t.Logf("wake=%d name=%s id=%s pair=%d/%d", wake, name, id, uses, results)
			}
			// When five wakes include native/generic ID reuse, real compaction,
			// and a new planner/store object after the fourth wake.
			nativeWant := 0
			if !scenario.tagged {
				nativeWant = 1
			}
			for wake := 1; wake <= 5; wake++ {
				provider.tokens = 0
				switch wake {
				case 1:
					provider.replies = [][]llm.ContentBlock{{use(name, "call_0")}}
				case 2:
					provider.replies = [][]llm.ContentBlock{{use("LS", "call_0")}}
				case 3:
					provider.replies = [][]llm.ContentBlock{{use(name, "call_7")}}
				case 4:
					provider.tokens = 95000
					for i := range 6 {
						provider.replies = append(provider.replies, []llm.ContentBlock{use("LS", fmt.Sprintf("ls%d", i))})
					}
				case 5:
					planner = NewPlanner(provider, "fixture", dir, transcript.NewStore(filepath.Join(dir, "transcripts")), 100000, 20)
					planner.SetNonStreaming(func() bool { return !scenario.streaming })
					provider.replies = [][]llm.ContentBlock{{use("LS", "call_0"), use(name, "call_7")}}
				}
				before := len(provider.requests)
				if _, _, err := planner.Plan(t.Context(), task.ID, d.Assets(), d.Exploration(task.ExplorationID), task.Goal, nil, nil); err != nil {
					t.Fatalf("wake %d failed: %v", wake, err)
				}
				req := provider.requests[len(provider.requests)-1]
				switch wake {
				case 1:
					pair(wake, req, name, "call_0", nativeWant)
				case 2:
					pair(wake, req, "LS", "call_0", 1)
				case 3:
					pair(wake, req, name, "call_7", nativeWant)
				case 4:
					if provider.summaries == 0 {
						t.Fatal("wake 4 did not compact")
					}
					for _, req := range provider.requests[before:] {
						pair(wake, req, name, "call_7", 0)
					}
				case 5:
					pair(wake, req, "LS", "call_0", 1)
					pair(wake, req, name, "call_7", nativeWant)
				}
			}
			// Then the raw file contains five independent writer roots and its
			// UUIDs still distinguish each wake, including the restart.
			records, err := store.Load(store.MainPath(session))
			if err != nil {
				t.Fatal(err)
			}
			roots := 0
			for _, rec := range records {
				if rec.ParentUUID == "" {
					roots++
				}
			}
			if roots != 5 {
				t.Fatalf("fresh planner roots=%d want=5", roots)
			}
			t.Logf("summaries=%d writer_roots=%d restart_wake=5", provider.summaries, roots)
		})
	}
}
