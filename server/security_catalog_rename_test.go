package server

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/locale"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

type catalogRenameProvider struct {
	t         *testing.T
	requests  []llm.CompletionRequest
	emit      *llm.ContentBlock
	parallel  []llm.ContentBlock
	tokens    int
	summaries int
}

func (p *catalogRenameProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
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

func (p *catalogRenameProvider) Complete(_ context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.requests = append(p.requests, req)
	if req.Thinking == "disabled" && len(req.Tools) == 0 {
		p.summaries++
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("fixture-summary")}}, "end_turn", llm.Usage{}, nil
	}
	if p.emit != nil {
		use := *p.emit
		p.emit = nil
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
			llm.TextBlock(use.Name), use,
		}}, "tool_use", llm.Usage{InputTokens: p.tokens}, nil
	}
	if len(p.parallel) > 0 {
		uses := p.parallel
		p.parallel = nil
		return llm.Message{Role: llm.RoleAssistant, Content: uses}, "tool_use", llm.Usage{InputTokens: p.tokens}, nil
	}
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("fixture-complete")}}, "end_turn", llm.Usage{InputTokens: p.tokens}, nil
}

func catalogConversation(t *testing.T, f *catalogFixture, ids []int64) (*agent.ChatAgent, *catalogRenameProvider, *transcript.Store, string) {
	t.Helper()
	a, err := f.s.m.pg.GetAgentByKey("auto")
	if err != nil || a == nil {
		t.Fatalf("auto agent: %v", err)
	}
	if err := f.s.m.pg.SetAgentVisibilityKind(a.ID, "mcp", ids); err != nil {
		t.Fatal(err)
	}
	wireAgentAugment(f.s.m.pg, f.s.skillDir, nil)
	agent.ToolResolve = nil
	session := strings.ReplaceAll(t.Name(), "/", "-")
	t.Cleanup(func() {
		if _, err := f.s.m.pg.Exec(`DELETE FROM mcp_catalog_native_uses WHERE session_id=$1`, session); err != nil {
			t.Error(err)
		}
	})
	store := transcript.NewStore(filepath.Join(f.s.skillDir, "transcripts"))
	provider := &catalogRenameProvider{t: t}
	chat := agent.NewChatAgent(provider, "fixture", f.s.skillDir, store, 100000)
	chat.SetNonStreaming(func() bool { return true })
	return chat, provider, store, session
}

func catalogPrompt(t *testing.T, chat *agent.ChatAgent, session string) {
	t.Helper()
	if _, err := chat.Chat(t.Context(), "auto", session, "Continue", 4, time.Minute, false, nil); err != nil {
		t.Fatal(err)
	}
}

func catalogBlockedPrompt(t *testing.T, chat *agent.ChatAgent, session string) {
	t.Helper()
	results := 0
	_, err := chat.Chat(t.Context(), "auto", session, "Continue", 4, time.Minute, false, func(a db.Activity) {
		if a.Kind == "tool_use" || a.Kind == "tool_result" {
			t.Error("blocked response reached tool dispatch")
		}
		if a.Kind == "result" {
			results++
			if !a.IsError || !strings.Contains(a.Detail, "`hook_stopped`") {
				t.Errorf("wrong host terminal classification: %+v", a)
			}
		}
	})
	if err == nil || results != 1 {
		t.Fatalf("blocked response err=%v results=%d", err, results)
	}
}

func catalogPair(t *testing.T, req llm.CompletionRequest, name, id string, want int) string {
	t.Helper()
	uses, results := 0, 0
	var output string
	for _, msg := range req.Messages {
		for _, block := range msg.Content {
			if block.Type == llm.BlockToolUse && block.ID == id {
				uses++
				if block.Name != name || string(block.Input) != `{}` {
					t.Fatalf("use changed: %+v", block)
				}
			}
			if block.Type == llm.BlockToolResult && block.ToolUseID == id {
				results++
				for _, text := range block.Content {
					output += text.Text
				}
			}
		}
	}
	if uses != want || results != want {
		t.Fatalf("%s/%s pair=%d/%d want=%d", name, id, uses, results, want)
	}
	return output
}

func TestSecurityCatalogRenameResume(t *testing.T) {
	for _, birth := range []string{"before", "after"} {
		for _, mutation := range []string{"failure", "replacement", "rename"} {
			t.Run(birth+"-"+mutation, func(t *testing.T) {
				// Given a real refreshed row and a model-emitted use, never a seeded mark.
				f := newCatalogFixture(t, "")
				f.save(t)
				refresh := func(want int) {
					t.Helper()
					rec := f.call(t, t.Context(), "POST", fmt.Sprintf("/api/mcp/%d/refresh", f.m.ID), nil, true, locale.En)
					if rec.Code != want {
						t.Fatalf("refresh HTTP %d want %d: %s", rec.Code, want, rec.Body.String())
					}
				}
				refresh(200)
				chat, p, store, session := catalogConversation(t, f, []int64{f.m.ID})
				if birth == "after" {
					f.m.Name += "Renamed"
					f.save(t)
				}
				native := "mcp__" + f.m.Name + "__unexpected_operation"
				p.emit = &llm.ContentBlock{Type: llm.BlockToolUse, ID: "native", Name: native, Input: json.RawMessage(`{}`)}
				catalogBlockedPrompt(t, chat, session)
				catalogPair(t, p.requests[len(p.requests)-1], native, "native", 0)
				records, err := store.Load(store.MainPath(session))
				if err != nil {
					t.Fatal(err)
				}
				born, _ := transcript.Messages(records)
				catalogPair(t, llm.CompletionRequest{Messages: born}, native, "native", 0)
				var marks int
				if err := f.s.m.pg.QueryRow(`SELECT count(*) FROM mcp_catalog_native_uses WHERE session_id=$1`, session).Scan(&marks); err != nil || marks != 0 {
					t.Fatalf("suppressed birth created marks=%d: %v", marks, err)
				}
				if birth == "before" {
					f.m.Name += "Renamed"
					f.save(t)
					catalogPrompt(t, chat, session)
					catalogPair(t, p.requests[len(p.requests)-1], native, "native", 0)
				}
				// When the cache is lost/replaced AFTER this alias was actually emitted.
				switch mutation {
				case "failure":
					held := f.m.Command + ".held"
					if err := os.Rename(f.m.Command, held); err != nil {
						t.Fatal(err)
					}
					refresh(502)
					if err := os.Rename(held, f.m.Command); err != nil {
						t.Fatal(err)
					}
				case "replacement":
					var env map[string]string
					if err := json.Unmarshal(f.m.Env, &env); err != nil {
						t.Fatal(err)
					}
					env["TASK3_FIXTURE_MUTATION"] = "replacement"
					var err error
					f.m.Env, err = json.Marshal(env)
					if err != nil {
						t.Fatal(err)
					}
					f.save(t)
					refresh(200)
				case "rename":
					f.m.Name += "Again"
					f.save(t)
				}
				catalogPrompt(t, chat, session)
				catalogPair(t, p.requests[len(p.requests)-1], native, "native", 0)
				f.m.Name += "Final"
				f.save(t)
				catalogPrompt(t, chat, session)
				catalogPair(t, p.requests[len(p.requests)-1], native, "native", 0)
				// Then every subsequent resumed pair stays excluded independent of names/cache.
				t.Logf("birth=%s mutation=%s: no new mark; native pair=0/0 throughout", birth, mutation)
			})
		}
	}
}

func TestSecurityCatalogGenericLabelReuse(t *testing.T) {
	for _, reused := range []bool{false, true} {
		t.Run(fmt.Sprint(reused), func(t *testing.T) {
			// Given a tagged row, then a real generic registration with fresh/departed label.
			f := newCatalogFixture(t, "")
			f.save(t)
			rec := f.call(t, t.Context(), "POST", fmt.Sprintf("/api/mcp/%d/refresh", f.m.ID), nil, true, locale.En)
			if rec.Code != 200 {
				t.Fatal(rec.Body.String())
			}
			departed := f.m.Name
			chat, p, _, session := catalogConversation(t, f, []int64{f.m.ID})
			old := "mcp__" + departed + "__unexpected_operation"
			p.emit = &llm.ContentBlock{Type: llm.BlockToolUse, ID: "tagged", Name: old, Input: json.RawMessage(`{}`)}
			catalogBlockedPrompt(t, chat, session)
			catalogPair(t, p.requests[len(p.requests)-1], old, "tagged", 0)
			f.m.Name += "Renamed"
			f.save(t)
			label := departed
			if !reused {
				label += "Fresh"
			}
			generic := *f.m
			generic.ID, generic.Name, generic.ProviderKind = 0, label, ""
			rec = f.call(t, t.Context(), "POST", "/api/mcp", generic, true, locale.En)
			var saved struct{ ID int64 }
			if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &saved) != nil {
				t.Fatalf("generic save: %s", rec.Body.String())
			}
			t.Cleanup(func() {
				if err := f.s.m.pg.DeleteMCP(saved.ID); err != nil {
					t.Error(err)
				}
			})
			a, err := f.s.m.pg.GetAgentByKey("auto")
			if err != nil || a == nil {
				t.Fatalf("auto agent: %v", err)
			}
			if err := f.s.m.pg.SetAgentVisibilityKind(a.ID, "mcp", []int64{f.m.ID, saved.ID}); err != nil {
				t.Fatal(err)
			}
			name := "mcp__" + label + "__unexpected_operation"
			// When the actual SDK calls the newly registered generic tool.
			p.emit = &llm.ContentBlock{Type: llm.BlockToolUse, ID: "generic", Name: name, Input: json.RawMessage(`{}`)}
			catalogPrompt(t, chat, session)
			output := catalogPair(t, p.requests[len(p.requests)-1], name, "generic", 1)
			if !strings.Contains(output, "FIXTURE_CALL_DISABLED") {
				t.Fatalf("generic tool did not reach the fixture: %s", output)
			}
			catalogPair(t, p.requests[len(p.requests)-1], old, "tagged", 0)
			generic.ID, generic.Name = saved.ID, label+"GenericRenamed"
			rec = f.call(t, t.Context(), "POST", "/api/mcp", generic, true, locale.En)
			if rec.Code != 200 {
				t.Fatal(rec.Body.String())
			}
			catalogPrompt(t, chat, session)
			catalogPair(t, p.requests[len(p.requests)-1], name, "generic", 1)
			// Then same-name births differ by identity; generic rename preserves its pair.
			var count int
			if err := f.s.m.pg.QueryRow(`SELECT count(*) FROM mcp_catalog_native_uses WHERE session_id=$1 AND tool_use_id='generic'`, session).Scan(&count); err != nil || count != 0 {
				t.Fatalf("generic was marked: %d %v", count, err)
			}
			t.Logf("reused=%t: generic fixture reached; generic pair=1/1; tagged pair=0/0", reused)
		})
	}
}
