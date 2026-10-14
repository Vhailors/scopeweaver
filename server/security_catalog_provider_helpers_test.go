package server

import (
	"context"
	"encoding/json"
	"iter"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

// The fixture provider only loads a Skill or ends a turn. No runtime work,
// network tools, spawned tasks, or engine loops can be requested by it.
type securityContextProvider struct {
	requests []llm.CompletionRequest
	load     string
}

func (p *securityContextProvider) Complete(_ context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.requests = append(p.requests, req)
	if p.load != "" {
		raw, _ := json.Marshal(map[string]string{"name": p.load})
		p.load = ""
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
			{Type: llm.BlockToolUse, ID: "context_skill", Name: "Skill", Input: raw},
		}}, "tool_use", llm.Usage{}, nil
	}
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("CONTEXT_DONE")}}, "end_turn", llm.Usage{}, nil
}

func (p *securityContextProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
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

func assertSecurityContextRequest(t *testing.T, req llm.CompletionRequest, want []string, helper bool, custom string) {
	t.Helper()
	var metadata struct {
		Skills []string `json:"skills"`
		Helper string   `json:"catalog_helper"`
	}
	blocks := 0
	for _, segment := range req.System {
		if strings.HasPrefix(segment, "<available-report-skills>\n") {
			body := strings.SplitN(strings.TrimPrefix(segment, "<available-report-skills>\n"), "\n</available-report-skills>", 2)
			if len(body) != 2 || json.Unmarshal([]byte(body[0]), &metadata) != nil {
				t.Fatal("invalid report identifier metadata")
			}
			blocks++
		}
	}
	wantBlocks := 0
	if len(want) > 0 {
		wantBlocks = 1
	}
	if blocks != wantBlocks || !slices.Equal(metadata.Skills, want) {
		t.Fatalf("provider report identifiers=%v blocks=%d want=%v", metadata.Skills, blocks, want)
	}
	wantHelper := ""
	if helper && len(want) > 0 {
		wantHelper = "security_catalog"
	}
	if metadata.Helper != wantHelper {
		t.Fatalf("provider helper identifier=%q want=%q", metadata.Helper, wantHelper)
	}
	if len(req.System) == 0 || !strings.HasPrefix(req.System[0], custom) {
		t.Fatal("customized prompt not preserved in provider request")
	}
	foundHelper := false
	for _, schema := range req.Tools {
		if strings.HasPrefix(schema.Name, "mcp__") {
			t.Fatal("provider received tagged native schema")
		}
		foundHelper = foundHelper || schema.Name == "security_catalog"
	}
	if foundHelper != helper {
		t.Fatalf("provider helper schema=%t want=%t", foundHelper, helper)
	}
}

func runSecurityContextRole(t *testing.T, pg *db.DB, key string, task *db.Task, intent *db.Node,
	provider *securityContextProvider, dir string, store *transcript.Store, streaming bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	ts := pg.Exploration(task.ExplorationID)
	var err error
	switch key {
	case "auto", "pentest":
		c := agent.NewChatAgent(provider, "fixture", dir, store, 100000)
		c.SetNonStreaming(func() bool { return !streaming })
		_, err = c.Chat(ctx, key, "context-"+key, "CONTEXT_INPUT", 5, 0, false, nil)
	case "mainagent":
		m := agent.NewMainAgent(provider, "fixture", dir, store, 100000, 5)
		m.SetNonStreaming(func() bool { return !streaming })
		_, err = m.Chat(ctx, task.ID, 0, nil, ts, task.Goal, "CONTEXT_INPUT", nil, nil, nil, nil, nil)
	case "planner":
		p := agent.NewPlanner(provider, "fixture", dir, store, 100000, 5)
		p.SetNonStreaming(func() bool { return !streaming })
		_, _, err = p.Plan(ctx, task.ID, nil, ts, task.Goal, nil, nil)
	case "worker":
		w := agent.NewWorker(provider, "fixture", dir, store, 100000, 5)
		w.SetNonStreaming(func() bool { return !streaming })
		_, _, err = w.Execute(ctx, "fixture-worker", task.ID, nil, ts, intent, nil, nil, nil, nil)
	default:
		t.Fatalf("unhandled role %s", key)
	}
	if err != nil {
		t.Fatal(err)
	}
}
