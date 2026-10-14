package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"iter"
	"testing"

	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

func deferredHistory(t *testing.T, messages []llm.Message) (*transcript.Store, context.Context, string) {
	t.Helper()
	store := transcript.NewStore(t.TempDir())
	writer := store.NewWriter("history", "")
	writer.RecordMessage(llm.UserText("history-start"), llm.Usage{})
	records, err := store.Load(store.MainPath("history"))
	if err != nil {
		t.Fatal(err)
	}
	parent := transcript.LastUUID(records)
	for _, msg := range messages {
		writer.RecordMessage(msg, llm.Usage{})
	}
	if err := writer.Err(); err != nil {
		t.Fatal(err)
	}
	return store, transcript.WithSessionID(t.Context(), "history"), parent
}

type deferredRequestProvider struct {
	requests []llm.CompletionRequest
}

func (p *deferredRequestProvider) Complete(_ context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.requests = append(p.requests, req)
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("fixture")}}, "end_turn", llm.Usage{}, nil
}

func (p *deferredRequestProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(y func(llm.StreamEvent, error) bool) {
		msg, stop, _, err := p.Complete(ctx, req)
		if err != nil {
			y(llm.StreamEvent{}, err)
			return
		}
		if !y(llm.StreamEvent{Type: llm.SETextDelta, Text: msg.Text()}, nil) {
			return
		}
		if !y(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: stop}, nil) {
			return
		}
		y(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
	}
}

func TestDeferredProviderFiltersMaterializedHistory(t *testing.T) {
	// Given a final request materialized from archived/compacted history.
	source := llm.CompletionRequest{
		System: []string{"mcp__old label__unexpected_operation mcp__generic server__allowed"},
		Tools:  []llm.ToolSchema{{Name: "mcp__old label__unexpected_operation"}, {Name: "mcp__generic server__allowed"}},
		Messages: []llm.Message{
			{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
				{Type: llm.BlockThinking, Thinking: "mcp__old label__unexpected_operation", Signature: "signed"},
				{Type: llm.BlockThinking, Thinking: "fixture", Signature: "preserved"},
				{Type: llm.BlockToolUse, ID: "old", Name: "mcp__old label__unexpected_operation", Input: json.RawMessage(`{}`)},
			}},
			{Role: llm.RoleUser, Content: []llm.ContentBlock{
				llm.ToolResultText("old", "mcp__old label__unexpected_operation mcp__generic server__allowed", false),
			}},
		},
	}
	before, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	probe := &deferredRequestProvider{}
	store, ctx, parent := deferredHistory(t, source.Messages)
	provider := deferredProvider(probe, DeferredInfo{
		CatalogNativeNames: []string{"mcp__old label__unexpected_operation"},
		CatalogUseIDs: func(context.Context, string) (map[string]map[string]bool, error) {
			return map[string]map[string]bool{parent: {"old": true}}, nil
		},
	}, store)
	// When both non-streaming and streaming calls cross the shared last boundary.
	if _, _, _, err := provider.Complete(ctx, source); err != nil {
		t.Fatal(err)
	}
	for _, err := range provider.Stream(ctx, source) {
		if err != nil {
			t.Fatal(err)
		}
	}
	// Then exact native definitions/use/result pairs are excluded. Free text,
	// signatures, generic tools and the source archive remain byte-identical.
	if len(probe.requests) != 2 {
		t.Fatalf("actual provider calls=%d want 2", len(probe.requests))
	}
	for _, req := range probe.requests {
		raw, err := json.Marshal(req)
		if err != nil || len(req.Tools) != 1 || req.Tools[0].Name != "mcp__generic server__allowed" ||
			len(req.Messages) != 1 || len(req.Messages[0].Content) != 2 ||
			req.Messages[0].Content[0].Signature != "signed" ||
			req.Messages[0].Content[1].Signature != "preserved" ||
			req.System[0] != source.System[0] {
			t.Fatalf("structural filter changed content or retained a native capability: %s %v", raw, err)
		}
	}
	after, err := json.Marshal(source)
	if err != nil || string(before) != string(after) {
		t.Fatalf("provider filter mutated original history: %s %v", after, err)
	}
}

func TestDeferredProviderPreservesOrdinaryContent(t *testing.T) {
	// Given the reviewer's escaped Bash input, wide free-text mention, signed
	// thinking, and generic tool output, even mentioning an exact blocked name.
	source := llm.CompletionRequest{
		System: []string{`mcp__free text "with spaces" until __ later`},
		Tools:  []llm.ToolSchema{{Name: "Bash"}},
		Messages: []llm.Message{
			llm.UserText(`mcp__free text "with spaces" until __ later`),
			{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
				llm.TextBlock(`mcp__catalog__blocked stays in ordinary text`),
				{Type: llm.BlockThinking, Thinking: `mcp__catalog__blocked "signed"`, Signature: "signed-byte-for-byte"},
				{Type: llm.BlockToolUse, ID: "bash", Name: "Bash",
					Input: json.RawMessage(`{"command":"grep \"mcp__zz__yy\" /dev/null; echo verify3"}`)},
			}},
			{Role: llm.RoleUser, Content: []llm.ContentBlock{
				llm.ToolResultText("bash", `mcp__free text "with spaces" until __ later`, false),
			}},
		},
	}
	before, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	probe := &deferredRequestProvider{}
	provider := deferredProvider(probe, DeferredInfo{CatalogNativeNames: []string{"mcp__catalog__blocked"}}, nil)
	// When both final provider modes execute twice, including the next turn.
	for range 2 {
		if _, _, _, err := provider.Complete(t.Context(), source); err != nil {
			t.Fatal(err)
		}
		for _, err := range provider.Stream(t.Context(), source) {
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	// Then all requests and source content retain exactly the same bytes.
	if len(probe.requests) != 4 {
		t.Fatalf("provider calls=%d", len(probe.requests))
	}
	for _, req := range append(probe.requests, source) {
		after, err := json.Marshal(req)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("ordinary session corrupted: %s %v", after, err)
		}
		if !json.Valid(req.Messages[1].Content[2].Input) ||
			!bytes.Equal(req.Messages[1].Content[2].Input, source.Messages[1].Content[2].Input) {
			t.Fatal("Bash input is no longer byte-identical valid JSON")
		}
	}
}
