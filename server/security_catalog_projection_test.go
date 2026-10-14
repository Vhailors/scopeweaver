package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/locale"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

func TestSecurityCatalogProjectionOccurrences(t *testing.T) {
	for _, noa := range []bool{false, true} {
		t.Run(fmt.Sprintf("noa=%t", noa), func(t *testing.T) {
			// Given two byte-identical calls, the first tagged and the second
			// executable, and a separate built-in positive control.
			f := newCatalogFixture(t, "")
			f.save(t)
			chat, p, store, session := catalogConversation(t, f, []int64{f.m.ID})
			chat.SetNoaEnabled(func() bool { return noa })
			name := "mcp__" + f.m.Name + "__unexpected_operation"
			label := f.m.Name
			p.parallel = []llm.ContentBlock{
				{Type: llm.BlockToolUse, ID: "call_0", Name: name, Input: json.RawMessage(`{}`)},
				{Type: llm.BlockToolUse, ID: "positive", Name: "LS", Input: json.RawMessage(`{}`)},
			}
			catalogPrompt(t, chat, session)
			catalogPair(t, p.requests[len(p.requests)-1], name, "call_0", 0)
			catalogPair(t, p.requests[len(p.requests)-1], "LS", "positive", 1)
			f.m.Name += "Away"
			f.save(t)
			generic := *f.m
			generic.ID, generic.Name, generic.ProviderKind = 0, label, ""
			r := f.call(t, t.Context(), "POST", "/api/mcp", generic, true, locale.En)
			var saved struct{ ID int64 }
			if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &saved) != nil {
				t.Fatal(r.Body.String())
			}
			t.Cleanup(func() {
				if err := f.s.m.pg.DeleteMCP(saved.ID); err != nil {
					t.Error(err)
				}
			})
			a, err := f.s.m.pg.GetAgentByKey("auto")
			if err != nil {
				t.Fatal(err)
			}
			if err := f.s.m.pg.SetAgentVisibilityKind(a.ID, "mcp", []int64{saved.ID}); err != nil {
				t.Fatal(err)
			}
			// When the second occurrence is in a recent tail while the first is
			// in a summarizer head, content equality cannot choose their origin.
			for range 5 {
				catalogPrompt(t, chat, session)
			}
			emitCatalogUse(p, "call_0", name)
			catalogPrompt(t, chat, session)
			if output := catalogPair(t, p.requests[len(p.requests)-1], name, "call_0", 1); !strings.Contains(output, "FIXTURE_CALL_DISABLED") {
				t.Fatal(output)
			}
			if !noa {
				records, err := store.Load(store.MainPath(session))
				if err != nil {
					t.Fatal(err)
				}
				writer := store.ResumeWriter(session, transcript.LastUUID(records))
				writer.RecordMessage(llm.UserText(strings.Repeat("padding ", 50000)), llm.Usage{})
				if err := writer.Err(); err != nil {
					t.Fatal(err)
				}
			}
			start := len(p.requests)
			catalogPrompt(t, chat, session)
			for _, req := range p.requests[start:] {
				if req.Thinking == "disabled" && len(req.Tools) == 0 {
					catalogPair(t, req, name, "call_0", 0)
				} else {
					catalogPair(t, req, name, "call_0", 1)
				}
			}
			if !noa && p.summaries == 0 {
				t.Fatal("summarizer head was not exercised")
			}
			// Then another cold resume preserves execution and the marked birth.
			catalogPrompt(t, chat, session)
			catalogPair(t, p.requests[len(p.requests)-1], name, "call_0", 1)
			t.Logf("projection noa=%t summaries=%d tagged head=0/0 executed tail=1/1", noa, p.summaries)
		})
	}
}

func TestSecurityCatalogNonPersistedOccurrences(t *testing.T) {
	// Given the same real registry/database without a transcript store.
	f := newCatalogFixture(t, "")
	f.save(t)
	_, p, _, session := catalogConversation(t, f, []int64{f.m.ID})
	chat := agent.NewChatAgent(p, "fixture", f.s.skillDir, nil, 100000)
	chat.SetNonStreaming(func() bool { return true })
	name := "mcp__" + f.m.Name + "__unexpected_operation"
	p.parallel = []llm.ContentBlock{
		{Type: llm.BlockToolUse, ID: "native", Name: name, Input: json.RawMessage(`{}`)},
		{Type: llm.BlockToolUse, ID: "positive", Name: "LS", Input: json.RawMessage(`{}`)},
	}
	// When the SDK performs the follow-up request within this unpersisted run.
	catalogPrompt(t, chat, session)
	// Then it filters the tagged occurrence and keeps the executed positive.
	catalogPair(t, p.requests[len(p.requests)-1], name, "native", 0)
	catalogPair(t, p.requests[len(p.requests)-1], "LS", "positive", 1)
}
