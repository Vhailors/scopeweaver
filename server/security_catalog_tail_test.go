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

func TestSecurityCatalogEditedTail(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		for _, micro := range []bool{false, true} {
			t.Run(fmt.Sprintf("stream=%t/micro=%t", streaming, micro), func(t *testing.T) {
				// Given a real catalog and enough old messages to summarize a head,
				// with the tagged use in the preserved tail, not the summarized head.
				f := newCatalogFixture(t, "")
				f.save(t)
				r := f.call(t, t.Context(), "POST", fmt.Sprintf("/api/mcp/%d/refresh", f.m.ID), nil, true, locale.En)
				if r.Code != 200 {
					t.Fatal(r.Body.String())
				}
				chat, p, store, session := catalogConversation(t, f, []int64{f.m.ID})
				chat.SetNonStreaming(func() bool { return !streaming })
				for range 3 {
					catalogPrompt(t, chat, session)
				}
				native := "mcp__" + f.m.Name + "__unexpected_operation"
				if micro {
					for i := range 6 {
						p.parallel = append(p.parallel, llm.ContentBlock{
							Type: llm.BlockToolUse, ID: fmt.Sprintf("read%d", i), Name: "Read",
							Input: json.RawMessage(`{"file_path":"nonexistent"}`),
						})
					}
				}
				p.parallel = append(p.parallel,
					llm.ContentBlock{Type: llm.BlockToolUse, ID: "native", Name: native, Input: json.RawMessage(`{}`)},
					llm.ContentBlock{Type: llm.BlockToolUse, ID: "control", Name: "LS", Input: json.RawMessage(`{}`)})
				catalogPrompt(t, chat, session)
				catalogPair(t, p.requests[len(p.requests)-1], native, "native", 0)
				catalogPair(t, p.requests[len(p.requests)-1], "LS", "control", 1)
				records, err := store.Load(store.MainPath(session))
				if err != nil {
					t.Fatal(err)
				}
				raw, _ := transcript.Messages(records)
				catalogPair(t, llm.CompletionRequest{Messages: raw}, native, "native", 0)
				writer := store.ResumeWriter(session, transcript.LastUUID(records))
				writer.RecordMessage(llm.UserText(strings.Repeat("padding ", 50000)), llm.Usage{})
				if err := writer.Err(); err != nil {
					t.Fatal(err)
				}
				// When MicroCompact edits a Read result and AutoCompact copies the
				// tail, the structural pair is excluded without comparing bodies.
				catalogPrompt(t, chat, session)
				if p.summaries == 0 {
					t.Fatal("AutoCompact did not run")
				}
				post := p.requests[len(p.requests)-1]
				catalogPair(t, post, native, "native", 0)
				catalogPair(t, post, "LS", "control", 1)
				cleared := 0
				for _, msg := range post.Messages {
					for _, b := range msg.Content {
						if b.Type == llm.BlockToolResult && b.ToolUseID == "read0" &&
							len(b.Content) == 1 && b.Content[0].Text == "[Old tool result content cleared]" {
							cleared++
						}
					}
				}
				if micro && cleared != 1 {
					t.Fatalf("MicroCompact evidence: cleared Read results=%d", cleared)
				}
				// Then a different ChatAgent cold-resumes the durable copy. Both the
				// positive LS pair and the exclusion must survive, in both modes.
				cold := agent.NewChatAgent(p, "fixture", f.s.skillDir, transcript.NewStore(f.s.skillDir+"/transcripts"), 100000)
				cold.SetNonStreaming(func() bool { return !streaming })
				catalogPrompt(t, cold, session)
				catalogPair(t, p.requests[len(p.requests)-1], native, "native", 0)
				catalogPair(t, p.requests[len(p.requests)-1], "LS", "control", 1)
				t.Logf("B8: summaries=%d cleared=%d post=0/0 cold=0/0 LS=1/1", p.summaries, cleared)
			})
		}
	}
}
