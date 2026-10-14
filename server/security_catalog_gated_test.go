package server

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/locale"
	"github.com/Autumn-27/norma/llm"
)

func TestSecurityCatalogRegisteredDeferred(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		for _, gated := range []bool{false, true} {
			t.Run(fmt.Sprintf("stream=%t/gated=%t", streaming, gated), func(t *testing.T) {
				// Given a departed tagged label now used by a real generic.
				f := newCatalogFixture(t, "")
				f.save(t)
				r := f.call(t, t.Context(), "POST", fmt.Sprintf("/api/mcp/%d/refresh", f.m.ID), nil, true, locale.En)
				if r.Code != 200 {
					t.Fatal(r.Body.String())
				}
				chat, p, _, session := catalogConversation(t, f, []int64{f.m.ID})
				chat.SetNonStreaming(func() bool { return !streaming })
				label := f.m.Name
				name := "mcp__" + label + "__unexpected_operation"
				emitCatalogUse(p, "call_0", name)
				catalogBlockedPrompt(t, chat, session)
				catalogPair(t, p.requests[len(p.requests)-1], name, "call_0", 0)
				f.m.Name += "Away"
				f.save(t)
				generic := *f.m
				generic.ID, generic.Name, generic.ProviderKind = 0, label, ""
				r = f.call(t, t.Context(), "POST", "/api/mcp", generic, true, locale.En)
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
				ids := []int64{saved.ID}
				if gated {
					ids = nil
					dir := filepath.Join(f.s.skillDir, "gate-probe")
					if err := os.Mkdir(dir, 0700); err != nil {
						t.Fatal(err)
					}
					body := "---\nname: gate-probe\ndescription: Fixture\nmcps:\n  - " + label + "\n---\nFixture.\n"
					if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(body), 0600); err != nil {
						t.Fatal(err)
					}
					if err := f.s.m.pg.ToggleSkillVisibility(a.ID, "gate-probe", true); err != nil {
						t.Fatal(err)
					}
				}
				if err := f.s.m.pg.SetAgentVisibilityKind(a.ID, "mcp", ids); err != nil {
					t.Fatal(err)
				}
				_, def, cleanup := agent.AugmentTools(t.Context(), "auto", nil)
				if !def.Callable(name) || gated && def.Unlock.Has(name) {
					cleanup()
					t.Fatal("registry precedence or locked positive control failed")
				}
				cleanup()
				// When called directly without Skill unlock, even with a reused id.
				before := 0
				for _, row := range f.records(t) {
					if row["method"] == "tools/call" {
						before++
					}
				}
				emitCatalogUse(p, "call_0", name)
				catalogPrompt(t, chat, session)
				output := catalogPair(t, p.requests[len(p.requests)-1], name, "call_0", 1)
				if !strings.Contains(output, "FIXTURE_CALL_DISABLED") {
					t.Fatal("generic did not reach executor: " + output)
				}
				calls := 0
				for _, row := range f.records(t) {
					if row["method"] == "tools/call" {
						calls++
					}
				}
				if calls-before != 1 {
					t.Fatalf("actual generic tools/call=%d want 1", calls-before)
				}
				// Then cold resume keeps only the executed occurrence. A parallel
				// Skill load plus direct call also remains executable and retained.
				catalogPrompt(t, chat, session)
				catalogPair(t, p.requests[len(p.requests)-1], name, "call_0", 1)
				if gated {
					p.parallel = []llm.ContentBlock{
						{Type: llm.BlockToolUse, ID: "skill", Name: "Skill", Input: json.RawMessage(`{"name":"gate-probe"}`)},
						{Type: llm.BlockToolUse, ID: "parallel", Name: name, Input: json.RawMessage(`{}`)},
					}
					catalogPrompt(t, chat, session)
					catalogPair(t, p.requests[len(p.requests)-1], name, "parallel", 1)
				}
				var count int
				if err := f.s.m.pg.QueryRow(`SELECT count(*) FROM mcp_catalog_native_uses WHERE session_id=$1`, session).Scan(&count); err != nil || count != 0 {
					t.Fatalf("marks=%d want no new native birth: %v", count, err)
				}
				t.Logf("B9: gated=%t actual tools/call=%d followup=1/1 cold=1/1 tagged occurrence=0/0", gated, calls-before)
			})
		}
	}
}
