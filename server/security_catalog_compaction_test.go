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
	"github.com/Autumn-27/norma/transcript"
)

func TestSecurityCatalogCompactionResume(t *testing.T) {
	// Given real Skill execution and native emission with durable birth metadata.
	f := newCatalogFixture(t, "")
	f.save(t)
	rec := f.call(t, t.Context(), "POST", fmt.Sprintf("/api/mcp/%d/refresh", f.m.ID), nil, true, locale.En)
	if rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	chat, p, store, session := catalogConversation(t, f, []int64{f.m.ID})
	dir := filepath.Join(f.s.skillDir, "catalog-probe")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf("---\nname: catalog-probe\ndescription: Fixture\nmcps:\n  - %s\n---\nFixture.\n", f.m.Name)
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	a, err := f.s.m.pg.GetAgentByKey("auto")
	if err != nil || a == nil {
		t.Fatalf("auto: %v", err)
	}
	if err := f.s.m.pg.ToggleSkillVisibility(a.ID, "catalog-probe", true); err != nil {
		t.Fatal(err)
	}
	p.emit = &llm.ContentBlock{Type: llm.BlockToolUse, ID: "skill", Name: "Skill", Input: json.RawMessage(`{"name":"catalog-probe"}`)}
	catalogPrompt(t, chat, session)
	native := "mcp__" + f.m.Name + "__unexpected_operation"
	p.emit = &llm.ContentBlock{Type: llm.BlockToolUse, ID: "native", Name: native, Input: json.RawMessage(`{}`)}
	catalogPrompt(t, chat, session)
	catalogPair(t, p.requests[len(p.requests)-1], native, "native", 0)
	original, err := store.Load(store.MainPath(session))
	if err != nil {
		t.Fatal(err)
	}
	// When real token-budget compaction runs, then its archived births materialize.
	padding := store.ResumeWriter(session, transcript.LastUUID(original))
	padding.RecordMessage(llm.UserText(strings.Repeat("padding ", 50000)), llm.Usage{})
	if err := padding.Err(); err != nil {
		t.Fatal(err)
	}
	for range 8 {
		catalogPrompt(t, chat, session)
	}
	if p.summaries == 0 {
		t.Fatal("no actual SDK summarizer request")
	}
	compacted, err := store.Load(store.MainPath(session))
	if err != nil {
		t.Fatal(err)
	}
	boundary := false
	for _, record := range compacted {
		boundary = boundary || record.Type == "boundary"
	}
	if !boundary {
		t.Fatal("no durable compaction boundary")
	}
	p.tokens = 0
	for _, record := range original {
		if record.Message != nil {
			// Materialization preserves archive identity, not just provider ids.
			if err := store.Append(store.MainPath(session), record); err != nil {
				t.Fatal(err)
			}
		}
	}
	old := f.m.Name
	f.m.Name += "Renamed"
	f.save(t)
	catalogPrompt(t, chat, session)
	positions, err := f.s.m.pg.CatalogNativeUseIDs(t.Context(), session)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("persisted birth positions: %v", positions)
	finalRecords, err := store.Load(store.MainPath(session))
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range finalRecords {
		if record.Message != nil && len(record.Message.ToolUses()) > 0 {
			t.Logf("record uuid=%s parent=%s uses=%v", record.UUID, record.ParentUUID, record.Message.ToolUses())
		}
	}
	catalogPair(t, p.requests[len(p.requests)-1], native, "native", 0)
	// Then post-compaction/Skill resume cannot restore tagged capabilities.
	for _, req := range p.requests {
		catalogPair(t, req, native, "native", 0)
		for _, schema := range req.Tools {
			if schema.Name == native {
				t.Fatal("native schema restored")
			}
		}
	}
	// Given a generic taking the departed label after real compaction.
	generic := *f.m
	generic.ID, generic.Name, generic.ProviderKind = 0, old, ""
	rec = f.call(t, t.Context(), "POST", "/api/mcp", generic, true, locale.En)
	var saved struct{ ID int64 }
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &saved) != nil {
		t.Fatal(rec.Body.String())
	}
	t.Cleanup(func() {
		if err := f.s.m.pg.DeleteMCP(saved.ID); err != nil {
			t.Error(err)
		}
	})
	if err := f.s.m.pg.SetAgentVisibilityKind(a.ID, "mcp", []int64{f.m.ID, saved.ID}); err != nil {
		t.Fatal(err)
	}
	// When the same name and provider call id are emitted by the generic.
	emitCatalogUse(p, "native", native)
	catalogPrompt(t, chat, session)
	if output := catalogPair(t, p.requests[len(p.requests)-1], native, "native", 1); !strings.Contains(output, "FIXTURE_CALL_DISABLED") {
		t.Fatal("post-compaction generic did not execute: " + output)
	}
	for range 3 {
		catalogPrompt(t, chat, session)
		catalogPair(t, p.requests[len(p.requests)-1], native, "native", 1)
	}
	_, def, cleanup := agent.AugmentTools(t.Context(), "auto", nil)
	defer cleanup()
	def.UnlockSkill("catalog-probe")
	currentNative := "mcp__" + f.m.Name + "__unexpected_operation"
	if def.Unlock.Has(currentNative) || !def.Unlock.Has(native) {
		t.Fatal("resumed Skill restored native names or unlocks")
	}
	t.Logf("actual summaries=%d; durable boundary; re-materialized native pair=0/0; duplicate-id generic pair=1/1; tagged Skill unlock=false", p.summaries)
}
