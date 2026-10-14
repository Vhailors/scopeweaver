package server

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"net/http/httptest"
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

type catalogResumeProvider struct {
	t      *testing.T
	calls  int
	native string
}

func (p *catalogResumeProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(y func(llm.StreamEvent, error) bool) { p.t.Fatal("unexpected streaming") }
}

func (p *catalogResumeProvider) Complete(_ context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.calls++
	raw, err := json.Marshal(req)
	if err != nil {
		p.t.Fatal(err)
	}
	for _, tool := range req.Tools {
		if tool.Name == p.native {
			p.t.Fatalf("resumed model request exposed native definition: %s", raw)
		}
	}
	for _, msg := range req.Messages {
		for _, use := range msg.ToolUses() {
			if use.Name == p.native {
				p.t.Fatalf("resumed model request exposed native invocation: %s", raw)
			}
		}
	}
	if !strings.Contains(string(raw), "mcp__old-provider-label__unexpected_operation") {
		p.t.Fatal("historical free text was rewritten")
	}
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("fixture-complete")}}, "end_turn", llm.Usage{}, nil
}

func TestSecurityCatalogPassiveBoundaries(t *testing.T) {
	// Given an enabled launchable tagged row and direct plus skill bindings.
	f := newCatalogFixture(t, "")
	f.save(t) // Regression for the Task 2 verifier's enabled-save gap.
	if err := f.s.m.pg.SaveMCPCatalog(t.Context(), f.m, db.MCPCatalog{Available: true,
		Tools: []db.MCPTool{{Name: "unexpected_operation"}}}); err != nil {
		t.Fatal(err)
	}
	native := "mcp__" + f.m.Name + "__unexpected_operation"
	a, err := f.s.m.pg.GetAgentByKey("auto")
	if err != nil || a == nil {
		t.Fatalf("auto agent: %v", err)
	}
	if err := f.s.m.pg.SetAgentVisibilityKind(a.ID, "mcp", []int64{f.m.ID}); err != nil {
		t.Fatal(err)
	}
	if err := f.s.m.pg.ToggleSkillVisibility(a.ID, "catalog-probe", true); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(f.s.skillDir, "catalog-probe")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	// Synthetic machine-consumed frontmatter, not shipped skill prose.
	skill := fmt.Sprintf("---\nname: catalog-probe\ndescription: Fixture\nmcps:\n  - %s\n---\nFixture.\n", f.m.Name)
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(skill), 0600); err != nil {
		t.Fatal(err)
	}
	wireAgentAugment(f.s.m.pg, f.s.skillDir, nil)
	agent.ToolResolve = nil
	// When save, status, startup discovery, assembly, skill load, and resume run.
	for _, path := range []string{"/api/mcp", fmt.Sprintf("/api/mcp/%d/tools", f.m.ID)} {
		rec := f.call(t, t.Context(), "GET", path, nil, true, locale.En)
		if rec.Code != 200 {
			t.Fatalf("passive status: %d %s", rec.Code, rec.Body.String())
		}
	}
	f.s.discoverEmptyMCPsOnStartup() // exactly the production startup routine, synchronously joined
	tools, def, cleanup := agent.AugmentTools(t.Context(), "auto", nil)
	defer cleanup()
	if len(def.Deferred) != 0 || len(def.GlobalNames) != 0 {
		t.Fatalf("catalog has deferred native names: %+v", def)
	}
	loaded := false
	for _, tool := range tools {
		if tool.Name() != "Skill" {
			t.Fatalf("native tool exposed: %s", tool.Name())
		}
		res, err := tool.Call(t.Context(), json.RawMessage(`{"name":"catalog-probe"}`), nil)
		if err != nil || res.IsError || strings.Contains(res.Flatten(), "unexpected_operation") || strings.Contains(res.Flatten(), "mcp__") {
			t.Fatalf("skill-load exposure: %v %+v", err, res)
		}
		loaded = true
	}
	if !loaded {
		t.Fatal("visible Skill was not actually loaded")
	}
	def.UnlockSkill("catalog-probe")
	if def.Unlock.Has("mcp__" + f.m.Name + "__unexpected_operation") {
		t.Fatal("catalog native tool unlocked")
	}
	store := transcript.NewStore(filepath.Join(f.s.skillDir, "transcripts"))
	writer := store.NewWriter("task3-resume", "")
	writer.RecordMessage(llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
		{Type: llm.BlockToolUse, ID: "prior-skill", Name: "Skill", Input: json.RawMessage(`{"name":"catalog-probe"}`)},
		{Type: llm.BlockToolUse, ID: "prior-native", Name: native, Input: json.RawMessage(`{}`)},
	}}, llm.Usage{})
	if err := f.s.m.pg.RecordCatalogNativeUse(t.Context(), "task3-resume", "", "prior-native", native); err != nil {
		t.Fatal(err)
	}
	writer.RecordMessage(llm.Message{Role: llm.RoleUser, Content: []llm.ContentBlock{
		llm.ToolResultText("prior-skill", "<available-deferred-tools>\nmcp__old-provider-label__unexpected_operation\n</available-deferred-tools>", false),
		llm.ToolResultText("prior-native", "native result", false),
	}}, llm.Usage{})
	if err := writer.Err(); err != nil {
		t.Fatal(err)
	}
	provider := &catalogResumeProvider{t: t, native: native}
	chat := agent.NewChatAgent(provider, "fixture", f.s.skillDir, store, 100000)
	chat.SetNonStreaming(func() bool { return true })
	if _, err := chat.Chat(t.Context(), "auto", "task3-resume", "Continue", 2, time.Minute, false, nil); err != nil {
		t.Fatal(err)
	}
	if provider.calls != 1 {
		t.Fatalf("resume did not reach the scripted provider: calls=%d", provider.calls)
	}
	// Then no process starts, native names, native schemas, or unlocks exist.
	if rows := f.records(t); len(rows) != 0 {
		t.Fatalf("passive path launched fixture: %+v", rows)
	}
	t.Log("save/status/startup/assembly/skill-load/resume starts=0; native/deferred/unlocked=0; tools/call=0; actual resumed model request inspected")
}

func TestSecurityCatalogExplicitRefresh(t *testing.T) {
	// Given an enabled catalog provider and real authenticated management mux.
	f := newCatalogFixture(t, "")
	f.save(t)
	path := fmt.Sprintf("/api/mcp/%d/refresh", f.m.ID)
	if rec := f.call(t, t.Context(), "POST", path, nil, false, locale.En); rec.Code != 401 {
		t.Fatalf("unauthenticated refresh: %d", rec.Code)
	}
	if len(f.records(t)) != 0 {
		t.Fatal("unauthenticated refresh launched a provider")
	}
	// When the operator explicitly refreshes once.
	rec := f.call(t, t.Context(), "POST", path, nil, true, locale.En)
	if rec.Code != 200 {
		t.Fatalf("refresh: %d %s", rec.Code, rec.Body.String())
	}
	var result struct {
		Tools   []db.MCPTool
		Catalog db.MCPCatalogStatus
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	status := result.Catalog
	if len(result.Tools) != 0 || status.Callable || status.Status != "discovered" || status.Provenance != "unverified" ||
		status.ExpectedSourceRevision != f.m.SourceRevision || status.Cache == nil ||
		len(status.Cache.ExecutableSHA256) != 64 || status.Cache.ObservedRevision != "1.0.0" ||
		len(status.Cache.Tools) != 1 || status.Cache.Tools[0].Name != "unexpected_operation" {
		t.Fatalf("catalog/provenance contract: %s", rec.Body.String())
	}
	rows := f.records(t)
	counts := map[string]int{}
	for _, row := range rows {
		counts[fmt.Sprint(row["event"])]++
		if row["method"] != nil {
			counts[fmt.Sprint(row["method"])]++
		}
	}
	// Then exactly one initialize/list/close occurred and never tools/call.
	if counts["start"] != 1 || counts["initialize"] != 1 || counts["tools/list"] != 1 || counts["stop"] != 1 || counts["tools/call"] != 0 {
		t.Fatalf("unexpected IPC: %+v", rows)
	}
	t.Logf("explicit refresh counts=%v; measured executable digest=%s; observed revision=%s; expected source SHA=%s; provenance=%s; callable=%t",
		counts, status.Cache.ExecutableSHA256, status.Cache.ObservedRevision, status.ExpectedSourceRevision, status.Provenance, status.Callable)
	// A discovered cache still cannot enter the real agent toolset.
	a, err := f.s.m.pg.GetAgentByKey("auto")
	if err != nil || a == nil {
		t.Fatalf("auto agent: %v", err)
	}
	if err := f.s.m.pg.SetAgentVisibilityKind(a.ID, "mcp", []int64{f.m.ID}); err != nil {
		t.Fatal(err)
	}
	wireAgentAugment(f.s.m.pg, f.s.skillDir, nil)
	agent.ToolResolve = nil
	tools, def, cleanup := agent.AugmentTools(t.Context(), "auto", nil)
	defer cleanup()
	if len(tools) != 0 || len(def.Deferred) != 0 || len(def.GlobalNames) != 0 {
		t.Fatalf("unexpected_operation exposed after discovery: tools=%d %+v", len(tools), def)
	}
	if len(f.records(t)) != len(rows) {
		t.Fatal("post-refresh assembly launched the catalog")
	}
}

func TestSecurityCatalogRevisionBarrier(t *testing.T) {
	for _, mutation := range []string{"change", "disable", "delete"} {
		t.Run(mutation, func(t *testing.T) {
			// Given a relay barrier BEFORE the tools/list response reaches Scopeweaver.
			f := newCatalogFixture(t, "barrier")
			f.save(t)
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				done <- f.call(t, t.Context(), "POST", fmt.Sprintf("/api/mcp/%d/refresh", f.m.ID), nil, true, locale.En)
			}()
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			select {
			case <-f.listed:
			case <-ctx.Done():
				t.Fatal("tools/list response barrier not reached")
			}
			// When the configuration changes/deactivates/disappears before publication.
			switch mutation {
			case "change":
				f.m.SourceRevision = "75d43aabdf9be0d7b497f0c51e38dac77f4ee7be"
				f.save(t)
			case "disable":
				f.m.Enabled = false
				f.save(t)
			case "delete":
				if err := f.s.m.pg.DeleteMCP(f.m.ID); err != nil {
					t.Fatal(err)
				}
			}
			close(f.release)
			var rec *httptest.ResponseRecorder
			select {
			case rec = <-done:
			case <-ctx.Done():
				t.Fatal("refresh did not finish after barrier release")
			}
			// Then publication is rejected, not silently accepted.
			var count int
			if err := f.s.m.pg.QueryRow(`SELECT count(*) FROM mcp_catalog_cache WHERE server_id=$1`, f.m.ID).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if rec.Code != 409 || count != 0 {
				t.Fatalf("stale publication: HTTP %d cache_rows=%d %s", rec.Code, count, rec.Body.String())
			}
			t.Logf("tools/list barrier -> %s -> release: HTTP %d published_rows=%d; no tools/call", mutation, rec.Code, count)
		})
	}
}
