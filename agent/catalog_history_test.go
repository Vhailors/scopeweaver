package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

func TestDeferredCatalogGeometryMismatch(t *testing.T) {
	// Given incomplete/displaced boundary data, including every indexing edge.
	user := llm.UserText("fixture")
	summary := llm.UserText("fixture-summary")
	meta := llm.BoundaryMeta{MessagesSummarized: 0}
	marker := llm.BoundaryMessage(meta)
	source := transcript.Record{UUID: "source", Type: "message", Message: &user}
	boundary := transcript.Record{UUID: "boundary", ParentUUID: "source", Type: "boundary", Boundary: &meta}
	header := []transcript.Record{
		source, boundary,
		{UUID: "marker", ParentUUID: "boundary", Type: "message", Message: &marker},
		{UUID: "summary", ParentUUID: "marker", Type: "message", Message: &summary},
	}
	negative, excessive, skills := meta, meta, meta
	negative.MessagesSummarized = -1
	excessive.MessagesSummarized = 2
	skills.ActiveSkills = []string{"fixture"}
	displaced := llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("fixture")}}
	for _, tc := range []struct {
		name    string
		records []transcript.Record
	}{
		{"nil-boundary", []transcript.Record{{Type: "boundary"}}},
		{"negative-head", []transcript.Record{{Type: "boundary", Boundary: &negative}}},
		{"excessive-head", []transcript.Record{source, {Type: "boundary", Boundary: &excessive}}},
		{"missing-marker", header[:2]},
		{"missing-summary", header[:3]},
		{"missing-tail", header},
		{"missing-skill", []transcript.Record{source, {Type: "boundary", Boundary: &skills}, header[2], header[3]}},
		{"displaced-copy", append(append([]transcript.Record(nil), header...), transcript.Record{UUID: "copy", ParentUUID: "summary", Message: &displaced})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// When reconstruction cannot establish correspondence.
			_, err := catalogRecordMarks(tc.records, nil)
			// Then it returns an error; an indexing panic fails the test.
			if err == nil {
				t.Fatal("invalid correspondence was accepted")
			}
		})
	}
}

func TestDeferredCatalogAppendFailureClosed(t *testing.T) {
	// Given a configured Session whose transcript path becomes unwritable.
	store := transcript.NewStore(t.TempDir())
	probe := &deferredRequestProvider{}
	opts := agentcore.Options{
		Provider: deferredProvider(probe, DeferredInfo{CatalogUseIDs: func(context.Context, string) (map[string]map[string]bool, error) {
			return nil, nil
		}}, store),
		Transcript: store, SessionID: "append-failure", PermissionMode: permission.ModeBypass,
	}
	enableNoa(&opts, nil, t.TempDir(), "append-failure", nil)
	if err := os.MkdirAll(store.MainPath("append-failure"), 0o755); err != nil {
		t.Fatal(err)
	}
	// When the SDK cannot append the current user record.
	_, _, err := captureRun(t.Context(), opts, "fixture", nil)
	// Then a no-mark live turn keeps SDK append-error recovery semantics.
	if err != nil || len(probe.requests) != 1 {
		t.Fatalf("append mismatch err=%v forwarded=%d", err, len(probe.requests))
	}
}

func TestDeferredCatalogResumedCleanupAndSettlement(t *testing.T) {
	// Given actual model-born native history interrupted before tool results.
	d := testDB(t)
	defer d.Close()
	store := transcript.NewStore(t.TempDir())
	session := "cleanup-" + transcript.NewSessionID()
	label := "Cleanup-" + transcript.NewSessionID()
	name := "mcp__" + label + "__unexpected_operation"
	id, err := d.SaveMCP(&db.MCPServer{Name: label, Transport: "stdio", ProviderKind: "yeepforge"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := d.DeleteMCP(id); err != nil {
			t.Error(err)
		}
		if _, err := d.Exec(`DELETE FROM mcp_catalog_native_uses WHERE session_id=$1`, session); err != nil {
			t.Error(err)
		}
	}()
	p := &plannerCatalogProvider{replies: [][]llm.ContentBlock{{{Type: llm.BlockToolUse, ID: "call_0", Name: name, Input: json.RawMessage(`{}`)}}}}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cleanup-control"), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	options := func() agentcore.Options {
		opts := agentcore.Options{
			Provider: deferredProvider(p, DeferredInfo{CatalogTagged: d.CatalogTaggedName, CatalogUseIDs: d.CatalogNativeUseIDs,
				Callable: func(name string) bool { return name == "LS" }}, store),
			Transcript: store, SessionID: session, Tools: actool.DefaultTools(),
			WorkingDir: dir, PermissionMode: permission.ModeBypass, NonStreaming: true,
			MaxTurns: 1, Settlement: wrapupSettlement("worker", []string{"Bash"}),
		}
		enableNoa(&opts, nil, dir, session, nil)
		return opts
	}
	firstOpts := options()
	first := agentcore.NewSession(firstOpts)
	for event, err := range first.Prompt(t.Context(), "fixture") {
		if err != nil {
			t.Fatal(err)
		}
		if event.Kind == harness.KindResult {
			if event.Terminal == nil || event.Terminal.Err == nil {
				t.Fatal("all-blocked response was reported as success")
			}
			break
		}
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	// When a cold resumed Session drops that trailing pending use and executes
	// the same ID through LS, then runs another prompt/settlement on itself.
	secondOpts := options()
	second := agentcore.NewSession(secondOpts)
	defer second.Close()
	resumeCatalogSession(t.Context(), second, secondOpts)
	for range 2 {
		p.replies = [][]llm.ContentBlock{{{Type: llm.BlockToolUse, ID: "call_0", Name: "LS", Input: json.RawMessage(`{}`)}}}
		if _, _, err := captureRunSession(t.Context(), second, "continue", nil); err != nil {
			t.Fatal(err)
		}
	}
	// Then both executed occurrences survive and the pending native does not.
	uses, results := 0, 0
	for _, msg := range p.requests[len(p.requests)-1].Messages {
		for _, b := range msg.Content {
			if b.Type == llm.BlockToolUse && b.Name == name {
				t.Fatal("pending native use leaked")
			}
			if b.Type == llm.BlockToolUse && b.Name == "LS" && b.ID == "call_0" {
				uses++
			}
			if b.Type == llm.BlockToolResult && b.ToolUseID == "call_0" {
				results++
			}
		}
	}
	if uses != 2 || results != 2 {
		t.Fatalf("resumed/settled executed pairs=%d/%d want=2/2", uses, results)
	}
}
