package agent

import (
	"context"
	"errors"
	"testing"

	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

func TestDeferredCatalogLegacyCompactionAndReuse(t *testing.T) {
	// Given actual pre-repair SDK births and a predecessor-scoped legacy mark.
	store := transcript.NewStore(t.TempDir())
	raw := &plannerCatalogProvider{}
	session, native := "legacy-compaction", "mcp__legacy__unexpected_operation"
	opts := agentcore.Options{Provider: raw, Transcript: store, SessionID: session, Tools: actool.DefaultTools(),
		PermissionMode: permission.ModeBypass, NonStreaming: true, WorkingDir: t.TempDir(), MaxTurns: 20,
		Compaction: compactionConfig(100000)}
	raw.replies = [][]llm.ContentBlock{{r7Use(native, "call_0")}, {r7Use("LS", "call_0")}}
	s := agentcore.NewSession(opts)
	if _, _, err := captureRunSession(t.Context(), s, "legacy fixture", nil); err != nil {
		t.Fatal(err)
	}
	s.Close()
	records, err := store.Load(store.MainPath(session))
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]map[string]bool{}
	for _, rec := range records {
		if rec.Message != nil {
			for _, use := range rec.Message.ToolUses() {
				if use.Name == native {
					ids[rec.ParentUUID] = map[string]bool{use.ID: true}
				}
			}
		}
	}
	if len(ids) != 1 {
		t.Fatal("legacy birth mark was not established")
	}
	wrapped := func() agentcore.Options {
		o := opts
		o.Provider = deferredProvider(raw, DeferredInfo{CatalogUseIDs: func(context.Context, string) (map[string]map[string]bool, error) {
			return ids, nil
		}}, store)
		configureCatalogHistory(&o)
		return o
	}
	// When the restored working set compacts, followed by another cold resume.
	raw.tokens = 95000
	for range 3 {
		raw.replies = append(raw.replies, []llm.ContentBlock{r7Use("LS", "padding")})
	}
	for turn := range 2 {
		o := wrapped()
		s := agentcore.NewSession(o)
		resumeCatalogSession(t.Context(), s, o)
		before := len(raw.requests)
		_, reason, err := captureRunSession(t.Context(), s, "continue", nil)
		s.Close()
		if err != nil {
			t.Fatalf("legacy turn=%d reason=%s err=%v", turn, reason, err)
		}
		for _, req := range raw.requests[before:] {
			for _, msg := range req.Messages {
				for _, block := range msg.Content {
					if block.Type == llm.BlockToolUse && block.Name == native {
						t.Fatal("legacy tagged operation leaked")
					}
				}
			}
		}
		raw.tokens = 0
	}
	if raw.summaries == 0 {
		t.Fatal("legacy compaction did not execute")
	}
	t.Logf("legacy mark=1; compaction summaries=%d; native replay=0; cold resumed without error", raw.summaries)
}

func TestDeferredCatalogLegacyAmbiguityLocal(t *testing.T) {
	// Given a legacy mark with no predecessor identity and a reused structural ID.
	store, _, _ := deferredHistory(t, []llm.Message{
		{Role: llm.RoleAssistant, Content: []llm.ContentBlock{r7Use("LS", "call_0")}},
		{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.ToolResultText("call_0", "fixture", false)}},
	})
	raw := &deferredRequestProvider{}
	opts := agentcore.Options{Provider: deferredProvider(raw, DeferredInfo{CatalogUseIDs: func(context.Context, string) (map[string]map[string]bool, error) {
		return map[string]map[string]bool{"": {"call_0": true}}, nil
	}}, store), Transcript: store, SessionID: "history", NonStreaming: true}
	configureCatalogHistory(&opts)
	s := agentcore.NewSession(opts)
	defer s.Close()
	resumeCatalogSession(t.Context(), s, opts)
	// When the occurrence cannot be resolved, fail closed before any model call.
	_, reason, err := captureRunSession(t.Context(), s, "continue", nil)
	var policy *catalogPolicyError
	if !errors.As(err, &policy) || reason != harness.ReasonHookStopped || len(raw.requests) != 0 {
		t.Fatalf("ambiguous legacy reason=%s err=%v requests=%d", reason, err, len(raw.requests))
	}
}

func TestDeferredCatalogLegacyDuplicateMarks(t *testing.T) {
	native := r7Use("mcp__legacy__blocked", "dup")
	generic := r7Use("LS", "dup")
	result := llm.ToolResultText("dup", "fixture-result", false)
	for _, test := range []struct {
		name    string
		uses    []llm.ContentBlock
		results []llm.ContentBlock
		marked  bool
		fail    bool
	}{
		{"marked-uses", []llm.ContentBlock{native, generic}, []llm.ContentBlock{result}, true, true},
		{"marked-results", []llm.ContentBlock{native}, []llm.ContentBlock{result, result}, true, true},
		{"unmarked-uses", []llm.ContentBlock{generic, generic}, []llm.ContentBlock{result}, false, false},
		{"unmarked-results", []llm.ContentBlock{generic}, []llm.ContentBlock{result, result}, false, false},
		{"unique-pair", []llm.ContentBlock{native}, []llm.ContentBlock{result}, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, _, parent := deferredHistory(t, []llm.Message{
				{Role: llm.RoleAssistant, Content: test.uses},
				{Role: llm.RoleUser, Content: test.results},
			})
			records, err := store.Load(store.MainPath("history"))
			if err != nil {
				t.Fatal(err)
			}
			ids := map[string]map[string]bool{}
			if test.marked {
				ids[parent] = map[string]bool{"dup": true}
			}
			marks, err := catalogRecordMarks(records, ids)
			if (err != nil) != test.fail {
				t.Fatalf("marked=%t err=%v want failure=%t", test.marked, err, test.fail)
			}
			if !test.fail {
				for _, rec := range records {
					if rec.Message != nil && len(rec.Message.ToolUses()) > 0 &&
						marks[rec.UUID]["dup"] != test.marked {
						t.Fatalf("unique/unmarked occurrence changed: %v", marks[rec.UUID])
					}
				}
			}
		})
	}
}

func TestDeferredCatalogLegacyOrphanResultReuse(t *testing.T) {
	// Given SDK-written legacy records whose compacted tail starts inside a
	// marked exchange, followed by an executed generic reuse of the same ID.
	source := []llm.Message{
		{Role: llm.RoleAssistant, Content: []llm.ContentBlock{r7Use("mcp__legacy__blocked", "call_0")}},
		{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.ToolResultText("call_0", "legacy-native-result", true)}},
		{Role: llm.RoleAssistant, Content: []llm.ContentBlock{r7Use("LS", "call_0")}},
		{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.ToolResultText("call_0", "executed-generic-result", false)}},
	}
	store, ctx, parent := deferredHistory(t, source)
	records, err := store.Load(store.MainPath("history"))
	if err != nil {
		t.Fatal(err)
	}
	writer := store.ResumeWriter("history", transcript.LastUUID(records))
	meta := llm.BoundaryMeta{Trigger: "auto", MessagesSummarized: 2}
	writer.RecordBoundary(meta)
	writer.RecordMessage(llm.BoundaryMessage(meta), llm.Usage{})
	writer.RecordMessage(llm.UserText("fixture-summary"), llm.Usage{})
	for _, msg := range source[1:] {
		writer.RecordMessage(msg, llm.Usage{})
	}
	if err := writer.Err(); err != nil {
		t.Fatal(err)
	}
	raw := &deferredRequestProvider{}
	opts := agentcore.Options{Provider: deferredProvider(raw, DeferredInfo{CatalogUseIDs: func(context.Context, string) (map[string]map[string]bool, error) {
		return map[string]map[string]bool{parent: {"call_0": true}}, nil
	}}, store), Transcript: store, SessionID: "history", NonStreaming: true}
	configureCatalogHistory(&opts)
	s := agentcore.NewSession(opts)
	defer s.Close()
	resumeCatalogSession(ctx, s, opts)
	// When SDK pairing sees the later generic use, it must not revive the old
	// tagged result merely because both provider IDs are call_0.
	if _, _, err := captureRunSession(ctx, s, "continue", nil); err != nil {
		t.Fatal(err)
	}
	u, r := r7Pair(raw.requests[0], "LS", "call_0")
	if u != 1 || r != 1 {
		t.Fatalf("orphan-result reuse retained pair=%d/%d want=1/1", u, r)
	}
	for _, msg := range raw.requests[0].Messages {
		for _, b := range msg.Content {
			if b.Type == llm.BlockToolResult && blocksText(b.Content) == "legacy-native-result" {
				t.Fatal("tagged orphan result leaked through later generic reuse")
			}
		}
	}
}
