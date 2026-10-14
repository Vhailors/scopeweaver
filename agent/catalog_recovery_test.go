package agent

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

func TestDeferredCatalogEveryIncompleteBoundary(t *testing.T) {
	// Given a real SDK compaction boundary, not a hand-authored copy layout.
	storeDir := t.TempDir()
	store := transcript.NewStore(storeDir)
	session := "boundary-cuts"
	raw := &plannerCatalogProvider{tokens: 95000}
	loads := 0
	options := func(marked bool) agentcore.Options {
		p := deferredProvider(raw, DeferredInfo{CatalogUseIDs: func(context.Context, string) (map[string]map[string]bool, error) {
			loads++
			if marked {
				return map[string]map[string]bool{"historical-parent": {"historical-native": true}}, nil
			}
			return nil, nil
		}}, store)
		opts := agentcore.Options{Provider: p, Transcript: store, SessionID: session, Tools: actool.DefaultTools(),
			PermissionMode: permission.ModeBypass, NonStreaming: true, WorkingDir: t.TempDir(), MaxTurns: 20,
			Compaction: compactionConfig(100000)}
		configureCatalogHistory(&opts)
		return opts
	}
	for i := range 6 {
		raw.replies = append(raw.replies, []llm.ContentBlock{r7Use("LS", fmt.Sprintf("ls%d", i))})
	}
	if _, _, err := captureRun(t.Context(), options(false), "fixture", nil); err != nil {
		t.Fatal(err)
	}
	records, err := store.Load(store.MainPath(session))
	if err != nil {
		t.Fatal(err)
	}
	boundary := -1
	for i, rec := range records {
		if rec.Type == "boundary" {
			boundary = i
		}
	}
	if boundary < 0 || raw.summaries == 0 {
		t.Fatal("no real compaction boundary")
	}
	working := catalogWorkingRecords(records[:boundary])
	copies := len(working) - records[boundary].Boundary.MessagesSummarized
	end := boundary + 3 + len(records[boundary].Boundary.ActiveSkills) + copies
	data, err := os.ReadFile(store.MainPath(session))
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.SplitAfter(data, []byte("\n"))[:len(records)]
	raw.tokens = 0
	// When each separate append is interrupted, with and without unrelated marks.
	for _, marked := range []bool{false, true} {
		for cut := boundary + 1; cut < end; cut++ {
			t.Run(fmt.Sprintf("marked=%t/cut=%d", marked, cut-boundary), func(t *testing.T) {
				if err := os.WriteFile(store.MainPath(session), bytes.Join(lines[:cut], nil), 0600); err != nil {
					t.Fatal(err)
				}
				for turn := range 3 {
					if turn == 2 {
						store = transcript.NewStore(storeDir)
					}
					opts := options(marked)
					s := agentcore.NewSession(opts)
					before := len(raw.requests)
					resumeCatalogSession(t.Context(), s, opts)
					_, _, err := captureRunSession(t.Context(), s, "continue", nil)
					s.Close()
					if err != nil || len(raw.requests)-before != 1 {
						t.Fatalf("cut=%d turn=%d err=%v requests=%d", cut, turn, err, len(raw.requests)-before)
					}
				}
				t.Log("three continued turns including new Session/Store state: no error; one request per turn")
			})
		}
	}
	t.Logf("boundary=%d copied-tail=%d cuts=%d guard mark loads=%d", boundary, copies, (end-boundary-1)*2, loads)
}

func TestDeferredCatalogNoMarkGuardReads(t *testing.T) {
	// Given an unreadable guard path and no exclusion marks.
	store := transcript.NewStore(t.TempDir())
	if err := os.Mkdir(store.MainPath("no-mark"), 0700); err != nil {
		t.Fatal(err)
	}
	p := &nativeHistoryProvider{store: store, load: func(context.Context, string) (map[string]map[string]bool, error) { return nil, nil }}
	// When the resumed-set adapter sees structural generic history.
	msgs := []llm.Message{{Role: llm.RoleAssistant, Content: []llm.ContentBlock{r7Use("LS", "id")}}}
	if err := p.restore(t.Context(), msgs, "no-mark"); err != nil {
		t.Fatalf("no-mark path read the guard transcript: %v", err)
	}
	// Then failed SDK Resume still runs from a fresh session, not partial records.
	raw := &deferredRequestProvider{}
	opts := agentcore.Options{Provider: deferredProvider(raw, DeferredInfo{
		CatalogUseIDs: p.load,
	}, store), Transcript: store, SessionID: "no-mark", NonStreaming: true}
	configureCatalogHistory(&opts)
	s := agentcore.NewSession(opts)
	defer s.Close()
	resumeCatalogSession(t.Context(), s, opts)
	if len(s.Messages()) != 0 {
		t.Fatal("failed Resume retained partial state")
	}
	if _, _, err := captureRunSession(t.Context(), s, "fixture", nil); err != nil || len(raw.requests) != 1 {
		t.Fatalf("fresh fallback err=%v requests=%d", err, len(raw.requests))
	}
}
