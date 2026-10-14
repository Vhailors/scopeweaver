package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"os"
	"path/filepath"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

type r7Provider struct {
	requests  []llm.CompletionRequest
	replies   [][]llm.ContentBlock
	tokens    int
	summaries int
	onCall    func()
}

func (p *r7Provider) Complete(_ context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.requests = append(p.requests, req)
	if p.onCall != nil {
		hook := p.onCall
		p.onCall = nil
		hook()
	}
	if req.Thinking == "disabled" && len(req.Tools) == 0 {
		p.summaries++
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("r7-summary")}}, "end_turn", llm.Usage{}, nil
	}
	blocks, stop := []llm.ContentBlock{llm.TextBlock("r7-complete")}, "end_turn"
	if len(p.replies) > 0 {
		blocks, p.replies, stop = p.replies[0], p.replies[1:], "tool_use"
	}
	return llm.Message{Role: llm.RoleAssistant, Content: blocks}, stop, llm.Usage{InputTokens: p.tokens}, nil
}

func (p *r7Provider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		yield(llm.StreamEvent{}, fmt.Errorf("r7 probe is non-streaming"))
	}
}

func r7Use(name, id string) llm.ContentBlock {
	return llm.ContentBlock{Type: llm.BlockToolUse, ID: id, Name: name, Input: json.RawMessage(`{}`)}
}

func r7Pair(req llm.CompletionRequest, name, id string) (int, int) {
	uses, results := 0, 0
	for _, msg := range req.Messages {
		for _, b := range msg.Content {
			if b.Type == llm.BlockToolUse && b.ID == id && b.Name == name {
				uses++
			}
			if b.Type == llm.BlockToolResult && b.ToolUseID == id {
				results++
			}
		}
	}
	return uses, results
}

type r7PlannerFixture struct {
	d       *db.DB
	task    *db.Task
	dir     string
	prov    *r7Provider
	planner *Planner
	session string
	store   *transcript.Store
}

func r7NewPlanner(t *testing.T) *r7PlannerFixture {
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	task, err := d.CreateTaskWithOptions("r7 probe", "local protocol fixture", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	augment, resolve := ToolAugment, ToolResolve
	t.Cleanup(func() { ToolAugment, ToolResolve = augment, resolve })
	ToolResolve = nil
	ToolAugment = func(context.Context, string) ([]actool.CoreTool, DeferredInfo, func()) {
		return nil, r7Def(d), func() {}
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "tasks", fmt.Sprint(task.ID)), 0o755); err != nil {
		t.Fatal(err)
	}
	f := &r7PlannerFixture{d: d, task: task, dir: dir, prov: &r7Provider{}, session: fmt.Sprintf("exp%d-planner", task.ExplorationID)}
	f.restart()
	return f
}

func (f *r7PlannerFixture) restart() {
	f.store = transcript.NewStore(filepath.Join(f.dir, "transcripts"))
	f.planner = NewPlanner(f.prov, "fixture", f.dir, f.store, 100000, 20)
	f.planner.SetNonStreaming(func() bool { return true })
}

func (f *r7PlannerFixture) plan(t *testing.T, wake int) (error, []llm.CompletionRequest) {
	before := len(f.prov.requests)
	_, _, err := f.planner.Plan(t.Context(), f.task.ID, f.d.Assets(), f.d.Exploration(f.task.ExplorationID), f.task.Goal, nil, nil)
	reqs := f.prov.requests[before:]
	t.Logf("R7 wake=%d err=%v requests=%d", wake, err, len(reqs))
	return err, reqs
}

// Crash in the middle of an append to the shared planner transcript: the final
// JSONL record is only partially on disk.
func TestR7ProbePlannerTruncatedTranscript(t *testing.T) {
	f := r7NewPlanner(t)
	f.prov.replies = [][]llm.ContentBlock{{r7Use("LS", "call_0")}}
	if err, _ := f.plan(t, 1); err != nil {
		t.Fatalf("wake 1: %v", err)
	}
	path := f.store.MainPath(f.session)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b = bytes.TrimSuffix(b, []byte("\n"))
	b = b[:len(b)-20]
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	failed := 0
	for wake := 2; wake <= 4; wake++ {
		if wake == 4 {
			f.restart() // new Planner and Store object = process restart
		}
		f.prov.replies = [][]llm.ContentBlock{{r7Use("LS", "call_0")}}
		if err, _ := f.plan(t, wake); err != nil {
			failed++
		}
	}
	t.Logf("R7RESULT planner-truncated failed_wakes=%d/3", failed)
	if failed != 0 {
		t.Fatalf("planner recovery failed wakes=%d", failed)
	}
}

// Another writer appends to the same planner file in the middle of a wake.
func TestR7ProbePlannerForeignAppend(t *testing.T) {
	f := r7NewPlanner(t)
	f.prov.replies = [][]llm.ContentBlock{{r7Use("LS", "call_0")}}
	if err, _ := f.plan(t, 1); err != nil {
		t.Fatalf("wake 1: %v", err)
	}
	foreign := llm.UserText("r7-foreign-writer")
	f.prov.onCall = func() {
		if err := f.store.Append(f.store.MainPath(f.session), transcript.Record{Type: "message", UUID: transcript.NewSessionID(), Message: &foreign}); err != nil {
			t.Error(err)
		}
	}
	f.prov.replies = [][]llm.ContentBlock{{r7Use("LS", "call_0")}}
	err2, reqs2 := f.plan(t, 2)
	f.prov.replies = [][]llm.ContentBlock{{r7Use("LS", "call_0")}}
	err3, reqs3 := f.plan(t, 3)
	u, r := -1, -1
	if len(reqs3) > 0 {
		u, r = r7Pair(reqs3[len(reqs3)-1], "LS", "call_0")
	}
	t.Logf("R7RESULT planner-foreign wake2_err=%v wake2_requests=%d wake3_err=%v wake3_ls0=%d/%d", err2, len(reqs2), err3, u, r)
}

// Crash inside recordNewBoundary of a resumed session (chat/mainagent/worker
// pattern): boundary, marker and summary are on disk, the copied tail is not.
func TestR7ProbeResumedBoundaryCrash(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	store := transcript.NewStore(t.TempDir())
	session := "r7crash-" + transcript.NewSessionID()
	prov := &r7Provider{}
	dir := t.TempDir()
	options := func() agentcore.Options {
		opts := agentcore.Options{
			Provider: r7Wrap(prov, d, store), Transcript: store, SessionID: session,
			Tools: actool.DefaultTools(), WorkingDir: dir, PermissionMode: permission.ModeBypass,
			NonStreaming: true, Compaction: compactionConfig(100000), MaxTurns: 20,
		}
		enableNoa(&opts, nil, dir, session, nil)
		return opts
	}
	run := func(label, input string) error {
		s := agentcore.NewSession(options())
		defer s.Close()
		if err := s.Resume(session); err != nil {
			t.Logf("R7 %s resume err=%v", label, err)
			return err
		}
		before := len(prov.requests)
		_, _, err := captureRunSession(t.Context(), s, input, nil)
		t.Logf("R7 %s err=%v requests=%d", label, err, len(prov.requests)-before)
		return err
	}
	prov.tokens = 95000
	for i := range 6 {
		prov.replies = append(prov.replies, []llm.ContentBlock{r7Use("LS", fmt.Sprintf("ls%d", i))})
	}
	if err := run("compact", "fixture"); err != nil {
		t.Fatal(err)
	}
	if prov.summaries == 0 {
		t.Fatal("no compaction")
	}
	prov.tokens = 0
	path := store.MainPath(session)
	records, err := store.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	last := -1
	for i, rec := range records {
		if rec.Type == "boundary" {
			last = i
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.SplitAfter(raw, []byte("\n"))
	if len(lines) > 0 && len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}
	if len(lines) != len(records) || last < 0 || len(records) <= last+3 {
		t.Fatalf("unexpected layout lines=%d records=%d boundary=%d", len(lines), len(records), last)
	}
	t.Logf("R7 records=%d last_boundary=%d summarized=%d kept=%d dropped=%d", len(records), last, records[last].Boundary.MessagesSummarized, last+3, len(records)-last-3)
	if err := os.WriteFile(path, bytes.Join(lines[:last+3], nil), 0o644); err != nil {
		t.Fatal(err)
	}
	failed := 0
	for i := 1; i <= 3; i++ {
		if err := run(fmt.Sprintf("resume%d", i), "continue"); err != nil {
			failed++
		}
	}
	t.Logf("R7RESULT resumed-boundary-crash failed_turns=%d/3", failed)
	if failed != 0 {
		t.Fatalf("resumed recovery failed turns=%d", failed)
	}
}
