package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/locale"
)

type catalogFixture struct {
	s        *Server
	m        *db.MCPServer
	handler  http.Handler
	token    string
	log      string
	listed   chan struct{}
	release  chan struct{}
	events   chan map[string]any
	scenario string
	run      string
}

func newCatalogFixture(t *testing.T, mode string) *catalogFixture {
	t.Helper()
	if !backportTestDatabaseAllowed(os.Getenv("ARTEX_PG_DSN")) {
		t.Fatal("Task 3 requires a disposable PostgreSQL DSN; skips are not evidence")
	}
	manager := backportTestManager(t)
	oldAugment, oldResolve := agent.ToolAugment, agent.ToolResolve
	t.Cleanup(func() { agent.ToolAugment, agent.ToolResolve = oldAugment, oldResolve })
	dir := t.TempDir()
	s := &Server{m: manager, ctx: t.Context(), skillDir: dir, jwtKey: bytes.Repeat([]byte("3"), 32)}
	f := &catalogFixture{s: s, handler: s.Handler(), listed: make(chan struct{}), release: make(chan struct{}), events: make(chan map[string]any, 64), scenario: t.Name()}
	f.run = filepath.Base(filepath.Dir(dir))
	var once sync.Once
	gate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/list" {
			once.Do(func() { close(f.listed) })
			select {
			case <-f.release:
			case <-r.Context().Done():
			}
		} else {
			var event map[string]any
			if json.NewDecoder(r.Body).Decode(&event) == nil {
				f.events <- event
			}
		}
		w.WriteHeader(200)
	}))
	t.Cleanup(gate.Close)
	driver := filepath.Join(dir, "catalog-fixture")
	build := exec.CommandContext(t.Context(), filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-o", driver, "testdata/security_catalog_fixture.go")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fixture relay: %v %s", err, output)
	}
	f.log = filepath.Join(dir, "ipc.jsonl")
	if path := os.Getenv("TASK3_IPC_LOG"); path != "" {
		f.log = path
	}
	fixture, err := filepath.Abs("../e2e/fixtures/security-tools/catalog-server.mjs")
	if err != nil {
		t.Fatal(err)
	}
	args := []string{fixture}
	if mode == "malformed" || mode == "hung" {
		args = append(args, "--"+mode)
	}
	env, err := json.Marshal(map[string]string{
		"TASK3_FIXTURE_LOG": f.log, "TASK3_FIXTURE_EVENTS": gate.URL,
		"TASK3_FIXTURE_SCENARIO": t.Name(), "TASK3_FIXTURE_BARRIER": fmt.Sprint(mode == "barrier"),
		"TASK3_FIXTURE_MUTATION": mode,
		"TASK3_FIXTURE_RUN":      f.run,
	})
	if err != nil {
		t.Fatal(err)
	}
	rawArgs, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	f.m = &db.MCPServer{Name: strings.ReplaceAll(t.Name(), "/", "-"), ProviderKind: "yeepforge",
		SourceRevision: "ee07fe352a994b4e53f20b382b58c605a1301060", Transport: "stdio",
		Command: driver, Args: rawArgs, Env: env, Enabled: true}
	f.token, err = signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if f.m.ID != 0 {
			if err := manager.pg.DeleteMCP(f.m.ID); err != nil {
				t.Errorf("delete fixture provider: %v", err)
			}
		}
	})
	return f
}

func (f *catalogFixture) call(t *testing.T, ctx context.Context, method, path string, body any, authenticated bool, lang locale.Lang) *httptest.ResponseRecorder {
	t.Helper()
	var raw []byte
	var err error
	if body != nil {
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw)).WithContext(ctx)
	if authenticated {
		req.Header.Set("Authorization", "Bearer "+f.token)
	}
	req.Header.Set("Accept-Language", string(lang))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func (f *catalogFixture) save(t *testing.T) {
	t.Helper()
	rec := f.call(t, t.Context(), "POST", "/api/mcp", f.m, true, locale.En)
	if rec.Code != 200 {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	var result struct{ ID int64 }
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil || result.ID == 0 {
		t.Fatalf("save did not return a persisted id: %s %v", rec.Body.String(), err)
	}
	f.m.ID = result.ID
	f.m = providerByName(t, f.s, f.m.Name)
}

func (f *catalogFixture) records(t *testing.T) []map[string]any {
	t.Helper()
	file, err := os.Open(f.log)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var rows []map[string]any
	dec := json.NewDecoder(file)
	for {
		var row map[string]any
		err := dec.Decode(&row)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if row["scenario"] == f.scenario && row["run"] == f.run {
			rows = append(rows, row)
		}
	}
	return rows
}

func awaitCatalogEvent(t *testing.T, f *catalogFixture, method string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	for {
		select {
		case event := <-f.events:
			if event["method"] == method {
				return
			}
		case <-ctx.Done():
			t.Fatalf("no fixture %s event: %v", method, ctx.Err())
		}
	}
}
