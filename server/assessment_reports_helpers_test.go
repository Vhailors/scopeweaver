package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/locale"
	"github.com/jackc/pgx/v5"
)

const assessmentHTTPCanary = "scopeweaver-secret-canary-01"

type assessmentHTTPFixture struct {
	s       *Server
	handler http.Handler
	task    *db.Task
	token   string
	dir     string
}

func newAssessmentHTTPFixture(t *testing.T) *assessmentHTTPFixture {
	t.Helper()
	config, err := pgx.ParseConfig(os.Getenv("ARTEX_PG_DSN"))
	if err != nil || !strings.HasPrefix(config.Database, "scopeweaver_test_") {
		t.Fatal("Task 6 requires a fresh scopeweaver_test_* PostgreSQL database; skips are not evidence")
	}
	dir := t.TempDir()
	manager, err := NewManager(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Error(err)
		}
	})
	s := &Server{m: manager, ctx: t.Context(), skillDir: filepath.Join(dir, "skills"),
		jwtKey: bytes.Repeat([]byte("6"), 32), engine: NewEngine(manager)}
	f := &assessmentHTTPFixture{s: s, handler: s.Handler(), dir: dir}
	if _, err := manager.pg.Exec(`DELETE FROM settings WHERE key IN ($1,$2)`, authPassKey, db.SettingSecurityReportsEnabled); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := manager.pg.Exec(`DELETE FROM settings WHERE key IN ($1,$2)`, authPassKey, db.SettingSecurityReportsEnabled); err != nil {
			t.Error(err)
		}
	})
	for _, route := range []string{"init", "login"} {
		req := httptest.NewRequest("POST", "/api/auth/"+route,
			strings.NewReader(`{"username":"ARTEX","password":"task6-synthetic-password"}`))
		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, req)
		var response struct{ Token string }
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &response) != nil || response.Token == "" {
			t.Fatalf("fixture authentication %s failed with HTTP %d", route, rec.Code)
		}
		f.token = response.Token
	}
	f.task = f.newTask(t)
	f.enabled(t, true)
	t.Logf("OWNED runtime=%s database=%s auth=real-init+login token=redacted", dir, config.Database)
	return f
}

func (f *assessmentHTTPFixture) newTask(t *testing.T) *db.Task {
	t.Helper()
	task, err := f.s.m.pg.CreateTask("Task 6 synthetic report fixture", "observe supplied data only", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.s.m.pg.DeleteTask(task.ID); err != nil {
			t.Error(err)
		}
	})
	return task
}

func (f *assessmentHTTPFixture) enabled(t *testing.T, enabled bool) {
	t.Helper()
	if err := f.s.m.pg.SetBool(db.SettingSecurityReportsEnabled, enabled); err != nil {
		t.Fatal(err)
	}
}

func (f *assessmentHTTPFixture) path() string {
	return fmt.Sprintf("/api/tasks/%d/assessment-reports", f.task.ID)
}

func assessmentHTTPBody(t *testing.T, producer, fixture string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "e2e", "fixtures", "security-tools", fixture+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return `{"producer":"` + producer + `","report":` + string(raw) + `}`
}

func assessmentHTTPFiles(t *testing.T, dir string) []string {
	t.Helper()
	var paths []string
	if err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		paths = append(paths, path)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return paths
}

func (f *assessmentHTTPFixture) call(t *testing.T, method, path, body, token, media string, lang locale.Lang, chunked bool) *httptest.ResponseRecorder {
	t.Helper()
	// Subscribe before the request; handlers complete synchronously, so no
	// timing-based waits are needed to assert they emitted no activity.
	events, unsubscribe := f.s.engine.Broadcaster().Subscribe(fmt.Sprint(f.task.ID))
	defer unsubscribe()
	files := assessmentHTTPFiles(t, f.dir)
	var logs bytes.Buffer
	oldOutput := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(oldOutput)
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", media)
	req.Header.Set("Accept-Language", string(lang))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if chunked {
		req.ContentLength = -1
		req.TransferEncoding = []string{"chunked"}
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), assessmentHTTPCanary) || strings.Contains(logs.String(), assessmentHTTPCanary) {
		t.Fatal("raw canary leaked through response or server logs")
	}
	select {
	case <-events:
		t.Fatal("report request emitted SSE/activity")
	default:
	}
	if !reflect.DeepEqual(files, assessmentHTTPFiles(t, f.dir)) {
		t.Fatal("report request created files")
	}
	if rec.Header().Get("Content-Language") != string(lang) ||
		rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("missing localized JSON headers: %v", rec.Header())
	}
	t.Logf("HTTP method=%s path=%s authenticated=%t content_type=%q chunked=%t status=%d headers=%v safe_body=%s logs_canary=0 sse_events=0 file_changes=0",
		method, path, token == f.token, media, chunked, rec.Code, rec.Header(), rec.Body.String())
	return rec
}

type assessmentHTTPCounts struct {
	Facts, Findings, Intents, Activity, Conversations, ConversationActivity, Events, Deliveries int
}

func (f *assessmentHTTPFixture) counts(t *testing.T) assessmentHTTPCounts {
	t.Helper()
	var counts assessmentHTTPCounts
	err := f.s.m.pg.QueryRow(`SELECT
 (SELECT count(*) FROM exploration_nodes WHERE kind='fact'),
 (SELECT count(*) FROM findings),
 (SELECT count(*) FROM exploration_nodes WHERE kind='intent'),
 (SELECT count(*) FROM activity),
 (SELECT count(*) FROM conversations),
 (SELECT count(*) FROM conversation_activities),
 (SELECT count(*) FROM notification_events),
 (SELECT count(*) FROM notification_deliveries)`).Scan(&counts.Facts, &counts.Findings,
		&counts.Intents, &counts.Activity, &counts.Conversations, &counts.ConversationActivity, &counts.Events, &counts.Deliveries)
	if err != nil {
		t.Fatal(err)
	}
	var leaks int
	if err := f.s.m.pg.QueryRow(`SELECT count(*) FROM (
 SELECT payload::text AS value FROM exploration_nodes
 UNION ALL SELECT row_to_json(a)::text FROM activity a
 UNION ALL SELECT row_to_json(c)::text FROM conversation_activities c
 ) stored WHERE value LIKE $1`, "%"+assessmentHTTPCanary+"%").Scan(&leaks); err != nil {
		t.Fatal(err)
	}
	if leaks != 0 {
		t.Fatal("raw canary persisted")
	}
	t.Logf("SQL_COUNTS %+v persisted_canary=0", counts)
	return counts
}

func assessmentHTTPError(t *testing.T, rec *httptest.ResponseRecorder, status int, code string, lang locale.Lang) {
	t.Helper()
	var response map[string]string
	if rec.Code != status || json.Unmarshal(rec.Body.Bytes(), &response) != nil ||
		len(response) != 2 || response["code"] != code {
		t.Fatalf("error contract: HTTP %d %s", rec.Code, rec.Body.String())
	}
	raw, exists := locale.Raw(lang, "security.assessment."+code)
	if !exists || raw == "" || response["error"] != raw {
		t.Fatal("error must use a complete raw shipped catalog entry")
	}
}
