package db

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func assessmentDB(t *testing.T) *DB {
	t.Helper()
	dsn, _, err := DSN()
	if err != nil {
		t.Fatal(err)
	}
	d, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	var name string
	if err := d.QueryRow(`SELECT current_database()`).Scan(&name); err != nil {
		d.Close()
		t.Fatal(err)
	}
	if !strings.HasPrefix(name, "scopeweaver_test_") {
		d.Close()
		t.Fatal("assessment tests require a disposable scopeweaver_test_* database")
	}
	t.Cleanup(func() {
		if err := d.Close(); err != nil {
			t.Error(err)
		}
	})
	var previous string
	err = d.QueryRow(`SELECT value FROM settings WHERE key='security_reports_enabled'`).Scan(&previous)
	if err != nil && err != sql.ErrNoRows {
		t.Fatal(err)
	}
	existed := err == nil
	t.Cleanup(func() {
		if existed {
			assessmentExec(t, d, `UPDATE settings SET value=$1 WHERE key='security_reports_enabled'`, previous)
		} else {
			assessmentExec(t, d, `DELETE FROM settings WHERE key='security_reports_enabled'`)
		}
	})
	assessmentExec(t, d, `INSERT INTO settings(key,value) VALUES('security_reports_enabled','true')
ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value`)
	return d
}

func assessmentTask(t *testing.T, d *DB) *Task {
	t.Helper()
	task, err := d.CreateTask("assessment storage fixture", "observe supplied data", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := d.DeleteTask(task.ID); err != nil {
			t.Error(err)
		}
	})
	return task
}

func assessmentExec(t *testing.T, d *DB, query string, args ...any) {
	t.Helper()
	if _, err := d.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}

type assessmentCountSnapshot struct {
	Facts, Findings, Intents, Events, Deliveries int
}

const assessmentCountSQL = `SELECT
 (SELECT count(*) FROM exploration_nodes WHERE exploration_id=$1 AND kind='fact' AND payload ? 'assessment_import'),
 (SELECT count(*) FROM findings WHERE task_id=$2),
 (SELECT count(*) FROM exploration_nodes WHERE exploration_id=$1 AND kind='intent'),
 (SELECT count(*) FROM notification_events),
 (SELECT count(*) FROM notification_deliveries)`

func assessmentCounts(t *testing.T, d *DB, task *Task) assessmentCountSnapshot {
	t.Helper()
	var c assessmentCountSnapshot
	if err := d.QueryRow(assessmentCountSQL, task.ExplorationID, task.ID).
		Scan(&c.Facts, &c.Findings, &c.Intents, &c.Events, &c.Deliveries); err != nil {
		t.Fatal(err)
	}
	t.Logf("SQL_SNAPSHOT task=%d exploration=%d facts=%d findings=%d intents=%d events=%d deliveries=%d",
		task.ID, task.ExplorationID, c.Facts, c.Findings, c.Intents, c.Events, c.Deliveries)
	return c
}

func assessmentRow(t *testing.T, d *DB, table string, id int64) string {
	t.Helper()
	var raw string
	// table is a test-owned literal, never report input.
	if err := d.QueryRow(`SELECT row_to_json(r)::text FROM `+table+` r WHERE id=$1`, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

// A driver tracer pauses the real importer at an exact SQL event, with no
// production hook, sleeps, polling or mocked transactions.
type assessmentSQLBarrier struct {
	match   string
	reached chan struct{}
	release chan struct{}
}

func (b *assessmentSQLBarrier) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.Contains(data.SQL, b.match) {
		select {
		case b.reached <- struct{}{}:
		case <-ctx.Done():
			return ctx
		}
		select {
		case <-b.release:
		case <-ctx.Done():
		}
	}
	return ctx
}

func (*assessmentSQLBarrier) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func assessmentBarrierDB(t *testing.T, match string) (*DB, *assessmentSQLBarrier) {
	t.Helper()
	dsn, _, err := DSN()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	barrier := &assessmentSQLBarrier{match: match, reached: make(chan struct{}, 1), release: make(chan struct{})}
	cfg.Tracer = barrier
	key := stdlib.RegisterConnConfig(cfg)
	sqlDB, err := sql.Open("pgx", key)
	if err != nil {
		stdlib.UnregisterConnConfig(key)
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if err := sqlDB.Close(); err != nil {
			t.Error(err)
		}
		stdlib.UnregisterConnConfig(key)
	})
	return &DB{sqlDB}, barrier
}

func assessmentSignal(t *testing.T, ctx context.Context, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func assessmentTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	t.Cleanup(cancel)
	return ctx
}
