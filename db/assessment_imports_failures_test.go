package db

import (
	"context"
	"errors"
	"testing"

	"github.com/Autumn-27/artex/assessment"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestAssessmentImportRejectsUnavailable(t *testing.T) {
	for _, scenario := range []string{"disabled", "missing_setting", "invalid_setting", "deleted_task", "soft_deleted_task", "inherited_task", "cancelled", "nil_report"} {
		t.Run(scenario, func(t *testing.T) {
			// Given: one unavailable intake condition, no imported facts.
			d := assessmentDB(t)
			task := assessmentTask(t, d)
			store := d.Exploration(task.ExplorationID)
			report := assessmentParsed(t)
			ctx := t.Context()
			wantErr := ErrAssessmentTaskUnavailable
			switch scenario {
			case "disabled", "invalid_setting":
				value := "false"
				if scenario == "invalid_setting" {
					value = "yes"
				}
				assessmentExec(t, d, `UPDATE settings SET value=$1 WHERE key='security_reports_enabled'`, value)
				wantErr = ErrAssessmentReportsDisabled
			case "missing_setting":
				assessmentExec(t, d, `DELETE FROM settings WHERE key='security_reports_enabled'`)
				wantErr = ErrAssessmentReportsDisabled
			case "deleted_task":
				if err := d.DeleteTask(task.ID); err != nil {
					t.Fatal(err)
				}
			case "soft_deleted_task":
				assessmentExec(t, d, `UPDATE tasks SET deleted_at=now() WHERE id=$1`, task.ID)
			case "inherited_task":
				source := assessmentTask(t, d)
				assessmentExec(t, d, `INSERT INTO task_relations(task_id,source_task_id) VALUES($1,$2)`, task.ID, source.ID)
				store = d.Exploration(source.ExplorationID)
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				wantErr = context.Canceled
			case "nil_report":
				report = nil
				wantErr = assessment.ErrInvalidType
			}
			before := assessmentCounts(t, d, task)
			// When: attempt publication through the actual importer.
			node, duplicate, err := store.ImportAssessment(ctx, task.ID, report)
			// Then: never return a misleading identity or publish any side effect.
			if node != nil || duplicate || !errors.Is(err, wantErr) {
				t.Fatalf("unavailable import: node=%v duplicate=%v err=%v want=%v", node, duplicate, err, wantErr)
			}
			if after := assessmentCounts(t, d, task); after != before {
				t.Fatalf("rejection left residue: before=%+v after=%+v", before, after)
			}
			if scenario == "inherited_task" {
				var facts int
				if err := d.QueryRow(`SELECT count(*) FROM exploration_nodes WHERE exploration_id=$1 AND payload ? 'assessment_import'`, store.ID()).Scan(&facts); err != nil || facts != 0 {
					t.Fatalf("source exploration received rejected import: count=%d err=%v", facts, err)
				}
				t.Logf("SQL_SOURCE_SNAPSHOT exploration=%d imports=%d", store.ID(), facts)
			}
		})
	}
}

func TestAssessmentImportCommitFailure(t *testing.T) {
	// Given: a real deferred constraint trigger fails only at COMMIT.
	d := assessmentDB(t)
	task := assessmentTask(t, d)
	assessmentExec(t, d, `CREATE FUNCTION task5_fail_commit() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'task5 injected commit failure'; END; $$ LANGUAGE plpgsql;
CREATE CONSTRAINT TRIGGER task5_fail_commit AFTER INSERT ON exploration_nodes
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
WHEN (NEW.payload ? 'assessment_import') EXECUTE FUNCTION task5_fail_commit();`)
	t.Cleanup(func() {
		assessmentExec(t, d, `DROP TRIGGER task5_fail_commit ON exploration_nodes; DROP FUNCTION task5_fail_commit();`)
	})
	before := assessmentCounts(t, d, task)
	// When: the insert succeeds but the database rejects the commit.
	node, duplicate, err := d.Exploration(task.ExplorationID).ImportAssessment(t.Context(), task.ID, assessmentParsed(t))
	// Then: the caller sees failure, not an uncommitted ID, and all writes roll back.
	var pgErr *pgconn.PgError
	if node != nil || duplicate || !errors.As(err, &pgErr) || pgErr.Code != "P0001" {
		t.Fatalf("commit failure reported as success: node=%v duplicate=%v err=%v", node, duplicate, err)
	}
	if after := assessmentCounts(t, d, task); after != before {
		t.Fatalf("commit failure left residue: before=%+v after=%+v", before, after)
	}
	t.Logf("commit_failure_sqlstate=%s published_id=false", pgErr.Code)
}

func TestAssessmentImportMutationBeforeLock(t *testing.T) {
	for _, mutation := range []string{"disable", "delete"} {
		t.Run(mutation, func(t *testing.T) {
			// Given: subscribe at the precise SELECT start, before the row lock.
			d := assessmentDB(t)
			task := assessmentTask(t, d)
			match := "SELECT value FROM settings"
			if mutation == "delete" {
				match = "SELECT exploration_id FROM tasks"
			}
			importer, barrier := assessmentBarrierDB(t, match)
			ctx, cancel := context.WithCancel(assessmentTestContext(t))
			defer cancel()
			report := assessmentParsed(t)
			before := assessmentCounts(t, d, task)
			done := make(chan assessmentImportResult, 1)
			go func() {
				node, duplicate, err := importer.Exploration(task.ExplorationID).ImportAssessment(ctx, task.ID, report)
				done <- assessmentImportResult{node, duplicate, err}
			}()
			assessmentSignal(t, ctx, barrier.reached)
			wantErr := ErrAssessmentReportsDisabled
			// When: the mutation commits before intake obtains that row lock.
			if mutation == "disable" {
				assessmentExec(t, d, `UPDATE settings SET value='false' WHERE key='security_reports_enabled'`)
			} else {
				if err := d.DeleteTask(task.ID); err != nil {
					t.Fatal(err)
				}
				wantErr = ErrAssessmentTaskUnavailable
			}
			close(barrier.release)
			// Then: the old task/feature snapshot cannot publish anything.
			select {
			case result := <-done:
				if result.node != nil || result.duplicate || !errors.Is(result.err, wantErr) {
					t.Fatalf("stale intake published: %+v", result)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if after := assessmentCounts(t, d, task); after != before {
				t.Fatalf("stale intake residue: before=%+v after=%+v", before, after)
			}
		})
	}
}
