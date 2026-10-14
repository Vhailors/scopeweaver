package db

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

type assessmentImportResult struct {
	node      *Node
	duplicate bool
	err       error
}

func TestAssessmentImportConcurrentDuplicates(t *testing.T) {
	// Given: 24 requests subscribed to one release event before any write.
	d := assessmentDB(t)
	task := assessmentTask(t, d)
	report := assessmentParsed(t)
	ctx := assessmentTestContext(t)
	const requests = 24
	ready := make(chan struct{}, requests)
	start := make(chan struct{})
	done := make(chan assessmentImportResult, requests)
	for range requests {
		go func() {
			ready <- struct{}{}
			select {
			case <-start:
				node, duplicate, err := d.Exploration(task.ExplorationID).ImportAssessment(ctx, task.ID, report)
				done <- assessmentImportResult{node, duplicate, err}
			case <-ctx.Done():
				done <- assessmentImportResult{err: ctx.Err()}
			}
		}()
	}
	for range requests {
		assessmentSignal(t, ctx, ready)
	}
	// When: all subscribed requests import the same bytes concurrently.
	close(start)
	var id int64
	inserted, duplicates := 0, 0
	for range requests {
		select {
		case result := <-done:
			if result.err != nil || result.node == nil {
				t.Fatalf("concurrent import: %v", result.err)
			}
			if id == 0 {
				id = result.node.ID
			}
			if result.node.ID != id {
				t.Fatal("concurrent duplicate returned a different fact")
			}
			if result.duplicate {
				duplicates++
			} else {
				inserted++
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	// Then: one committed fact, the same identity, no publication side effects.
	counts := assessmentCounts(t, d, task)
	if inserted != 1 || duplicates != requests-1 || counts.Facts != 1 ||
		counts.Findings != 0 || counts.Intents != 0 {
		t.Fatalf("duplicates: inserted=%d duplicates=%d counts=%+v", inserted, duplicates, counts)
	}
	t.Logf("requests=%d inserted=%d duplicates=%d same_fact_id=%d", requests, inserted, duplicates, id)
}

func TestAssessmentImportLocksUntilCommit(t *testing.T) {
	for _, mutation := range []string{"disable", "delete"} {
		t.Run(mutation, func(t *testing.T) {
			// Given: pause the real driver immediately before its insert.
			d := assessmentDB(t)
			task := assessmentTask(t, d)
			importer, barrier := assessmentBarrierDB(t, "INSERT INTO exploration_nodes")
			ctx, cancel := context.WithCancel(assessmentTestContext(t))
			defer cancel()
			report := assessmentParsed(t)
			done := make(chan assessmentImportResult, 1)
			go func() {
				node, duplicate, err := importer.Exploration(task.ExplorationID).ImportAssessment(ctx, task.ID, report)
				done <- assessmentImportResult{node, duplicate, err}
			}()
			assessmentSignal(t, ctx, barrier.reached)
			// Then: independently attempting either locked row yields 55P03.
			for _, query := range []string{
				`SELECT value FROM settings WHERE key='security_reports_enabled' FOR UPDATE NOWAIT`,
				`SELECT id FROM tasks WHERE id=$1 FOR UPDATE NOWAIT`,
			} {
				args := []any{}
				if query == `SELECT id FROM tasks WHERE id=$1 FOR UPDATE NOWAIT` {
					args = append(args, task.ID)
				}
				_, err := d.ExecContext(ctx, query, args...)
				var pgErr *pgconn.PgError
				if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
					t.Fatalf("publication row not locked: %v", err)
				}
			}
			writer, writerBarrier := assessmentBarrierDB(t, "UPDATE")
			writeDone := make(chan error, 1)
			go func() {
				query := `UPDATE settings SET value='false' WHERE key='security_reports_enabled'`
				args := []any{}
				if mutation == "delete" {
					query = `UPDATE tasks SET deleted_at=now() WHERE id=$1`
					args = append(args, task.ID)
				}
				_, err := writer.ExecContext(ctx, query, args...)
				writeDone <- err
			}()
			assessmentSignal(t, ctx, writerBarrier.reached)
			close(writerBarrier.release)
			// When: publication commits, the queued mutation can complete.
			close(barrier.release)
			select {
			case result := <-done:
				if result.err != nil || result.node == nil || result.duplicate {
					t.Fatalf("import holding locks failed: %v", result.err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			select {
			case err := <-writeDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			before := assessmentCounts(t, d, task)
			wantErr := ErrAssessmentReportsDisabled
			if mutation == "delete" {
				wantErr = ErrAssessmentTaskUnavailable
			}
			node, duplicate, err := d.Exploration(task.ExplorationID).ImportAssessment(ctx, task.ID, report)
			if node != nil || duplicate || !errors.Is(err, wantErr) || assessmentCounts(t, d, task) != before {
				t.Fatalf("mutation returned but intake still published: %v", err)
			}
			t.Logf("setting_and_task_locks=55P03 mutation=%s commit_then_mutation=true retry_rejected=true", mutation)
		})
	}
}
