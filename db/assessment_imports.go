package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Autumn-27/artex/assessment"
)

var (
	ErrAssessmentReportsDisabled = errors.New("assessment_reports_disabled")
	ErrAssessmentTaskUnavailable = errors.New("assessment_task_unavailable")
)

// ImportAssessment accepts only the application-owned result of assessment.Parse,
// never an inbound JSON-decoded Report. taskID is the authenticated current task;
// a related task's exploration is not a writable destination.
// A confirmed fact records that an import was observed, not a confirmed finding.
func (s *ExplorationStore) ImportAssessment(ctx context.Context, taskID int64, report *assessment.Report) (*Node, bool, error) {
	if report == nil {
		return nil, false, assessment.ErrInvalidType
	}
	payload, err := json.Marshal(report)
	if err != nil {
		return nil, false, fmt.Errorf("encode assessment import: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, fmt.Errorf("begin assessment import: %w", err)
	}
	defer tx.Rollback()

	// SHARE permits concurrent imports but excludes setting updates/deletion
	// until publication completes. Missing settings fail closed without a write.
	var enabled string
	err = tx.QueryRowContext(ctx, `SELECT value FROM settings
WHERE key='security_reports_enabled' FOR SHARE`).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, ErrAssessmentReportsDisabled
	}
	if err != nil {
		return nil, false, fmt.Errorf("lock assessment setting: %w", err)
	}
	if enabled != "true" && enabled != "1" {
		return nil, false, ErrAssessmentReportsDisabled
	}

	var explorationID int64
	err = tx.QueryRowContext(ctx, `SELECT exploration_id FROM tasks
WHERE id=$1 AND deleted_at IS NULL FOR SHARE`, taskID).Scan(&explorationID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, ErrAssessmentTaskUnavailable
	}
	if err != nil {
		return nil, false, fmt.Errorf("lock assessment task: %w", err)
	}
	if explorationID != s.expID {
		return nil, false, ErrAssessmentTaskUnavailable
	}

	node, err := scanNode(tx.QueryRowContext(ctx, `
INSERT INTO exploration_nodes(exploration_id, kind, payload, state, origin)
VALUES ($1, 'fact', $2, 'confirmed', 'assessment_import')
ON CONFLICT (exploration_id, (payload->>'assessment_id'))
WHERE kind='fact' AND payload ? 'assessment_id' AND payload ? 'assessment_import'
DO NOTHING RETURNING `+nodeCols, s.expID, string(payload)))
	duplicate := errors.Is(err, sql.ErrNoRows)
	if duplicate {
		// A separate READ COMMITTED statement sees a competing insert after its
		// commit. DO UPDATE would mutate timestamps and operator triage.
		node, err = scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeCols+`
FROM exploration_nodes WHERE exploration_id=$1 AND kind='fact'
AND payload ? 'assessment_import' AND payload->>'assessment_id'=$2`,
			s.expID, report.AssessmentID))
	}
	if err != nil {
		return nil, false, fmt.Errorf("persist assessment import: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("commit assessment import: %w", err)
	}
	return node, duplicate, nil
}
