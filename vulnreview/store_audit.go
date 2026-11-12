package vulnreview

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

func (s *Store) Active(ctx context.Context, project, id string) (bool, error) {
	var active bool
	err := s.db.QueryRowContext(ctx, `SELECT status='running' FROM vulnerability_review_runs WHERE project_id=$1 AND id=$2`, project, id).Scan(&active)
	return active, err
}
func (s *Store) Audit(ctx context.Context, project, cursor string) ([]Decision, string, error) {
	if cursor != "" {
		var exists bool
		err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM vulnerability_review_decisions WHERE project_id=$1 AND id=$2)`, project, cursor).Scan(&exists)
		if err != nil {
			return nil, "", err
		}
		if !exists {
			return nil, "", ErrNotFound
		}
	}
	rows, err := s.db.QueryContext(ctx, `SELECT doc FROM vulnerability_review_decisions WHERE project_id=$1 AND ($2='' OR (created_at,id)<(SELECT created_at,id FROM vulnerability_review_decisions WHERE project_id=$1 AND id=$2)) ORDER BY created_at DESC,id DESC LIMIT 101`, project, cursor)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	out := []Decision{}
	for rows.Next() {
		var raw []byte
		var d Decision
		if err = rows.Scan(&raw); err != nil {
			return nil, "", err
		}
		if err = json.Unmarshal(raw, &d); err != nil {
			return nil, "", err
		}
		out = append(out, d)
	}
	if err = rows.Err(); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, "", err
	}
	next := ""
	if len(out) > 100 {
		out = out[:100]
		next = out[len(out)-1].ID
	}
	return out, next, nil
}
