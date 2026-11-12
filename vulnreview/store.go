package vulnreview

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

var ErrBusy = errors.New("a review is already active or the review queue is full")
var ErrNotFound = errors.New("review project or run not found")
var ErrInventoryChanged = errors.New("inventory changed; preview or review the current snapshot")

type Store struct{ db *sql.DB }

func NewStore(ctx context.Context, db *sql.DB) (*Store, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(747398201)`); err != nil {
		return nil, err
	}
	_, err = tx.ExecContext(ctx, `
 CREATE TABLE IF NOT EXISTS vulnerability_review_projects(id text PRIMARY KEY, doc jsonb NOT NULL);
 CREATE TABLE IF NOT EXISTS vulnerability_review_runs(id text PRIMARY KEY, project_id text NOT NULL REFERENCES vulnerability_review_projects(id), status text NOT NULL, created_at timestamptz NOT NULL, lease_until timestamptz NOT NULL, doc jsonb NOT NULL);
 CREATE UNIQUE INDEX IF NOT EXISTS vulnerability_review_active ON vulnerability_review_runs(project_id) WHERE status IN ('queued','running');
 CREATE INDEX IF NOT EXISTS vulnerability_review_run_history ON vulnerability_review_runs(project_id,created_at DESC);
 CREATE TABLE IF NOT EXISTS vulnerability_review_decisions(id text PRIMARY KEY, project_id text NOT NULL REFERENCES vulnerability_review_projects(id), created_at timestamptz NOT NULL, doc jsonb NOT NULL);
 CREATE INDEX IF NOT EXISTS vulnerability_review_decision_history ON vulnerability_review_decisions(project_id,created_at DESC);
 CREATE INDEX IF NOT EXISTS vulnerability_review_decision_latest ON vulnerability_review_decisions(project_id,(doc->>'inventory_hash'),(doc->>'finding_key'),(doc->>'package_version'),created_at DESC,id DESC);
 `)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}
func (s *Store) List(ctx context.Context) ([]Project, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT doc FROM vulnerability_review_projects ORDER BY doc->>'updated_at' DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Project{}
	for rows.Next() {
		var raw []byte
		var p Project
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(raw, &p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
func (s *Store) Project(ctx context.Context, id string) (Project, error) {
	var p Project
	var raw []byte
	err := s.db.QueryRowContext(ctx, `SELECT doc FROM vulnerability_review_projects WHERE id=$1`, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	if err != nil {
		return p, err
	}
	err = json.Unmarshal(raw, &p)
	return p, err
}
func (s *Store) Create(ctx context.Context, p Project) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(747398202)`); err != nil {
		return err
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM vulnerability_review_projects`).Scan(&count); err != nil {
		return err
	}
	if count >= 100 {
		return ErrBusy
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO vulnerability_review_projects(id,doc) VALUES($1,$2)`, p.ID, raw); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) Update(ctx context.Context, id string, change func(*Project) error) (Project, error) {
	var p Project
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return p, err
	}
	defer tx.Rollback()
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT doc FROM vulnerability_review_projects WHERE id=$1 FOR UPDATE`, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	if err != nil {
		return p, err
	}
	if err = json.Unmarshal(raw, &p); err != nil {
		return p, err
	}
	if err = change(&p); err != nil {
		return p, err
	}
	raw, err = json.Marshal(p)
	if err != nil {
		return p, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE vulnerability_review_projects SET doc=$2 WHERE id=$1`, id, raw); err != nil {
		return p, err
	}
	return p, tx.Commit()
}
func (s *Store) Enqueue(ctx context.Context, r Run) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(747398203)`); err != nil {
		return err
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM vulnerability_review_runs WHERE status IN ('queued','running')`).Scan(&count); err != nil {
		return err
	}
	if count >= 20 {
		return ErrBusy
	}
	var active bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM vulnerability_review_runs WHERE project_id=$1 AND status IN ('queued','running'))`, r.ProjectID).Scan(&active); err != nil {
		return err
	}
	if active {
		return ErrBusy
	}
	var current []byte
	if err = tx.QueryRowContext(ctx, `SELECT doc FROM vulnerability_review_projects WHERE id=$1 FOR SHARE`, r.ProjectID).Scan(&current); err != nil {
		return err
	}
	var p Project
	if err = json.Unmarshal(current, &p); err != nil {
		return err
	}
	if p.InventoryHash != r.InventoryHash {
		return ErrBusy
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO vulnerability_review_runs(id,project_id,status,created_at,lease_until,doc) VALUES($1,$2,$3,$4,$5,$6)`, r.ID, r.ProjectID, r.Status, r.CreatedAt, r.CreatedAt.Add(30*time.Minute), raw)
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) SaveRun(ctx context.Context, r Run) (bool, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return false, err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE vulnerability_review_runs SET status=$3,doc=$4,lease_until=CASE WHEN $3='running' THEN now()+interval '3 minutes' ELSE lease_until END WHERE id=$1 AND project_id=$2 AND status IN ('queued','running')`, r.ID, r.ProjectID, r.Status, raw)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n > 0, err
}
func (s *Store) GetRun(ctx context.Context, project, id string) (Run, error) {
	var r Run
	var raw []byte
	err := s.db.QueryRowContext(ctx, `SELECT doc FROM vulnerability_review_runs WHERE id=$1 AND project_id=$2`, id, project).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	if err != nil {
		return r, err
	}
	err = json.Unmarshal(raw, &r)
	normalizeRun(&r)
	return r, err
}
func (s *Store) History(ctx context.Context, project string) ([]RunSummary, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT doc FROM vulnerability_review_runs WHERE project_id=$1 ORDER BY created_at DESC LIMIT 30`, project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RunSummary{}
	for rows.Next() {
		var raw []byte
		var r Run
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(raw, &r); err != nil {
			return nil, err
		}
		out = append(out, RunSummary{ID: r.ID, Status: r.Status, InventoryHash: r.InventoryHash, CreatedAt: r.CreatedAt, FinishedAt: r.FinishedAt, Findings: len(r.Findings), Changes: r.Changes, Error: r.Error})
	}
	return out, rows.Err()
}
func (s *Store) PreviousSuccess(ctx context.Context, project, exclude string) (Run, error) {
	var r Run
	var raw []byte
	err := s.db.QueryRowContext(ctx, `SELECT doc FROM vulnerability_review_runs WHERE project_id=$1 AND id<>$2 AND status='succeeded' ORDER BY created_at DESC LIMIT 1`, project, exclude).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	if err != nil {
		return r, err
	}
	err = json.Unmarshal(raw, &r)
	normalizeRun(&r)
	return r, err
}
func (s *Store) Decisions(ctx context.Context, project, hash string) ([]Decision, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT doc FROM (SELECT DISTINCT ON (doc->>'finding_key',coalesce(doc->>'package_version','')) doc,created_at,id FROM vulnerability_review_decisions WHERE project_id=$1 AND doc->>'inventory_hash'=$2 ORDER BY doc->>'finding_key',coalesce(doc->>'package_version',''),created_at DESC,id DESC) latest ORDER BY created_at DESC,id DESC`, project, hash)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Decision{}
	for rows.Next() {
		var raw []byte
		var d Decision
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(raw, &d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
func (s *Store) AddDecision(ctx context.Context, d Decision) error {
	raw, err := json.Marshal(d)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var hash string
	err = tx.QueryRowContext(ctx, `SELECT doc->>'inventory_hash' FROM vulnerability_review_projects WHERE id=$1 FOR SHARE`, d.ProjectID).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if hash != d.InventoryHash {
		return ErrInventoryChanged
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO vulnerability_review_decisions(id,project_id,created_at,doc) VALUES($1,$2,$3,$4)`, d.ID, d.ProjectID, d.CreatedAt, raw); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) Expire(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `UPDATE vulnerability_review_runs SET status='failed', doc=jsonb_set(jsonb_set(jsonb_set(doc,'{status}','"failed"'::jsonb),'{error}','"Review interrupted or lease expired; previous evidence is unchanged"'::jsonb),'{finished_at}',to_jsonb(now())) WHERE status IN ('queued','running') AND lease_until<now()`)
	return err
}
