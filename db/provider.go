package db

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

const ProviderSchema = "scopeweaver.assessment.v1"

var ErrProviderAccess = errors.New("provider access denied")
var ErrProviderCursor = errors.New("provider snapshot unavailable")
var ErrProviderRevision = errors.New("source revision changed")

func ProviderChecksum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// Preserve PostgreSQL integer precision while normalizing JSON for checksums.
func ProviderCanonicalJSON(b []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

var ProviderFamilies = []string{"company", "scope", "asset", "task", "task_scope", "finding", "report", "evidence", "retest", "evidence_reference", "goal", "research_node", "research_edge", "constraint", "coverage_anchor", "lineage", "task_asset", "activity", "archive", "publication", "rejected"}

type ProviderGrant struct {
	ID        string    `json:"id"`
	CompanyID int64     `json:"company_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// CreateProviderGrant is an administrator operation; callers must not log the returned secret.
func (d *DB) CreateProviderGrant(ctx context.Context, company int64, ttl time.Duration) (ProviderGrant, string, error) {
	g := ProviderGrant{ID: uuid.NewString(), CompanyID: company, ExpiresAt: time.Now().UTC().Add(ttl)}
	if company <= 0 || ttl <= 0 || ttl > 30*24*time.Hour {
		return g, "", ErrProviderAccess
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return g, "", err
	}
	token := "swp_" + hex.EncodeToString(b)
	_, err := d.ExecContext(ctx, `WITH initialize AS (INSERT INTO provider_instance(singleton,id) VALUES(true,$5) ON CONFLICT DO NOTHING) INSERT INTO provider_grants(id,company_id,token_hash,expires_at) VALUES($1,$2,$3,$4)`, g.ID, company, ProviderChecksum([]byte(token)), g.ExpiresAt, uuid.NewString())
	return g, token, err
}
func (d *DB) ProviderGrant(ctx context.Context, token string, company int64) (ProviderGrant, error) {
	var g ProviderGrant
	err := d.QueryRowContext(ctx, `SELECT id,company_id,expires_at FROM provider_grants WHERE token_hash=$1 AND company_id=$2 AND revoked_at IS NULL AND expires_at>now()`, ProviderChecksum([]byte(token)), company).Scan(&g.ID, &g.CompanyID, &g.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrProviderAccess
	}
	return g, err
}

type ProviderRecord struct {
	Schema     string          `json:"schema_version"`
	Source     string          `json:"source_instance"`
	Company    int64           `json:"company_id"`
	Family     string          `json:"family"`
	ID         string          `json:"record_id"`
	Revision   string          `json:"revision"`
	Checksum   string          `json:"checksum"`
	ObservedAt time.Time       `json:"observed_at"`
	Deleted    bool            `json:"deleted"`
	Payload    json.RawMessage `json:"payload"`
}
type ProviderManifest struct {
	Schema     string         `json:"schema_version"`
	Source     string         `json:"source_instance"`
	Company    int64          `json:"company_id"`
	ObservedAt time.Time      `json:"observed_at"`
	Counts     map[string]int `json:"counts"`
	Rejected   map[string]int `json:"rejected"`
	Gaps       []string       `json:"coverage_gaps"`
	Absence    string         `json:"absence_policy"`
	Checksum   string         `json:"checksum"`
}
type ProviderSnapshot struct {
	ID       string
	PageSize int
	Manifest ProviderManifest
	Records  []ProviderRecord
}

// Snapshot builds every family under one MVCC view and commits records + manifest
// together. No partial generation can be resumed as a complete assessment.
func (d *DB) CreateProviderSnapshot(ctx context.Context, g ProviderGrant, limit int) (ProviderSnapshot, error) {
	out := ProviderSnapshot{ID: uuid.NewString(), PageSize: limit, Records: []ProviderRecord{}}
	if limit < 1 || limit > 500 {
		return out, ErrProviderCursor
	}
	tx, err := d.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	// Recheck access inside the same transaction as materialization.
	var valid bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM provider_grants WHERE id=$1 AND company_id=$2 AND revoked_at IS NULL AND expires_at>now())`, g.ID, g.CompanyID).Scan(&valid); err != nil {
		return out, err
	}
	if !valid {
		return out, ErrProviderAccess
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO provider_instance(singleton,id) VALUES(true,$1) ON CONFLICT DO NOTHING`, uuid.NewString()); err != nil {
		return out, err
	}
	var source string
	var observed time.Time
	if err = tx.QueryRowContext(ctx, `SELECT id,transaction_timestamp() FROM provider_instance WHERE singleton`).Scan(&source, &observed); err != nil {
		return out, err
	}
	m := ProviderManifest{Schema: ProviderSchema, Source: source, Company: g.CompanyID, ObservedAt: observed, Counts: map[string]int{}, Rejected: map[string]int{}, Absence: "replace_only_after_complete_snapshot_without_rejections", Gaps: []string{
		"Structured identifiers, scope values, metadata and assessment text are automatic under the declared redaction policy; removed or unsupported fields carry explicit notices.",
		"Report/evidence bodies remain source-held and are available automatically through revision-pinned redacted detail reads. Credentials, code/traffic blocks, authentication values and parameter values are excluded.",

		"Unattributed records are not broadcast. Company-associated conflicts are rejected with identities but no source content.",
		"Cold archive contents and filesystem artifacts have no company-safe approval mapping; use explicit publications after review.",
		"Coverage exports source scopes, anchors and links, not an independently recomputed coverage score.",
	}}
	for _, family := range ProviderFamilies {
		m.Counts[family] = 0
	}
	rows, err := tx.QueryContext(ctx, providerRecordsSQL, g.CompanyID)
	if err != nil {
		return out, err
	}
	totalBytes := 0
	for rows.Next() {
		var family, id string
		var payload []byte
		var deleted bool
		if err = rows.Scan(&family, &id, &payload, &deleted); err != nil {
			rows.Close()
			return out, err
		}
		// Canonical Go JSON ensures stable content revisions independent of JSONB formatting.
		payload, err = ProviderPayload(family, payload, false)
		if err != nil {
			rows.Close()
			return out, err
		}
		sum := ProviderChecksum(payload)
		out.Records = append(out.Records, ProviderRecord{Schema: ProviderSchema, Source: source, Company: g.CompanyID, Family: family, ID: id, Revision: sum, Checksum: sum, ObservedAt: observed, Deleted: deleted, Payload: payload})
		m.Counts[family]++
		if family == "rejected" {
			var rejected struct {
				Reason string `json:"reason"`
			}
			_ = json.Unmarshal(payload, &rejected)
			m.Rejected[rejected.Reason]++
		}
		totalBytes += len(payload)
		if len(out.Records) > 100000 || totalBytes > 64<<20 {
			rows.Close()
			return out, fmt.Errorf("provider snapshot budget exceeded")
		}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return out, err
	}
	rows.Close()
	keys := make([]string, 0, len(out.Records))
	for _, r := range out.Records {
		keys = append(keys, r.Family+":"+r.ID+":"+r.Revision)
	}
	keyJSON, _ := json.Marshal(keys)
	m.Checksum = ProviderChecksum(keyJSON)
	out.Manifest = m
	records, err := json.Marshal(out.Records)
	if err != nil {
		return out, err
	}
	if len(records) > 64<<20 {
		return out, fmt.Errorf("provider serialized snapshot budget exceeded")
	}
	manifest, err := json.Marshal(m)
	if err != nil {
		return out, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO provider_snapshots(id,grant_id,company_id,observed_at,expires_at,page_size,manifest,records) VALUES($1,$2,$3,$4,LEAST($5,$4::timestamptz+interval '24 hours'),$6,$7,$8)`, out.ID, g.ID, g.CompanyID, observed, g.ExpiresAt, limit, string(manifest), string(records))
	if err != nil {
		return out, err
	}
	// Bound retention per grant; old cursors explicitly expire rather than reading a changed dataset.
	if _, err = tx.ExecContext(ctx, `DELETE FROM provider_snapshots WHERE grant_id=$1 AND (expires_at<=now() OR id IN (SELECT id FROM provider_snapshots WHERE grant_id=$1 ORDER BY observed_at DESC,id DESC OFFSET 12))`, g.ID); err != nil {
		return out, err
	}
	return out, tx.Commit()
}

// ProviderSnapshotPage is a persisted read, so restart and duplicate delivery keep
// the same content. Every request also checks current grant expiry/revocation.
func (d *DB) ProviderSnapshotPage(ctx context.Context, g ProviderGrant, id string, offset int) (ProviderSnapshot, int, error) {
	out := ProviderSnapshot{ID: id, Records: []ProviderRecord{}}
	var manifest, records []byte
	var total int
	err := d.QueryRowContext(ctx, `WITH current_records AS (`+providerRecordsSQL+`) SELECT s.page_size,s.manifest,jsonb_array_length(s.records),COALESCE((SELECT jsonb_agg(e.value ORDER BY e.ordinality) FROM jsonb_array_elements(s.records) WITH ORDINALITY e WHERE e.ordinality>$4 AND e.ordinality<=$4+s.page_size),'[]'::jsonb) FROM provider_snapshots s JOIN provider_grants g ON g.id=s.grant_id WHERE s.id=$2 AND s.grant_id=$3 AND s.company_id=$1 AND s.expires_at>now() AND g.revoked_at IS NULL AND g.expires_at>now()
 AND NOT EXISTS (
  SELECT 1 FROM jsonb_array_elements(s.records) old
  WHERE (
   (old->>'family'='asset' AND EXISTS(SELECT 1 FROM assets a WHERE a.id::text=old->>'record_id')) OR
   (old->>'family'='task' AND EXISTS(SELECT 1 FROM tasks t WHERE t.id::text=old->>'record_id')) OR
   (old->>'family'='finding' AND EXISTS(SELECT 1 FROM findings f WHERE f.id::text=old->>'record_id')) OR
   old->>'family'='publication'
  ) AND NOT EXISTS(SELECT 1 FROM current_records c WHERE c.family=old->>'family' AND c.id=old->>'record_id')
 )`, g.CompanyID, id, g.ID, offset).Scan(&out.PageSize, &manifest, &total, &records)
	if errors.Is(err, sql.ErrNoRows) {
		return out, 0, ErrProviderCursor
	}
	if err != nil {
		return out, 0, err
	}
	if offset < 0 || offset > total || offset%out.PageSize != 0 {
		return out, 0, ErrProviderCursor
	}
	if err = json.Unmarshal(manifest, &out.Manifest); err != nil {
		return out, 0, err
	}
	err = json.Unmarshal(records, &out.Records)
	return out, total, err
}

// ProviderDetail returns the current eligible source version, never an unpinned
// body or a reconstructed historical report. Originals remain in source storage.
func (d *DB) ProviderDetail(ctx context.Context, company int64, family, id, revision string) (ProviderRecord, error) {
	var out ProviderRecord
	var raw []byte
	var source string
	var observed time.Time
	err := d.QueryRowContext(ctx, `SELECT q.payload,i.id,statement_timestamp() FROM (`+providerRecordsSQL+`) q CROSS JOIN provider_instance i WHERE i.singleton AND q.family=$2 AND q.id=$3 AND NOT q.deleted`, company, family, id).Scan(&raw, &source, &observed)
	if err != nil {
		return out, err
	}
	var p map[string]any
	if err = json.Unmarshal(raw, &p); err != nil {
		return out, err
	}
	if revision == "" || p["source_revision"] != revision {
		return out, ErrProviderRevision
	}
	safe, err := ProviderPayload(family, raw, true)
	if err != nil {
		return out, err
	}
	sum := ProviderChecksum(safe)
	out = ProviderRecord{Schema: ProviderSchema, Source: source, Company: company, Family: family, ID: id, Revision: sum, Checksum: sum, ObservedAt: observed, Payload: safe}
	return out, nil
}
