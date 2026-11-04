package server

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/google/uuid"
)

type providerCursor struct {
	Snapshot string `json:"snapshot"`
	Offset   int    `json:"offset"`
}

// serveProvider is a separate security boundary, not an administrator API alias.
// It accepts only header service credentials, and never dispatches a write route.
func (s *Server) serveProvider(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeErr(w, 405, "Provider access is read-only")
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/provider/v1/companies/"), "/")
	if !strings.HasPrefix(r.URL.Path, "/api/provider/v1/companies/") || len(parts) < 2 {
		writeErr(w, 404, "Provider route not found")
		return
	}
	company, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || company < 1 {
		writeErr(w, 400, "Invalid company")
		return
	}
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer swp_") || len(header) != len("Bearer swp_")+64 {
		writeErr(w, 401, "Company provider credential required")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	g, err := pg.ProviderGrant(ctx, strings.TrimPrefix(header, "Bearer "), company)
	if errors.Is(err, db.ErrProviderAccess) {
		writeErr(w, 403, "Provider access denied")
		return
	}
	if err != nil {
		providerUnavailable(w)
		return
	}
	if parts[1] == "records" && len(parts) == 4 {
		family := parts[2]
		if family != "report" && family != "evidence" && family != "retest" {
			writeErr(w, 404, "Detail family unavailable")
			return
		}
		revision := r.URL.Query().Get("source_revision")
		if len(revision) != 64 {
			writeErr(w, 400, "Exact source revision required")
			return
		}
		record, err := pg.ProviderDetail(ctx, g.CompanyID, family, parts[3], revision)
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, 404, "Company detail unavailable")
			return
		}
		if errors.Is(err, db.ErrProviderRevision) {
			writeErr(w, 409, "Source changed; obtain a fresh snapshot")
			return
		}
		if err != nil {
			providerUnavailable(w)
			return
		}
		writeJSON(w, 200, record)
		return
	}
	if parts[1] == "publications" && len(parts) == 3 {
		content, err := pg.ProviderPublication(ctx, company, parts[2])
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, 404, "Approved publication unavailable")
			return
		}
		if err != nil {
			providerUnavailable(w)
			return
		}
		writeJSON(w, 200, content)
		return
	}
	if parts[1] != "snapshot" || len(parts) != 2 {
		writeErr(w, 404, "Provider route not found")
		return
	}
	cursor := providerCursor{}
	if c := r.URL.Query().Get("cursor"); c != "" {
		if len(c) > 512 {
			writeErr(w, 400, "Invalid cursor")
			return
		}
		b, e := base64.RawURLEncoding.DecodeString(c)
		if e != nil || json.Unmarshal(b, &cursor) != nil || cursor.Offset < 0 {
			writeErr(w, 400, "Invalid cursor")
			return
		}
		if _, e = uuid.Parse(cursor.Snapshot); e != nil {
			writeErr(w, 400, "Invalid cursor")
			return
		}
	} else {
		limit := 100
		if l := r.URL.Query().Get("limit"); l != "" {
			limit, err = strconv.Atoi(l)
			if err != nil || limit < 1 || limit > 500 {
				writeErr(w, 400, "Page size must be between 1 and 500")
				return
			}
		}
		snapshot, e := pg.CreateProviderSnapshot(ctx, g, limit)
		if e != nil {
			providerUnavailable(w)
			return
		}
		cursor.Snapshot = snapshot.ID
	}
	page, total, err := pg.ProviderSnapshotPage(ctx, g, cursor.Snapshot, cursor.Offset)
	if errors.Is(err, db.ErrProviderCursor) {
		writeErr(w, 410, "Snapshot expired or unavailable; restart without a cursor")
		return
	}
	if err != nil {
		providerUnavailable(w)
		return
	}
	next := ""
	complete := cursor.Offset+len(page.Records) >= total
	if !complete {
		b, _ := json.Marshal(providerCursor{Snapshot: cursor.Snapshot, Offset: cursor.Offset + page.PageSize})
		next = base64.RawURLEncoding.EncodeToString(b)
	}
	writeJSON(w, 200, map[string]any{"snapshot_id": cursor.Snapshot, "manifest": page.Manifest, "records": page.Records, "next_cursor": next, "complete": complete, "total": total, "offset": cursor.Offset})
}
func providerUnavailable(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "2")
	writeErr(w, 503, "Provider unavailable; retry at most three times, then retain the previous complete snapshot")
}

func (s *Server) providerCreateGrant(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var req struct {
		Company int64 `json:"company_id"`
		TTL     int64 `json:"ttl_seconds"`
	}
	if decode(r, &req) != nil || req.TTL <= 0 || req.TTL > 30*86400 {
		writeErr(w, 400, "Company and expiry up to 30 days required")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	g, token, err := pg.CreateProviderGrant(r.Context(), req.Company, time.Duration(req.TTL)*time.Second)
	if err != nil {
		writeErr(w, 400, "Cannot create provider grant")
		return
	}
	writeJSON(w, 201, map[string]any{"grant": g, "token": token})
}
func (s *Server) providerRevokeGrant(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	_, err := pg.ExecContext(r.Context(), `UPDATE provider_grants SET revoked_at=now() WHERE id=$1`, r.PathValue("id"))
	if err != nil {
		providerUnavailable(w)
		return
	}
	writeJSON(w, 200, map[string]bool{"revoked": true})
}

// Publication is a separate explicit administrator approval, not automatic
// redaction of arbitrary source text. Source revision changes invalidate it.
func (s *Server) providerApprovePublication(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		Company  int64           `json:"company_id"`
		Family   string          `json:"family"`
		Record   string          `json:"record_id"`
		Revision string          `json:"source_revision"`
		Content  json.RawMessage `json:"content"`
		Reviewed bool            `json:"reviewed_redacted"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&req) != nil || !req.Reviewed || req.Company < 1 || len(req.Revision) != 64 || len(req.Content) == 0 || !json.Valid(req.Content) {
		writeErr(w, 400, "Reviewed redacted content and a source revision are required")
		return
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		writeErr(w, 400, "Invalid publication")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	// Eligibility is checked through the same safe projection used for reads.
	records, err := pg.ProviderSourceRecord(r.Context(), req.Company, req.Family, req.Record)
	if err != nil {
		writeErr(w, 404, "Company source record unavailable")
		return
	}
	var payload map[string]any
	if json.Unmarshal(records, &payload) != nil || payload["source_revision"] != req.Revision {
		writeErr(w, 409, "Source revision changed")
		return
	}
	content, err := db.ProviderCanonicalJSON(req.Content)
	if err != nil {
		writeErr(w, 400, "Invalid publication content")
		return
	}
	id := uuid.NewString()
	sum := db.ProviderChecksum(content)
	_, err = pg.ExecContext(r.Context(), `INSERT INTO provider_publications(id,company_id,family,record_id,source_revision,content,checksum) VALUES($1,$2,$3,$4,$5,$6,$7)`, id, req.Company, req.Family, req.Record, req.Revision, string(content), sum)
	if err != nil {
		providerUnavailable(w)
		return
	}
	writeJSON(w, 201, map[string]string{"id": id, "checksum": sum})
}
func (s *Server) providerWithdrawPublication(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	_, err := pg.ExecContext(r.Context(), `UPDATE provider_publications SET withdrawn_at=now() WHERE id=$1`, r.PathValue("id"))
	if err != nil {
		providerUnavailable(w)
		return
	}
	writeJSON(w, 200, map[string]bool{"withdrawn": true})
}
