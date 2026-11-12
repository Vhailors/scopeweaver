package vulnreview

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, message string) {
	respond(w, status, map[string]string{"error": message})
}
func readBody(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, MaxBody)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		var size *http.MaxBytesError
		if errors.As(err, &size) {
			fail(w, 413, "Request exceeds 2 MiB")
		} else {
			fail(w, 400, "Invalid request JSON or unknown field")
		}
		return false
	}
	if err := d.Decode(new(any)); !errors.Is(err, io.EOF) {
		fail(w, 400, "Request must contain exactly one JSON object")
		return false
	}
	return true
}
func storeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		fail(w, 404, ErrNotFound.Error())
	case errors.Is(err, ErrInventoryChanged):
		fail(w, 409, err.Error())
	case errors.Is(err, ErrBusy):
		fail(w, 409, ErrBusy.Error())
	default:
		fail(w, 503, "Vulnerability review storage is unavailable; retry later")
	}
}
func validName(name string) bool { return len(strings.TrimSpace(name)) > 0 && len(name) <= 120 }
func (s *Service) Register(mux *http.ServeMux) {
	const base = "/api/vulnerability-review"
	mux.HandleFunc("GET "+base+"/capabilities", func(w http.ResponseWriter, r *http.Request) {
		respond(w, 200, map[string]any{"provider": "cve.now", "max_packages": MaxPackages, "supported_lockfiles": []string{"package-lock.json v1/v2/v3"}, "ecosystems": ecosystems, "read_only": true, "outbound_request_interval_ms_per_instance": 125, "outbound_concurrency_per_instance": 4, "coverage": Coverage, "attribution": Attribution, "privacy": "Only approved ecosystem/name/version tuples are transmitted; lockfile bodies, project names and registry URLs remain local. No hosted stack upload is used.", "authorization": "Existing shared ScopeWeaver administrator authentication; not tenant isolation."})
	})
	mux.HandleFunc("POST "+base+"/inventory/preview", func(w http.ResponseWriter, r *http.Request) {
		var in Input
		if !readBody(w, r, &in) {
			return
		}
		inv, err := Normalize(in)
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		respond(w, 200, map[string]any{"inventory": inv, "inventory_hash": digest(inv)})
	})
	mux.HandleFunc("GET "+base+"/projects", s.listProjects)
	mux.HandleFunc("POST "+base+"/projects", s.createProject)
	mux.HandleFunc("GET "+base+"/projects/{project}", s.projectDetail)
	mux.HandleFunc("GET "+base+"/projects/{project}/decisions", func(w http.ResponseWriter, r *http.Request) {
		project := r.PathValue("project")
		if _, err := s.store.Project(r.Context(), project); err != nil {
			storeError(w, err)
			return
		}
		cursor := r.URL.Query().Get("cursor")
		if len(cursor) > 32 {
			fail(w, 400, "Invalid audit cursor")
			return
		}
		items, next, err := s.store.Audit(r.Context(), project, cursor)
		if err != nil {
			storeError(w, err)
			return
		}
		respond(w, 200, map[string]any{"items": items, "next_cursor": next})
	})
	mux.HandleFunc("PATCH "+base+"/projects/{project}", s.updateProject)
	mux.HandleFunc("POST "+base+"/projects/{project}/runs", s.startRun)
	mux.HandleFunc("GET "+base+"/projects/{project}/runs/{run}", s.getRun)
	mux.HandleFunc("POST "+base+"/projects/{project}/runs/{run}/cancel", s.cancelRun)
	mux.HandleFunc("PUT "+base+"/projects/{project}/findings/{finding}", s.reviewFinding)
	mux.HandleFunc("POST "+base+"/projects/{project}/acknowledge", s.acknowledge)
}
func (s *Service) listProjects(w http.ResponseWriter, r *http.Request) {
	projects, err := s.store.List(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	type entry struct {
		Project Project     `json:"project"`
		Latest  *RunSummary `json:"latest"`
		Unread  bool        `json:"unread"`
	}
	out := []entry{}
	for _, p := range projects {
		history, err := s.store.History(r.Context(), p.ID)
		if err != nil {
			storeError(w, err)
			return
		}
		e := entry{Project: p}
		if len(history) > 0 {
			e.Latest = &history[0]
			for _, run := range history {
				if run.FinishedAt != nil && run.FinishedAt.After(p.AcknowledgedAt) && (run.Changes.New+run.Changes.Changed+run.Changes.NoLongerObserved > 0 || run.Status == "failed" || run.Status == "partial") {
					e.Unread = true
					break
				}
			}
		}
		out = append(out, e)
	}
	respond(w, 200, out)
}
func (s *Service) createProject(w http.ResponseWriter, r *http.Request) {
	var in Input
	if !readBody(w, r, &in) {
		return
	}
	if !validName(in.Name) {
		fail(w, 400, "Project name must contain 1–120 characters")
		return
	}
	if !in.Approved {
		fail(w, 400, "Approve sending the normalized dependency inventory to cve.now before saving")
		return
	}
	inv, err := Normalize(in)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	if in.ExpectedHash != digest(inv) {
		fail(w, 409, "Preview the current inventory before approving external lookup")
		return
	}
	now := time.Now().UTC()
	p := Project{ID: newID(), Name: strings.TrimSpace(in.Name), Inventory: inv, InventoryHash: digest(inv), Daily: in.Daily, ApprovedAt: now, CreatedAt: now, UpdatedAt: now}
	if err = s.store.Create(r.Context(), p); err != nil {
		storeError(w, err)
		return
	}
	respond(w, 201, p)
}
func (s *Service) projectDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("project")
	p, err := s.store.Project(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	history, err := s.store.History(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	decisions, err := s.store.Decisions(r.Context(), id, p.InventoryHash)
	if err != nil {
		storeError(w, err)
		return
	}
	var previous *Run
	baseline, err := s.store.PreviousSuccess(r.Context(), id, "")
	if err == nil {
		previous = &baseline
	} else if !errors.Is(err, ErrNotFound) {
		storeError(w, err)
		return
	}
	respond(w, 200, map[string]any{"project": p, "runs": history, "decisions": decisions, "last_successful": previous})
}
func (s *Service) updateProject(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name         *string    `json:"name"`
		ExpectedHash string     `json:"expected_inventory_hash"`
		Packages     *[]Package `json:"packages"`
		Lockfile     *string    `json:"lockfile_content"`
		Approved     bool       `json:"approve_external_lookup"`
		Daily        *bool      `json:"daily"`
	}
	if !readBody(w, r, &in) {
		return
	}
	if in.Name != nil && !validName(*in.Name) {
		fail(w, 400, "Project name must contain 1–120 characters")
		return
	}
	var inventory *Inventory
	if in.Packages != nil || in.Lockfile != nil {
		if !in.Approved {
			fail(w, 400, "Replacing inventory requires fresh external-lookup approval")
			return
		}
		raw := Input{}
		if in.Packages != nil {
			raw.Packages = *in.Packages
		}
		if in.Lockfile != nil {
			raw.Lockfile = *in.Lockfile
		}
		inv, err := Normalize(raw)
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		if in.ExpectedHash != digest(inv) {
			fail(w, 409, "Preview the current inventory before approving external lookup")
			return
		}
		inventory = &inv
	}
	p, err := s.store.Update(r.Context(), r.PathValue("project"), func(p *Project) error {
		if in.Name != nil {
			p.Name = strings.TrimSpace(*in.Name)
		}
		if in.Daily != nil {
			p.Daily = *in.Daily
		}
		if inventory != nil {
			p.Inventory = *inventory
			p.InventoryHash = digest(*inventory)
			p.ApprovedAt = time.Now().UTC()
		}
		p.UpdatedAt = time.Now().UTC()
		return nil
	})
	if err != nil {
		storeError(w, err)
		return
	}
	respond(w, 200, p)
}
func (s *Service) startRun(w http.ResponseWriter, r *http.Request) {
	p, err := s.store.Project(r.Context(), r.PathValue("project"))
	if err != nil {
		storeError(w, err)
		return
	}
	if p.ApprovedAt.IsZero() {
		fail(w, 403, "External lookup approval is required")
		return
	}
	run, err := s.Submit(r.Context(), p)
	if err != nil {
		storeError(w, err)
		return
	}
	respond(w, 202, run)
}
func (s *Service) getRun(w http.ResponseWriter, r *http.Request) {
	run, err := s.store.GetRun(r.Context(), r.PathValue("project"), r.PathValue("run"))
	if err != nil {
		storeError(w, err)
		return
	}
	run.Decisions, err = s.store.Decisions(r.Context(), run.ProjectID, run.InventoryHash)
	if err != nil {
		storeError(w, err)
		return
	}
	respond(w, 200, run)
}
func (s *Service) cancelRun(w http.ResponseWriter, r *http.Request) {
	run, err := s.Cancel(r.Context(), r.PathValue("project"), r.PathValue("run"))
	if err != nil {
		storeError(w, err)
		return
	}
	respond(w, 200, run)
}
func (s *Service) reviewFinding(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RunID  string `json:"run_id"`
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	if !readBody(w, r, &in) {
		return
	}
	switch in.Status {
	case "open", "accepted_risk", "resolved", "dismissed":
	default:
		fail(w, 400, "Invalid review status")
		return
	}
	in.Reason = strings.TrimSpace(in.Reason)
	if len(in.Reason) < 3 || len(in.Reason) > 2000 {
		fail(w, 400, "A review reason of 3–2000 characters is required")
		return
	}
	p, err := s.store.Project(r.Context(), r.PathValue("project"))
	if err != nil {
		storeError(w, err)
		return
	}
	run, err := s.store.GetRun(r.Context(), p.ID, in.RunID)
	if err != nil {
		storeError(w, err)
		return
	}
	if run.InventoryHash != p.InventoryHash {
		fail(w, 409, "Inventory changed; review the current snapshot instead")
		return
	}
	if run.Status != "succeeded" && run.Status != "partial" {
		fail(w, 409, "Only completed review evidence can receive a decision")
		return
	}
	found := false
	version := ""
	for _, f := range run.Findings {
		if f.Key == r.PathValue("finding") {
			found = true
			version = f.Package.Version
			break
		}
	}
	if !found {
		fail(w, 404, "Finding does not belong to this review")
		return
	}
	d := Decision{ID: newID(), ProjectID: p.ID, FindingKey: r.PathValue("finding"), PackageVersion: version, InventoryHash: run.InventoryHash, Status: in.Status, Reason: in.Reason, CreatedAt: time.Now().UTC()}
	if err = s.store.AddDecision(r.Context(), d); err != nil {
		storeError(w, err)
		return
	}
	respond(w, 201, d)
}
func (s *Service) acknowledge(w http.ResponseWriter, r *http.Request) {
	p, err := s.store.Update(r.Context(), r.PathValue("project"), func(p *Project) error { p.AcknowledgedAt = time.Now().UTC(); return nil })
	if err != nil {
		storeError(w, err)
		return
	}
	respond(w, 200, p)
}
