package server

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/Autumn-27/artex/assessment"
	"github.com/Autumn-27/artex/locale"
)

func TestAssessmentReportsHTTPBoundedHistory(t *testing.T) {
	f := newAssessmentHTTPFixture(t)
	// Given more than one page of real parser/importer-produced facts.
	ids := make(map[int64]bool)
	for i := range 101 {
		raw := []byte(fmt.Sprintf(`{"tool":"YeepForge","findings":[],"discarded_index":%d}`, i))
		report, err := assessment.Parse("yeepforge", raw, time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC))
		if err != nil {
			t.Fatal(err)
		}
		node, duplicate, err := f.s.m.pg.Exploration(f.task.ExplorationID).ImportAssessment(t.Context(), f.task.ID, report)
		if err != nil || duplicate {
			t.Fatalf("history fixture import failed: duplicate=%t err=%v", duplicate, err)
		}
		ids[node.ID] = true
	}
	f.enabled(t, false)
	before := f.counts(t)
	// When the operator reads bounded pages after disabling intake.
	var page struct {
		Reports    []assessmentReportSummary `json:"reports"`
		HasMore    bool                      `json:"has_more"`
		NextBefore int64                     `json:"next_before"`
	}
	rec := f.call(t, "GET", f.path(), "", f.token, "", locale.En, false)
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &page) != nil ||
		len(page.Reports) != 100 || !page.HasMore || page.NextBefore != page.Reports[99].FactID {
		t.Fatal("first history page must be bounded with a continuation cursor")
	}
	for _, report := range page.Reports {
		if !ids[report.FactID] {
			t.Fatal("history returned an unexpected fact")
		}
		delete(ids, report.FactID)
	}
	rec = f.call(t, "GET", fmt.Sprintf("%s?before=%d", f.path(), page.NextBefore), "", f.token, "", locale.En, false)
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &page) != nil ||
		len(page.Reports) != 1 || page.HasMore || page.NextBefore != 0 || !ids[page.Reports[0].FactID] {
		t.Fatal("older retained history must remain reachable without repeats")
	}
	// Then all 101 imports remain readable without writes or raw observations.
	delete(ids, page.Reports[0].FactID)
	if len(ids) != 0 || f.counts(t) != before {
		t.Fatal("history pagination omitted imports or wrote state")
	}
}
