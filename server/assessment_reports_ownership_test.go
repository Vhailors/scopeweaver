package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/locale"
)

func TestAssessmentReportsHTTPTaskOwnership(t *testing.T) {
	f := newAssessmentHTTPFixture(t)
	// Given a read-only direct source relationship.
	current, err := f.s.m.pg.CreateTaskWithOptions("Task 6 current fixture", "observe supplied data",
		db.TaskCreateOptions{SourceTaskIDs: []int64{f.task.ID}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.s.m.pg.DeleteTask(current.ID); err != nil {
			t.Error(err)
		}
	})
	body := assessmentHTTPBody(t, "yeepforge", "yeepforge-valid")
	var sourceImport, localImport, changedImport assessmentReportResult
	rec := f.call(t, "POST", f.path(), body, f.token, "application/json", locale.En, false)
	if rec.Code != 201 || json.Unmarshal(rec.Body.Bytes(), &sourceImport) != nil {
		t.Fatal("source fixture import failed")
	}
	path := fmt.Sprintf("/api/tasks/%d/assessment-reports", current.ID)
	// When the URL selects the current task, the report goes only there.
	rec = f.call(t, "POST", path, body, f.token, "application/json", locale.En, false)
	if rec.Code != 201 || json.Unmarshal(rec.Body.Bytes(), &localImport) != nil ||
		localImport.AssessmentID != sourceImport.AssessmentID || localImport.FactID == sourceImport.FactID {
		t.Fatal("URL task must own its own immutable import")
	}
	changed := strings.Replace(body, `"version": "1.0"`, `"version": "1.1"`, 1)
	if body == changed {
		t.Fatal("changed-byte fixture did not change")
	}
	rec = f.call(t, "POST", path, changed, f.token, "application/json", locale.En, false)
	if rec.Code != 201 || json.Unmarshal(rec.Body.Bytes(), &changedImport) != nil ||
		changedImport.AssessmentID == localImport.AssessmentID || changedImport.FactID == localImport.FactID {
		t.Fatal("changed bytes must create a distinct import")
	}
	// Then current-task history excludes source imports and unrelated facts,
	// even if ordinary facts carry similarly named payload fields.
	if _, err := f.s.m.pg.Exec(`INSERT INTO exploration_nodes(exploration_id,kind,state,origin,payload)
VALUES($1,'fact','confirmed','manual','{"assessment_id":"manual","assessment_import":{},"summary":"manual"}')`, current.ExplorationID); err != nil {
		t.Fatal(err)
	}
	rec = f.call(t, "GET", path, "", f.token, "", locale.En, false)
	var page struct {
		Reports []assessmentReportSummary `json:"reports"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &page) != nil || len(page.Reports) != 2 {
		t.Fatal("history included inherited or unrelated facts")
	}
	ids := map[int64]bool{}
	for _, report := range page.Reports {
		ids[report.FactID] = true
		if report.FactID == sourceImport.FactID {
			t.Fatal("read-only source report leaked into current-task history")
		}
	}
	if !ids[localImport.FactID] || !ids[changedImport.FactID] ||
		page.Reports[0].SanitizedSHA256 != page.Reports[1].SanitizedSHA256 {
		t.Fatal("byte-specific identity must not merge canonically identical imports")
	}
	f.counts(t)
}
