package server

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/assessment"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/locale"
)

func TestAssessmentReportsHTTPImports(t *testing.T) {
	f := newAssessmentHTTPFixture(t)
	for _, tc := range []struct{ producer, fixture, completeness string }{
		{"yeepforge", "yeepforge-valid", "unknown"},
		{"adstrike", "adstrike-valid", "unknown"},
		{"confirmesc", "confirmesc-valid", "unknown"},
		{"yeepforge", "yeepforge-empty", "no_observations"},
		{"adstrike", "adstrike-empty", "no_observations"},
		{"confirmesc", "confirmesc-empty", "no_observations"},
		{"confirmesc", "confirmesc-errorful", "has_errors"},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			// Given synthetic producer bytes, an authenticated operator, and
			// no library skills or agent visibility bindings.
			before := f.counts(t)
			body := assessmentHTTPBody(t, tc.producer, tc.fixture)
			// When the real mux parses and imports the report.
			rec := f.call(t, "POST", f.path(), body, f.token, "application/json; charset=utf-8", locale.En, false)
			var first assessmentReportResult
			if rec.Code != 201 || json.Unmarshal(rec.Body.Bytes(), &first) != nil ||
				first.Duplicate || len(first.AssessmentID) != 64 || first.FactID <= 0 ||
				first.Producer != tc.producer || first.Completeness != tc.completeness ||
				first.ValidationStatus != "producer_reported" || first.RecommendedSkill != "" {
				t.Fatalf("first import contract: %d %s", rec.Code, rec.Body.String())
			}
			after := f.counts(t)
			want := before
			want.Facts++
			if after != want {
				t.Fatalf("only one observation fact may be written: before=%+v after=%+v", before, after)
			}
			// Then a duplicate preserves the entire stored row, including
			// operator triage and timestamps.
			if _, err := f.s.m.pg.Exec(`UPDATE exploration_nodes SET state='dismissed' WHERE id=$1`, first.FactID); err != nil {
				t.Fatal(err)
			}
			var original, repeated string
			if err := f.s.m.pg.QueryRow(`SELECT row_to_json(n)::text FROM exploration_nodes n WHERE id=$1`, first.FactID).Scan(&original); err != nil {
				t.Fatal(err)
			}
			rec = f.call(t, "POST", f.path(), body, f.token, "application/json", locale.Ko, true)
			var duplicate assessmentReportResult
			if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &duplicate) != nil || !duplicate.Duplicate {
				t.Fatal("retry must return HTTP 200 and duplicate=true")
			}
			duplicate.Duplicate = false
			if first != duplicate {
				t.Fatal("retry changed immutable import identity")
			}
			if err := f.s.m.pg.QueryRow(`SELECT row_to_json(n)::text FROM exploration_nodes n WHERE id=$1`, first.FactID).Scan(&repeated); err != nil {
				t.Fatal(err)
			}
			if original != repeated || f.counts(t) != after {
				t.Fatal("retry mutated stored row or wrote side effects")
			}
		})
	}
}

func TestAssessmentReportsHTTPHistoryAfterDisable(t *testing.T) {
	f := newAssessmentHTTPFixture(t)
	// Given an available operator library entry with no agent binding.
	dir := filepath.Join(f.s.skillDir, "yeepforge")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: yeepforge\ndescription: Synthetic report library fixture\n---\nFixture.\n"), 0600); err != nil {
		t.Fatal(err)
	}
	body := assessmentHTTPBody(t, "yeepforge", "yeepforge-valid")
	rec := f.call(t, "POST", f.path(), body, f.token, "application/json", locale.En, false)
	var imported assessmentReportResult
	if rec.Code != 201 || json.Unmarshal(rec.Body.Bytes(), &imported) != nil ||
		imported.RecommendedSkill != "yeepforge" || imported.RecommendationContext != "operator_library" {
		t.Fatal("operator library availability must be separate from agent visibility")
	}
	other := f.newTask(t)
	before := f.counts(t)
	// When intake is disabled through the actual authenticated settings route.
	rec = f.call(t, "PUT", "/api/settings", `{"security_reports_enabled":false}`, f.token, "application/json", locale.ZhHans, false)
	if rec.Code != 200 {
		t.Fatal("disable failed")
	}
	rec = f.call(t, "POST", f.path(), body, f.token, "application/json", locale.ZhHans, false)
	assessmentHTTPError(t, rec, 403, "assessment_reports_disabled", locale.ZhHans)
	// Then retained sanitized history remains readable without new writes.
	rec = f.call(t, "GET", f.path(), "", f.token, "", locale.ZhHans, false)
	var page struct {
		Reports    []assessmentReportSummary `json:"reports"`
		HasMore    bool                      `json:"has_more"`
		NextBefore int64                     `json:"next_before"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &page) != nil ||
		len(page.Reports) != 1 || page.HasMore || page.NextBefore != 0 {
		t.Fatal("disabled feature hid sanitized history")
	}
	got := page.Reports[0]
	if got.AssessmentID != imported.AssessmentID || got.FactID != imported.FactID ||
		got.ParserVersion != 1 || got.ParserSourceRevision == "" ||
		got.SourceVerification != "unverified" || got.RuntimeVerification != "unverified" ||
		len(got.OriginalSHA256) != 64 || len(got.SanitizedSHA256) != 64 || got.ImportedAt == "" {
		t.Fatal("history omitted safe provenance")
	}
	if strings.Contains(rec.Body.String(), `"observations"`) || strings.Contains(rec.Body.String(), `"detail"`) {
		t.Fatal("history must return bounded summaries, not report bodies")
	}
	rec = f.call(t, "GET", fmt.Sprintf("/api/tasks/%d/assessment-reports", other.ID), "", f.token, "", locale.En, false)
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &page) != nil || len(page.Reports) != 0 {
		t.Fatal("history leaked into an unrelated task")
	}
	if f.counts(t) != before {
		t.Fatal("disabled intake or history wrote side effects")
	}
}

func TestAssessmentReportsHTTPBodyBoundaries(t *testing.T) {
	f := newAssessmentHTTPFixture(t)
	base := `{"producer":"yeepforge","report":{"tool":"YeepForge","findings":[],"ignored":""}}`
	exact := strings.Replace(base, `"ignored":""`, `"ignored":"`+strings.Repeat("x", assessment.MaxInputBytes-len(base))+`"`, 1)
	if len(exact) != assessment.MaxInputBytes {
		t.Fatal("invalid exact-size fixture")
	}
	// Given a complete one-MiB JSON envelope, including discarded report data.
	rec := f.call(t, "POST", f.path(), exact, f.token, "application/json", locale.En, false)
	if rec.Code != 201 {
		t.Fatal("exact-size envelope must be accepted")
	}
	before := f.counts(t)
	// When one extra whitespace byte crosses the total request limit, both
	// known-length and chunked bodies are rejected before any write.
	for _, chunked := range []bool{false, true} {
		rec = f.call(t, "POST", f.path(), exact+" ", f.token, "application/json", locale.En, chunked)
		assessmentHTTPError(t, rec, 413, "assessment_input_too_large", locale.En)
		if f.counts(t) != before {
			t.Fatal("oversized request wrote data")
		}
	}
	for _, count := range []int{assessment.MaxFindings, assessment.MaxFindings + 1} {
		body := `{"producer":"yeepforge","report":{"tool":"YeepForge","findings":[` +
			strings.TrimSuffix(strings.Repeat(`{},`, count), ",") + `]}}`
		rec = f.call(t, "POST", f.path(), body, f.token, "application/json", locale.En, false)
		if count == assessment.MaxFindings {
			if rec.Code != 201 {
				t.Fatal("1000 observations must be accepted")
			}
			before = f.counts(t)
		} else {
			assessmentHTTPError(t, rec, 400, "assessment_invalid_request", locale.En)
			if f.counts(t) != before {
				t.Fatal("finding limit rejection wrote data")
			}
		}
	}
	for _, depth := range []int{assessment.MaxDepth, assessment.MaxDepth + 1} {
		body := `{"producer":"yeepforge","report":{"tool":"YeepForge","findings":[],"ignored":` +
			strings.Repeat("[", depth-2) + "0" + strings.Repeat("]", depth-2) + `}}`
		rec = f.call(t, "POST", f.path(), body, f.token, "application/json", locale.En, false)
		if depth == assessment.MaxDepth {
			if rec.Code != 201 {
				t.Fatal("total envelope depth 32 must be accepted")
			}
			before = f.counts(t)
		} else {
			assessmentHTTPError(t, rec, 400, "assessment_invalid_request", locale.En)
			if f.counts(t) != before {
				t.Fatal("depth limit rejection wrote data")
			}
		}
	}
}

func TestSecurityReportsSetting(t *testing.T) {
	f := newAssessmentHTTPFixture(t)
	if _, err := f.s.m.pg.Exec(`DELETE FROM settings WHERE key=$1`, db.SettingSecurityReportsEnabled); err != nil {
		t.Fatal(err)
	}
	if f.s.m.pg.SecurityReportsEnabled() {
		t.Fatal("missing setting must default off")
	}
	for _, enabled := range []bool{true, false} {
		// Given an explicit authenticated operator toggle.
		rec := f.call(t, "PUT", "/api/settings", fmt.Sprintf(`{"security_reports_enabled":%t}`, enabled), f.token, "application/json", locale.En, false)
		if rec.Code != 200 {
			t.Fatal("setting toggle failed")
		}
		// When a later settings write omits the toggle.
		rec = f.call(t, "PUT", "/api/settings", `{}`, f.token, "application/json", locale.En, false)
		var payload struct {
			Enabled bool `json:"security_reports_enabled"`
		}
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &payload) != nil || payload.Enabled != enabled {
			t.Fatal("omitted setting lost operator toggle")
		}
		rec = f.call(t, "GET", "/api/settings", "", f.token, "", locale.En, false)
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &payload) != nil || payload.Enabled != enabled {
			t.Fatal("setting read lost operator toggle")
		}
		// Then a real DB reopen preserves the value.
		reopened, err := db.Open(os.Getenv("ARTEX_PG_DSN"))
		if err != nil {
			t.Fatal(err)
		}
		preserved := reopened.SecurityReportsEnabled()
		if err := reopened.Close(); err != nil {
			t.Fatal(err)
		}
		if preserved != enabled {
			t.Fatal("schema reapply lost operator toggle")
		}
	}
}
