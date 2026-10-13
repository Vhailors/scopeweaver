package db

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/assessment"
)

var assessmentTestTime = time.Date(2026, 10, 13, 12, 30, 0, 0, time.UTC)

func assessmentFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "e2e", "fixtures", "security-tools", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func assessmentParsed(t *testing.T) *assessment.Report {
	t.Helper()
	report, err := assessment.Parse("yeepforge", assessmentFixture(t, "yeepforge-valid"), assessmentTestTime)
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func TestAssessmentImportFixtures(t *testing.T) {
	d := assessmentDB(t)
	task := assessmentTask(t, d)
	for _, tc := range []struct {
		name, producer, completeness string
		count, errors                int
		wantErr                      error
	}{
		{"yeepforge-valid", "yeepforge", "unknown", 2, 0, nil},
		{"yeepforge-empty", "yeepforge", "no_observations", 0, 0, nil},
		{"adstrike-valid", "adstrike", "unknown", 2, 0, nil},
		{"adstrike-empty", "adstrike", "no_observations", 0, 0, nil},
		{"confirmesc-valid", "confirmesc", "unknown", 3, 0, nil},
		{"confirmesc-empty", "confirmesc", "no_observations", 0, 0, nil},
		{"confirmesc-errorful", "confirmesc", "has_errors", 1, 1, nil},
		{"yeepforge-wrong-profile", "yeepforge", "", 0, 0, assessment.ErrUnsupportedProfile},
		{"adstrike-wrong-profile", "adstrike", "", 0, 0, assessment.ErrUnsupportedProfile},
		{"confirmesc-wrong-profile", "confirmesc", "", 0, 0, assessment.ErrUnsupportedProfile},
		{"malformed", "yeepforge", "", 0, 0, assessment.ErrMalformedJSON},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Given: exact synthetic producer bytes and an enabled live task.
			raw := assessmentFixture(t, tc.name)
			before := assessmentCounts(t, d, task)
			report, err := assessment.Parse(tc.producer, raw, assessmentTestTime)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) || report != nil {
					t.Fatalf("invalid fixture accepted: %v", err)
				}
				node, duplicate, storeErr := d.Exploration(task.ExplorationID).ImportAssessment(t.Context(), task.ID, report)
				if node != nil || duplicate || !errors.Is(storeErr, assessment.ErrInvalidType) {
					t.Fatalf("failed parse reached storage: node=%v duplicate=%v err=%v", node, duplicate, storeErr)
				}
				if after := assessmentCounts(t, d, task); after != before {
					t.Fatalf("rejected fixture published data: before=%+v after=%+v", before, after)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			// When: the real importer commits one observation fact.
			node, duplicate, err := d.Exploration(task.ExplorationID).ImportAssessment(t.Context(), task.ID, report)
			if err != nil || node == nil || duplicate {
				t.Fatalf("import: node=%v duplicate=%v err=%v", node, duplicate, err)
			}
			// Then: counts and provenance survive without producer prose.
			var stored assessment.Report
			if err := json.Unmarshal(node.Payload, &stored); err != nil {
				t.Fatal(err)
			}
			original := sha256.Sum256(raw)
			id := sha256.Sum256([]byte(tc.producer + "\x00" + stored.Import.ParserProfile + "\x00" + hex.EncodeToString(original[:])))
			canonical, err := stored.Import.CanonicalJSON()
			if err != nil {
				t.Fatal(err)
			}
			sanitized := sha256.Sum256(canonical)
			if !reflect.DeepEqual(stored, *report) || stored.AssessmentID != hex.EncodeToString(id[:]) ||
				stored.Import.OriginalSHA256 != hex.EncodeToString(original[:]) ||
				stored.Import.SanitizedSHA256 != hex.EncodeToString(sanitized[:]) ||
				stored.Import.ObservationCount != tc.count || stored.Import.ErrorCount != tc.errors ||
				stored.Import.Completeness != tc.completeness || stored.Import.ValidationStatus != "producer_reported" ||
				stored.Import.SourceVerification != "unverified" || stored.Import.RuntimeVerification != "unverified" ||
				node.Kind != KindFact || node.State != "confirmed" {
				t.Fatal("stored counts, digest, provenance or observation semantics differ")
			}
			if strings.Contains(string(node.Payload), "scopeweaver-secret-canary-01") {
				t.Fatal("canary persisted")
			}
			want := before
			want.Facts++
			if after := assessmentCounts(t, d, task); after != want {
				t.Fatalf("unexpected publication: got=%+v want=%+v", after, want)
			}
			t.Logf("fixture=%s fact_id=%d assessment_id=%s original=%s sanitized=%s observations=%d errors=%d completeness=%s",
				tc.name, node.ID, stored.AssessmentID, stored.Import.OriginalSHA256, stored.Import.SanitizedSHA256,
				tc.count, tc.errors, tc.completeness)
		})
	}
}

func TestAssessmentImportDuplicatePreservesTriage(t *testing.T) {
	// Given: a retained fact with operator triage and an unrelated finding.
	d := assessmentDB(t)
	task := assessmentTask(t, d)
	store := d.Exploration(task.ExplorationID)
	report := assessmentParsed(t)
	first, _, err := store.ImportAssessment(t.Context(), task.ID, report)
	if err != nil {
		t.Fatal(err)
	}
	assessmentExec(t, d, `UPDATE exploration_nodes SET state='dismissed', priority=7, owner='operator',
blocked_reason='reviewed', content_version=11, completed_at='2026-10-13T13:00:00Z',
payload=payload || '{"triage":"retained"}'::jsonb WHERE id=$1`, first.ID)
	var findingID int64
	if err := d.QueryRow(`INSERT INTO findings(task_id,name,severity,status) VALUES($1,'retained','high','resolved') RETURNING id`, task.ID).Scan(&findingID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { assessmentExec(t, d, `DELETE FROM findings WHERE id=$1`, findingID) })
	before := assessmentRow(t, d, "exploration_nodes", first.ID)
	findingBefore := assessmentRow(t, d, "findings", findingID)
	later, err := assessment.Parse("yeepforge", assessmentFixture(t, "yeepforge-valid"), assessmentTestTime.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// When: the same bytes arrive with a different application import time.
	repeated, duplicate, err := store.ImportAssessment(t.Context(), task.ID, later)
	// Then: return the old fact and retain every column, including timestamps.
	if err != nil || repeated == nil || !duplicate || repeated.ID != first.ID || repeated.State != "dismissed" ||
		assessmentRow(t, d, "exploration_nodes", first.ID) != before ||
		assessmentRow(t, d, "findings", findingID) != findingBefore {
		t.Fatalf("duplicate changed retained data: duplicate=%v err=%v", duplicate, err)
	}
	t.Logf("duplicate fact_id=%d full_row_immutable=true existing_finding_immutable=true", first.ID)
}

func TestDirectSourceAssessmentImport(t *testing.T) {
	// Given: a current task with one explicit direct source.
	d := assessmentDB(t)
	source := assessmentTask(t, d)
	current := assessmentTask(t, d)
	assessmentExec(t, d, `INSERT INTO task_relations(task_id,source_task_id) VALUES($1,$2)`, current.ID, source.ID)
	report := assessmentParsed(t)
	node, _, err := d.Exploration(source.ExplorationID).ImportAssessment(t.Context(), source.ID, report)
	if err != nil {
		t.Fatal(err)
	}
	// When: current task reads the source fact and tries to write through it.
	inherited, err := d.Exploration(current.ExplorationID).GetNodeWithSources(node.ID)
	if err != nil || inherited == nil || !inherited.Inherited || inherited.SourceTaskID != source.ID ||
		string(inherited.Payload) != string(node.Payload) {
		t.Fatalf("sanitized provenance lost through source read: node=%v err=%v", inherited, err)
	}
	rejected, duplicate, err := d.Exploration(source.ExplorationID).ImportAssessment(t.Context(), current.ID, report)
	// Then: inherited data is reusable, never a writable destination.
	if rejected != nil || duplicate || !errors.Is(err, ErrAssessmentTaskUnavailable) {
		t.Fatalf("inherited task accepted: node=%v duplicate=%v err=%v", rejected, duplicate, err)
	}
	local, _, err := d.Exploration(current.ExplorationID).ImportAssessment(t.Context(), current.ID, report)
	if err != nil || local == nil || local.ID == node.ID {
		t.Fatalf("identity must be exploration-scoped: node=%v err=%v", local, err)
	}
}
