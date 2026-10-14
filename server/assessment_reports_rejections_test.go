package server

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/locale"
)

func TestAssessmentReportsHTTPRejections(t *testing.T) {
	f := newAssessmentHTTPFixture(t)
	valid := assessmentHTTPBody(t, "yeepforge", "yeepforge-valid")
	for _, tc := range []struct {
		name, method, body, media, auth, code string
		status                                int
	}{
		{"missing-auth-post", "POST", valid, "application/json", "missing", "assessment_unauthorized", 401},
		{"invalid-auth-post", "POST", valid, "application/json", "invalid", "assessment_unauthorized", 401},
		{"missing-auth-get", "GET", "", "", "missing", "assessment_unauthorized", 401},
		{"invalid-auth-get", "GET", "", "", "invalid", "assessment_unauthorized", 401},
		{"disabled", "POST", valid, "application/json", "", "assessment_reports_disabled", 403},
		{"missing-setting", "POST", valid, "application/json", "", "assessment_reports_disabled", 403},
		{"missing-task-post", "POST", valid, "application/json", "", "assessment_task_unavailable", 404},
		{"missing-task-get", "GET", "", "", "", "assessment_task_unavailable", 404},
		{"deleted-task-post", "POST", valid, "application/json", "", "assessment_task_unavailable", 404},
		{"deleted-task-get", "GET", "", "", "", "assessment_task_unavailable", 404},
		{"invalid-task-id", "POST", valid, "application/json", "", "assessment_task_unavailable", 404},
		{"missing-media", "POST", valid, "", "", "assessment_content_type", 415},
		{"plain-text", "POST", valid, "text/plain", "", "assessment_content_type", 415},
		{"multipart", "POST", valid, "multipart/form-data; boundary=synthetic", "", "assessment_content_type", 415},
		{"invalid-media", "POST", valid, "application/json; =invalid", "", "assessment_content_type", 415},
		{"unsupported-producer", "POST", strings.Replace(valid, `"yeepforge"`, `"unsupported"`, 1), "application/json", "", "assessment_unsupported_producer", 422},
		{"yeepforge-wrong-profile", "POST", assessmentHTTPBody(t, "yeepforge", "yeepforge-wrong-profile"), "application/json", "", "assessment_unsupported_profile", 422},
		{"adstrike-wrong-profile", "POST", assessmentHTTPBody(t, "adstrike", "adstrike-wrong-profile"), "application/json", "", "assessment_unsupported_profile", 422},
		{"confirmesc-wrong-profile", "POST", assessmentHTTPBody(t, "confirmesc", "confirmesc-wrong-profile"), "application/json", "", "assessment_unsupported_profile", 422},
		{"malformed", "POST", `{"producer":"yeepforge","report":` + assessmentHTTPCanary, "application/json", "", "assessment_invalid_request", 400},
		{"empty", "POST", "", "application/json", "", "assessment_invalid_request", 400},
		{"outer-null", "POST", "null", "application/json", "", "assessment_invalid_request", 400},
		{"outer-array", "POST", "[]", "application/json", "", "assessment_invalid_request", 400},
		{"producer-null", "POST", `{"producer":null,"report":{}}`, "application/json", "", "assessment_invalid_request", 400},
		{"producer-type", "POST", `{"producer":1,"report":{}}`, "application/json", "", "assessment_invalid_request", 400},
		{"report-null", "POST", `{"producer":"yeepforge","report":null}`, "application/json", "", "assessment_invalid_request", 400},
		{"report-array", "POST", `{"producer":"yeepforge","report":[]}`, "application/json", "", "assessment_invalid_request", 400},
		{"missing-report", "POST", `{"producer":"yeepforge"}`, "application/json", "", "assessment_invalid_request", 400},
		{"missing-producer", "POST", `{"report":{}}`, "application/json", "", "assessment_invalid_request", 400},
		{"caller-identity", "POST", strings.Replace(valid, `{"producer"`, `{"actor":"`+assessmentHTTPCanary+`","producer"`, 1), "application/json", "", "assessment_invalid_request", 400},
		{"caller-task", "POST", strings.Replace(valid, `{"producer"`, `{"task_id":1,"producer"`, 1), "application/json", "", "assessment_invalid_request", 400},
		{"caller-source", "POST", strings.Replace(valid, `{"producer"`, `{"source_task_id":1,"producer"`, 1), "application/json", "", "assessment_invalid_request", 400},
		{"caller-file", "POST", strings.Replace(valid, `{"producer"`, `{"filename":"fixture.json","producer"`, 1), "application/json", "", "assessment_invalid_request", 400},
		{"duplicate-producer", "POST", strings.Replace(valid, `{"producer"`, `{"producer":"unsupported","producer"`, 1), "application/json", "", "assessment_invalid_request", 400},
		{"escaped-duplicate", "POST", strings.Replace(valid, `{"producer"`, `{"\u0070roducer":"yeepforge","producer"`, 1), "application/json", "", "assessment_invalid_request", 400},
		{"duplicate-report-key", "POST", `{"producer":"yeepforge","report":{"tool":"YeepForge","tool":"YeepForge","findings":[]}}`, "application/json", "", "assessment_invalid_request", 400},
		{"trailing-json", "POST", valid + `{}`, "application/json", "", "assessment_invalid_request", 400},
		{"trailing-garbage", "POST", valid + assessmentHTTPCanary, "application/json", "", "assessment_invalid_request", 400},
		{"invalid-utf8", "POST", strings.Replace(valid, "Synthetic", "\xff", 1), "application/json", "", "assessment_invalid_request", 400},
		{"findings-type", "POST", `{"producer":"yeepforge","report":{"tool":"YeepForge","findings":null}}`, "application/json", "", "assessment_invalid_request", 400},
		{"last-finding-type", "POST", `{"producer":"yeepforge","report":{"tool":"YeepForge","findings":[{},null]}}`, "application/json", "", "assessment_invalid_request", 400},
		{"cvss-range", "POST", `{"producer":"adstrike","report":{"schema_version":"2.0","findings":[{},{"cvss":{"score":11}}]}}`, "application/json", "", "assessment_invalid_request", 400},
		{"invalid-cursor", "GET", "", "", "", "assessment_invalid_request", 400},
	} {
		for _, lang := range locale.Languages() {
			t.Run(tc.name+"/"+string(lang), func(t *testing.T) {
				// Given a rejection fixture with no trusted caller identities.
				f.enabled(t, true)
				path, token := f.path(), f.token
				switch tc.name {
				case "disabled":
					f.enabled(t, false)
				case "missing-setting":
					if _, err := f.s.m.pg.Exec(`DELETE FROM settings WHERE key='security_reports_enabled'`); err != nil {
						t.Fatal(err)
					}
				case "missing-task-post", "missing-task-get":
					path = "/api/tasks/9223372036854775807/assessment-reports"
				case "deleted-task-post", "deleted-task-get":
					deleted := f.newTask(t)
					if _, err := f.s.m.pg.Exec(`UPDATE tasks SET deleted_at=now() WHERE id=$1`, deleted.ID); err != nil {
						t.Fatal(err)
					}
					path = fmt.Sprintf("/api/tasks/%d/assessment-reports", deleted.ID)
				case "invalid-task-id":
					path = "/api/tasks/bad/assessment-reports"
				case "invalid-cursor":
					path += "?before=-1"
				}
				switch tc.auth {
				case "missing":
					token = ""
				case "invalid":
					token = "invalid-synthetic-token"
				}
				before := f.counts(t)
				// When the actual authenticated mux processes the entire request.
				rec := f.call(t, tc.method, path, tc.body, token, tc.media, lang, false)
				// Then fixed localized errors reject without writes or leaks.
				assessmentHTTPError(t, rec, tc.status, tc.code, lang)
				if f.counts(t) != before {
					t.Fatal("rejected request wrote persistent state")
				}
			})
		}
	}
}
