package assessment_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/assessment"
)

func TestAssessmentReportMalformedJSON(t *testing.T) {
	for _, tc := range []struct{ name, raw string }{
		{"empty", ""},
		{"truncated", `{"tool":"YeepForge","findings":[],"` + canary + `":`},
		{"trailing_object", `{"tool":"YeepForge","findings":[]} {"` + canary + `":true}`},
		{"trailing_text", `{"tool":"YeepForge","findings":[]} ` + canary},
		{"duplicate_marker", `{"tool":"YeepForge","tool":"` + canary + `","findings":[]}`},
		{"escaped_duplicate", `{"tool":"YeepForge","findings":[],"discard":{"a":0,"\u0061":"` + canary + `"}}`},
		{"malformed_discarded_value", `{"tool":"YeepForge","findings":[],"discard":[1,]}`},
		{"invalid_number", `{"tool":"YeepForge","findings":[],"discard":NaN}`},
		{"invalid_utf8", `{"tool":"YeepForge","findings":[],"discard":"` + string([]byte{0xff}) + `"}`},
		{"broken_container", `{"tool":"YeepForge","findings":[}`},
		{"unclosed_discard", `{"tool":"YeepForge","findings":[],"discard":{"` + canary + `":true}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireRejected(t, "yeepforge", []byte(tc.raw), assessment.ErrMalformedJSON)
		})
	}
}

func TestAssessmentReportLimits(t *testing.T) {
	t.Run("exact_byte_limit", func(t *testing.T) {
		raw := []byte(`{"tool":"YeepForge","findings":[]}`)
		raw = append(raw, bytes.Repeat([]byte(" "), assessment.MaxInputBytes-len(raw))...)
		parsed(t, "yeepforge", raw)
	})
	t.Run("oversize", func(t *testing.T) {
		raw := bytes.Repeat([]byte(" "), assessment.MaxInputBytes+1)
		copy(raw, canary)
		requireRejected(t, "yeepforge", raw, assessment.ErrTooLarge)
	})
	for _, depth := range []int{32, 33} {
		name := "depth_32"
		if depth == 33 {
			name = "depth_33"
		}
		t.Run(name, func(t *testing.T) {
			// The root object is depth 1; unknown values are still bounded.
			raw := `{"tool":"YeepForge","findings":[],"` + canary + `":` +
				strings.Repeat("[", depth-1) + `"` + canary + `"` + strings.Repeat("]", depth-1) + `}`
			if depth == 33 {
				requireRejected(t, "yeepforge", []byte(raw), assessment.ErrTooDeep)
			} else {
				parsed(t, "yeepforge", []byte(raw))
			}
		})
	}
	for _, count := range []int{1000, 1001} {
		name := "findings_1000"
		if count == 1001 {
			name = "findings_1001"
		}
		t.Run(name, func(t *testing.T) {
			findings := make([]any, count)
			for i := range findings {
				findings[i] = map[string]any{"severity": "Info", "title": canary}
			}
			raw := encoded(t, map[string]any{"tool": "YeepForge", "findings": findings})
			if count == 1001 {
				requireRejected(t, "yeepforge", raw, assessment.ErrTooManyFindings)
			} else {
				report := parsed(t, "yeepforge", raw)
				if report.Import.ObservationCount != 1000 || len(report.Detail) > 8192 {
					t.Fatal("missing observations or unbounded generated detail")
				}
			}
		})
	}
	t.Run("identifier_limit", func(t *testing.T) {
		ids := make([]string, assessment.MaxIdentifiers+1)
		for i := range ids {
			ids[i] = canary
		}
		raw := encoded(t, map[string]any{"schema_version": "2.0", "findings": []any{
			map[string]any{"mitre_ids": ids},
		}})
		requireRejected(t, "adstrike", raw, assessment.ErrTooManyIdentifiers)
	})
}

func TestAssessmentReportRetainedFieldTypes(t *testing.T) {
	cases := []struct {
		name, producer, raw string
	}{
		{"root_array", "yeepforge", `[]`},
		{"root_null", "yeepforge", `null`},
		{"missing_findings", "yeepforge", `{"tool":"YeepForge"}`},
		{"findings_null", "yeepforge", `{"tool":"YeepForge","findings":null}`},
		{"findings_object", "yeepforge", `{"tool":"YeepForge","findings":{}}`},
		{"finding_null", "yeepforge", `{"tool":"YeepForge","findings":[null]}`},
		{"finding_array", "yeepforge", `{"tool":"YeepForge","findings":[[]]}`},
		{"finding_number", "yeepforge", `{"tool":"YeepForge","findings":[1]}`},
		{"severity_object", "yeepforge", `{"tool":"YeepForge","findings":[{"severity":{}}]}`},
		{"cwe_number", "yeepforge", `{"tool":"YeepForge","findings":[{"cwe":79}]}`},
		{"cve_array", "confirmesc", `{"meta":{},"errors":{},"findings":[{"cve":[]}]}`},
		{"owasp_object", "yeepforge", `{"tool":"YeepForge","findings":[{"owasp":{}}]}`},
		{"confidence_number", "confirmesc", `{"meta":{},"errors":{},"findings":[{"confidence":1}]}`},
		{"timestamp_number", "adstrike", `{"schema_version":"2.0","findings":[{"timestamp":1}]}`},
		{"report_timestamp_array", "yeepforge", `{"tool":"YeepForge","generated":[],"findings":[]}`},
		{"cvss_scalar", "adstrike", `{"schema_version":"2.0","findings":[{"cvss":7.5}]}`},
		{"cvss_string_score", "adstrike", `{"schema_version":"2.0","findings":[{"cvss":{"score":"7.5"}}]}`},
		{"cvss_bool", "adstrike", `{"schema_version":"2.0","findings":[{"cvss":{"score":true}}]}`},
		{"cvss_negative", "adstrike", `{"schema_version":"2.0","findings":[{"cvss":{"score":-0.1}}]}`},
		{"cvss_above_ten", "adstrike", `{"schema_version":"2.0","findings":[{"cvss":{"score":10.1}}]}`},
		{"cvss_overflow", "adstrike", `{"schema_version":"2.0","findings":[{"cvss":{"score":1e999}}]}`},
		{"mitre_string", "adstrike", `{"schema_version":"2.0","findings":[{"mitre_ids":"T1068"}]}`},
		{"mitre_number", "adstrike", `{"schema_version":"2.0","findings":[{"mitre_ids":[1068]}]}`},
		{"mitre_null", "adstrike", `{"schema_version":"2.0","findings":[{"mitre_ids":[null]}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			requireRejected(t, tc.producer, []byte(tc.raw), assessment.ErrInvalidType)
		})
	}
	for _, raw := range []string{
		`{"tool":1,"findings":[]}`,
		`{"schema_version":2,"findings":[]}`,
		`{"meta":{},"findings":[]}`,
		`{"meta":{},"errors":[],"findings":[]}`,
	} {
		producer := "confirmesc"
		if strings.Contains(raw, `"tool"`) {
			producer = "yeepforge"
		} else if strings.Contains(raw, `"schema_version"`) {
			producer = "adstrike"
		}
		requireRejected(t, producer, []byte(raw), assessment.ErrUnsupportedProfile)
	}
}

func TestAssessmentReportInvalidImportTime(t *testing.T) {
	for _, timestamp := range []time.Time{
		{},
		time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(1, 1, 1, 0, 0, 0, 0, time.FixedZone("east", 14*60*60)),
	} {
		report, err := assessment.Parse("yeepforge", fixture(t, "yeepforge-valid"), timestamp)
		requireNoCanary(t, report, err)
		if !errors.Is(err, assessment.ErrInvalidImportTime) || report != nil {
			t.Fatal("invalid import time accepted")
		}
	}
}

func TestAssessmentReportNoPartialSuccess(t *testing.T) {
	raw := []byte(`{"tool":"YeepForge","findings":[{"severity":"High"},{"severity":{"` + canary + `":true}}]}`)
	requireRejected(t, "yeepforge", raw, assessment.ErrInvalidType)
	// A misleading producer success flag cannot bypass any structural error.
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	value["success"] = true
	value["validation_status"] = "confirmed"
	requireRejected(t, "yeepforge", encoded(t, value), assessment.ErrInvalidType)
}
