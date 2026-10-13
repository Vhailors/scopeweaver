package assessment_test

import (
	"fmt"
	"reflect"
	"testing"
)

func TestAssessmentReportProducerSemantics(t *testing.T) {
	yeepforge := parsed(t, "yeepforge", fixture(t, "yeepforge-valid")).Import
	if yeepforge.Observations[0].CVSS != nil || yeepforge.Observations[1].Severity != "info" ||
		yeepforge.ObservedAt != "2026-10-13T12:00:00.000001" {
		t.Fatal("aggregate risk was promoted, INFO elevated or naive timestamp altered")
	}
	adstrike := parsed(t, "adstrike", fixture(t, "adstrike-valid")).Import
	if adstrike.Observations[0].CVSS == nil || *adstrike.Observations[0].CVSS != 7.5 ||
		adstrike.Observations[1].CVSS == nil || *adstrike.Observations[1].CVSS != 0 ||
		!reflect.DeepEqual(adstrike.Observations[0].ATTACK, []string{"T1068"}) ||
		adstrike.Observations[0].Confidence != "unknown" ||
		adstrike.Observations[0].ObservedAt != "2026-10-13T11:59:00.000001" {
		t.Fatal("nested finding CVSS, ATT&CK or timestamp semantics changed")
	}
	confirmesc := parsed(t, "confirmesc", fixture(t, "confirmesc-valid")).Import
	for i, confidence := range []string{"confirmed", "likely", "info"} {
		observation := confirmesc.Observations[i]
		if observation.Confidence != confidence || observation.Severity != "unknown" ||
			observation.CVSS != nil || observation.ObservedAt != "" {
			t.Fatal("producer certainty incorrectly promoted to severity or local confirmation")
		}
	}
	if confirmesc.ObservedAt != "" || confirmesc.ValidationStatus != "producer_reported" {
		t.Fatal("invented confirmesc timestamp or local validation")
	}
	for _, tc := range []struct {
		name, raw, completeness string
		count                   int
	}{
		{"empty_errorful", `{"meta":{},"errors":{"` + canary + `":"` + canary + `"},"findings":[]}`, "has_errors", 1},
		{"confidence_error", `{"meta":{},"errors":{},"findings":[{"confidence":"ERROR"}]}`, "has_errors", 0},
		{"lowercase_certainty", `{"meta":{},"errors":{},"findings":[{"confidence":"confirmed"}]}`, "unknown", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := parsed(t, "confirmesc", []byte(tc.raw))
			if report.Import.Completeness != tc.completeness || report.Import.ErrorCount != tc.count {
				t.Fatal("empty/errorful structural semantics changed")
			}
			if tc.name == "lowercase_certainty" && report.Import.Observations[0].Confidence != "unknown" {
				t.Fatal("non-native confidence string accepted")
			}
		})
	}
	report := parsed(t, "yeepforge", []byte(`{"tool":"YeepForge","findings":[],"errors":{"`+canary+`":"failure"},"success":true}`))
	if report.Import.ErrorCount != 0 || report.Import.Completeness != "no_observations" {
		t.Fatal("invented native error envelope or clean-assessment claim")
	}
}

func TestAssessmentReportClassifications(t *testing.T) {
	for _, tc := range []struct {
		name, producer, finding string
		cwe, cve, owasp, attack []string
	}{
		{"yeepforge_identifiers", "yeepforge", `{"cwe":"CWE-79","cve":"CVE-2021-4034","owasp":"A03:2021"}`,
			[]string{"CWE-79"}, []string{"CVE-2021-4034"}, []string{"A03:2021"}, nil},
		{"adstrike_techniques", "adstrike", `{"mitre_ids":["T1068","privilege-escalation","T1003.001","T1068","TA0004","T0000"]}`,
			nil, nil, nil, []string{"T1003.001", "T1068"}},
		{"injected_identifiers", "yeepforge", `{"cwe":"CWE-79 ` + canary + `","cve":"CVE-2021-4034\n` + canary + `","owasp":"A03:2021;` + canary + `"}`,
			nil, nil, nil, nil},
		{"invalid_identifiers", "yeepforge", `{"cwe":"CWE-0","cve":"CVE-21-4034","owasp":"A11:2021"}`,
			nil, nil, nil, nil},
		{"unknown_severity", "yeepforge", `{"severity":"` + canary + `"}`,
			nil, nil, nil, nil},
		{"unknown_confidence", "confirmesc", `{"confidence":"` + canary + `"}`,
			nil, nil, nil, nil},
		{"unrelated_fields", "confirmesc", `{"timestamp":"2026-10-13T12:00:00Z","cvss":{"score":10},"owasp":"A03:2021","mitre_ids":["T1068"]}`,
			nil, nil, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			envelope := `{"tool":"YeepForge",`
			switch tc.producer {
			case "adstrike":
				envelope = `{"schema_version":"2.0",`
			case "confirmesc":
				envelope = `{"meta":{},"errors":{},`
			}
			report := parsed(t, tc.producer, []byte(envelope+`"findings":[`+tc.finding+`]}`))
			o := report.Import.Observations[0]
			if !reflect.DeepEqual(o.CWE, tc.cwe) || !reflect.DeepEqual(o.CVE, tc.cve) ||
				!reflect.DeepEqual(o.OWASP, tc.owasp) || !reflect.DeepEqual(o.ATTACK, tc.attack) ||
				o.Index != 0 || o.SourcePointer != "/findings/0" {
				t.Fatalf("unexpected retained identifiers/pointer: %+v", o)
			}
			if len(o.Title) == 0 || len(o.Guidance) == 0 {
				t.Fatal("generated title/guidance absent")
			}
		})
	}
	zero := parsed(t, "adstrike", []byte(`{"schema_version":"2.0","findings":[{"cvss":{"score":-0}}]}`))
	positive := parsed(t, "adstrike", []byte(`{"schema_version":"2.0","findings":[{"cvss":{"score":0.0}}]}`))
	if zero.Import.SanitizedSHA256 != positive.Import.SanitizedSHA256 {
		t.Fatal("equivalent numeric scores changed canonical digest")
	}
}

func TestAssessmentReportTimestamps(t *testing.T) {
	for index, tc := range []struct{ value, want string }{
		{"2026-10-13T12:00:00.000001", "2026-10-13T12:00:00.000001"},
		{"2026-10-13T12:00:00", "2026-10-13T12:00:00"},
		{"2026-10-13T12:00:00.100000", "2026-10-13T12:00:00.1"},
		{"2026-10-13T12:00:00Z", "2026-10-13T12:00:00Z"},
		{"2026-10-13T12:00:00+00:00", "2026-10-13T12:00:00+00:00"},
		{"2026-10-13T12:00:00-00:00", "2026-10-13T12:00:00-00:00"},
		{"2026-10-13T12:00:00+09:00", "2026-10-13T12:00:00+09:00"},
		{"2026-02-30T12:00:00", ""},
		{"2026-10-13T25:00:00", ""},
		{"2026-10-13T12:00:00+24:00", ""},
		{"0000-10-13T12:00:00Z", ""},
		{"2026-10-13T12:00:00.1234567890", ""},
		{canary, ""},
		{"", ""},
	} {
		t.Run(fmt.Sprintf("case_%02d", index), func(t *testing.T) {
			raw := encoded(t, map[string]any{"tool": "YeepForge", "findings": []any{}, "generated": tc.value})
			report := parsed(t, "yeepforge", raw)
			if report.Import.ObservedAt != tc.want {
				t.Fatalf("timestamp=%q want=%q", report.Import.ObservedAt, tc.want)
			}
		})
	}
	// confirmesc exports no timestamp; unknown timestamps at any level drop.
	report := parsed(t, "confirmesc", []byte(`{"meta":{"timestamp":"2026-10-13T12:00:00Z"},"errors":{},"findings":[],"generated_at":"2026-10-13T12:00:00Z"}`))
	if report.Import.ObservedAt != "" {
		t.Fatal("unknown timestamp retained")
	}
}
