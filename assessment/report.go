// Package assessment normalizes supplied reports as producer-reported data.
// It does not execute producers, retain their prose, or confirm vulnerabilities.
package assessment

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const ParserVersion = 1

// Observation contains only generated text and validated producer fields.
// Confidence is the producer's certainty, not local validation.
type Observation struct {
	Index         int      `json:"index"`
	SourcePointer string   `json:"source_pointer"`
	Severity      string   `json:"producer_severity"`
	Confidence    string   `json:"producer_confidence"`
	CVSS          *float64 `json:"producer_cvss,omitempty"`
	CWE           []string `json:"cwe,omitempty"`
	CVE           []string `json:"cve,omitempty"`
	OWASP         []string `json:"owasp,omitempty"`
	ATTACK        []string `json:"attack,omitempty"`
	ObservedAt    string   `json:"observed_at,omitempty"`
	Title         string   `json:"title"`
	Guidance      string   `json:"guidance"`
}

// SanitizedReport is the entire canonical digest input. encoding/json fixes
// struct key order; identifier sets are sorted and findings stay in source order.
// Original byte hashes, assessment identity and import time are excluded so
// reordering input object keys does not change the sanitized digest.
type SanitizedReport struct {
	Producer             string        `json:"producer"`
	ParserProfile        string        `json:"parser_profile"`
	ParserVersion        int           `json:"parser_version"`
	ParserSourceRevision string        `json:"parser_source_revision"`
	SourceVerification   string        `json:"source_verification"`
	RuntimeVerification  string        `json:"runtime_verification"`
	ValidationStatus     string        `json:"validation_status"`
	ObservedAt           string        `json:"observed_at,omitempty"`
	ObservationCount     int           `json:"observation_count"`
	ErrorCount           int           `json:"error_count"`
	Completeness         string        `json:"completeness"`
	Observations         []Observation `json:"observations"`
}

type AssessmentImport struct {
	SanitizedReport
	OriginalSHA256  string `json:"original_sha256"`
	SanitizedSHA256 string `json:"sanitized_sha256"`
	ImportedAt      string `json:"imported_at"`
}

// Report is ready for Task 5's single observation fact. Parse performs no writes.
type Report struct {
	AssessmentID string           `json:"assessment_id"`
	Summary      string           `json:"summary"`
	Detail       string           `json:"detail"`
	Import       AssessmentImport `json:"assessment_import"`
}

// Parse validates the whole report before returning any retained values.
// importedAt is application-owned; no producer or caller actor identity is read.
func Parse(producer string, raw []byte, importedAt time.Time) (*Report, error) {
	profile, revision, err := producerProfile(producer)
	if err != nil {
		return nil, err
	}
	if err := validateJSON(raw); err != nil {
		return nil, err
	}
	root, err := object(raw)
	if err != nil {
		return nil, err
	}
	if err := validateProfile(producer, root); err != nil {
		return nil, err
	}
	findings, err := array(root["findings"])
	if err != nil {
		return nil, err
	}
	if len(findings) > MaxFindings {
		return nil, ErrTooManyFindings
	}
	importedAt = importedAt.UTC()
	if importedAt.IsZero() || importedAt.Year() < 1 || importedAt.Year() > 9999 {
		return nil, ErrInvalidImportTime
	}
	sanitized := SanitizedReport{
		Producer: producer, ParserProfile: profile, ParserVersion: ParserVersion,
		ParserSourceRevision: revision, SourceVerification: "unverified",
		RuntimeVerification: "unverified", ValidationStatus: "producer_reported",
		ObservationCount: len(findings), Completeness: "unknown",
		Observations: make([]Observation, 0, len(findings)),
	}
	switch producer {
	case "yeepforge":
		sanitized.ObservedAt, err = timestampField(root, "generated")
	case "adstrike":
		sanitized.ObservedAt, err = timestampField(root, "generated_at")
	case "confirmesc":
		exportedErrors, objectErr := object(root["errors"])
		if objectErr != nil {
			return nil, objectErr
		}
		sanitized.ErrorCount = len(exportedErrors)
	}
	if err != nil {
		return nil, err
	}
	hasErrors := sanitized.ErrorCount > 0
	for index, rawFinding := range findings {
		finding, err := object(rawFinding)
		if err != nil {
			return nil, err
		}
		observation, err := normalizeObservation(producer, finding, index)
		if err != nil {
			return nil, err
		}
		hasErrors = hasErrors || observation.Confidence == "error"
		sanitized.Observations = append(sanitized.Observations, observation)
	}
	switch {
	case hasErrors:
		sanitized.Completeness = "has_errors"
	case len(findings) == 0:
		sanitized.Completeness = "no_observations"
	}
	canonical, err := sanitized.CanonicalJSON()
	if err != nil {
		return nil, ErrInvalidType
	}
	originalHash := digest(raw)
	report := &Report{
		AssessmentID: digest([]byte(producer + "\x00" + profile + "\x00" + originalHash)),
		Import: AssessmentImport{
			SanitizedReport: sanitized, OriginalSHA256: originalHash,
			SanitizedSHA256: digest(canonical),
			ImportedAt:      importedAt.Format(time.RFC3339Nano),
		},
	}
	report.Summary = fmt.Sprintf("%s: %d producer-reported observations (%s)",
		producer, len(findings), sanitized.Completeness)
	report.Detail = renderDetail(sanitized)
	return report, nil
}

func (r SanitizedReport) CanonicalJSON() ([]byte, error) {
	return json.Marshal(r)
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func normalizeObservation(producer string, fields map[string]json.RawMessage, index int) (Observation, error) {
	observation := Observation{
		Index: index, SourcePointer: fmt.Sprintf("/findings/%d", index),
		Severity: "unknown", Confidence: "unknown",
	}
	var err error
	if producer == "confirmesc" {
		observation.Confidence, err = confidenceField(fields)
	} else {
		observation.Severity, err = severityField(fields)
	}
	if err != nil {
		return Observation{}, err
	}
	observation.CVE, err = identifierField(fields, "cve", cvePattern)
	if err != nil {
		return Observation{}, err
	}
	switch producer {
	case "yeepforge", "adstrike":
		observation.CWE, err = identifierField(fields, "cwe", cwePattern)
		if err != nil {
			return Observation{}, err
		}
	}
	switch producer {
	case "yeepforge":
		observation.OWASP, err = identifierField(fields, "owasp", owaspPattern)
	case "adstrike":
		observation.ATTACK, err = identifierArray(fields, "mitre_ids", attackPattern)
		if err != nil {
			return Observation{}, err
		}
		observation.CVSS, err = cvssField(fields)
		if err != nil {
			return Observation{}, err
		}
		observation.ObservedAt, err = timestampField(fields, "timestamp")
	}
	if err != nil {
		return Observation{}, err
	}
	observation.Title, observation.Guidance = generatedText(observation)
	return observation, nil
}

func generatedText(o Observation) (string, string) {
	switch {
	case len(o.CWE) > 0:
		return "Producer-reported " + o.CWE[0] + " observation",
			"Independently review the classified weakness and relevant defensive controls."
	case len(o.CVE) > 0:
		return "Producer-reported " + o.CVE[0] + " observation",
			"Independently check affected versions and vendor advisories before deciding on remediation."
	case len(o.OWASP) > 0:
		return "Producer-reported OWASP " + o.OWASP[0] + " observation",
			"Independently review the classified OWASP category and applicable defensive controls."
	case len(o.ATTACK) > 0:
		return "Producer-reported ATT&CK " + o.ATTACK[0] + " observation",
			"Independently review the classified technique and defensive detection coverage."
	default:
		return "Producer-reported observation",
			"Independent review is required; the supplied report does not establish a confirmed vulnerability."
	}
}

// Detail is a bounded generated rendering for existing graph readers, not a
// second copy of the producer's report. Structured observations remain complete.
func renderDetail(r SanitizedReport) string {
	var text strings.Builder
	fmt.Fprintf(&text, "%s; profile=%s; validation=%s; completeness=%s; observations=%d; errors=%d",
		r.Producer, r.ParserProfile, r.ValidationStatus, r.Completeness, r.ObservationCount, r.ErrorCount)
	const renderedObservations = 20
	for _, o := range r.Observations[:min(len(r.Observations), renderedObservations)] {
		fmt.Fprintf(&text, "\n%s: %s; producer severity=%s; producer confidence=%s",
			o.SourcePointer, o.Title, o.Severity, o.Confidence)
	}
	if len(r.Observations) > renderedObservations {
		fmt.Fprintf(&text, "\n%d additional structured observations.", len(r.Observations)-renderedObservations)
	}
	return text.String()
}
