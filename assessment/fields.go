package assessment

import (
	"encoding/json"
	"math"
	"regexp"
	"slices"
	"strings"
	"time"
)

var (
	cwePattern       = regexp.MustCompile(`^CWE-[1-9][0-9]{0,5}$`)
	cvePattern       = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,10}$`)
	owaspPattern     = regexp.MustCompile(`^A(0[1-9]|10):2021$`)
	attackPattern    = regexp.MustCompile(`^T[1-9][0-9]{3}(\.[0-9]{3})?$`)
	timestampPattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-]([01][0-9]|2[0-3]):[0-5][0-9])?$`)
)

func severityField(fields map[string]json.RawMessage) (string, error) {
	value, err := stringField(fields, "severity")
	if err != nil {
		return "", err
	}
	if len(value) <= 16 {
		switch normalized := strings.ToLower(value); normalized {
		case "critical", "high", "medium", "low", "info":
			return normalized, nil
		}
	}
	return "unknown", nil
}

func confidenceField(fields map[string]json.RawMessage) (string, error) {
	value, err := stringField(fields, "confidence")
	if err != nil {
		return "", err
	}
	switch value {
	case "CONFIRMED", "LIKELY", "INFO", "ERROR":
		return strings.ToLower(value), nil
	default:
		return "unknown", nil
	}
}

func identifierField(fields map[string]json.RawMessage, key string, pattern *regexp.Regexp) ([]string, error) {
	value, err := stringField(fields, key)
	if err != nil {
		return nil, err
	}
	if len(value) <= 32 && pattern.MatchString(value) {
		return []string{value}, nil
	}
	return nil, nil
}

func identifierArray(fields map[string]json.RawMessage, key string, pattern *regexp.Regexp) ([]string, error) {
	if absent(fields[key]) {
		return nil, nil
	}
	values, err := array(fields[key])
	if err != nil {
		return nil, err
	}
	if len(values) > MaxIdentifiers {
		return nil, ErrTooManyIdentifiers
	}
	var identifiers []string
	for _, raw := range values {
		var value string
		if err := json.Unmarshal(raw, &value); err != nil || absent(raw) {
			return nil, ErrInvalidType
		}
		if len(value) <= 32 && pattern.MatchString(value) {
			identifiers = append(identifiers, value)
		}
	}
	slices.Sort(identifiers)
	return slices.Compact(identifiers), nil
}

// Only AdStrike's nested per-finding numeric score is CVSS in the pinned
// profiles. Aggregate risk values and strings are never coerced into CVSS.
func cvssField(fields map[string]json.RawMessage) (*float64, error) {
	if absent(fields["cvss"]) {
		return nil, nil
	}
	cvss, err := object(fields["cvss"])
	if err != nil {
		return nil, err
	}
	if absent(cvss["score"]) {
		return nil, nil
	}
	var score float64
	if err := json.Unmarshal(cvss["score"], &score); err != nil {
		return nil, ErrInvalidType
	}
	if math.IsNaN(score) || math.IsInf(score, 0) || score < 0 || score > 10 {
		return nil, ErrInvalidType
	}
	// Canonicalize -0 so numerically identical scores have identical JSON.
	if score == 0 {
		score = 0
	}
	return &score, nil
}

func timestampField(fields map[string]json.RawMessage, key string) (string, error) {
	value, err := stringField(fields, key)
	if err != nil {
		return "", err
	}
	if len(value) > 35 || !timestampPattern.MatchString(value) {
		return "", nil
	}
	// Preserve naive producer time as naive time, not a claimed UTC instant.
	const naiveLayout = "2006-01-02T15:04:05.999999999"
	layout := naiveLayout
	if strings.HasSuffix(value, "Z") || strings.ContainsAny(value[19:], "+-") {
		layout = time.RFC3339Nano
	}
	parsed, err := time.Parse(layout, value)
	if err != nil || parsed.Year() < 1 {
		return "", nil
	}
	normalized := parsed.Format(naiveLayout)
	if layout == naiveLayout {
		return normalized, nil
	}
	if strings.HasSuffix(value, "Z") {
		return normalized + "Z", nil
	}
	// Preserve explicit offsets, especially -00:00 (unknown local offset),
	// which time.Format would otherwise misrepresent as a known UTC instant.
	return normalized + value[len(value)-6:], nil
}
