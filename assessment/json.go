package assessment

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

const (
	MaxInputBytes  = 1 << 20
	MaxFindings    = 1000
	MaxDepth       = 32
	MaxIdentifiers = 32
)

// Fixed codes can be mapped to localized errors at the HTTP boundary. Decoder
// errors and input snippets are deliberately never wrapped or returned.
var (
	ErrUnsupportedProducer = errors.New("assessment_unsupported_producer")
	ErrUnsupportedProfile  = errors.New("assessment_unsupported_profile")
	ErrMalformedJSON       = errors.New("assessment_malformed_json")
	ErrTooLarge            = errors.New("assessment_input_too_large")
	ErrTooDeep             = errors.New("assessment_input_too_deep")
	ErrTooManyFindings     = errors.New("assessment_too_many_findings")
	ErrTooManyIdentifiers  = errors.New("assessment_too_many_identifiers")
	ErrInvalidType         = errors.New("assessment_invalid_type")
	ErrInvalidImportTime   = errors.New("assessment_invalid_import_time")
)

func producerProfile(producer string) (string, string, error) {
	switch producer {
	case "yeepforge":
		return "yeepforge-json-ee07fe3", "ee07fe352a994b4e53f20b382b58c605a1301060", nil
	case "adstrike":
		return "adstrike-json-2.0", "75d43aabdf9be0d7b497f0c51e38dac77f4ee7be", nil
	case "confirmesc":
		return "confirmesc-json-36f1ec8", "36f1ec85e869357439a35dd08ec833bde5ef8041", nil
	default:
		return "", "", ErrUnsupportedProducer
	}
}

func validateProfile(producer string, fields map[string]json.RawMessage) error {
	switch producer {
	case "yeepforge":
		var tool string
		if json.Unmarshal(fields["tool"], &tool) != nil || tool != "YeepForge" {
			return ErrUnsupportedProfile
		}
	case "adstrike":
		var schema string
		if json.Unmarshal(fields["schema_version"], &schema) != nil || schema != "2.0" {
			return ErrUnsupportedProfile
		}
	case "confirmesc":
		if _, err := object(fields["meta"]); err != nil {
			return ErrUnsupportedProfile
		}
		if _, err := object(fields["errors"]); err != nil {
			return ErrUnsupportedProfile
		}
	}
	return nil
}

// Walk tokens before decoding profile fields. Even discarded values must be
// valid JSON within the depth limit. Duplicate (including escaped) keys are
// rejected to prevent conflicting interpretations by downstream decoders.
func validateJSON(raw []byte) error {
	if len(raw) > MaxInputBytes {
		return ErrTooLarge
	}
	if !utf8.Valid(raw) {
		return ErrMalformedJSON
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := walkValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrMalformedJSON
	}
	return nil
}

func walkValue(decoder *json.Decoder, depth int) error {
	token, err := decoder.Token()
	if err != nil {
		return ErrMalformedJSON
	}
	delim, container := token.(json.Delim)
	if !container {
		return nil
	}
	if depth >= MaxDepth {
		return ErrTooDeep
	}
	switch delim {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return ErrMalformedJSON
			}
			key, ok := keyToken.(string)
			if !ok {
				return ErrMalformedJSON
			}
			if _, exists := keys[key]; exists {
				return ErrMalformedJSON
			}
			keys[key] = struct{}{}
			if err := walkValue(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := walkValue(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return ErrMalformedJSON
	}
	if _, err := decoder.Token(); err != nil {
		return ErrMalformedJSON
	}
	return nil
}

func object(raw json.RawMessage) (map[string]json.RawMessage, error) {
	if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, ErrInvalidType
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, ErrInvalidType
	}
	return fields, nil
}

func array(raw json.RawMessage) ([]json.RawMessage, error) {
	if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, ErrInvalidType
	}
	var values []json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, ErrInvalidType
	}
	return values, nil
}

func absent(raw json.RawMessage) bool {
	return len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func stringField(fields map[string]json.RawMessage, key string) (string, error) {
	raw := fields[key]
	if absent(raw) {
		return "", nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", ErrInvalidType
	}
	return value, nil
}
