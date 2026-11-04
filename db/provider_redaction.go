package db

import (
	"bytes"
	"encoding/json"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

const ProviderRedactionPolicy = "scopeweaver.redaction.v1"

var providerURLPattern = regexp.MustCompile("(?i)https?://[^\\s<>\"'`]+")
var providerOpaquePattern = regexp.MustCompile(`[A-Za-z0-9_+/=-]{24,}`)
var providerJWT = regexp.MustCompile(`[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)
var providerAssignment = regexp.MustCompile(`(?i)\b[A-Za-z0-9_-]*?(password|passwd|pass|pwd|token|access[_-]?token|refresh[_-]?token|api[_-]?key|secret|client[_-]?secret|session[_-]?id|cookie|authorization|auth|signature|credential)[A-Za-z0-9_-]*\b["']?\s*(?:[:=]|\bis\b)\s*[^\r\n]+`)
var providerSensitiveWord = regexp.MustCompile(`(?i)^(auth|authorization|cookie|setcookie|password|passwd|pwd|token|accesstoken|refreshtoken|apikey|secret|clientsecret|session|sessionid|privatekey|credential|credentials|signature|headers|requestheaders|responseheaders|requestbody|responsebody|rawrequest|rawresponse|body)$`)
var providerHeaderLine = regexp.MustCompile(`(?im)^\s*(authorization|proxy-authorization|cookie|set-cookie|x-api-key)\s*:`)
var providerTrafficLine = regexp.MustCompile(`(?im)^\s*(HTTP/[123](?:\.[01])?\s+\d{3}|(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\S+\s+HTTP/[123])`)
var providerSafeName = regexp.MustCompile(`^[A-Za-z0-9_.\[\]-]{1,64}$`)
var providerHost = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
var providerReference = regexp.MustCompile(`(?i)^(?:[a-f0-9]{32}|[a-f0-9]{64}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$`)

// Policy paths never echo unknown key names or removed source values.
type providerRedactor struct{ notices map[string]bool }

func (r *providerRedactor) note(reason string) { r.notices[reason] = true }
func providerNormalizedKey(s string) string {
	return strings.Map(func(c rune) rune {
		if unicode.IsLetter(c) || unicode.IsDigit(c) {
			return unicode.ToLower(c)
		}
		return -1
	}, s)
}

func (r *providerRedactor) text(value string) string {
	if value == "" {
		return value
	}
	if len(value) > 256<<10 {
		r.note("text_size_limit")
		return "[withheld: text size limit]"
	}
	if strings.Contains(value, "-----BEGIN ") {
		r.note("key_material")
		return "[withheld: key material]"
	}
	if json.Valid([]byte(value)) {
		decoder := json.NewDecoder(strings.NewReader(value))
		decoder.UseNumber()
		var structured any
		if decoder.Decode(&structured) == nil {
			safe := r.assessment(structured, 1)
			b, err := json.Marshal(safe)
			if err == nil {
				return string(b)
			}
		}
	}
	// Drop fenced blocks, not just the visible headers: arbitrary traffic and
	// executable payloads inside them are outside the assessment-text contract.
	lines := strings.Split(strings.ReplaceAll(value, "\r\n", "\n"), "\n")
	out := make([]string, 0, len(lines))
	fence := ""
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			mark := trimmed[:3]
			if fence == "" {
				fence = mark
				out = append(out, "[withheld: code or traffic block]")
				r.note("code_or_traffic_block")
			} else if mark == fence {
				fence = ""
			}
			continue
		}
		if fence != "" {
			continue
		}
		if providerTrafficLine.MatchString(line) {
			r.note("raw_traffic")
			return "[withheld: raw traffic outside a fenced block]"
		}
		if providerHeaderLine.MatchString(line) {
			r.note("credential_header")
			out = append(out, "[redacted: credential header]")
			continue
		}
		line = providerURLPattern.ReplaceAllStringFunc(line, func(raw string) string { return r.url(raw) })
		next := providerAssignment.ReplaceAllString(line, "$1=[redacted]")
		if next != line {
			r.note("credential_assignment")
		}
		line = next
		next = providerJWT.ReplaceAllString(line, "[redacted]")
		if next != line {
			r.note("opaque_value")
		}
		line = next
		next = providerOpaquePattern.ReplaceAllString(line, "[redacted]")
		if next != line {
			r.note("opaque_value")
		}
		out = append(out, next)
	}
	return strings.Join(out, "\n")
}

func (r *providerRedactor) url(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		r.note("invalid_url")
		return "[withheld: invalid URL]"
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" {
		r.note("invalid_url")
		return "[withheld: invalid URL]"
	}
	if u.User != nil {
		r.note("url_credentials")
		u.User = nil
	}
	if u.Fragment != "" {
		r.note("url_fragment")
		u.Fragment = ""
		u.RawFragment = ""
	}
	host := u.Hostname()
	if net.ParseIP(host) == nil && !providerHost.MatchString(host) {
		r.note("invalid_url_host")
		return "[withheld: invalid URL host]"
	}
	// Opaque host labels can themselves contain credentials (e.g. signed subdomains).
	for _, label := range strings.Split(host, ".") {
		if providerOpaquePattern.MatchString(label) {
			r.note("opaque_url_host")
			return "[withheld: opaque URL host]"
		}
	}
	segments := strings.Split(u.Path, "/")
	sensitiveNext := false
	for i, segment := range segments {
		decoded := segment
		for n := 0; n < 2; n++ {
			v, e := url.PathUnescape(decoded)
			if e != nil {
				break
			}
			if v == decoded {
				break
			}
			decoded = v
		}
		sensitive := sensitiveNext || providerOpaquePattern.MatchString(decoded) || providerJWT.MatchString(decoded) || providerAssignment.MatchString(decoded) || strings.Contains(decoded, "%")
		normalized := providerNormalizedKey(decoded)
		sensitiveNext = sensitiveNext || providerSensitiveWord.MatchString(normalized) || strings.Contains(normalized, "password")
		switch normalized {
		case "reset", "verify", "verification", "activate", "activation", "invite", "invitation", "magic", "magiclink", "confirm", "callback":
			sensitiveNext = true
		}
		if sensitive {
			segments[i] = "[redacted]"
			r.note("url_path_value")
		}
	}
	u.Path = strings.Join(segments, "/")
	u.RawPath = ""
	if u.RawQuery != "" {
		query, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			u.RawQuery = ""
			r.note("url_query")
		} else {
			safe := url.Values{}
			for name := range query {
				if providerSafeName.MatchString(name) && !providerOpaquePattern.MatchString(name) {
					safe[name] = []string{"[redacted]"}
				} else {
					r.note("url_query_name")
				}
			}
			u.RawQuery = safe.Encode()
			r.note("url_query")
		}
	}
	return u.String()
}

// Only known assessment JSON keys are interpreted. Unknown keys and credential
// values are not copied, even when nested. No source JSON controls destination scope.
var providerAssessmentKeys = map[string]bool{}

func init() {
	for _, s := range strings.Fields("title name text summary description goal rationale reason status severity confidence evidence conclusion verdict notes detail label type kind method location required data_type value version vendor product platform framework language os tags technologies service services port protocol cve cwe cvss score risk impact recommendation remediation references url domain ip hostname source scope target result expected actual steps constraints assumptions hypothesis observation observations facts finding findings report metadata parameters params properties deprecated format default example examples app_name bundle_id category app_description page_title service_name service_type record_type record_value root_domain c_segment icp app_icp bound_domains open_ports favicon_mmh3") {
		providerAssessmentKeys[s] = true
	}
}
func (r *providerRedactor) assessment(value any, depth int) any {
	if depth > 12 {
		r.note("json_depth_limit")
		return "[withheld: depth limit]"
	}
	switch v := value.(type) {
	case map[string]any:
		out := map[string]any{}
		for key, child := range v {
			normalized := providerNormalizedKey(key)
			if providerSensitiveWord.MatchString(normalized) {
				r.note("credential_or_traffic_field")
				continue
			}
			if !providerAssessmentKeys[key] {
				r.note("unsupported_metadata_field")
				continue
			}
			// Parameter values and examples are not inventory metadata.
			if key == "value" || key == "default" || key == "example" || key == "examples" {
				r.note("parameter_or_example_value")
				continue
			}
			if key == "url" {
				if value, ok := child.(string); ok {
					out[key] = r.url(value)
					continue
				}
			}
			out[key] = r.assessment(child, depth+1)
		}
		return out
	case []any:
		if len(v) > 1000 {
			r.note("json_array_limit")
			return "[withheld: array size limit]"
		}
		out := make([]any, 0, len(v))
		for _, child := range v {
			out = append(out, r.assessment(child, depth+1))
		}
		return out
	case string:
		return r.text(v)
	default:
		return value
	}
}

// ProviderPayload is the single serializer for automatic snapshot and on-demand
// content. SQL first enforces company ownership, then this function applies an
// explicit projection/redaction policy. It never reads credential files.
func ProviderPayload(family string, raw []byte, detail bool) ([]byte, error) {
	if family == "rejected" {
		return ProviderCanonicalJSON(raw)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var p map[string]any
	if err := decoder.Decode(&p); err != nil {
		return nil, err
	}
	r := providerRedactor{notices: map[string]bool{}}
	// Structured columns explicitly selected by the provider SQL, not arbitrary keys.
	for key, value := range p {
		text, ok := value.(string)
		if !ok {
			continue
		}
		switch key {
		case "source_revision", "request_checksum", "response_checksum", "checksum":
			continue // computed or validated integrity fields
		case "body", "url":
			continue // projected separately below
		case "snapshot_id":
			if providerReference.MatchString(text) {
				continue
			}
		}
		p[key] = r.text(text)
	}
	for _, key := range []string{"domain", "root_domain"} {
		if text, ok := p[key].(string); ok && text != "" {
			if !providerHost.MatchString(text) || providerOpaquePattern.MatchString(text) {
				p[key] = "[withheld: invalid or opaque domain]"
				r.note("invalid_domain")
			}
		}
	}
	if rawURL, ok := p["url"].(string); ok && rawURL != "" {
		p["url"] = r.url(rawURL)
	}
	if ip, ok := p["ip"].(string); ok && ip != "" && net.ParseIP(ip) == nil {
		p["ip"] = "[withheld: invalid IP]"
		r.note("invalid_ip")
	}
	for _, key := range []string{"technologies", "bound_domains", "open_ports", "params", "extra", "research", "retest_summary"} {
		if v, ok := p[key]; ok {
			if (key == "extra" || key == "research") && v != nil {
				if _, object := v.(map[string]any); !object {
					delete(p, key)
					r.note("unsupported_metadata_shape")
					continue
				}
			}
			if key == "params" {
				rows, valid := v.([]any)
				safeRows := []any{}
				if !valid && v != nil {
					r.note("unsupported_parameter_shape")
				}
				if len(rows) > 1000 {
					p[key] = safeRows
					r.note("parameter_array_limit")
					continue
				}
				for _, row := range rows {
					fields, valid := row.(map[string]any)
					if !valid {
						r.note("unsupported_parameter_shape")
						continue
					}
					safe := map[string]any{}
					for _, field := range []string{"name", "location", "type", "description", "required"} {
						if value, present := fields[field]; present {
							safe[field] = r.assessment(value, 0)
						}
					}
					if len(fields) > len(safe) {
						r.note("parameter_values_or_unsupported_fields")
					}
					safeRows = append(safeRows, safe)
				}
				p[key] = safeRows
				continue
			}
			p[key] = r.assessment(v, 0)
		}
	}
	if values, ok := p["record_value"]; ok && values != nil {
		recordType, _ := p["record_type"].(string)
		switch strings.ToUpper(recordType) {
		case "A", "AAAA", "CNAME", "MX", "NS", "PTR":
			p["record_value"] = r.assessment(values, 0)
		default:
			delete(p, "record_value")
			r.note("unsupported_dns_record_value")
		}
	}
	if body, ok := p["body"].(string); ok {
		if detail {
			safe := r.text(body)
			p["body"] = safe
			p["content_checksum"] = ProviderChecksum([]byte(safe))
		} else {
			delete(p, "body")
			p["detail_available"] = body != ""
		}
	}
	// Publication content is also subjected to the automatic redaction policy;
	// approval cannot bypass credential/traffic exclusions.
	if content, ok := p["content"]; ok {
		safe := r.assessment(content, 0)
		p["content"] = safe
		p["source_checksum"] = p["checksum"]
		encoded, err := json.Marshal(safe)
		if err != nil {
			return nil, err
		}
		p["checksum"] = ProviderChecksum(encoded)
	}
	p["redaction_policy"] = ProviderRedactionPolicy
	p["untrusted_evidence"] = true
	notices := make([]string, 0, len(r.notices))
	for reason := range r.notices {
		notices = append(notices, reason)
	}
	sort.Strings(notices)
	if len(notices) > 0 {
		p["redactions"] = notices
	}
	return json.Marshal(p)
}
