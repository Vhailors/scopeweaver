package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/assessment"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/locale"
	"github.com/Autumn-27/norma/skill"
)

type assessmentReportResult struct {
	AssessmentID     string `json:"assessment_id"`
	FactID           int64  `json:"fact_id"`
	Duplicate        bool   `json:"duplicate"`
	Producer         string `json:"producer"`
	ParserProfile    string `json:"parser_profile"`
	ValidationStatus string `json:"validation_status"`
	ObservationCount int    `json:"observation_count"`
	Completeness     string `json:"completeness"`
	RecommendedSkill string `json:"recommended_skill,omitempty"`
	// An operator library entry does not establish any agent's visibility.
	RecommendationContext string `json:"recommendation_context,omitempty"`
}

type assessmentReportSummary struct {
	assessmentReportResult
	Summary              string `json:"summary"`
	ParserVersion        int    `json:"parser_version"`
	ParserSourceRevision string `json:"parser_source_revision"`
	SourceVerification   string `json:"source_verification"`
	RuntimeVerification  string `json:"runtime_verification"`
	OriginalSHA256       string `json:"original_sha256"`
	SanitizedSHA256      string `json:"sanitized_sha256"`
	ImportedAt           string `json:"imported_at"`
	ObservedAt           string `json:"observed_at,omitempty"`
	ErrorCount           int    `json:"error_count"`
}

func writeAssessmentError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{
		"code": code, "error": locale.Text(responseLanguage(w), "security.assessment."+code),
	})
}

// Preserve normal authentication for other routes while giving this contract
// fixed machine codes even when authentication rejects before the mux runs.
func (s *Server) assessmentReportsAuth(next http.Handler) http.Handler {
	authenticated := s.requireAuth(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) == 5 && parts[1] == "api" && parts[2] == "tasks" && parts[4] == "assessment-reports" &&
			(r.Method == http.MethodPost || r.Method == http.MethodGet) {
			if !verifyJWT(extractToken(r), s.jwtKey) {
				writeAssessmentError(w, http.StatusUnauthorized, "assessment_unauthorized")
				return
			}
		}
		authenticated.ServeHTTP(w, r)
	})
}

func (s *Server) assessmentTask(w http.ResponseWriter, r *http.Request) *db.Task {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeAssessmentError(w, http.StatusNotFound, "assessment_task_unavailable")
		return nil
	}
	if s.m.pg == nil {
		writeAssessmentError(w, http.StatusServiceUnavailable, "assessment_unavailable")
		return nil
	}
	task, err := s.m.pg.GetTask(id)
	if err != nil {
		writeAssessmentError(w, http.StatusServiceUnavailable, "assessment_unavailable")
		return nil
	}
	if task == nil {
		writeAssessmentError(w, http.StatusNotFound, "assessment_task_unavailable")
	}
	return task
}

func (s *Server) assessmentResult(id int64, report *assessment.Report, duplicate bool) assessmentReportResult {
	result := assessmentReportResult{
		AssessmentID: report.AssessmentID, FactID: id, Duplicate: duplicate,
		Producer: report.Import.Producer, ParserProfile: report.Import.ParserProfile,
		ValidationStatus: report.Import.ValidationStatus, ObservationCount: report.Import.ObservationCount,
		Completeness: report.Import.Completeness,
	}
	if reg, err := skill.LoadDir(s.skillDir); err == nil && reg != nil {
		for _, loaded := range reg.List() {
			if loaded.Name == result.Producer && filepath.Base(loaded.Dir) == result.Producer {
				result.RecommendedSkill = result.Producer
				result.RecommendationContext = "operator_library"
				break
			}
		}
	}
	return result
}

func (s *Server) importAssessmentReport(w http.ResponseWriter, r *http.Request) {
	task := s.assessmentTask(w, r)
	if task == nil {
		return
	}
	if !s.m.pg.SecurityReportsEnabled() {
		writeAssessmentError(w, http.StatusForbidden, "assessment_reports_disabled")
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || r.Header.Get("Content-Encoding") != "" {
		writeAssessmentError(w, http.StatusUnsupportedMediaType, "assessment_content_type")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, assessment.MaxInputBytes)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeAssessmentError(w, http.StatusRequestEntityTooLarge, "assessment_input_too_large")
		} else {
			writeAssessmentError(w, http.StatusBadRequest, "assessment_invalid_request")
		}
		return
	}
	producer, supplied, err := assessmentEnvelope(raw)
	if err != nil {
		writeAssessmentError(w, http.StatusBadRequest, "assessment_invalid_request")
		return
	}
	report, err := assessment.Parse(producer, supplied, time.Now())
	if err != nil {
		switch {
		case errors.Is(err, assessment.ErrUnsupportedProducer):
			writeAssessmentError(w, http.StatusUnprocessableEntity, "assessment_unsupported_producer")
		case errors.Is(err, assessment.ErrUnsupportedProfile):
			writeAssessmentError(w, http.StatusUnprocessableEntity, "assessment_unsupported_profile")
		default:
			writeAssessmentError(w, http.StatusBadRequest, "assessment_invalid_request")
		}
		return
	}
	node, duplicate, err := s.m.pg.Exploration(task.ExplorationID).ImportAssessment(r.Context(), task.ID, report)
	if err != nil {
		switch {
		case errors.Is(err, db.ErrAssessmentReportsDisabled):
			writeAssessmentError(w, http.StatusForbidden, "assessment_reports_disabled")
		case errors.Is(err, db.ErrAssessmentTaskUnavailable):
			writeAssessmentError(w, http.StatusNotFound, "assessment_task_unavailable")
		default:
			writeAssessmentError(w, http.StatusServiceUnavailable, "assessment_unavailable")
		}
		return
	}
	// Use the immutable stored import on repeats, not the retry's import time.
	if json.Unmarshal(node.Payload, report) != nil {
		writeAssessmentError(w, http.StatusServiceUnavailable, "assessment_unavailable")
		return
	}
	status := http.StatusCreated
	if duplicate {
		status = http.StatusOK
	}
	writeJSON(w, status, s.assessmentResult(node.ID, report, duplicate))
}

// Validate the entire envelope, including depth counted from its outer object.
// The parser separately validates all report keys/types, even discarded values.
func assessmentEnvelope(raw []byte) (string, json.RawMessage, error) {
	if !utf8.Valid(raw) {
		return "", nil, assessment.ErrMalformedJSON
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	depth := 0
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", nil, assessment.ErrMalformedJSON
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{', '[':
				depth++
				if depth > assessment.MaxDepth {
					return "", nil, assessment.ErrTooDeep
				}
			case '}', ']':
				depth--
			}
		}
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return "", nil, assessment.ErrInvalidType
	}
	fields := make(map[string]json.RawMessage, 2)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return "", nil, assessment.ErrMalformedJSON
		}
		key, ok := token.(string)
		if !ok || (key != "producer" && key != "report") || fields[key] != nil {
			return "", nil, assessment.ErrInvalidType
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return "", nil, assessment.ErrMalformedJSON
		}
		fields[key] = value
	}
	if _, err := decoder.Token(); err != nil {
		return "", nil, assessment.ErrMalformedJSON
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return "", nil, assessment.ErrMalformedJSON
	}
	var producer string
	if len(fields) != 2 || json.Unmarshal(fields["producer"], &producer) != nil ||
		bytes.Equal(fields["producer"], []byte("null")) {
		return "", nil, assessment.ErrInvalidType
	}
	report := bytes.TrimSpace(fields["report"])
	if len(report) == 0 || report[0] != '{' {
		return "", nil, assessment.ErrInvalidType
	}
	return producer, fields["report"], nil
}

func (s *Server) listAssessmentReports(w http.ResponseWriter, r *http.Request) {
	task := s.assessmentTask(w, r)
	if task == nil {
		return
	}
	var before int64
	if value := r.URL.Query().Get("before"); value != "" {
		var err error
		before, err = strconv.ParseInt(value, 10, 64)
		if err != nil || before <= 0 {
			writeAssessmentError(w, http.StatusBadRequest, "assessment_invalid_request")
			return
		}
	}
	const limit = 100
	rows, err := s.m.pg.QueryContext(r.Context(), `SELECT id, payload FROM exploration_nodes
WHERE exploration_id=$1 AND kind='fact' AND origin='assessment_import'
AND payload ? 'assessment_id' AND payload ? 'assessment_import'
AND ($2::bigint=0 OR id<$2) ORDER BY id DESC LIMIT $3`, task.ExplorationID, before, limit+1)
	if err != nil {
		writeAssessmentError(w, http.StatusServiceUnavailable, "assessment_unavailable")
		return
	}
	defer rows.Close()
	reports := make([]assessmentReportSummary, 0)
	hasMore := false
	for rows.Next() {
		var id int64
		var payload []byte
		var report assessment.Report
		if err := rows.Scan(&id, &payload); err != nil || json.Unmarshal(payload, &report) != nil {
			writeAssessmentError(w, http.StatusServiceUnavailable, "assessment_unavailable")
			return
		}
		if len(reports) == limit {
			hasMore = true
			break
		}
		meta := report.Import
		reports = append(reports, assessmentReportSummary{
			assessmentReportResult: s.assessmentResult(id, &report, false), Summary: report.Summary,
			ParserVersion: meta.ParserVersion, ParserSourceRevision: meta.ParserSourceRevision,
			SourceVerification: meta.SourceVerification, RuntimeVerification: meta.RuntimeVerification,
			OriginalSHA256: meta.OriginalSHA256, SanitizedSHA256: meta.SanitizedSHA256,
			ImportedAt: meta.ImportedAt, ObservedAt: meta.ObservedAt, ErrorCount: meta.ErrorCount,
		})
	}
	if err := rows.Err(); err != nil {
		writeAssessmentError(w, http.StatusServiceUnavailable, "assessment_unavailable")
		return
	}
	var nextBefore int64
	if hasMore {
		nextBefore = reports[len(reports)-1].FactID
	}
	writeJSON(w, http.StatusOK, map[string]any{"reports": reports, "has_more": hasMore, "next_before": nextBefore})
}
