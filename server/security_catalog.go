package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/locale"
	actool "github.com/Autumn-27/norma/tool"
)

type catalogAgentKey struct{}

var catalogHelperAgents = []string{"auto", "pentest", "mainagent", "planner", "worker"}

type catalogAvailability struct {
	Status     string `json:"status"`
	Configured bool   `json:"configured"`
	Enabled    bool   `json:"enabled"`
	Callable   bool   `json:"callable"`
	Provenance string `json:"provenance"`
}

type catalogProfile struct {
	Producer string                `json:"producer"`
	Profile  string                `json:"parser_profile"`
	Skill    string                `json:"skill,omitempty"`
	Statuses []catalogAvailability `json:"providers"`
}

func (s *Server) seedSecurityCatalog() error {
	t := s.toolSecurityCatalog("", locale.En)
	schema, err := json.Marshal(t.InputSchema())
	if err != nil {
		return err
	}
	bindings, err := json.Marshal(catalogHelperAgents)
	if err != nil {
		return err
	}
	return s.m.pg.SeedTool(t.Name(), t.Description(), schema, bindings)
}

// Identity is captured by server-owned assembly, never accepted in tool input.
// Calls read current bindings, feature state, visible skills and cached status.
func (s *Server) toolSecurityCatalog(agentKey string, langs ...locale.Lang) actool.CoreTool {
	lang := locale.First(langs)
	return roTool("security_catalog", locale.T(lang, "security.catalog.description"),
		objSchema(map[string]any{
			"producer": map[string]any{"type": "string",
				"description": locale.T(lang, "security.catalog.producer_parameter"),
				"enum":        []string{"yeepforge", "adstrike", "confirmesc"}},
		}), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			failure := func(code string) (actool.Result, error) {
				return actool.Errorf(locale.T(locale.FromContext(ctx), "security.catalog."+code)), nil
			}
			if !s.m.pg.SecurityReportsEnabled() {
				return failure("disabled")
			}
			rows, err := s.m.pg.ListTools()
			if err != nil {
				return failure("unavailable")
			}
			bound := false
			for _, row := range rows {
				if row.Key == "security_catalog" && row.Enabled && contains(row.Agents, agentKey) {
					bound = true
				}
			}
			a, err := s.m.pg.GetAgentByKey(agentKey)
			if !bound || err != nil || a == nil || !a.Enabled {
				return failure("not_bound")
			}
			var input struct {
				Producer string `json:"producer"`
			}
			decoder := json.NewDecoder(bytes.NewReader(in))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&input) != nil {
				return failure("invalid_request")
			}
			profiles := []catalogProfile{
				{Producer: "yeepforge", Profile: "yeepforge-json-ee07fe3", Statuses: []catalogAvailability{}},
				{Producer: "adstrike", Profile: "adstrike-json-2.0", Statuses: []catalogAvailability{}},
				{Producer: "confirmesc", Profile: "confirmesc-json-36f1ec8", Statuses: []catalogAvailability{}},
			}
			if input.Producer != "" && input.Producer != "yeepforge" && input.Producer != "adstrike" && input.Producer != "confirmesc" {
				return failure("invalid_request")
			}
			reg, err := visibleSkillRegistry(s.m.pg, s.skillDir, a.ID)
			if err != nil {
				return failure("unavailable")
			}
			visible := visibleReportSkills(reg)
			for _, row := range rows {
				if row.Key == "Skill" && (!row.Enabled || !contains(row.Agents, agentKey)) {
					visible = nil
				}
			}
			ids, err := s.m.pg.AgentVisible(a.ID, "mcp")
			if err != nil {
				return failure("unavailable")
			}
			visibleProviders := idSet(ids)
			providers, err := s.m.pg.ListMCP()
			if err != nil {
				return failure("unavailable")
			}
			out := []catalogProfile{}
			for _, profile := range profiles {
				if input.Producer != "" && profile.Producer != input.Producer {
					continue
				}
				if contains(visible, profile.Producer) {
					profile.Skill = profile.Producer
				}
				for _, provider := range providers {
					if provider.ProviderKind != profile.Producer || !visibleProviders[provider.ID] || provider.Catalog == nil {
						continue
					}
					status := provider.Catalog
					profile.Statuses = append(profile.Statuses, catalogAvailability{
						Status: status.Status, Configured: status.Configured, Enabled: status.Enabled,
						Callable: false, Provenance: status.Provenance,
					})
				}
				out = append(out, profile)
			}
			if !s.m.pg.SecurityReportsEnabled() {
				return failure("disabled")
			}
			return jsonResult(map[string]any{"catalog": out})
		})
}

type catalogError struct {
	Code string
}

func (e *catalogError) Error() string {
	return e.MessageForLanguage(locale.En)
}

func (e *catalogError) MessageForLanguage(lang locale.Lang) string {
	return locale.T(lang, "security.catalog."+e.Code)
}

// refreshSecurityCatalog is called only by the authenticated refresh route.
func (s *Server) refreshSecurityCatalog(w http.ResponseWriter, r *http.Request, m *db.MCPServer) {
	if !m.Enabled || m.Command == "" {
		writeError(w, http.StatusConflict, &catalogError{Code: "not_ready"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	cache, discoverErr := listSecurityCatalog(ctx, m)
	if discoverErr != nil {
		// Failed refreshes never leave old names looking like fresh success.
		cache.Available, cache.Tools = false, nil
	}
	err := s.m.pg.SaveMCPCatalog(ctx, m, cache)
	if errors.Is(err, db.ErrCatalogStale) {
		writeError(w, http.StatusConflict, &catalogError{Code: "stale"})
		return
	}
	if err != nil || discoverErr != nil {
		writeError(w, http.StatusBadGateway, &catalogError{Code: "unavailable"})
		return
	}
	status, err := s.m.pg.MCPProviderStatus(m)
	if err != nil {
		writeError(w, http.StatusInternalServerError, &catalogError{Code: "unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tools": []db.MCPTool{}, "catalog": status})
}
