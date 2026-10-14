package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/locale"
)

func providerByName(t *testing.T, s *Server, name string) *db.MCPServer {
	t.Helper()
	rows, err := s.m.pg.ListMCP()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.Name == name {
			return row
		}
	}
	t.Fatalf("missing MCP %s", name)
	return nil
}

func TestSecurityProviderManagement(t *testing.T) {
	// Given the real authenticated management mux and disposable PostgreSQL.
	s := newMgmtFixture(t)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	call := func(lang locale.Lang, method string, body []byte) (int, []byte) {
		t.Helper()
		req, err := http.NewRequest(method, srv.URL+"/api/mcp", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept-Language", string(lang))
		req.Header.Set("Content-Type", "application/json")
		res, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		out, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		return res.StatusCode, out
	}
	save := func(lang locale.Lang, m *db.MCPServer) (int, []byte) {
		t.Helper()
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return call(lang, http.MethodPost, raw)
	}
	for _, lang := range locale.Languages() {
		t.Run(string(lang), func(t *testing.T) {
			m := &db.MCPServer{
				Name: "task2-managed-" + string(lang), ProviderKind: "yeepforge", Transport: "stdio",
				SourceRevision: "ee07fe352a994b4e53f20b382b58c605a1301060",
			}
			// When an operator saves then renames a tagged provider.
			code, body := save(lang, m)
			if code != 200 {
				t.Fatalf("create: HTTP %d %s", code, body)
			}
			var out struct{ ID int64 }
			if err := json.Unmarshal(body, &out); err != nil || out.ID == 0 {
				t.Fatalf("create response: %s err=%v", body, err)
			}
			m.ID, m.Name, m.Enabled = out.ID, m.Name+"-renamed", true
			if code, body := save(lang, m); code != 200 {
				t.Fatalf("rename: HTTP %d %s", code, body)
			}
			// Then the list API returns configured metadata, not observed provenance.
			code, body = call(lang, http.MethodGet, nil)
			var list struct{ Servers []*db.MCPServer }
			if code != 200 || json.Unmarshal(body, &list) != nil {
				t.Fatalf("list: HTTP %d %s", code, body)
			}
			found := false
			for _, row := range list.Servers {
				if row.ID == m.ID {
					found = row.Name == m.Name && row.ProviderKind == m.ProviderKind &&
						row.SourceRevision == m.SourceRevision && row.Enabled && !row.UpdatedAt.IsZero()
				}
			}
			if !found {
				t.Fatal("list API lost provider metadata")
			}
			t.Logf("HTTP happy lang=%s id=%d kind=%s revision=%s renamed=%s", lang, m.ID, m.ProviderKind, m.SourceRevision, m.Name)
			before := providerByName(t, s, m.Name)
			for _, tc := range []struct {
				name string
				edit func(*db.MCPServer)
			}{
				{"strip_kind", func(v *db.MCPServer) { v.ProviderKind = "" }},
				{"change_kind", func(v *db.MCPServer) { v.ProviderKind = "adstrike" }},
				{"unknown_kind", func(v *db.MCPServer) { v.ProviderKind = "confirmesc" }},
				{"http", func(v *db.MCPServer) { v.Transport = "http" }},
				{"sse", func(v *db.MCPServer) { v.Transport = "sse" }},
				{"url", func(v *db.MCPServer) { v.URL = "http://fixture.invalid" }},
				{"insecure", func(v *db.MCPServer) { v.Insecure = true }},
				{"invalid_sha", func(v *db.MCPServer) { v.SourceRevision = "NOT-A-SHA" }},
				{"deleted_id", func(v *db.MCPServer) { v.ID = -1 }},
			} {
				t.Run(tc.name, func(t *testing.T) {
					input := *m
					tc.edit(&input)
					code, body := save(lang, &input)
					var rejected struct{ Error string }
					if code != 400 || json.Unmarshal(body, &rejected) != nil || rejected.Error == "" {
						t.Fatalf("expected rejected save: HTTP %d %s", code, body)
					}
					after := providerByName(t, s, m.Name)
					if !after.UpdatedAt.Equal(before.UpdatedAt) {
						t.Fatal("rejected save changed configuration")
					}
					t.Logf("HTTP rejected lang=%s case=%s status=%d body=%s", lang, tc.name, code, body)
				})
			}
			t.Run("malformed_json", func(t *testing.T) {
				code, body := call(lang, http.MethodPost, []byte(`{"provider_kind":17,"name":"scopeweaver-secret-canary-01"}`))
				if code != 400 || strings.Contains(string(body), "scopeweaver-secret-canary-01") {
					t.Fatalf("malformed input: HTTP %d %s", code, body)
				}
				t.Logf("HTTP malformed lang=%s status=%d body=%s", lang, code, body)
			})
		})
	}
}

func TestSecurityProviderPlatform(t *testing.T) {
	// Given the real Auto create/update tools with the same persistence boundary.
	s := newMgmtFixture(t)
	for _, lang := range locale.Languages() {
		t.Run(string(lang), func(t *testing.T) {
			ctx := locale.WithLang(t.Context(), lang)
			input := map[string]any{
				"name": "task2-auto-" + string(lang), "transport": "stdio", "provider_kind": "adstrike",
				"source_revision": "75d43aabdf9be0d7b497f0c51e38dac77f4ee7be",
			}
			// When Auto creates a provider without an enabled field.
			text := workflowCall(t, ctx, s.toolCreateMCP(lang), input, false)
			m := providerByName(t, s, input["name"].(string))
			// Then it remains opt-in and its metadata survives a rename.
			if m.Enabled || m.ProviderKind != "adstrike" || m.SourceRevision != input["source_revision"] {
				t.Fatalf("unsafe Auto defaults: %+v", m)
			}
			input["id"], input["name"], input["enabled"] = m.ID, m.Name+"-renamed", false
			workflowCall(t, ctx, s.toolUpdateMCP(lang), input, false)
			m = providerByName(t, s, input["name"].(string))
			if m.ProviderKind != "adstrike" || m.SourceRevision != input["source_revision"] {
				t.Fatal("Auto update lost metadata")
			}
			t.Logf("Auto happy lang=%s result=%s id=%d disabled=%t kind=%s", lang, text, m.ID, !m.Enabled, m.ProviderKind)
			for _, tc := range []struct{ field, value string }{
				{"provider_kind", ""}, {"provider_kind", "yeepforge"},
				{"transport", "http"}, {"transport", "sse"}, {"source_revision", "INVALID"},
			} {
				t.Run(tc.field+"_"+tc.value, func(t *testing.T) {
					invalid := make(map[string]any, len(input))
					for key, value := range input {
						invalid[key] = value
					}
					invalid[tc.field] = tc.value
					text := workflowCall(t, ctx, s.toolUpdateMCP(lang), invalid, true)
					if after := providerByName(t, s, m.Name); !after.UpdatedAt.Equal(m.UpdatedAt) {
						t.Fatal("rejected Auto update changed configuration")
					}
					t.Logf("Auto rejected lang=%s field=%s value=%q result=%s", lang, tc.field, tc.value, text)
				})
			}
			t.Run("invalid_create_and_json", func(t *testing.T) {
				for _, transport := range []string{"http", "sse"} {
					text := workflowCall(t, ctx, s.toolCreateMCP(lang), map[string]any{
						"name": "invalid-" + string(lang), "transport": transport, "provider_kind": "adstrike",
					}, true)
					t.Logf("Auto create rejected lang=%s transport=%s result=%s", lang, transport, text)
				}
				res, err := s.toolCreateMCP(lang).Call(ctx, json.RawMessage(`{"name":17}`), nil)
				if err != nil || !res.IsError {
					t.Fatalf("malformed Auto create: %v %s", err, res.Flatten())
				}
				t.Logf("Auto malformed lang=%s result=%s", lang, res.Flatten())
			})
		})
	}
}
