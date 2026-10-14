package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestSecurityProvider(t *testing.T) {
	dsn := testDSN(t)
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil || !strings.HasPrefix(cfg.Database, "scopeweaver_test_") {
		t.Fatal("provider tests require a disposable scopeweaver_test_* database")
	}
	// Given an older installation with each supported generic transport.
	raw, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_, err = raw.Exec(`CREATE TABLE IF NOT EXISTS mcp_servers (
id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL UNIQUE,
transport TEXT NOT NULL CHECK (transport IN ('stdio','http','sse')),
command TEXT, args JSONB NOT NULL DEFAULT '[]', env JSONB NOT NULL DEFAULT '{}',
url TEXT, enabled BOOLEAN NOT NULL DEFAULT true,
created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
INSERT INTO mcp_servers(name,transport,url) VALUES
('legacy-stdio','stdio',NULL),('legacy-http','http','http://fixture.invalid'),
('legacy-sse','sse','http://fixture.invalid');`)
	if err != nil {
		t.Fatal(err)
	}
	// When the additive schema and defaults are first applied.
	d, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	find := func(name string) *MCPServer {
		t.Helper()
		rows, err := d.ListMCP()
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			if row.Name == name {
				return row
			}
		}
		t.Fatalf("missing server %s", name)
		return nil
	}
	snapshot := func(label string) {
		t.Helper()
		var rows string
		if err := d.QueryRow(`SELECT jsonb_agg(to_jsonb(m) ORDER BY id)::text
FROM (SELECT id,name,transport,command,args,env,url,enabled,insecure,provider_kind,source_revision,updated_at FROM mcp_servers) m`).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		t.Logf("SQL %s: %s", label, rows)
	}
	snapshot("before")
	t.Run("no_template_seeds_and_legacy_transports", func(t *testing.T) {
		var kinds string
		if err := d.QueryRow(`SELECT coalesce(string_agg(provider_kind, ',' ORDER BY provider_kind), '')
FROM mcp_servers WHERE provider_kind <> ''`).Scan(&kinds); err != nil || kinds != "" {
			t.Fatalf("schema seeded catalog templates: %q err=%v", kinds, err)
		}
		for _, transport := range []string{"stdio", "http", "sse"} {
			m := find("legacy-" + transport)
			if m.Transport != transport || !m.Enabled || m.ProviderKind != "" || m.SourceRevision != "" {
				t.Fatalf("changed legacy row: %+v", m)
			}
		}
	})
	if _, err := d.SaveMCP(&MCPServer{Name: "YeepForge", Transport: "stdio", ProviderKind: "yeepforge"}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.SaveMCP(&MCPServer{Name: "AdStrike", Transport: "stdio", ProviderKind: "adstrike"}); err != nil {
		t.Fatal(err)
	}
	m := find("YeepForge")
	t.Run("rename_update_restart", func(t *testing.T) {
		m.Name = "Operator catalog"
		m.Command = "/operator/python"
		m.Args = json.RawMessage(`["/operator/mcp_server.py"]`)
		m.Env = json.RawMessage(`{"FIXTURE_SETTING":"operator-value"}`)
		m.SourceRevision = "ee07fe352a994b4e53f20b382b58c605a1301060"
		m.Enabled = true
		if _, err := d.SaveMCP(m); err != nil {
			t.Fatal(err)
		}
		before := find(m.Name)
		reopened, err := Open(dsn)
		if err != nil {
			t.Fatal(err)
		}
		if err := reopened.Close(); err != nil {
			t.Fatal(err)
		}
		after := find(m.Name)
		if after.ID != m.ID || after.ProviderKind != "yeepforge" || after.SourceRevision != m.SourceRevision ||
			after.Command != m.Command || !after.Enabled || string(after.Args) != string(before.Args) ||
			string(after.Env) != string(before.Env) || !after.UpdatedAt.Equal(before.UpdatedAt) {
			t.Fatalf("restart changed configuration: before=%+v after=%+v", before, after)
		}
		var count int
		if err := d.QueryRow(`SELECT count(*) FROM mcp_servers WHERE provider_kind='yeepforge'`).Scan(&count); err != nil || count != 1 {
			t.Fatalf("renamed template was reseeded: count=%d err=%v", count, err)
		}
		if !before.UpdatedAt.After(m.UpdatedAt) {
			t.Fatal("save did not advance configuration revision")
		}
	})
	t.Run("rejected_saves_are_atomic", func(t *testing.T) {
		before := find(m.Name)
		for _, tc := range []struct {
			name string
			edit func(*MCPServer)
		}{
			{"strip_kind", func(v *MCPServer) { v.ProviderKind = "" }},
			{"change_kind", func(v *MCPServer) { v.ProviderKind = "adstrike" }},
			{"unknown_kind", func(v *MCPServer) { v.ProviderKind = "confirmesc" }},
			{"http", func(v *MCPServer) { v.Transport = "http" }},
			{"sse", func(v *MCPServer) { v.Transport = "sse" }},
			{"url", func(v *MCPServer) { v.URL = "http://fixture.invalid" }},
			{"insecure", func(v *MCPServer) { v.Insecure = true }},
			{"uppercase_sha", func(v *MCPServer) { v.SourceRevision = strings.ToUpper(v.SourceRevision) }},
			{"short_sha", func(v *MCPServer) { v.SourceRevision = "ee07fe3" }},
			{"missing_row", func(v *MCPServer) { v.ID = -1 }},
		} {
			t.Run(tc.name, func(t *testing.T) {
				input := *before
				tc.edit(&input)
				_, err := d.SaveMCP(&input)
				var validation *MCPValidationError
				if !errors.As(err, &validation) {
					t.Fatalf("expected validation rejection, got %v", err)
				}
				after := find(before.Name)
				if !after.UpdatedAt.Equal(before.UpdatedAt) || after.ProviderKind != before.ProviderKind {
					t.Fatalf("rejection wrote configuration: %+v", after)
				}
			})
		}
	})
	t.Run("database_constraints", func(t *testing.T) {
		for _, query := range []string{
			`UPDATE mcp_servers SET provider_kind='' WHERE provider_kind='yeepforge'`,
			`UPDATE mcp_servers SET transport='http' WHERE provider_kind='yeepforge'`,
			`UPDATE mcp_servers SET source_revision='INVALID' WHERE provider_kind='yeepforge'`,
			`INSERT INTO mcp_servers(name,transport,provider_kind) VALUES ('invalid-provider','stdio','confirmesc')`,
		} {
			_, err := d.Exec(query)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
				t.Fatalf("constraint did not reject %q: %v", query, err)
			}
		}
	})
	t.Run("generic_name_collision_preserved_and_reported", func(t *testing.T) {
		ad := find("AdStrike")
		if err := d.DeleteMCP(ad.ID); err != nil {
			t.Fatal(err)
		}
		generic := &MCPServer{Name: "AdStrike", Transport: "sse", URL: "http://fixture.invalid", Enabled: true}
		id, err := d.SaveMCP(generic)
		if err != nil {
			t.Fatal(err)
		}
		reopened, err := Open(dsn)
		if err != nil {
			t.Fatal(err)
		}
		if err := reopened.Close(); err != nil {
			t.Fatal(err)
		}
		collision := find("AdStrike")
		if collision.ID != id || collision.ProviderKind != "" || collision.Transport != "sse" || !collision.Enabled {
			t.Fatalf("collision converted: %+v", collision)
		}
		collision.ProviderKind, collision.Transport, collision.URL = "adstrike", "stdio", ""
		if _, err := d.SaveMCP(collision); err == nil {
			t.Fatal("generic name collision acquired provider identity")
		}
	})
	snapshot("after")
}
