package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

var ErrCatalogStale = errors.New("catalog configuration changed")

// MCPCatalog is metadata only. A measured file digest and a producer-reported
// version do not authenticate the expected upstream source revision.
type MCPCatalog struct {
	ConfigRevision   time.Time `json:"config_revision"`
	DiscoveredAt     time.Time `json:"discovered_at"`
	Available        bool      `json:"available"`
	ExecutableSHA256 string    `json:"executable_sha256"`
	ObservedRevision string    `json:"observed_revision"`
	Tools            []MCPTool `json:"tools"`
}

type MCPCatalogStatus struct {
	Status                 string      `json:"status"`
	Configured             bool        `json:"configured"`
	Enabled                bool        `json:"enabled"`
	Callable               bool        `json:"callable"`
	Provenance             string      `json:"provenance"`
	ExpectedSourceRevision string      `json:"expected_source_revision"`
	Cache                  *MCPCatalog `json:"cache,omitempty"`
}

// MCPProviderStatus reads cached metadata only; it never contacts a provider.
func (d *DB) MCPProviderStatus(m *MCPServer) (*MCPCatalogStatus, error) {
	out := &MCPCatalogStatus{
		Status: "not_discovered", Configured: m.Command != "", Enabled: m.Enabled,
		Provenance: "unverified", ExpectedSourceRevision: m.SourceRevision,
	}
	var cache MCPCatalog
	var raw []byte
	err := d.QueryRow(`SELECT config_revision,discovered_at,available,executable_sha256,observed_revision,tools
FROM mcp_catalog_cache WHERE server_id=$1`, m.ID).Scan(
		&cache.ConfigRevision, &cache.DiscoveredAt, &cache.Available, &cache.ExecutableSHA256, &cache.ObservedRevision, &raw)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if err == nil {
		if err := json.Unmarshal(raw, &cache.Tools); err != nil {
			return nil, err
		}
		out.Cache = &cache
		switch {
		case !cache.ConfigRevision.Equal(m.UpdatedAt):
			out.Status = "stale"
		case !cache.Available:
			out.Status = "unavailable"
		default:
			out.Status = "discovered"
		}
	}
	if !out.Configured {
		out.Status = "not_configured"
	}
	if !m.Enabled {
		out.Status = "disabled"
	}
	return out, nil
}

// SaveMCPCatalog serializes publication against config saves/deletion. The row
// lock and exact captured revision comparison are in the SAME transaction.
func (d *DB) SaveMCPCatalog(ctx context.Context, m *MCPServer, cache MCPCatalog) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var revision time.Time
	var enabled bool
	err = tx.QueryRowContext(ctx, `SELECT updated_at,enabled FROM mcp_servers
WHERE id=$1 AND provider_kind=$2 AND provider_kind<>'' FOR UPDATE`, m.ID, m.ProviderKind).Scan(&revision, &enabled)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (!enabled || !revision.Equal(m.UpdatedAt)) {
		return ErrCatalogStale
	}
	if err != nil {
		return err
	}
	if cache.Tools == nil {
		cache.Tools = []MCPTool{}
	}
	raw, err := json.Marshal(cache.Tools)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mcp_catalog_cache
(server_id,config_revision,available,executable_sha256,observed_revision,tools)
VALUES ($1,$2,$3,$4,$5,$6)
ON CONFLICT (server_id) DO UPDATE SET config_revision=EXCLUDED.config_revision,
discovered_at=now(),available=EXCLUDED.available,executable_sha256=EXCLUDED.executable_sha256,
observed_revision=EXCLUDED.observed_revision,tools=EXCLUDED.tools`,
		m.ID, m.UpdatedAt, cache.Available, cache.ExecutableSHA256, cache.ObservedRevision, raw)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// CatalogTaggedName uses current and historical labels, including never-refreshed
// providers. It records nothing; the host gives registered tools precedence.
func (d *DB) CatalogTaggedName(ctx context.Context, name string) (bool, error) {
	var tagged bool
	err := d.QueryRowContext(ctx, `SELECT EXISTS (
SELECT 1 FROM mcp_servers m JOIN mcp_catalog_labels l ON l.server_id=m.id
WHERE m.provider_kind<>'' AND left($1,length('mcp__'||l.label||'__'))='mcp__'||l.label||'__'
)`, name).Scan(&tagged)
	return tagged, err
}

// RecordCatalogNativeUse classifies a newly emitted use against the row set
// visible in this statement. A later cache/label change never reclassifies it.
func (d *DB) RecordCatalogNativeUse(ctx context.Context, session, messageID, useID, name string) error {
	_, err := d.ExecContext(ctx, `INSERT INTO mcp_catalog_native_uses
(session_id,message_id,tool_use_id,provider_id,provider_kind,tool_name)
SELECT $1,$2,$3,m.id,m.provider_kind,$4
FROM mcp_servers m JOIN mcp_catalog_labels l ON l.server_id=m.id
WHERE m.provider_kind<>'' AND left($4,length('mcp__'||l.label||'__'))='mcp__'||l.label||'__'
ORDER BY length(l.label) DESC,m.id LIMIT 1
ON CONFLICT (session_id,message_id,tool_use_id) DO NOTHING`, session, messageID, useID, name)
	return err
}

func (d *DB) CatalogNativeUseIDs(ctx context.Context, session string) (map[string]map[string]bool, error) {
	rows, err := d.QueryContext(ctx, `SELECT message_id,tool_use_id FROM mcp_catalog_native_uses WHERE session_id=$1`, session)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := map[string]map[string]bool{}
	for rows.Next() {
		var messageID, id string
		if err := rows.Scan(&messageID, &id); err != nil {
			return nil, err
		}
		if ids[messageID] == nil {
			ids[messageID] = map[string]bool{}
		}
		ids[messageID][id] = true
	}
	return ids, rows.Err()
}
