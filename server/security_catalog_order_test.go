package server

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/locale"
	"github.com/Autumn-27/norma/llm"
)

func emitCatalogUse(p *catalogRenameProvider, id, name string) {
	p.emit = &llm.ContentBlock{Type: llm.BlockToolUse, ID: id, Name: name, Input: json.RawMessage(`{}`)}
}

func TestSecurityCatalogEmissionOrder(t *testing.T) {
	for _, order := range []string{"before-refresh", "failed-gap", "old-alias"} {
		for _, deleted := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/delete=%t", order, deleted), func(t *testing.T) {
				// Given a surviving tagged identity, regardless of cache availability.
				f := newCatalogFixture(t, "")
				f.save(t)
				old := f.m.Name
				refresh := func(want int) {
					t.Helper()
					r := f.call(t, t.Context(), "POST", fmt.Sprintf("/api/mcp/%d/refresh", f.m.ID), nil, true, locale.En)
					if r.Code != want {
						t.Fatalf("refresh=%d want=%d: %s", r.Code, want, r.Body.String())
					}
				}
				chat, p, _, session := catalogConversation(t, f, []int64{f.m.ID})
				switch order {
				case "failed-gap":
					refresh(200)
					if err := os.Rename(f.m.Command, f.m.Command+".held"); err != nil {
						t.Fatal(err)
					}
					refresh(502)
				case "old-alias":
					refresh(200)
					f.m.Name += "Renamed"
					f.save(t)
				}
				name := "mcp__" + old + "__unexpected_operation"
				// When an unknown/non-callable emission uses a tagged prefix.
				emitCatalogUse(p, "call_0", name)
				catalogBlockedPrompt(t, chat, session)
				catalogPair(t, p.requests[len(p.requests)-1], name, "call_0", 0)
				unknown := "mcp__unconfigured_unknown__operation"
				emitCatalogUse(p, "unknown", unknown)
				catalogPrompt(t, chat, session)
				catalogPair(t, p.requests[len(p.requests)-1], name, "call_0", 0)
				catalogPair(t, p.requests[len(p.requests)-1], unknown, "unknown", 1)
				if order == "failed-gap" {
					if err := os.Rename(f.m.Command+".held", f.m.Command); err != nil {
						t.Fatal(err)
					}
				}
				f.m.Name = old
				f.save(t)
				refresh(200)
				catalogPrompt(t, chat, session)
				catalogPair(t, p.requests[len(p.requests)-1], name, "call_0", 0)
				f.m.Name = old + "Final"
				f.save(t)
				refresh(200)
				catalogPrompt(t, chat, session)
				catalogPair(t, p.requests[len(p.requests)-1], name, "call_0", 0)
				if deleted {
					if err := f.s.m.pg.DeleteMCP(f.m.ID); err != nil {
						t.Fatal(err)
					}
					var labels int
					if err := f.s.m.pg.QueryRow(`SELECT count(*) FROM mcp_catalog_labels WHERE server_id=$1`, f.m.ID).Scan(&labels); err != nil || labels != 0 {
						t.Fatalf("deleted labels=%d: %v", labels, err)
					}
				}
				// Then a later generic birth may reuse both the label AND call id.
				generic := *f.m
				generic.ID, generic.Name, generic.ProviderKind = 0, old, ""
				r := f.call(t, t.Context(), "POST", "/api/mcp", generic, true, locale.En)
				var saved struct{ ID int64 }
				if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &saved) != nil {
					t.Fatal(r.Body.String())
				}
				t.Cleanup(func() {
					if err := f.s.m.pg.DeleteMCP(saved.ID); err != nil {
						t.Error(err)
					}
				})
				a, err := f.s.m.pg.GetAgentByKey("auto")
				if err != nil {
					t.Fatal(err)
				}
				if err := f.s.m.pg.SetAgentVisibilityKind(a.ID, "mcp", []int64{saved.ID}); err != nil {
					t.Fatal(err)
				}
				emitCatalogUse(p, "call_0", name)
				catalogPrompt(t, chat, session)
				if output := catalogPair(t, p.requests[len(p.requests)-1], name, "call_0", 1); !strings.Contains(output, "FIXTURE_CALL_DISABLED") {
					t.Fatal("generic did not execute: " + output)
				}
				for range 3 {
					catalogPrompt(t, chat, session)
					catalogPair(t, p.requests[len(p.requests)-1], name, "call_0", 1)
					catalogPair(t, p.requests[len(p.requests)-1], unknown, "unknown", 1)
				}
				var marked int
				if err := f.s.m.pg.QueryRow(`SELECT count(*) FROM mcp_catalog_native_uses WHERE session_id=$1 AND tool_use_id='call_0' AND message_id<>''`, session).Scan(&marked); err != nil || marked != 0 {
					t.Fatalf("position marks=%d: %v", marked, err)
				}
				t.Logf("%s delete=%t: tagged 0/0; duplicate-id generic 1/1 in every later request", order, deleted)
			})
		}
	}
}

func TestSecurityCatalogCallableAmbiguousPrefix(t *testing.T) {
	// Given a tagged X__x and callable generic X/x__unexpected_operation.
	f := newCatalogFixture(t, "")
	base := f.m.Name
	f.m.Name += "__x"
	f.save(t)
	r := f.call(t, t.Context(), "POST", fmt.Sprintf("/api/mcp/%d/refresh", f.m.ID), nil, true, locale.En)
	if r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	chat, p, _, session := catalogConversation(t, f, []int64{f.m.ID})
	blocked := "mcp__" + f.m.Name + "__not_callable"
	emitCatalogUse(p, "native", blocked)
	catalogBlockedPrompt(t, chat, session)
	catalogPair(t, p.requests[len(p.requests)-1], blocked, "native", 0)
	generic := *f.m
	generic.ID, generic.Name, generic.ProviderKind = 0, base, ""
	var settings map[string]string
	if err := json.Unmarshal(generic.Env, &settings); err != nil {
		t.Fatal(err)
	}
	settings["TASK3_FIXTURE_MUTATION"] = "ambiguous"
	var err error
	generic.Env, err = json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	r = f.call(t, t.Context(), "POST", "/api/mcp", generic, true, locale.En)
	var saved struct{ ID int64 }
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &saved) != nil {
		t.Fatal(r.Body.String())
	}
	t.Cleanup(func() {
		if err := f.s.m.pg.DeleteMCP(saved.ID); err != nil {
			t.Error(err)
		}
	})
	a, err := f.s.m.pg.GetAgentByKey("auto")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.s.m.pg.SetAgentVisibilityKind(a.ID, "mcp", []int64{f.m.ID, saved.ID}); err != nil {
		t.Fatal(err)
	}
	// When the real generic capability has the same spelling as a tagged prefix.
	name := "mcp__" + base + "__x__unexpected_operation"
	emitCatalogUse(p, "generic", name)
	catalogPrompt(t, chat, session)
	// Then callable precedence keeps execution/history and the marked control is absent.
	if output := catalogPair(t, p.requests[len(p.requests)-1], name, "generic", 1); !strings.Contains(output, "FIXTURE_CALL_DISABLED") {
		t.Fatal(output)
	}
	catalogPair(t, p.requests[len(p.requests)-1], blocked, "native", 0)
	var count int
	if err := f.s.m.pg.QueryRow(`SELECT count(*) FROM mcp_catalog_native_uses WHERE session_id=$1 AND tool_use_id='generic'`, session).Scan(&count); err != nil || count != 0 {
		t.Fatalf("generic marked: %d %v", count, err)
	}
}

func TestSecurityCatalogLiveLabelCollision(t *testing.T) {
	// Given a live tagged row and an independently registered generic row.
	f := newCatalogFixture(t, "")
	f.save(t)
	generic := *f.m
	generic.ID, generic.Name, generic.ProviderKind = 0, f.m.Name+"Generic", ""
	r := f.call(t, t.Context(), "POST", "/api/mcp", generic, true, locale.En)
	var saved struct{ ID int64 }
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &saved) != nil {
		t.Fatal(r.Body.String())
	}
	t.Cleanup(func() {
		if err := f.s.m.pg.DeleteMCP(saved.ID); err != nil {
			t.Error(err)
		}
	})
	snapshot := func() string {
		t.Helper()
		var raw string
		if err := f.s.m.pg.QueryRow(`SELECT jsonb_build_object('rows',(SELECT jsonb_agg(to_jsonb(m) ORDER BY id) FROM mcp_servers m),'labels',(SELECT jsonb_agg(to_jsonb(l) ORDER BY server_id,label) FROM mcp_catalog_labels l),'marks',(SELECT jsonb_agg(to_jsonb(u) ORDER BY session_id,message_id,tool_use_id) FROM mcp_catalog_native_uses u))::text`).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	before := snapshot()
	// When create and rename deliberately collide with the live tagged label.
	for _, id := range []int64{0, saved.ID} {
		generic.ID, generic.Name = id, f.m.Name
		r = f.call(t, t.Context(), "POST", "/api/mcp", generic, true, locale.En)
		// Then the unchanged generic save path returns its existing SQL 500.
		if r.Code != 500 || !strings.Contains(r.Body.String(), "23505") || !strings.Contains(r.Body.String(), "mcp_servers_name_key") {
			t.Fatalf("collision HTTP %d: %s", r.Code, r.Body.String())
		}
		if snapshot() != before {
			t.Fatal("collision changed rows, labels or marks")
		}
		t.Logf("generic id=%d collision HTTP 500: %s; rows/labels/marks unchanged", id, r.Body.String())
	}
}
