package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/jackc/pgx/v5"
)

func TestSCR95PairedApplications(t *testing.T) {
	if os.Getenv("SCOPEWEAVER_PROVIDER_E2E") != "1" {
		t.Skip("requires disposable provider database and explicit opt-in")
	}
	cfg, err := pgx.ParseConfig(os.Getenv("ARTEX_PG_DSN"))
	if err != nil || !strings.HasPrefix(cfg.Database, "scopeweaver_provider_") {
		t.Fatal("explicit disposable scopeweaver_provider_* database required")
	}
	for _, key := range []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "ARTEX_LLM_PROVIDER"} {
		t.Setenv(key, "")
	}
	var fixture struct {
		Assets   []map[string]any `json:"assets"`
		Findings []map[string]any `json:"findings"`
	}
	raw, err := os.ReadFile(filepath.Join("testdata", "provider_records.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Assets) != 6 || len(fixture.Findings) == 0 {
		t.Fatal("real source fixture must contain all six asset types and findings")
	}
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal("isolated manager initialization failed")
	}
	defer m.Close()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := m.pg.Exec(q, args...); err != nil {
			t.Fatalf("fixture SQL failed: %v", err)
		}
	}
	id := func(q string, args ...any) int64 {
		t.Helper()
		var n int64
		if err := m.pg.QueryRow(q, args...).Scan(&n); err != nil {
			t.Fatalf("fixture identity failed: %v", err)
		}
		return n
	}
	// Run this opt-in journey alone, never in a shared package fixture database.
	// Refuse model profiles before making any destructive fixture changes.
	if n := id(`SELECT count(*) FROM llm_profiles`); n != 0 {
		t.Fatal("test database must not contain model credentials")
	}
	// The explicit database-name guard above prevents destructive fixtures on source.
	exec(`TRUNCATE companies,explorations,traffic_evidence_snapshots RESTART IDENTITY CASCADE`)
	exec(`UPDATE mcp_servers SET enabled=false`)
	a := id(`INSERT INTO companies(name,nkey) VALUES('Anonymized source A','provider-fixture-a') RETURNING id`)
	b := id(`INSERT INTO companies(name,nkey) VALUES('Anonymized source B','provider-fixture-b') RETURNING id`)
	assetIDs := []int64{}
	var endpointID int64
	for i, sample := range fixture.Assets {
		aid := id(`INSERT INTO assets(type,company_id,domain,ip,bundle_id,url,method,port,status_code,content_length,extra) VALUES($1,$2,$3,$4,$5,$6,'GET',$7,$8,$9,'{"credential":"DO_NOT_EXPORT_SOURCE_CONTENT"}') RETURNING id`, sample["type"], a, fmt.Sprintf("asset-%d.fixture.invalid", i), fmt.Sprintf("192.0.2.%d", i+1), fmt.Sprintf("fixture.%d", i), fmt.Sprintf("https://asset-%d.fixture.invalid/path?token=DO_NOT_EXPORT_SOURCE_CONTENT", i), sample["port"], sample["status_code"], sample["content_length"])
		assetIDs = append(assetIDs, aid)
		if sample["type"] == "endpoint" {
			endpointID = aid
		}
	}
	// Controlled mutations of the anonymized source records exercise redaction
	// and automatic metadata; these are not observations about production content.
	endpointSourceURL := "HTTPS://fixture-user:DO_NOT_EXPORT_SOURCE_CONTENT@endpoint.fixture.invalid/path?token=DO_NOT_EXPORT_SOURCE_CONTENT#DO_NOT_EXPORT_SOURCE_CONTENT"
	exec(`UPDATE assets SET url=$2,technologies=ARRAY['REDACTED source technology'],page_title='REDACTED source page',extra='{"description":"REDACTED source metadata","credential":"DO_NOT_EXPORT_SOURCE_CONTENT","unmapped":"DO_NOT_EXPORT_SOURCE_CONTENT"}',params=ARRAY['{"location":"query","name":"filter","type":"string","value":"DO_NOT_EXPORT_SOURCE_CONTENT"}'::jsonb],auth=ARRAY['{"type":"bearer","token":"DO_NOT_EXPORT_SOURCE_CONTENT"}'::jsonb] WHERE id=$1`, endpointID, endpointSourceURL)
	foreign := id(`INSERT INTO assets(type,company_id,url) VALUES('endpoint',$1,'https://other.fixture.invalid/private') RETURNING id`, b)
	unassigned := id(`INSERT INTO assets(type,url) VALUES('endpoint','https://unassigned.fixture.invalid/private') RETURNING id`)
	_ = unassigned
	exp := id(`INSERT INTO explorations(goal) VALUES('REDACTED source goal') RETURNING id`)
	task := id(`INSERT INTO tasks(description,goal,exploration_id,company_id) VALUES('REDACTED source description','REDACTED source goal',$1,$2) RETURNING id`, exp, a)
	exp2 := id(`INSERT INTO explorations(goal) VALUES('REDACTED lineage') RETURNING id`)
	task2 := id(`INSERT INTO tasks(description,goal,exploration_id,company_id) VALUES('REDACTED','REDACTED',$1,$2) RETURNING id`, exp2, a)
	exp3 := id(`INSERT INTO explorations(goal) VALUES('REDACTED ambiguous') RETURNING id`)
	badTask := id(`INSERT INTO tasks(description,goal,exploration_id,company_id) VALUES('REDACTED','REDACTED',$1,$2) RETURNING id`, exp3, a)
	exec(`INSERT INTO task_scope(task_id,kind,company_id) VALUES($1,'company',$2)`, badTask, b)
	exec(`INSERT INTO task_scope(task_id,kind,company_id) VALUES($1,'company',$2)`, task, a)
	exec(`INSERT INTO company_scope(company_id,kind,domain,raw) VALUES($1,'domain','fixture.invalid','DO_NOT_EXPORT_SOURCE_CONTENT')`, a)
	exec(`INSERT INTO task_relations(task_id,source_task_id) VALUES($1,$2)`, task, task2)
	exec(`INSERT INTO task_asset_links(task_id,asset_id) VALUES($1,$2)`, task, assetIDs[0])
	goal := id(`INSERT INTO exploration_nodes(exploration_id,kind,state,payload) VALUES($1,'goal','open','{"text":"DO_NOT_EXPORT_SOURCE_CONTENT"}') RETURNING id`, exp)
	node := id(`INSERT INTO exploration_nodes(exploration_id,kind,state) VALUES($1,'fact','confirmed') RETURNING id`, exp)
	exec(`INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id) VALUES($1,$2,'proves',$3)`, exp, node, goal)
	exec(`INSERT INTO exploration_anchors(node_id,asset_id) VALUES($1,$2)`, node, assetIDs[0])
	exec(`INSERT INTO task_constraints(exploration_id,kind,text) VALUES($1,'deny','DO_NOT_EXPORT_SOURCE_CONTENT')`, exp)
	exec(`INSERT INTO activity(exploration_id,node_id,kind,summary,detail,metadata) VALUES($1,$2,'tool_result','DO_NOT_EXPORT_SOURCE_CONTENT','DO_NOT_EXPORT_SOURCE_CONTENT','{"secret":"DO_NOT_EXPORT_SOURCE_CONTENT"}')`, exp, node)
	findingIDs := []int64{}
	for _, f := range fixture.Findings {
		fid := id(`INSERT INTO findings(task_id,node_id,severity,status,asset_ids,report,evidence,evidence_version,report_evidence_version) VALUES($1,$2,$3,$4,$5,'DO_NOT_EXPORT_SOURCE_CONTENT','DO_NOT_EXPORT_SOURCE_CONTENT',$6,$7) RETURNING id`, task, node, f["severity"], f["status"], fmt.Sprintf("[%d]", assetIDs[0]), f["evidence_version"], f["report_evidence_version"])
		findingIDs = append(findingIDs, fid)
	}
	ownFinding := findingIDs[0]
	exec("UPDATE findings SET summary=$1,report=$2,evidence=$3 WHERE id=$4", "REDACTED source finding summary", "REDACTED source-held assessment report.\nAuthorization: Basic fixture-only\nDB_PASSWORD=short-demo\n```http\nGET /private HTTP/1.1\nCookie: DO_NOT_EXPORT_SOURCE_CONTENT\n```\nReference https://asset-1.fixture.invalid/v1/profile?token=DO_NOT_EXPORT_SOURCE_CONTENT", "REDACTED source-held evidence.\npassword=DO_NOT_EXPORT_SOURCE_CONTENT", ownFinding)
	exec(`UPDATE exploration_nodes SET payload='{"text":"REDACTED source goal","credential":"DO_NOT_EXPORT_SOURCE_CONTENT","unmapped":"DO_NOT_EXPORT_SOURCE_CONTENT"}' WHERE id=$1`, goal)
	orphan := id(`INSERT INTO findings(severity,status,asset_ids) VALUES('high','pending',$1) RETURNING id`, fmt.Sprintf("[%d]", assetIDs[1]))
	badFinding := id(`INSERT INTO findings(task_id,severity,asset_ids) VALUES($1,'high',$2) RETURNING id`, task, fmt.Sprintf("[%d,%d]", assetIDs[0], foreign))
	exec(`INSERT INTO findings(task_id,severity,asset_ids) VALUES($1,'high','[]')`, task)
	exec(`INSERT INTO findings(severity,asset_ids) VALUES('high','[]')`)
	exec(`INSERT INTO finding_retests(finding_id,status,verdict,snapshot) VALUES($1,'completed','inconclusive','{}')`, ownFinding)
	exec(`INSERT INTO traffic_evidence_snapshots(id,source_traffic_id,captured_at,url,method,status,req_head,resp_head,req_hash,resp_hash,req_len,resp_len) VALUES('fixture-snapshot','DO_NOT_EXPORT_SOURCE_CONTENT',0,'https://fixture.invalid/?secret=DO_NOT_EXPORT_SOURCE_CONTENT','GET',200,'DO_NOT_EXPORT_SOURCE_CONTENT','DO_NOT_EXPORT_SOURCE_CONTENT','fixture-request-digest','fixture-response-digest',10,20)`)
	exec(`INSERT INTO finding_traffic_bindings(finding_id,snapshot_id,position) VALUES($1,'fixture-snapshot',0)`, ownFinding)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	directory := t.TempDir()
	s := New(ctx, m, directory, directory, directory)
	httpServer := httptest.NewServer(s.Handler())
	defer httpServer.Close()
	admin, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal("scratch administrator signing failed")
	}
	type response struct {
		Code int
		Body []byte
	}
	var transcript []map[string]any
	if evidencePath := os.Getenv("SCOPEWEAVER_PROVIDER_EVIDENCE"); evidencePath != "" {
		defer func() {
			data, err := json.MarshalIndent(transcript, "", "  ")
			if err != nil || os.WriteFile(evidencePath, data, 0600) != nil {
				t.Error("sanitized evidence write failed")
			}
		}()
	}
	do := func(method, path, token string, body any) response {
		t.Helper()
		var reader io.Reader
		if body != nil {
			data, e := json.Marshal(body)
			if e != nil {
				t.Fatal(e)
			}
			reader = bytes.NewReader(data)
		}
		req, e := http.NewRequest(method, httpServer.URL+path, reader)
		if e != nil {
			t.Fatal("request construction failed")
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		res, e := http.DefaultClient.Do(req)
		if e != nil {
			t.Fatal("isolated HTTP transport failed")
		}
		defer res.Body.Close()
		data, e := io.ReadAll(io.LimitReader(res.Body, 80<<20))
		if e != nil {
			t.Fatal("response read failed")
		}
		if bytes.Contains(data, []byte("DO_NOT_EXPORT_SOURCE_CONTENT")) {
			t.Fatal("source content escaped provider redaction boundary")
		}
		if os.Getenv("SCOPEWEAVER_PROVIDER_EVIDENCE") != "" {
			decoder := json.NewDecoder(bytes.NewReader(data))
			decoder.UseNumber()
			var safe any
			if decoder.Decode(&safe) != nil {
				t.Fatal("evidence response was not JSON")
			}
			providerRedactEvidence(safe)
			transcript = append(transcript, map[string]any{"method": method, "request_path": strings.SplitN(path, "?", 2)[0], "status": res.StatusCode, "response": safe})
		}
		return response{res.StatusCode, data}
	}
	expect := func(r response, code int) {
		t.Helper()
		if r.Code != code {
			t.Fatalf("expected HTTP %d, got %d (body suppressed)", code, r.Code)
		}
	}
	grant := func(company int64) (string, string) {
		t.Helper()
		res := do("POST", "/api/provider-grants", admin, map[string]any{"company_id": company, "ttl_seconds": 3600})
		expect(res, 201)
		var out struct {
			Token string           `json:"token"`
			Grant db.ProviderGrant `json:"grant"`
		}
		if json.Unmarshal(res.Body, &out) != nil || out.Token == "" {
			t.Fatal("grant response invalid")
		}
		return out.Token, out.Grant.ID
	}
	token, grantID := grant(a)
	other, _ := grant(b)

	// Intent: SCR-95 / accepted SCR-92. Reuse minimized source readings in a
	// second isolated company, then run actual AiSOC services against this app.
	for i, sample := range fixture.Assets {
		id(`INSERT INTO assets(type,company_id,domain,ip,bundle_id,url,method,port,status_code,content_length) VALUES($1,$2,$3,$4,$5,$6,'GET',$7,$8,$9) RETURNING id`, sample["type"], b, fmt.Sprintf("b-asset-%d.fixture.invalid", i), fmt.Sprintf("198.51.100.%d", i+1), fmt.Sprintf("fixture.b.%d", i), fmt.Sprintf("https://b-asset-%d.fixture.invalid/path", i), sample["port"], sample["status_code"], sample["content_length"])
	}
	tlsServer := httptest.NewTLSServer(s.Handler())
	defer tlsServer.Close()
	private := os.Getenv("SCR95_PRIVATE")
	if private == "" {
		t.Fatal("private harness directory required")
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsServer.Certificate().Raw})
	certPath := filepath.Join(private, "source-cert.pem")
	if os.WriteFile(certPath, cert, 0600) != nil {
		t.Fatal("cannot write test certificate")
	}
	settings := map[string]any{"base": tlsServer.URL, "certificate": certPath, "company_a": a, "company_b": b, "token_a": token, "token_b": other, "grant_a": grantID, "finding_a": ownFinding, "bad_finding": badFinding, "bad_task": badTask, "orphan": orphan, "endpoint": endpointID, "source_dsn": os.Getenv("ARTEX_PG_DSN")}
	data, err := json.Marshal(settings)
	if err != nil || os.WriteFile(filepath.Join(private, "source.json"), data, 0600) != nil {
		t.Fatal("cannot write private harness configuration")
	}
	output, err := os.OpenFile(filepath.Join(private, "paired-private.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal("cannot open private harness log")
	}
	defer output.Close()
	command := osexec.Command("/tmp/aisoc-scr94-tools/api/bin/python", filepath.Join(private, "paired.py"))
	command.Stdout = output
	command.Stderr = output
	if command.Run() != nil {
		t.Fatal("paired application journey failed; private diagnostic log retained, no body disclosed")
	}
}
