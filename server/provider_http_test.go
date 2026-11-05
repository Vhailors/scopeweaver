package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Intent: SCR-93 / accepted SCR-92 direction A. Exercise provider company
// boundaries, every attributable family, and restart-safe snapshots through real
// HTTP and PostgreSQL. Fixtures are minimized readings from the existing source;
// mutations below are isolated boundary/failure scenarios, not production facts.
func TestProviderCompanyContractPG(t *testing.T) {
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
	// Intent: SCR-107 requires opaque composite identities even for credential-pattern
	// relationship text. Current schema rejects such labels; model legacy constraint
	// drift only in this disposable database, then immediately restore enforcement.
	credentialRelations := []string{"password=scr107-pass-a", "password=scr107-pass-b", "Authorization: Bearer scr107-header"}
	_, err = m.pg.Exec(`INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id) VALUES($1,$2,$3,$4)`, exp, node, credentialRelations[0], goal)
	var checkError *pgconn.PgError
	if !errors.As(err, &checkError) || checkError.Code != "23514" {
		t.Fatal("current schema must reject credential-pattern relationship labels")
	}
	var relationCheck string
	if err = m.pg.QueryRow(`SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='exploration_edges'::regclass AND conname='ck_edge_rel'`).Scan(&relationCheck); err != nil {
		t.Fatal("relationship constraint definition unavailable")
	}
	exec(`ALTER TABLE exploration_edges DROP CONSTRAINT ck_edge_rel`)
	for _, relation := range credentialRelations {
		exec(`INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id) VALUES($1,$2,$3,$4)`, exp, node, relation, goal)
	}
	exec(`ALTER TABLE exploration_edges ADD CONSTRAINT ck_edge_rel ` + relationCheck + ` NOT VALID`)
	defer func() {
		if _, e := m.pg.Exec(`DELETE FROM exploration_edges WHERE rel=ANY($1)`, credentialRelations); e != nil {
			t.Error("controlled relationship fixture cleanup failed")
		}
		if _, e := m.pg.Exec(`ALTER TABLE exploration_edges VALIDATE CONSTRAINT ck_edge_rel`); e != nil {
			t.Error("relationship constraint restoration failed")
		}
	}()
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
		for _, value := range []string{"scr107-pass-a", "scr107-pass-b", "scr107-header"} {
			if bytes.Contains(data, []byte(value)) {
				t.Fatal("credential-pattern relationship escaped provider envelope")
			}
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
	path := fmt.Sprintf("/api/provider/v1/companies/%d/snapshot", a)
	otherPath := fmt.Sprintf("/api/provider/v1/companies/%d/snapshot", b)
	type page struct {
		ID       string              `json:"snapshot_id"`
		Manifest db.ProviderManifest `json:"manifest"`
		Records  []db.ProviderRecord `json:"records"`
		Next     string              `json:"next_cursor"`
		Complete bool                `json:"complete"`
		Total    int                 `json:"total"`
	}
	parse := func(r response) page {
		t.Helper()
		expect(r, 200)
		var p page
		if json.Unmarshal(r.Body, &p) != nil {
			t.Fatal("invalid page")
		}
		return p
	}
	first := parse(do("GET", path+"?limit=2", token, nil))
	if first.Complete || first.Next == "" {
		t.Fatal("fixture must span multiple pages")
	}
	// Changes during paging cannot change this persisted snapshot.
	exec(`UPDATE findings SET status='risk_accepted' WHERE id=$1`, ownFinding)
	added := id(`INSERT INTO assets(type,company_id,url) VALUES('endpoint',$1,'https://later.fixture.invalid/new') RETURNING id`, a)
	nextResponse := do("GET", path+"?cursor="+first.Next, token, nil)
	duplicate := do("GET", path+"?cursor="+first.Next, token, nil)
	if !bytes.Equal(nextResponse.Body, duplicate.Body) {
		t.Fatal("duplicate page delivery changed content")
	}
	// A new manager and handler with a separate scratch home have no cursor state.
	restartedManager, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal("restart manager initialization failed")
	}
	defer restartedManager.Close()
	restartedDirectory := t.TempDir()
	restartedServer := New(ctx, restartedManager, restartedDirectory, restartedDirectory, restartedDirectory)
	restart := httptest.NewServer(restartedServer.Handler())
	defer restart.Close()
	old := httpServer
	httpServer = restart
	replay := do("GET", path+"?cursor="+first.Next, token, nil)
	httpServer = old
	if !bytes.Equal(replay.Body, nextResponse.Body) {
		t.Fatal("restart resume changed snapshot")
	}
	all := append([]db.ProviderRecord{}, first.Records...)
	p := first
	for p.Next != "" {
		p = parse(do("GET", path+"?cursor="+p.Next, token, nil))
		all = append(all, p.Records...)
	}
	if !p.Complete || len(all) != p.Total {
		t.Fatal("snapshot completion/count mismatch")
	}
	seen := map[string]map[string]db.ProviderRecord{}
	for _, record := range all {
		if seen[record.Family] == nil {
			seen[record.Family] = map[string]db.ProviderRecord{}
		}
		if _, exists := seen[record.Family][record.ID]; exists {
			t.Fatal("duplicate record identity")
		}
		seen[record.Family][record.ID] = record
		if record.Company != a || record.Schema != db.ProviderSchema || record.Source == "" || record.ObservedAt.IsZero() || record.Checksum == "" {
			t.Fatal("incomplete record envelope")
		}
		var v any
		_ = json.Unmarshal(record.Payload, &v)
		canonical, _ := json.Marshal(v)
		if db.ProviderChecksum(canonical) != record.Checksum {
			t.Fatal("checksum mismatch")
		}
	}
	for _, family := range []string{"company", "scope", "asset", "task", "task_scope", "finding", "report", "evidence", "retest", "evidence_reference", "goal", "research_node", "research_edge", "constraint", "coverage_anchor", "lineage", "task_asset", "activity", "rejected"} {
		if len(seen[family]) == 0 {
			t.Fatalf("missing family %s", family)
		}
	}
	compositeFamilies := []string{"research_edge", "coverage_anchor", "lineage", "task_asset"}
	for _, family := range compositeFamilies {
		for identity := range seen[family] {
			if !strings.HasPrefix(identity, "pc1_") || len(identity) != len("pc1_")+sha256.Size*2 {
				t.Fatal("composite provider identity is not an opaque digest")
			}
			if _, e := hex.DecodeString(strings.TrimPrefix(identity, "pc1_")); e != nil {
				t.Fatal("composite provider identity has invalid digest encoding")
			}
			if _, e := m.pg.ProviderSourceRecord(ctx, a, family, identity); e != nil {
				t.Fatal("snapshot composite identity does not resolve at its source")
			}
		}
	}
	// Different raw keys must remain distinct even when their payload labels redact
	// to the same text. Keep the normal relation useful to the graph reader.
	if len(seen["research_edge"]) != len(credentialRelations)+1 {
		t.Fatal("redacted relationship labels collapsed distinct source identities")
	}
	relationIDs := map[string]string{}
	for identity, edge := range seen["research_edge"] {
		var payload struct {
			Rel string `json:"rel"`
		}
		if json.Unmarshal(edge.Payload, &payload) != nil {
			t.Fatal("relationship payload unavailable")
		}
		relationIDs[identity] = payload.Rel
	}
	var normalEdge string
	redactedAssignments := 0
	for identity, relation := range relationIDs {
		if relation == "proves" {
			normalEdge = identity
		}
		if relation == "password=[redacted]" {
			redactedAssignments++
		}
	}
	if normalEdge == "" || redactedAssignments != 2 {
		t.Fatal("relationship payload redaction lost safe labels or retained assignments")
	}
	if len(seen["asset"]) != 6 {
		t.Fatal("all six source asset types must appear, without another company or later additions")
	}
	payloadOf := func(family, identity string) map[string]any {
		t.Helper()
		var payload map[string]any
		if json.Unmarshal(seen[family][identity].Payload, &payload) != nil {
			t.Fatal("automatic payload unavailable")
		}
		return payload
	}
	endpointPayload := payloadOf("asset", strconv.FormatInt(endpointID, 10))
	parsedURL, err := url.Parse(endpointPayload["url"].(string))
	expectedURL, _ := url.Parse(endpointSourceURL)
	if err != nil || parsedURL.Scheme != "https" || parsedURL.Path != expectedURL.Path || parsedURL.Hostname() != expectedURL.Hostname() || parsedURL.User != nil || parsedURL.Fragment != "" || parsedURL.Query().Get("token") != "[redacted]" {
		t.Fatal("automatic URL lost its identity or retained credentials, query values or fragments")
	}
	if _, exists := endpointPayload["auth"]; exists {
		t.Fatal("authentication values entered automatic metadata")
	}
	if endpointPayload["authentication_present"] != true {
		t.Fatal("safe authentication presence metadata was lost")
	}
	if endpointPayload["page_title"] != "REDACTED source page" || len(endpointPayload["technologies"].([]any)) == 0 {
		t.Fatal("useful asset metadata still needs publication")
	}
	extra := endpointPayload["extra"].(map[string]any)
	if extra["description"] != "REDACTED source metadata" || extra["credential"] != nil || extra["unmapped"] != nil {
		t.Fatal("automatic metadata allowlist did not preserve safe fields and remove unsupported content")
	}
	param := endpointPayload["params"].([]any)[0].(map[string]any)
	if param["name"] != "filter" || param["value"] != nil {
		t.Fatal("parameter metadata or value exclusion failed")
	}
	if payloadOf("company", strconv.FormatInt(a, 10))["name"] != "Anonymized source A" || payloadOf("task", strconv.FormatInt(task, 10))["description"] != "REDACTED source description" {
		t.Fatal("company/task labels still require publication")
	}
	if payloadOf("goal", strconv.FormatInt(goal, 10))["research"].(map[string]any)["text"] != "REDACTED source goal" {
		t.Fatal("automatic research text unavailable")
	}
	if payloadOf("finding", strconv.FormatInt(ownFinding, 10))["summary"] != "REDACTED source finding summary" {
		t.Fatal("automatic finding summary unavailable")
	}
	if id(`SELECT count(*) FROM provider_publications`) != 0 {
		t.Fatal("automatic coverage must be proven before any publication")
	}
	reportMetadata := payloadOf("report", strconv.FormatInt(ownFinding, 10))
	if reportMetadata["body"] != nil || reportMetadata["detail_available"] != true {
		t.Fatal("report originals must stay source-held behind automatic detail reads")
	}
	automaticRevision := reportMetadata["source_revision"].(string)
	detailPath := fmt.Sprintf("/api/provider/v1/companies/%d/records/report/%d", a, ownFinding)
	automaticDetail := do("GET", detailPath+"?source_revision="+automaticRevision, token, nil)
	expect(automaticDetail, 200)
	var detailRecord db.ProviderRecord
	if json.Unmarshal(automaticDetail.Body, &detailRecord) != nil || detailRecord.Company != a || detailRecord.Source != first.Manifest.Source || detailRecord.Schema != db.ProviderSchema {
		t.Fatal("automatic detail envelope is incomplete")
	}
	detailCanonical, err := db.ProviderCanonicalJSON(detailRecord.Payload)
	if err != nil || detailRecord.Checksum != db.ProviderChecksum(detailCanonical) || detailRecord.Revision != detailRecord.Checksum || detailRecord.ObservedAt.IsZero() || detailRecord.Family != "report" || detailRecord.ID != strconv.FormatInt(ownFinding, 10) {
		t.Fatal("automatic detail identity or payload integrity failed")
	}
	var detailPayload map[string]any
	_ = json.Unmarshal(detailRecord.Payload, &detailPayload)
	body := detailPayload["body"].(string)
	if !strings.Contains(body, "REDACTED source-held assessment report.") || strings.Contains(body, "GET /private") || strings.Contains(body, "fixture-only") || strings.Contains(body, "short-demo") || detailPayload["content_checksum"] != db.ProviderChecksum([]byte(body)) {
		t.Fatal("redacted report content or integrity is incorrect")
	}
	expect(do("GET", detailPath, token, nil), 400)
	expect(do("GET", detailPath+"?source_revision="+strings.Repeat("0", 64), token, nil), 409)
	for i, f := range fixture.Findings {
		var data map[string]any
		_ = json.Unmarshal(seen["finding"][strconv.FormatInt(findingIDs[i], 10)].Payload, &data)
		if data["severity"] != f["severity"] || data["status"] != f["status"] {
			t.Fatal("original severity/disposition changed")
		}
	}
	if _, ok := seen["finding"][strconv.FormatInt(orphan, 10)]; !ok {
		t.Fatal("unambiguous asset-only finding omitted")
	}
	if _, ok := seen["finding"][strconv.FormatInt(badFinding, 10)]; ok {
		t.Fatal("mixed-company finding exported")
	}
	if _, ok := seen["task"][strconv.FormatInt(badTask, 10)]; ok {
		t.Fatal("mixed-company task exported")
	}
	if first.Manifest.Rejected["ambiguous_company_attribution"] < 2 || len(first.Manifest.Gaps) == 0 {
		t.Fatal("omissions must be visible")
	}
	// Non-key edits change content revisions, not identities. This fresh snapshot
	// also proves stability across the new manager used during restart replay.
	exec(`UPDATE exploration_edges SET created_at=created_at+interval '1 second' WHERE exploration_id=$1 AND src_id=$2 AND rel='proves' AND dst_id=$3`, exp, node, goal)
	exec(`UPDATE task_asset_links SET source_summary='Updated source summary' WHERE task_id=$1 AND asset_id=$2`, task, assetIDs[0])
	fresh := parse(do("GET", path+"?limit=500", token, nil))
	for _, family := range compositeFamilies {
		count := 0
		for _, record := range fresh.Records {
			if record.Family != family {
				continue
			}
			count++
			if _, ok := seen[family][record.ID]; !ok {
				t.Fatal("non-key edit changed composite identity")
			}
			if family == "research_edge" && record.ID == normalEdge && record.Revision == seen[family][record.ID].Revision {
				t.Fatal("relationship content edit did not change revision")
			}
		}
		if count != len(seen[family]) {
			t.Fatal("fresh snapshot lost composite records")
		}
	}
	// Legacy persisted pages must fail closed before returning ANY page, including
	// one whose records precede the affected family. Never rewrite a pinned page.
	for _, family := range compositeFamilies {
		legacy := parse(do("GET", path+"?limit=2", token, nil))
		legacyIdentity := fmt.Sprintf("%d:%d:%s:%d", exp, node, credentialRelations[0], goal)
		exec(`UPDATE provider_snapshots SET records=(SELECT jsonb_agg(CASE WHEN r->>'family'=$3 THEN jsonb_set(r,'{record_id}',to_jsonb($2::text)) ELSE r END ORDER BY ord) FROM jsonb_array_elements(records) WITH ORDINALITY e(r,ord)) WHERE id=$1`, legacy.ID, legacyIdentity, family)
		expect(do("GET", path+"?cursor="+legacy.Next, token, nil), 410)
		zero, _ := json.Marshal(providerCursor{Snapshot: legacy.ID, Offset: 0})
		expect(do("GET", path+"?cursor="+base64.RawURLEncoding.EncodeToString(zero), token, nil), 410)
	}
	// Primary-key removal is absence in the next complete snapshot; restoring the
	// same source key recovers the same opaque ID, not a new random identifier.
	exec(`DELETE FROM exploration_edges WHERE exploration_id=$1 AND src_id=$2 AND rel='proves' AND dst_id=$3`, exp, node, goal)
	withoutEdge := parse(do("GET", path+"?limit=500", token, nil))
	for _, record := range withoutEdge.Records {
		if record.Family == "research_edge" && record.ID == normalEdge {
			t.Fatal("removed composite key remains in fresh snapshot")
		}
	}
	exec(`INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id) VALUES($1,$2,'proves',$3)`, exp, node, goal)
	restoredEdge := parse(do("GET", path+"?limit=500", token, nil))
	foundEdge := false
	for _, record := range restoredEdge.Records {
		if record.Family == "research_edge" && record.ID == normalEdge {
			foundEdge = true
		}
	}
	if !foundEdge {
		t.Fatal("restoring a source key changed its composite identity")
	}
	transcript = append(transcript, map[string]any{"check": "SCR-107 opaque composite identities", "families": compositeFamilies, "distinct_relationships": len(seen["research_edge"]), "same_redacted_label_distinct_identities": redactedAssignments, "source_lookup": "passed", "non_key_update_stability": "passed", "removal_and_restoration": "passed", "legacy_cursor_refusal": "410 for each family, including offset zero", "schema_constraint": "credential label rejected before controlled legacy fixture"})

	if fresh.Manifest.Checksum == first.Manifest.Checksum || fresh.Total <= first.Total {
		t.Fatal("fresh cycle missed updates/additions")
	}
	// Source ownership changes override historical snapshot authorization.
	freshCursorBytes, _ := json.Marshal(providerCursor{Snapshot: fresh.ID, Offset: 0})
	freshCursor := base64.RawURLEncoding.EncodeToString(freshCursorBytes)
	exec(`UPDATE assets SET company_id=$1 WHERE id=$2`, b, assetIDs[5])
	expect(do("GET", path+"?cursor="+freshCursor, token, nil), 410)
	exec(`UPDATE assets SET company_id=$1 WHERE id=$2`, a, assetIDs[5])
	expect(do("GET", path+"?cursor="+freshCursor, token, nil), 200)
	expect(do("GET", otherPath, token, nil), 403)
	expect(do("GET", path, other, nil), 403)
	expect(do("GET", detailPath+"?source_revision="+automaticRevision, other, nil), 403)
	expect(do("GET", fmt.Sprintf("/api/provider/v1/companies/%d/records/report/%d?source_revision=%s", b, ownFinding, automaticRevision), other, nil), 404)
	expect(do("GET", path, admin, nil), 401)
	expect(do("GET", "/api/tasks", token, nil), 401)
	expect(do("POST", "/api/tasks", token, map[string]any{}), 401)
	expect(do("POST", path, token, map[string]any{}), 405)
	expect(do("GET", path+"?limit=501", token, nil), 400)
	expect(do("GET", path+"?cursor=invalid", token, nil), 400)
	token2, _ := grant(a)
	expect(do("GET", path+"?cursor="+first.Next, token2, nil), 410)
	expect(do("GET", path+"?token="+token, "", nil), 401)
	// Authenticate from headers only: neither cookies nor query strings are credentials.
	req, _ := http.NewRequest("GET", httpServer.URL+path, nil)
	req.AddCookie(&http.Cookie{Name: "artex_token", Value: token})
	res, e := http.DefaultClient.Do(req)
	if e != nil {
		t.Fatal("cookie check failed")
	}
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("provider accepted cookie auth")
	}
	exec(`UPDATE provider_snapshots SET expires_at=now()-interval '1 second' WHERE id=$1`, first.ID)
	expect(do("GET", path+"?cursor="+first.Next, token, nil), 410)
	// Explicit publication approval is required; raw reports are never a fallback.
	var report db.ProviderRecord
	for _, r := range fresh.Records {
		if r.Family == "report" && r.ID == strconv.FormatInt(ownFinding, 10) {
			report = r
		}
	}
	var reportData map[string]any
	_ = json.Unmarshal(report.Payload, &reportData)
	request := map[string]any{"company_id": a, "family": "report", "record_id": report.ID, "source_revision": reportData["source_revision"], "content": map[string]any{"text": "REDACTED source-held assessment report"}, "reviewed_redacted": false}
	expect(do("POST", "/api/provider-publications", admin, request), 400)
	request["reviewed_redacted"] = true
	published := do("POST", "/api/provider-publications", admin, request)
	expect(published, 201)
	var publication map[string]string
	_ = json.Unmarshal(published.Body, &publication)
	publicationPath := fmt.Sprintf("/api/provider/v1/companies/%d/publications/%s", a, publication["id"])
	approved := do("GET", publicationPath, token, nil)
	expect(approved, 200)
	if !bytes.Contains(approved.Body, []byte("REDACTED source-held assessment report")) {
		t.Fatal("approved report not retrievable")
	}
	expect(do("GET", fmt.Sprintf("/api/provider/v1/companies/%d/publications/%s", b, publication["id"]), other, nil), 404)
	approvedSnapshot := parse(do("GET", path+"?limit=500", token, nil))
	var approvedCursor string
	// Offset zero is a valid restart cursor for an existing persisted snapshot.
	c, _ := json.Marshal(providerCursor{Snapshot: approvedSnapshot.ID, Offset: 0})
	approvedCursor = base64.RawURLEncoding.EncodeToString(c)
	exec(`UPDATE findings SET report='Changed REDACTED source-held report' WHERE id=$1`, ownFinding)
	expect(do("GET", detailPath+"?source_revision="+automaticRevision, token, nil), 409)
	expect(do("GET", publicationPath, token, nil), 404)
	expect(do("GET", path+"?cursor="+approvedCursor, token, nil), 410)
	expect(do("POST", "/api/provider-publications", admin, request), 409)
	expect(do("DELETE", "/api/provider-publications/"+publication["id"], admin, nil), 200)
	expect(do("GET", publicationPath, token, nil), 404)
	// Incomplete transactions never publish records/progress or a completion marker.
	before := id(`SELECT count(*) FROM provider_snapshots`)
	exec(`ALTER TABLE provider_snapshots ADD CONSTRAINT provider_fixture_failure CHECK(false) NOT VALID`)
	expect(do("GET", path, token, nil), 503)
	if after := id(`SELECT count(*) FROM provider_snapshots`); after != before {
		t.Fatal("failed snapshot committed partial progress")
	}
	exec(`ALTER TABLE provider_snapshots DROP CONSTRAINT provider_fixture_failure`)
	// Complete-snapshot absence, rather than an invented hard-deletion history.
	exec(`DELETE FROM assets WHERE id=$1`, added)
	removed := parse(do("GET", path+"?limit=500", token, nil))
	for _, r := range removed.Records {
		if r.Family == "asset" && r.ID == strconv.FormatInt(added, 10) {
			t.Fatal("deleted asset remains in fresh snapshot")
		}
	}
	sourceAssetCount := id(`SELECT count(*) FROM assets WHERE company_id=$1`, a)
	if removed.Manifest.Counts["asset"] != int(sourceAssetCount) {
		t.Fatal("complete snapshot count disagrees with source")
	}
	t.Logf("Deletion reconciliation: provider assets=%d, persisted company assets=%d", removed.Manifest.Counts["asset"], sourceAssetCount)
	transcript = append(transcript, map[string]any{"check": "post-deletion reconciliation", "exported_company_assets": removed.Manifest.Counts["asset"], "persisted_company_assets": sourceAssetCount})
	exec(`UPDATE tasks SET deleted_at=now() WHERE id=$1`, task2)
	deleted := parse(do("GET", path+"?limit=500", token, nil))
	foundDeleted := false
	for _, r := range deleted.Records {
		if r.Family == "task" && r.ID == strconv.FormatInt(task2, 10) && r.Deleted {
			foundDeleted = true
		}
	}
	if !foundDeleted {
		t.Fatal("soft-deletion marker missing")
	}
	exec(`UPDATE provider_grants SET expires_at=now()-interval '1 second' WHERE id=$1`, grantID)
	expect(do("GET", path, token, nil), 403)
	token3, grant3 := grant(a)
	expect(do("DELETE", "/api/provider-grants/"+grant3, admin, nil), 200)
	expect(do("GET", path, token3, nil), 403)
	t.Log("Verified real HTTP/PostgreSQL: automatic identifiers, redacted URLs, metadata, assessment text and revision-pinned source-held reports without publication; all six asset types; original dispositions; optional reviewed artifacts; company, expiry and read-only refusals; immutable paging and duplicate/restart replay; update/removal markers; atomic rollback. No production credentials, scans or model calls.")
}

// Only isolated fixture responses are recorded; credentials and query values are
// never evidence. This preserves product-level API results without raw logs.
func providerRedactEvidence(value any) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			switch strings.ToLower(key) {
			case "token", "password", "secret", "cookie", "authorization":
				v[key] = "[removed]"
			default:
				providerRedactEvidence(child)
			}
		}
	case []any:
		for _, child := range v {
			providerRedactEvidence(child)
		}
	}
}
