# Company-scoped assessment provider

This is the provider-only part of SCR-92 direction A. The existing native connector and its administrator login are unchanged. AiSOC must explicitly adopt this contract in the next piece; adding these routes does not switch any running consumer or establish five-minute freshness. Do not activate the provider, issue production credentials, or rebuild the deployed application without the separately required consent.

## Coverage limit requiring acceptance

The source has no existing company-safe approval mapping for arbitrary assessment content. This provider **does not automatically export free text, URLs, arbitrary metadata, credentials, traffic bodies, workspace files, or model settings**. It exports typed assessment metadata, relationships, versions and integrity references, with explicit content-required-publication flags and coverage gaps. An administrator can publish a reviewed, redacted JSON representation tied to an eligible source record and its exact source revision. That is a deliberate coverage limit, not a claim that “everything we've got” already flows automatically.

All six asset types have separate stable record identities. URL distinctions and rich asset metadata can be published, but they are not in the automatic projection. Company scope values, task names/descriptions, goal text, constraint text, finding summaries/reports, research payloads and artifact content also need reviewed publications. No automatic redactor can certify arbitrary source text as secret-free or unrelated-company-free. Approval is an explicit trust boundary: the reviewer must remove both before setting `reviewed_redacted=true`. Approved content is still untrusted evidence, not executable instructions.

Original evidence stays in ScopeWeaver. Approved redacted publications are also stored in ScopeWeaver and can be retrieved on demand. There is no unrestricted file or traffic download route, and no new scans, retests, model calls or response actions.

## Authentication and routes

Administrator-authenticated native routes manage the provider:

- `POST /api/provider-grants`: `{company_id, ttl_seconds}`. Expiry must be positive and at most 30 days. Returns the grant and a high-entropy bearer secret once. Only its SHA-256 digest is stored. Never log this response or put credentials in URLs.
- `DELETE /api/provider-grants/{id}` revokes the grant immediately.
- `POST /api/provider-publications`: `{company_id, family, record_id, source_revision, content, reviewed_redacted:true}`. Body is bounded to 1 MiB. The source record must be company-eligible, not deleted, and still at the supplied revision. The response contains publication identity and checksum, not a source blob.
- `DELETE /api/provider-publications/{id}` withdraws an approval.

Service reads accept **only** an `Authorization: Bearer` header containing a provider grant. Administrator sessions, cookies and query credentials are not accepted:

- `GET /api/provider/v1/companies/{company_id}/snapshot?limit=100`
- The same route with the returned `cursor` resumes the persisted snapshot. Do not supply a new limit when resuming; its original page size is authoritative.
- `GET /api/provider/v1/companies/{company_id}/publications/{id}` returns only a currently approved, company-eligible redacted publication. A stale, withdrawn or nonexistent approval is unavailable; there is no raw-source fallback.

A service grant belongs to exactly one company and cannot access any native administrator route. Provider routes accept GET only. Invalid or missing service credentials return 401; wrong-company, expired or revoked grants return 403. Provider routes neither create nor edit assessment records. Snapshot materialization writes only provider storage.

## Record and snapshot semantics

Every record carries `schema_version=scopeweaver.assessment.v1`, persisted source-instance identity, company identity, family, source record identity, content revision, SHA-256 checksum, observation timestamp, deletion flag and an explicit payload. Large integer values retain their JSON precision. Consumers key records by **source instance + company + family + record identity**, never by display label or URL host.

The checksum/revision is SHA-256 of the payload after parsing JSON with integer precision retained and serializing with Go's standard JSON encoder (sorted object keys, compact form, standard HTML escaping). Source-revision fields separately hash the authoritative source row or report/evidence content inside PostgreSQL. A source revision is an opaque invalidation token, not an instruction to reconstruct or infer private source content. Do not confuse a report's content revision with its original evidence/report-evidence counters.

An initial read materializes a full, ordered repeatable-read snapshot, then commits its records and manifest **atomically**. Partial generation cannot produce a visible snapshot or completion marker. No database transaction stays open across page requests. Paging and replay read persisted records, so ordinary inserts and edits during a scan do not change its ordering or content. A separate server/manager can resume the same cursor. Source ownership changes that make an existing record ineligible invalidate cached snapshots; withdrawn/stale publications invalidate them too. Access is rechecked on every page. Hard-deleted source metadata can remain in its prior authorized observation, but the next complete snapshot records its absence; raw content is never a fallback.

Records are ordered by family and record identity (text order). The manifest gives all known family counts, reason-counted rejections, explicit coverage gaps, the observation time and a checksum of the ordered `[family:identity:revision, ...]` list serialized as compact JSON. Consumers must validate identity uniqueness, counts and checksums before accepting a complete snapshot.

Pages include `snapshot_id`, `offset`, `total`, `records`, `manifest`, `next_cursor` and `complete`. Only the final page has `complete=true` and no next cursor. Persist each destination page and its cursor in the **same destination transaction**; that consumer responsibility belongs to the next piece. Duplicate delivery must upsert by source identity/revision, never overwrite analyst-owned fields, and never generate attack alerts.

Soft-deleted task/node records carry `deleted=true`. There is no fabricated historical hard-deletion stream. The absence policy is full-snapshot reconciliation **only after every page is complete and there are no rejected records**. A partial read, expired cursor, failed read or rejected record must never cause destination deletions. A rejected record includes an opaque source identity and a reason, not the source content. Completely unattributed records are not broadcast or automatically assigned; the manifest discloses that exclusion without exposing unrelated-company counts.

## Attribution and family mapping

Tasks require one consistent company across their direct company and explicit company-scope links; known task-asset links to unassigned/other-company assets reject that task. Findings require all asset links to resolve to the same authorized company and no conflicting task attribution. A finding with no task can use unanimous asset attribution; a finding with no asset links can use an eligible task. Malformed asset links and unsupported source severity/disposition values are rejected rather than normalized or assigned automatically. Original supported severity and disposition strings are preserved.

Research nodes belong to an eligible task exploration; foreign/unassigned asset anchors exclude a node. Edges, anchors, task links and lineage export only eligible endpoints. No destination company comes from source text, a model or a publication payload.

| Family | Automatic projection | Explicit exclusion/publication boundary |
| --- | --- | --- |
| company, scope | Identity, kinds, timestamps, source revisions | Names, rules/values and explanatory text require publication |
| asset | All six types, company-source, port/status/size, creation/update/last-seen times | URLs, identifiers displayed as text, technologies, auth, parameters and arbitrary metadata require reviewed redacted publication; credentials must never be approved |
| task, task_scope | Status, exploration, coverage switch, scope kind/source, lifecycle timestamps | Names, goals, descriptions and scope values require publication |
| finding | Original severity/disposition, eligible task/node/asset links, evidence/report-evidence versions | Summary, title, class, worker and evidence text require publication |
| report, evidence | Presence flags, content revisions and source version counters | Original bodies stay source-held; only approved redacted content is retrievable |
| evidence_reference | Finding/version, snapshot identity, validated request/response digests, lengths, ordering and time | URLs, headers, bodies and notes are never copied automatically; malformed digests are null |
| retest | Finding, status/verdict, timestamps and source revision | No retest is launched; historical snapshot, notes, conclusions and evidence text require publication |
| goal, research_node, research_edge | Kinds/states, source versions, eligible relationships and times | Research payloads require publication; no automatic instruction execution |
| constraint | Kind, exploration, timestamps and source revision | Constraint text requires publication |
| coverage_anchor, task_asset, lineage | Eligible asset/node/task relationships and timestamps | Source coverage inputs, not a newly calculated coverage score; free-text provenance omitted |
| activity | Exploration, eligible node, error flag and timestamp | Sanitized structural provenance only; no tool inputs, output, summaries, metadata, tokens or transcript content |
| archive | Attributable task and archive identity | Cold archive contents and filesystem artifacts lack a safe mapping and are explicitly excluded |
| publication | Approval identity/time, exact source revision, reviewed content and integrity checksum | Represents approved artifacts or redacted detail anchored to an eligible source record; stale/withdrawn approvals cannot be read |
| rejected | Candidate identity and reason | No raw content, unrelated-company identifiers, or automatic ownership rewrite |

This version does not reconstruct source history the source never retained. Published report versions remain independently identified, but changes to their source invalidate their readability until reviewed again. A missing approval is a coverage gap, not an empty report or successful content import.

## Limits, retry and operation

- Page size 1–500, default 100; snapshot maximum 100,000 records and 64 MiB serialized data; read timeout 30 seconds.
- A cursor expires at the earlier of grant expiry and 24 hours. Only the newest 12 snapshots per grant are retained. Retention eviction returns 410, never a different dataset at that cursor.
- On 410, abandon that incomplete attempt and start a new snapshot without deleting the destination's prior complete state.
- On transient 503/network failure, retry the same read **at most three times**, honoring `Retry-After: 2` for 503 and using bounded backoff. After the budget, show stale/failed status and retain the last complete snapshot. The provider does not automatically retry database operations; clients must implement the bounded transport budget in the next piece.
- Do not retry 400/401/403/404 as transient failures. Authentication and authorization failures must remain visible.
- Per-grant retention cleanup runs during materialization; operators should remove retired grants/expired provider snapshots under their normal database retention procedure. This feature does not install a background worker or alter existing schedulers.
- The five-minute poll interval and consumer-side atomic record/progress commits are next-piece responsibilities. Freshness and multi-company rollout are not proven by this provider alone.

## Validation

Use the project's required separate disposable database gate for all Go packages. The opt-in provider journey requires `SCOPEWEAVER_PROVIDER_E2E=1` and an explicit `ARTEX_PG_DSN` database named `scopeweaver_provider_*`; it fails closed otherwise. The test refuses a database containing model profiles and disables external MCP entries in that disposable database. Do not point tests at deployed data.

`go test ./server -run '^TestProviderCompanyContractPG$' -count=1 -v` exercises real HTTP and PostgreSQL with minimized source-derived fixtures. It covers all six asset types; original finding states; attributable families; approvals/staleness; wrong-company and read-only refusals; expiry/revocation; stable paging, duplicate replay and a fresh manager/handler; updates, deletion/absence; and transaction rollback under an injected database constraint failure. It reports actual persisted versus exported deletion counts without printing source content or credentials.

Evidence belongs in the isolated ScopeWeaver working copy's `evidence/provider-scr93` folder, uncommitted. The deployed checkout, public ports, source originals and production credentials remain untouched. Follow this with the existing adapter transport gate, the full required suite, ten consecutive journey passes without retries, and a negative control that removes company enforcement and must fail at the wrong-company refusal assertion. Restore the fix and rerun the positive journey before delivery.
