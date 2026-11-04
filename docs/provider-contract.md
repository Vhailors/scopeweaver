# Company-scoped assessment provider

This is the provider-only part of SCR-92 direction A. The native consumer and its administrator login are unchanged. AiSOC adoption, five-minute scheduling and rollout are later pieces. This isolated implementation must not be merged, activated or issued production credentials without the captain's separate direction.

## Automatic coverage

Ordinary company names, scope values, all six asset types and useful metadata, finding summaries, task descriptions, goals, constraints and supported research content are automatic. **No individual publication is required for those records.** Source-held report/evidence bodies can also be retrieved automatically, with a required source-version pin and deterministic redaction.

The projection is explicit, not a database dump. It excludes authentication values, parameter values, raw traffic headers/bodies, arbitrary tool input/output, model settings and credential files. Unknown structured metadata keys and unsupported shapes are omitted with per-record notices. Public identifiers and URL paths are retained where the policy permits; URL credentials, query values and fragments are removed. Some opaque identifiers or sensitive path segments are deliberately redacted, so consumers must keep source record IDs rather than deduplicate by display URL.

Text uses a bounded deterministic policy, not a model: credential-header/assignment patterns, private-key material, JWT/opaque values, and URL credentials are removed; fenced code/traffic blocks are withheld. Unfenced raw HTTP causes the affected text to be withheld rather than copied as unrestricted traffic. Supported text/metadata remains available; removed portions carry reason codes. This is **not a universal secret detector or a guarantee that unlabelled sensitive prose can be classified correctly**. Source text remains untrusted evidence, never instructions or authority for company selection, scans, response or model configuration. Review these residual disclosure risks before production activation; the isolated tests prove the named cases, not an arbitrary production corpus.

Reviewed redacted publications remain optional for approved artifacts. They are not the prerequisite for routine data. They cannot bypass credential/traffic filtering or the metadata policy. Original evidence stays in ScopeWeaver. No route reads arbitrary workspace files or launches a scan, retest or paid model call.

## Authentication and routes

Native administrator-authenticated management:

- `POST /api/provider-grants`: `{company_id, ttl_seconds}`; positive expiry, maximum 30 days. Returns the grant and a high-entropy secret once; only the secret's SHA-256 digest is stored. Never log its response or use credentials in URLs.
- `DELETE /api/provider-grants/{id}` revokes the grant for subsequent reads.
- `POST /api/provider-publications`: `{company_id, family, record_id, source_revision, content, reviewed_redacted:true}`; maximum 1 MiB. The source must still be eligible and at that revision. Content is also filtered on export; use supported structured keys or a `text` representation for a reviewed artifact. Approval does not authorize credential export.
- `DELETE /api/provider-publications/{id}` withdraws it.

Company service reads accept only a provider credential in an `Authorization: Bearer` header. Administrator sessions, cookies and query credentials do not authenticate these routes:

- `GET /api/provider/v1/companies/{company_id}/snapshot?limit=100`
- The same route with its `cursor` resumes that persisted snapshot; its original page size remains authoritative.
- `GET /api/provider/v1/companies/{company_id}/records/{family}/{id}?source_revision={exact_revision}` automatically retrieves current redacted detail for `report`, `evidence` or `retest`. The pin comes from that record's snapshot payload `source_revision`, **not** its envelope checksum/revision. A missing pin returns 400, an unavailable/ineligible record 404, and a changed source version 409. There is no unpinned fallback or substituted historical body.
- `GET /api/provider/v1/companies/{company_id}/publications/{id}` retrieves a currently approved, eligible optional publication. Stale/withdrawn/absent approvals are unavailable, never a raw-source fallback.

A service grant belongs to one company and cannot access native administrator routes. Provider routes accept GET only. Missing/malformed service credentials return 401; wrong-company, expired or revoked grants return 403. Provider reads modify only provider snapshot storage, never assessments. Production access remains disabled until separately activated and configured.

## Records, redaction and integrity

Snapshot records and automatic detail responses have `schema_version=scopeweaver.assessment.v1`, persisted source-instance identity, company identity, family, record identity, revision, checksum, observation time, deletion flag and payload. Key records by **source instance + company + family + record identity**, never by a display name, URL host or redacted URL. Large JSON integers retain precision.

Automatic payloads name `redaction_policy=scopeweaver.redaction.v1` and `untrusted_evidence=true`. A `redactions` array gives removed/unsupported portions without echoing removed values or unknown metadata keys. Snapshot report/evidence records include presence, version and `detail_available` metadata, not report bodies. Automatic detail responses include the redacted `body`, its `content_checksum`, source revision and redaction notices. Even wholly withheld content remains visible as an explicit marker/gap, not a successful empty original report.

The envelope checksum/revision hashes its canonical safe payload: JSON parsed with integer precision retained and serialized by Go's standard encoder (sorted object keys, compact form, standard HTML escaping). The manifest hashes the ordered compact JSON `[family:identity:revision, ...]` list. Source revisions separately hash authoritative source rows or original report/evidence bodies inside PostgreSQL. They are opaque invalidation tokens and integrity references, not exported originals. `content_checksum` hashes redacted body UTF-8 bytes. Optional publications expose a checksum of the filtered delivered content and a separate `source_checksum` for the reviewed source publication; do not confuse them.

Original evidence/report-evidence counters, including source stale markers, are preserved rather than repaired. A report's original content revision and its evidence counters are different facts. This provider does not reconstruct source history the source never retained. If the pinned original changed, refresh metadata or show an unavailable historical version; never silently cite the new body as the old one.

## Snapshots and progress

An initial read materializes a full ordered repeatable-read snapshot, then commits all records and its manifest atomically. A failed generation publishes neither partial records nor a completion marker. No transaction stays open across HTTP pages. Inserts and ordinary updates during paging do not change that snapshot; duplicate delivery and a fresh manager/handler resume the same persisted pages.

Access is checked on each request. Ownership changes making existing records ineligible invalidate historical snapshot reads; withdrawn/stale publications invalidate cached approvals too. Hard-deleted metadata may remain in its prior authorized observation, with absence visible on the next complete snapshot. Bodies are read from the source under current eligibility and their exact revision pin, not cached as unrestricted originals.

The manifest includes counts for every known family, reason-counted rejections, observation time, coverage gaps, absence policy and checksum. Pages include `snapshot_id`, `offset`, `total`, `records`, `manifest`, `next_cursor`, `complete`. Records are ordered by family and identity as text. Only the final page is complete, with no next cursor. Validate unique identities, counts and checksums before accepting completeness.

Soft-deleted tasks/nodes carry `deleted=true`. Hard deletions use complete-snapshot absence, not an invented historical deletion stream. Reconcile absence **only after all pages complete without rejected records**. A partial read, failed read, expired cursor or rejected record must never cause destination deletion. Record/progress commits on the destination must use one destination transaction per page; that consumer implementation belongs to the next piece, as do duplicate upserts that preserve analyst-owned fields and never create attack alerts.

## Attribution and family coverage

Tasks need one consistent company across direct company and company-scope links; links to foreign/unassigned assets reject the task. Findings need every asset link to resolve to the authorized company and no conflicting task attribution. Asset-only attribution is allowed only when there is no task and all links agree; task-only attribution requires an eligible task. Malformed links and unsupported severity/disposition values are rejected, never silently normalized or assigned to every company.

Research nodes need an eligible task exploration and no foreign/unassigned asset anchors. Edges, anchors, lineage and task links export eligible endpoints only. Rejections expose candidate identity and reason, not source content. Completely unattributed records are not broadcast, with an explicit coverage gap rather than unrelated-company counts. Neither source text nor model output supplies destination company scope.

| Family | Automatic coverage | Explicit limits |
| --- | --- | --- |
| company, scope | Names, kinds, typed values, explanatory text, timestamps and source revisions | Text/URL redaction applies; no company discovery for an ungranted company |
| asset | All six types; domain/IP/network, app and service labels, URLs, methods, technologies, titles, port/status/size, supported extra metadata, parameter descriptors and timestamps | Authentication values never selected; parameter values omitted; unsupported DNS record values, arbitrary metadata keys/shapes and opaque values produce notices |
| task, task_scope | Status, names/descriptions/goals, scope kinds/values, coverage switch and lifecycle times | No model-provider settings or foreign links |
| finding | Original severity/disposition, names/class/summary, eligible task/node/asset links and evidence/report-evidence versions | Assessment evidence, not a fabricated live incident; text policy applies |
| report, evidence | Versions, source integrity references and automatic revision-pinned redacted body retrieval | Originals remain source-held; missing historical versions return a visible failure; code/traffic/credential portions withheld |
| retest | Finding, status/verdict, notes/summary/error, times and automatic redacted evidence detail | No retest launched; embedded historical snapshots with uncertain attribution are excluded |
| evidence_reference | Finding/version, snapshot identity, validated request/response digests, lengths, redacted URL, method/status/content type, ordering, role/note and time | No original headers or traffic bodies; malformed digests are null |
| goal, research_node, research_edge | Kinds/states, supported research text/metadata, source versions and eligible relationships | Unknown payload fields and unsupported shapes produce notices |
| constraint | Kind, text, origin, exploration, timestamps and source revision | Text policy applies; not permission to run actions |
| coverage_anchor, task_asset, lineage | Eligible relationships, supported source summaries and times | Source coverage inputs, not a fabricated coverage score; foreign links excluded |
| activity | Exploration, eligible node, kind/tool, redacted summary, error flag and time | No raw tool inputs/outputs, detailed metadata, transcripts or credentials |
| archive | Attributable task/archive identity | No safe automatic mapping for cold archive contents or arbitrary filesystem artifacts |
| publication | Optional reviewed artifact/detail identity, eligible exact source revision, filtered content and integrity references | Approval cannot bypass company, source-version, credential, traffic or supported-field checks |
| rejected | Candidate identity and fixed reason | No raw content or automatic ownership rewrite |

## Bounds and retries

Page size is 1–500 (default 100); snapshots are bounded to 100,000 records and 64 MiB serialized data, reads to 30 seconds. Body text is capped at 256 KiB, structured arrays at 1,000 entries and nesting at 12 levels; unsupported/oversized portions carry markers. URL user information, fragments and all query values are removed; opaque/sensitive path values can be redacted while ordinary route paths remain useful. Non-HTTP URLs are withheld.

Cursors expire at the earlier of grant expiry and 24 hours; only the newest 12 snapshots per grant are retained. Expiry/eviction returns 410, never a different dataset. Start a new snapshot without deleting the last complete destination state. On transient 503/network failure, retry the same read at most three times, honoring `Retry-After: 2` and bounded backoff, then expose stale/failed status. Do not treat 400/401/403/404/409 as transient success. The provider does not automatically retry database operations; consumer transport retries belong to the next piece.

Per-grant cleanup runs during materialization; retired grants and expired provider storage need the normal retention procedure. No new background scheduler, public port or response capability is installed. Freshness, production-volume performance and multi-company rollout are not proven by this piece alone.

## Isolated validation

Run the existing package gate exactly as CI, with a separate initialized disposable database per package. Run the opt-in provider journey **separately**: `SCOPEWEAVER_PROVIDER_E2E=1`, an explicit disposable `scopeweaver_provider_*` database in `ARTEX_PG_DSN`, and `go test ./server -run '^TestProviderCompanyContractPG$' -count=1 -v`. It refuses model profiles before destructive fixtures and disables external MCP entries only in that disposable database. Never target the deployed database.

The test uses minimized existing-source readings, anonymized identities, and labelled controlled redaction/ownership mutations. Through real HTTP/PostgreSQL it verifies automatic metadata and bodies before any publication, retained URL paths without credentials/query values, supported metadata without auth/parameter values, report version pins, original dispositions, company/expiry/read-only refusals, replay through a fresh manager, updates/removals and rollback. Reconcile deletion against actual stored and exported counts rather than a guessed total.

Then run the adapter transport gate, frontend tests/static build, embedded build, ten consecutive journeys without retries, a company-enforcement negative control, and a redaction-bypass negative control. Both must fail through the real interface at their intended assertions; restore the implementation and verify positive controls. Sanitized responses, outcomes and commands remain uncommitted under this isolated ScopeWeaver working copy's `evidence/provider-scr93/automatic` folder. Do not edit the deployed checkout or production credentials.
