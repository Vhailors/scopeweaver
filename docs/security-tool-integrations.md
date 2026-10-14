# Security report integration

ScopeWeaver can read JSON reports exported by YeepForge, AdStrike and confirmesc, and it can list the two provider entries in a read-only catalog. Everything here is optional and off by default.

What ships:

- Two provider entries in Settings > MCP, with kinds `yeepforge` and `adstrike`. They are catalog-only.
- Three report-reading skills: `yeepforge`, `adstrike` and `confirmesc`.
- Report import on a task's Report tab.

Korean: [한국어 문서](ko/security-tool-integrations.md)

## Setup

ScopeWeaver installs none of these tools. The operator installs them separately.

1. Open Settings > MCP. The `YeepForge` and `AdStrike` entries are seeded disabled with stdio transport. They are only added if the name is free; an existing server with that name is left alone.
2. Fill in the command (your interpreter) and the arguments (the entrypoint). Use absolute paths. The server resolves the command with a normal executable lookup, so a bare name depends on `PATH`.
3. Only stdio is accepted for these entries. A URL or disabled TLS verification is rejected.
4. The kind is fixed once the entry exists.
5. The optional source revision is a 40-character lowercase SHA-1 of the upstream commit you installed. It records what you expect. It does not prove what runs. Provenance always shows as unverified.

## What the catalog does

- Saving a provider never starts it.
- Enabled means the entry is eligible for an explicit Refresh. It does not mean agents can call it.
- Refresh starts the provider once, lists its tools, and closes it. It sends no tool call, and the provider's stderr is discarded.
- Agents never receive the provider's tools. The only agent-facing piece is the read-only `security_catalog` helper, which reports cached status. Its `callable` field is always false.

Status values:

| Status | Meaning |
| --- | --- |
| `not_configured` | No command is set. |
| `disabled` | The entry is switched off. |
| `not_discovered` | Never refreshed. |
| `discovered` | The cache matches the current configuration and the last refresh worked. |
| `stale` | The configuration changed after the last refresh. Refresh again. |
| `unavailable` | The last refresh failed. Old tool names are cleared, not kept. |

Provenance is a separate field and always reads `unverified`; ScopeWeaver does not authenticate which executable is installed.

The page also shows the expected revision, the version the provider reported about itself (not authenticated), and a SHA-256 of the entrypoint file when ScopeWeaver could measure it.

Report import does not need any of this. It works with no provider installed.

## Report import

1. In Settings > MCP, turn on the report intake switch. It is stored as the `security_reports_enabled` setting and defaults to off.
2. Open a task's Report tab and upload the JSON export for the matching producer.

Limits: 1 MiB, 1000 findings, nesting depth 32. Requests must be `application/json`. Supported profiles:

| Producer | Profile |
| --- | --- |
| `yeepforge` | `yeepforge-json-ee07fe3` |
| `adstrike` | `adstrike-json-2.0` |
| `confirmesc` | `confirmesc-json-36f1ec8` |

The whole report is validated in memory before anything is kept. A report that fails validation stores nothing.

Kept: the finding position, normalized severity and confidence (unknown values become `unknown`), a producer-reported CVSS number, valid CWE, CVE, OWASP and ATT&CK identifiers, the producer timestamp when valid, the producer and profile names, hashes of the original and sanitized data, the import time, counts, and a completeness flag (`unknown`, `no_observations` or `has_errors`).

Dropped: all free text (titles, descriptions, evidence, remediation, commands), hosts, users, URLs, credentials and any unknown field. Displayed titles and guidance are generated from the kept classifications. The original file is not stored.

An import is one observation fact with status `producer_reported`. It is not a confirmed finding and creates no finding. Severity and confidence are what the producer claimed. `no_observations` and `has_errors` never mean the target is clean.

The same file uploaded again for the same task returns the stored entry (HTTP 200 with `duplicate: true`) instead of a new one. With the feature off, existing import history stays readable and new imports are refused.

## Agents

The three skills are opt-in. Make them visible to an agent through the existing skill visibility controls. The `security_catalog` helper only answers when report intake is on, the helper is bound to the calling agent, and the agent is enabled. Reusing an import in a child task needs the import named explicitly as a source; a parent link alone does not carry it over.

## Upgrading an existing binary install

Self-update replaces only the binary. It does not touch skill files, and a plain `cp -r <unpacked>/skills ./` would overwrite skills you customized. Install only the missing skills through the authenticated upload API instead, without `overwrite=true`:

- `POST /api/skills/upload` with a multipart `file` field holding a skill `.zip`.
- The skill name comes from the `name:` field in SKILL.md.
- If a skill of that name already exists, the call returns 409 and the existing skill is left unchanged. A new skill returns 201.
- Only `overwrite=true` replaces an existing skill, so leave it out.

The release archive ships `skills/yeepforge`, `skills/adstrike` and `skills/confirmesc`. Zip each of those directories and upload it.

## Rollback

In this order:

1. Turn the report intake switch off.
2. Disable the two provider entries.
3. Remove their agent bindings.
4. Confirm no discovery process is still running.
5. Start the prior binary (v0.3.1, commit `d999b19`).

The extra schema and the sanitized facts stay in the database. Restore only the values the integration changed, such as skill visibility.

## Upstream pins

| Project | Pinned commit | License |
| --- | --- | --- |
| YeepForge | `ee07fe352a994b4e53f20b382b58c605a1301060` | MIT, plus an authorized-testing notice |
| AdStrike | `75d43aabdf9be0d7b497f0c51e38dac77f4ee7be` | MIT |
| confirmesc | `36f1ec85e869357439a35dd08ec833bde5ef8041` | MIT |

The pin names the report format ScopeWeaver parses. ScopeWeaver vendors no upstream code.
