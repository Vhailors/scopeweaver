---
name: yeepforge
description: Interpret a YeepForge JSON export that an operator has supplied to a task, and explain what the sanitized import does and doesn't establish. Use when a task has an imported YeepForge assessment report, the user mentions YeepForge results, or the security catalog lists the YeepForge provider.
---

# YeepForge report analysis

This skill is about reading a YeepForge report that already exists. It doesn't run YeepForge, and nothing here should be turned into a request to launch it.

## Provenance

- Upstream: capture0x/YeepForge, pinned revision `ee07fe352a994b4e53f20b382b58c605a1301060`.
- Parser profile: `yeepforge-json-ee07fe3`. The report is the JSON export with `tool: "YeepForge"`, a `version`, and a `findings` array, and it has no schema version.
- Upstream is MIT licensed and adds an authorized-testing notice. ScopeWeaver vendors no upstream code.
- The pinned revision identifies which parser contract was read. It doesn't authenticate the executable that produced a given report, and a reported tool version doesn't either. Treat the producer as unverified unless the operator measured it some other way.

## What an import keeps

The operator uploads the JSON in the task's Report tab. The server checks it in memory and keeps only a lossy summary:

- the finding position, producer severity and confidence (unknown values become `unknown`), a producer-reported CVSS number, valid CWE, CVE, OWASP and ATT&CK identifiers, and the producer timestamp when valid;
- the producer, profile, hashes, import time, counts and a completeness flag.

Everything else is dropped: titles, descriptions, evidence, remediation, commands, hosts, users, URLs, credentials and any unknown field. Displayed titles and fixes are generated from the kept classifications, so they aren't YeepForge's own words. The original file isn't stored. Limits are 1 MiB, 1000 findings and nesting depth 32.

Don't ask the user to paste raw report text into the conversation. If they do, don't repeat it, and point them to the upload.

## Reading the result

- The import is one fact recording that a report was observed. Its validation status is `producer_reported`. It's not a confirmed vulnerability and it creates no finding.
- Severity and confidence are what YeepForge claimed. Keep them separate from any CVSS value and from the project's own triage. A high claim doesn't raise anything on its own.
- `completeness` matters. `no_observations` means the report held no findings, and `has_errors` means it was partial. Neither one says the target is clean.
- An unknown classification gets generic guidance: have a person reproduce it independently within the authorized scope before treating it as real.
- To reuse an import in later work, the task must name it explicitly as a source. A parent link alone grants no evidence.

## When something is missing

Say plainly which state applies and stop there; don't work around it.

- Report intake is switched off, or this skill isn't visible to the agent: tell the operator it's opt-in and they control it.
- The `security_catalog` helper reports the provider as disabled, not discovered, stale, unavailable or unverified: relay that status. A cached catalog entry isn't a callable tool, and the provider is installed outside ScopeWeaver by the operator.
- No report is attached: ask for an upload. Don't suggest generating one.

## Boundaries

Don't scan, probe or contact any target, and don't treat the machine ScopeWeaver runs on as a target because a report exists. Don't collect credentials, plan exploitation, apply fixes or promote an import to a finding. Follow the task's scope controls.
