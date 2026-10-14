---
name: adstrike
description: Interpret an AdStrike schema 2.0 JSON report that an operator has supplied to a task, and explain what the sanitized import does and doesn't establish. Use when a task has an imported AdStrike assessment report, the user mentions AdStrike results, or the security catalog lists the AdStrike provider.
---

# AdStrike report analysis

This skill covers reading an AdStrike report that already exists. It doesn't run AdStrike. Nothing in it should become a request to start an assessment or to generate a report.

## Provenance

- Upstream: capture0x/AdStrike, pinned revision `75d43aabdf9be0d7b497f0c51e38dac77f4ee7be`.
- Parser profile: `adstrike-json-2.0`. The report is the JSON export carrying `schema_version: "2.0"` and a `findings` array.
- Upstream is MIT licensed. ScopeWeaver vendors none of its code.
- The pinned revision names the parser contract that was read. It doesn't authenticate whichever executable made a report, and a reported version string doesn't either. Treat the producer as unverified unless the operator measured it independently.

## What an import keeps

The operator uploads the JSON in the task's Report tab. The server validates it in memory and keeps a lossy summary only:

- the finding position, producer severity and confidence (unknown values become `unknown`), a producer-reported CVSS number, valid CWE, CVE, OWASP and ATT&CK identifiers, and the producer timestamp when valid;
- the producer, profile, hashes, import time, counts and a completeness flag.

Everything else is discarded: titles, descriptions, evidence, remediation, commands, domain and host details, accounts, URLs, credentials and unknown fields. Active Directory material is exactly the sort of thing that must not survive, so the generated titles and fixes come from the kept classifications alone. They're not AdStrike's text. The original file is never stored. Limits are 1 MiB, 1000 findings and nesting depth 32.

If a user starts pasting raw report content into the chat, don't echo it; send them to the upload.

## Reading the result

- One import becomes one fact with validation status `producer_reported`. It's not a confirmed vulnerability, and no finding is created.
- Severity and confidence are AdStrike's own claims. Keep them apart from CVSS and from the project's triage; a confident producer isn't a verified result.
- Check `completeness`. `no_observations` means the report held no findings. `has_errors` means it was incomplete. Neither one proves a clean environment, and an empty AdStrike session in particular says nothing about safety.
- Unknown classifications get generic guidance: a person should reproduce the issue independently inside the authorized scope first.
- Reusing an import needs the task to list it explicitly as a source. A parent reference doesn't carry evidence across.

## When something is missing

Report the state and stop; don't improvise around it.

- Report intake is off, or this skill isn't visible to the agent: the operator opts in and controls both.
- The `security_catalog` helper says the provider is disabled, not discovered, stale, unavailable or unverified: pass that along. A cached catalog entry isn't a callable tool, and the operator installs the provider externally.
- No report has been attached: ask for an upload and don't offer to produce one.

## Boundaries

Don't scan or contact any target, and don't assume the application host is one because a report was imported. Don't gather credentials, chain attacks, run remediation or turn an import into a finding. Stay inside the task's scope controls.
