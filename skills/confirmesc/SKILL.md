---
name: confirmesc
description: Interpret a confirmesc JSON report that an operator has already supplied to a task, and explain what the sanitized import does and doesn't establish. Use when a task has an imported confirmesc privilege-escalation report, the user mentions confirmesc results, or Linux post-exploitation context comes up with a report in hand.
---

# confirmesc report analysis

This skill accepts supplied JSON only. confirmesc builds its report by running a scan on the machine it's installed on, so producing one is an action, not a lookup. Don't ask for it to be generated, and don't offer to.

## Provenance

- Upstream: capture0x/confirmesc, pinned revision `36f1ec85e869357439a35dd08ec833bde5ef8041`.
- Parser profile: `confirmesc-json-36f1ec8`. The report is the JSON export with a `meta` object, a `duration`, a `findings` array and an `errors` object.
- Upstream is MIT licensed. Its optional MCP server is not integrated here, and ScopeWeaver vendors no upstream code.
- The pinned revision names the parser contract, nothing more. It doesn't authenticate the executable behind a report, and a reported version doesn't either. Treat the producer as unverified unless the operator measured it independently.

## What an import keeps

The operator uploads the JSON in the task's Report tab. The server checks it in memory and keeps a lossy summary:

- the finding position, producer severity and confidence (unknown values become `unknown`), a producer-reported CVSS number, valid CWE, CVE, OWASP and ATT&CK identifiers, and the producer timestamp when valid;
- the producer, profile, hashes, import time, counts and a completeness flag.

Everything else is dropped, including `meta` contents, file paths, user and host names, captured secrets, commands and every free-form string. Generated titles and fixes come from the kept classifications, so they aren't confirmesc's wording. The original report isn't stored. Limits are 1 MiB, 1000 findings and nesting depth 32.

Don't let users paste raw report text into the conversation, and don't repeat it if they do.

## Reading the result

- Each import is one fact with validation status `producer_reported`. confirmesc labels some results as confirmed; here that's still the producer's confidence, not independent confirmation. No finding is created.
- Severity and confidence stay separate from CVSS and from project triage.
- `completeness` carries real information. A report with entries in `errors` becomes `has_errors`, meaning some checks didn't finish, and `no_observations` means nothing was reported. Neither means the system is safe.
- Version-based matches deserve extra doubt, since a producer can flag a package without proving it's exploitable. Unknown classifications get generic guidance: reproduce independently, in scope, before relying on them.
- Reuse in later tasks needs an explicit source reference. A parent link grants nothing.

## No host-as-target inference

A confirmesc report describes the system it ran on. That the report came from a Linux or container environment says nothing about which system ScopeWeaver should treat as the target. Never conclude that the application host, its container or a neighboring machine is in scope. The task's declared scope decides, and if the report's subject is unclear, ask the operator.

## When something is missing

State the condition and stop.

- Report intake is off, or this skill isn't visible to the agent: both are operator opt-ins.
- The `security_catalog` helper reports confirmesc as unavailable or unverified: relay it. Only YeepForge and AdStrike have catalog providers, so there's no discovery state to expect here, and the operator installs confirmesc externally.
- No report is attached: ask for an upload.

## Boundaries

Don't scan, escalate privileges, collect credentials, exploit anything, apply remediation or promote an import to a finding. Follow the task's scope controls.
