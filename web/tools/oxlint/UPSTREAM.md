# Anti-slop Oxlint plugin provenance

- Source repository: https://github.com/dmmulroy/anti-slop
- Source commit: c44ef22ca116d0ba62a3ff663a0bd13a3f3fa40b
- Upstream subtree: skills/install-anti-slop/assets/anti-slop (via the install-anti-slop skill, `scripts/install.mjs`)
- Installed path: `web/tools/oxlint/anti-slop/` (generic plugin)
- Effect plugin (`effect/`) is vendored but NOT enabled: `effect` is not a direct dependency of `web/`.
- Dependency pins (exact, devDependencies): `oxlint@1.88.0`, `@oxlint/plugins@1.88.0` (current npm `latest` on 2026-10-13)
- Config: `web/.oxlintrc.json`
- Deviations from the upstream copy: one addition, `web/tools/oxlint/anti-slop/LICENSE`, the MIT notice copied verbatim from the install-anti-slop skill's own `LICENSE` (the skill's `install.mjs` copies `assets/anti-slop` only, which has no top-level license file). No upstream file was modified. `UPSTREAM.md` (this file) and `web/.oxlintrc.json` are local files outside the vendored directory.
- The vendored directory is excluded from Biome (`biome.json` files.includes) and from `tsconfig.json`.

## Licenses

- Plugin: MIT, Copyright (c) 2026 Dillon Mulroy. Full notice in `web/tools/oxlint/anti-slop/LICENSE`, a verbatim copy of `install-anti-slop/LICENSE` (checked with `cmp`).
- Nested rule: the vendored `padding-line-between-statements` (ESLint Stylistic commit 435c3ea0fd26a5fef9042c4b36b6e165fbbf8d08, used by `require-readable-spacing`) is MIT, Copyright OpenJS Foundation and other contributors and (c) 2023-PRESENT ESLint Stylistic contributors. The license is in `web/tools/oxlint/anti-slop/vendor/eslint-stylistic/LICENSE`, with provenance and local adaptations in the neighbouring `UPSTREAM.md`.

## Running the lint

- Whole package: `cd web && npm run lint:anti-slop`.
- Specific files inside `web/`: `cd web && npm run lint:anti-slop -- <paths relative to web/>`.
- Changed files anywhere in the repo (including `e2e/`): from the repo root, `web/node_modules/.bin/oxlint -c web/.oxlintrc.json <repo-relative paths>`. The equivalent from `web/` is `npm run lint:anti-slop:repo -- <repo-relative paths>`. Oxlint rejects `..` in paths, so do not run `lint:anti-slop` with `../e2e/...`.

## Intentional configuration decision

`web/.oxlintrc.json` sets `"categories": { "correctness": "off" }`. The install-anti-slop skill lists exactly the rules to enable (`oxc/no-accumulating-spread` plus 18 `anti-slop/*`) and says nothing about Oxlint's built-in categories. Oxlint enables `correctness` by default, and re-enabling it adds 396 warning-level built-in diagnostics (eslint/no-unused-vars 388, unicorn/no-useless-spread 5, and 3 others) that are outside the skill's rule set and overlap Biome's general linting. Warnings do not change Oxlint's exit code, so the line does not make the gate pass. All 19 skill rules stay at `error`. To restore Oxlint's defaults, delete the `categories` line.
