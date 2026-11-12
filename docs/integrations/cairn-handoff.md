# ScopeWeaver ↔ Cairn context handoff

## What ships

A reviewed, bidirectional snapshot handoff between ScopeWeaver on port 8787 and Cairn on port 8000. This is context exchange, not automatic execution or continuous synchronization.

- Select 1–100 ScopeWeaver tasks, then **Handoff to Cairn** in the selection toolbar.
- Open a Cairn project, then **Handoff to ScopeWeaver** next to its export controls.
- Both workspaces also have **Receive handoff** for JSON-file imports.
- Write a title, goal, requested intent and human input, or choose a preset / saved template.
- Review the exact payload and destination. Send opens the other workspace; its user explicitly receives, reviews and creates the destination draft.
- A successful import creates one paused ScopeWeaver task or one stopped Cairn project with bootstrap disabled. Neither integration endpoint dispatches work.

## Data contract

Version 1 JSON contains a UUIDv4 handoff ID, source system/origin, title, goal, requested intent, human input, template label and namespaced source items.

ScopeWeaver supplies task metadata, graph nodes and edges, direct-source graphs, constraints, linked assets and asset references, and findings/reports. Cairn supplies its project, facts, intent relationships and hints. Source IDs remain in their original namespaces; they are not rewritten into executable destination intents. ScopeWeaver stores the reviewed envelope in the task description; Cairn stores it in the origin fact, with a native goal fact and a human-input hint. This retains logical relationships as reference data rather than pretending the two graph schemas are interchangeable.

Files, workspaces, raw traffic snapshots, asset authentication material, profile credentials and LLM traces are not transferred. Findings or other free text can still contain sensitive material: inspect the payload before sending. Known structured secret fields are masked in the browser. Disabling graph inclusion sends metadata only; ScopeWeaver constraints are retained.

Limits: 100 source items, 8 MiB per document, and 100,000 nodes/edges/assets per exported ScopeWeaver graph. Oversized graphs fail explicitly, not as silently truncated exports. Imports validate the envelope and keep durable handoff receipts in the same transaction as draft creation, so retrying the same ID returns the original destination. Reloading the source composer starts a new logical handoff with a new ID.

Saved templates are origin-local browser storage and contain only goal/intent. Human input and snapshots are not saved in the template library. Received template labels are preserved without silently installing them as local templates.

## Browser / Tailscale transport

The browser, not a Docker container, opens the destination origin. The default is the same hostname with port 8000 or 8787; edit it when the applications use different Tailscale names. Enter an HTTP(S) origin without a path. No server needs another service's API token, Docker host networking or permissive CORS.

A popup handshake checks the exact origin, window identity and random channel in both directions. The snapshot stays out of URLs. Receiving and creating are separate user actions. Popups expire after five minutes; downloading and importing the same versioned JSON document is the fallback. HTTP Tailscale origins are supported using the platform's secure random generator when randomUUID is unavailable.

ScopeWeaver API requests use its existing local login. Cairn retains its existing access controls; keep it behind appropriate Tailscale ACLs rather than exposing its unauthenticated API publicly. No credentials are copied across origins.

## Endpoints and files

ScopeWeaver:

- `GET /api/tasks/{id}/handoff`: authenticated context snapshot; direct-source IDs preserved.
- `POST /api/handoffs`: validated, idempotent paused-task import.
- `/handoff.html?system=scopeweaver`: receiver; append `&ids=1,2,3` for a source composer.
- `db.TaskCreateOptions.Paused` makes the initial pause atomic; existing callers retain their previous behavior.

Cairn:

- `POST /handoffs`: validated, idempotent stopped-project import.
- `/static/handoff.html?system=cairn`: receiver; append `&ids=p1,p2` for a source composer.

Both schemas add an idempotent `integration_handoffs` receipt table. Existing records are untouched. The shared static HTML/CSS/JS files are kept byte-identical in both repositories.

## Verification and release boundary

Implementation is isolated in fresh `feat/cairn-handoff` and `feat/scopeweaver-handoff` worktrees. The existing live checkouts have unrelated local modifications; the ScopeWeaver checkout is also behind upstream. Do not deploy an entire upstream worktree over the live installation without first reconciling those differences. No live Docker container or Cairn service was restarted, and nothing was committed, pushed or deployed.

Local verification used disposable PostgreSQL on 55439, ScopeWeaver API on 18787 / browser UI on 18788, and a disposable Cairn database/API on 18000. No dispatcher, model or worker was configured. The retained E2E script drives native task selection, popup transfers both ways, paused/stopped records, duplicate receipts, graph/asset/constraint preservation, template reuse, file import, masking, mobile overflow and absence of start/resume/bootstrap requests. It refuses production ports 8787, 8797 and 8000.

Artifacts are under the ScopeWeaver worktree's `.empryo/verification/`: `handoff_e2e.py`, `handoff-e2e.json` and desktop/mobile screenshots. The script needs the local test services, the `scopeweaver-handoff-verify` disposable PostgreSQL container, and Python Playwright/Chromium. Run it using the Cairn Python environment. Existing Go and Cairn suites and ScopeWeaver TypeScript checking also ran. Python typing/lint checks are scoped to the new router because the existing repository has unrelated whole-project lint/type errors.

## Reproduce locally

Use fresh worktrees and separate terminals; none of these commands targets the live ports. Dependencies must be installed in the ScopeWeaver `web` and Cairn `cairn` directories.

Start the disposable database:

```sh
docker run --name scopeweaver-handoff-verify --rm -d -e POSTGRES_USER=handoff -e POSTGRES_PASSWORD=handoff-local -e POSTGRES_DB=handoff -p 127.0.0.1:55439:5432 postgres:17-alpine
```

From the ScopeWeaver worktree:

```sh
ARTEX_PG_DSN="postgres://handoff:handoff-local@127.0.0.1:55439/handoff?sslmode=disable" go run ./cmd/artex -addr 127.0.0.1:18787 -proxy "" -data ./data-handoff-verify
```

From its `web` directory, in another terminal:

```sh
AUTOPENTEST_API=http://127.0.0.1:18787 pnpm dev --hostname 127.0.0.1 --port 18788
```

From the Cairn worktree's `cairn` directory:

```sh
uv run python -c 'from pathlib import Path; from cairn.server import db; db.configure(Path(".empryo/verification/cairn.sqlite")); import uvicorn; from cairn.server.app import app; uvicorn.run(app, host="127.0.0.1", port=18000)'
```

In another terminal in that same Cairn directory:

```sh
uv pip install playwright
uv run playwright install chromium
uv run python ../../scopeweaver-cairn-handoff/.empryo/verification/handoff_e2e.py
```

The fixture script writes only to loopback test applications and the specifically named disposable PostgreSQL container. It exercises anchor-only assets as well as task-scoped assets, native graph edges, constraints and findings/reports. It also checks rejection of non-JSON simple requests, wrong-origin/window messages, and concurrent duplicate imports. Both import endpoints require `Content-Type: application/json`; Cairn performs SQLite work in its thread pool, not its event loop.

Stop the three test processes with Ctrl-C and run `docker stop scopeweaver-handoff-verify` afterwards. The `--rm` container contains only disposable verification records. For consistent snapshots of actively changing work, pause the source tasks before exporting.
