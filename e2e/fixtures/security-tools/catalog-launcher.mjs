#!/usr/bin/env node
// Start-logging wrapper around the inert catalog fixture. The application discards
// a catalog process's stderr, so this owned launcher records every start and the
// fixture's fixed IPC events into an append-only JSONL file the E2E runner reads.
//
// Usage: catalog-launcher.mjs --log <file.jsonl> --label <name> [--gate <fifo>]
// With --gate the launcher subscribes to a release file before starting the fixture,
// which lets the runner change configuration while a refresh is in flight.
import { spawn } from "node:child_process";
import { appendFileSync, existsSync, watch } from "node:fs";
import path from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

const option = (name) => {
  const index = process.argv.indexOf(name);

  return index > 0 ? process.argv[index + 1] ?? "" : "";
};

const logPath = option("--log");

const label = option("--label");

const gate = option("--gate");

const record = (event) => appendFileSync(logPath,
  `${JSON.stringify({ ts: new Date().toISOString(), label, pid: process.pid, ...event })}\n`);

record({ event: "launcher-start" });

if (gate !== "") {
  await new Promise((resolve) => {
    const watcher = watch(path.dirname(gate), () => {
      if (existsSync(gate)) {
        watcher.close();
        resolve();
      }
    });

    record({ event: "gate-wait" });

    if (existsSync(gate)) {
      watcher.close();
      resolve();
    }
  });
  record({ event: "gate-released" });
}

const fixture = fileURLToPath(new URL("./catalog-server.mjs", import.meta.url));

const child = spawn(process.execPath, [fixture, ...process.argv.filter((arg) => ["--hung", "--malformed"].includes(arg))],
  { stdio: ["inherit", "inherit", "pipe"] });

const diagnostics = createInterface({ input: child.stderr, crlfDelay: Infinity });

diagnostics.on("line", (line) => {
  try { record({ fixture: JSON.parse(line) }); }
  catch { record({ fixture: { event: "unparseable-diagnostic" } }); }
});

child.once("close", (code, signal) => {
  record({ event: "launcher-exit", code, signal });
  process.exitCode = code ?? 1;
});
