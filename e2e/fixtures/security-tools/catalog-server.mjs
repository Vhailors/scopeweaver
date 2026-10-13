#!/usr/bin/env node
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

const protocolVersion = "2024-11-05";
const tools = [{
  name: "unexpected_operation",
  description: "Inert catalog sentinel; execution is always rejected.",
  inputSchema: { type: "object", properties: {}, additionalProperties: false },
}];
const methods = new Set(["initialize", "notifications/initialized", "tools/list", "tools/call", "shutdown"]);
const malformed = process.argv.includes("--malformed");
const hung = process.argv.includes("--hung");
const log = (event) => process.stderr.write(`${JSON.stringify(event)}\n`);
const send = (message) => process.stdout.write(`${JSON.stringify(message)}\n`);

function serve() {
  const input = createInterface({ input: process.stdin, crlfDelay: Infinity });
  let initialized = false;
  let ready = false;
  let stopping = false;
  const stop = (reason, code = 0) => {
    if (stopping) return;
    stopping = true;
    process.exitCode = code;
    log({ event: "stop", reason });
    input.close();
    process.stdin.destroy();
  };
  process.once("SIGINT", () => stop("SIGINT", 130));
  process.once("SIGTERM", () => stop("SIGTERM", 143));
  input.once("close", () => stop("EOF"));
  log({ event: "start" });
  input.on("line", (line) => {
    if (stopping || line.length === 0) return;
    let request;
    try { request = JSON.parse(line); }
    catch {
      send({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "FIXTURE_PARSE_ERROR" } });
      return;
    }
    if (!request || Array.isArray(request) || request.jsonrpc !== "2.0" ||
        typeof request.method !== "string" ||
        ("id" in request && typeof request.id !== "string" && !Number.isFinite(request.id))) {
      send({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "FIXTURE_INVALID_REQUEST" } });
      return;
    }
    const method = methods.has(request.method) ? request.method : "unknown";
    log({ event: "request", method });
    if (!("id" in request)) {
      if (method === "notifications/initialized" && initialized) ready = true;
      return;
    }
    const reply = (result) => send({ jsonrpc: "2.0", id: request.id, result });
    const reject = (code, message) => send({ jsonrpc: "2.0", id: request.id, error: { code, message } });
    switch (method) {
      case "initialize":
        initialized = true;
        reply({ protocolVersion, capabilities: { tools: { listChanged: false } },
          serverInfo: { name: "inert-security-catalog-fixture", version: "1.0.0" } });
        break;
      case "tools/list":
        if (!ready) reject(-32002, "FIXTURE_NOT_INITIALIZED");
        else if (hung) break; // Deliberately leave this request pending for cancellation probes.
        else if (malformed) process.stdout.write('{"scopeweaver-secret-canary-01":\n');
        else reply({ tools });
        break;
      case "tools/call":
        reject(-32601, "FIXTURE_CALL_DISABLED");
        break;
      case "shutdown":
        reply(null);
        stop("shutdown");
        break;
      default:
        reject(-32601, "FIXTURE_METHOD_NOT_FOUND");
    }
  });
}

async function bounded(promise) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error("IPC_TIMEOUT")), 5000);
    })]);
  } finally { clearTimeout(timer); }
}

async function selfCheck() {
  // Given: an owned local child, with exit and wire listeners installed before requests.
  const child = spawn(process.execPath, [fileURLToPath(import.meta.url),
    ...(malformed ? ["--malformed"] : []), ...(hung ? ["--hung"] : [])],
    { stdio: ["pipe", "pipe", "pipe"] });
  const pending = new Map();
  const received = [];
  let diagnostics = "";
  let failure;
  const fail = (code) => {
    failure ??= new Error(code);
    for (const waiter of pending.values()) waiter.reject(failure);
    pending.clear();
  };
  const closed = new Promise((resolve) => {
    child.once("close", (code, signal) => {
      fail("IPC_CLOSED");
      resolve({ code, signal });
    });
  });
  child.once("error", () => fail("IPC_SPAWN_ERROR"));
  child.stdin.on("error", () => fail("IPC_WRITE_ERROR"));
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => { diagnostics += chunk; });
  const output = createInterface({ input: child.stdout, crlfDelay: Infinity });
  output.on("line", (line) => {
    let message;
    try { message = JSON.parse(line); }
    catch { fail("IPC_MALFORMED_RESPONSE"); return; }
    if (!message || message.jsonrpc !== "2.0" || !pending.has(message.id)) {
      fail("IPC_UNEXPECTED_RESPONSE");
      return;
    }
    received.push(message);
    const waiter = pending.get(message.id);
    pending.delete(message.id);
    waiter.resolve(message);
  });
  const interrupt = () => { fail("IPC_INTERRUPTED"); child.kill("SIGKILL"); };
  process.once("SIGINT", interrupt);
  process.once("SIGTERM", interrupt);
  let nextID = 0;
  const call = async (method, params = {}) => {
    if (failure) throw failure;
    const id = ++nextID;
    const response = bounded(new Promise((resolve, reject) => pending.set(id, { resolve, reject })));
    // Subscribe to this exact ID and the bounded failure path before writing.
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
    return await response;
  };
  let exit;
  try {
    // When: initialize, notify, list, then shut down over real NDJSON pipes.
    const init = await call("initialize", { protocolVersion, capabilities: {},
      clientInfo: { name: "fixture-self-check", version: "1.0.0" } });
    assert.equal(init.result.protocolVersion, protocolVersion);
    assert.deepEqual(init.result.capabilities, { tools: { listChanged: false } });
    send({ assertion: "initialize", received: init });
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
    const catalog = await call("tools/list");
    assert.deepEqual(catalog.result.tools, tools);
    send({ assertion: "tools/list", received: catalog });
    const shutdown = await call("shutdown");
    assert.equal(shutdown.result, null);
    send({ assertion: "shutdown", received: shutdown });
  } finally {
    child.stdin.end();
    try { exit = await bounded(closed); }
    catch {
      child.kill("SIGKILL");
      exit = await bounded(closed);
    } finally {
      output.close();
      process.removeListener("SIGINT", interrupt);
      process.removeListener("SIGTERM", interrupt);
    }
    // Only fixed fixture diagnostics are forwarded; malformed wire bytes never leave the child reader.
    process.stderr.write(diagnostics);
    send({ assertion: "child-exit", received: exit, ownedChildReaped: true });
  }
  // Then: actual responses, request ordering, and a successful reaped exit are required.
  assert.deepEqual(exit, { code: 0, signal: null });
  assert.deepEqual(received.map((message) => message.id), [1, 2, 3]);
  assert.deepEqual(diagnostics.trim().split("\n").map((line) => JSON.parse(line)), [
    { event: "start" },
    { event: "request", method: "initialize" },
    { event: "request", method: "notifications/initialized" },
    { event: "request", method: "tools/list" },
    { event: "request", method: "shutdown" },
    { event: "stop", reason: "shutdown" },
  ]);
  send({ assertion: "request-order-and-zero-tools/call", passed: true });
}

if (process.argv.includes("--self-check")) {
  try { await selfCheck(); }
  catch (error) {
    const code = error instanceof Error && /^IPC_[A-Z_]+$/.test(error.message)
      ? error.message : "IPC_ASSERTION_FAILED";
    log({ error: code });
    process.exitCode = 1;
  }
} else {
  serve();
}
