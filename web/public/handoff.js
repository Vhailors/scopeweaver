function setupHandoff() {
  const $ = (id) => document.getElementById(id);
  const params = new URLSearchParams(location.search);
  const system = params.get("system") === "cairn" ? "cairn" : "scopeweaver";
  const other = system === "cairn" ? "scopeweaver" : "cairn";
  const label = (value) => (value === "cairn" ? "Cairn" : "ScopeWeaver");
  const prefix = system === "cairn" ? "" : "/api";
  const limit = 8 * 1024 * 1024;
  let envelope = null;
  let receiving = true;
  let completed = false;
  let popup = null;
  let peer = null;
  let timeout = null;
  let expectedChannel = null;
  let expectedOrigin = null;
  let templates = {};
  const presets = {
    review: {
      goal: "Produce a clear, evidence-backed summary of the selected context.",
      intent: "Review facts, intents and their relationships; separate established facts from open questions.",
    },
    plan: {
      goal: "Prepare a human-reviewed plan from the selected context.",
      intent: "Identify gaps, dependencies, constraints and proposed next steps. Do not execute actions.",
    },
    followup: {
      goal: "Resolve the questions described in the human input.",
      intent: "Use the source snapshot as reference, preserve provenance and identify what needs human confirmation.",
    },
  };
  function uuid() {
    if (crypto.randomUUID) return crypto.randomUUID();
    const a = crypto.getRandomValues(new Uint8Array(16));
    a[6] = (a[6] & 15) | 64;
    a[8] = (a[8] & 63) | 128;
    const h = [...a].map((b) => b.toString(16).padStart(2, "0")).join("");
    return [h.slice(0, 8), h.slice(8, 12), h.slice(12, 16), h.slice(16, 20), h.slice(20)].join("-");
  }
  function status(text, error = false) {
    $("status").textContent = text;
    $("status").dataset.error = String(error);
  }
  function checkSize(data) {
    if (new TextEncoder().encode(JSON.stringify(data)).byteLength > limit)
      throw new Error("Snapshot exceeds 8 MiB. Select fewer items.");
  }
  function origin(value) {
    const url = new URL(value);
    if (
      !["http:", "https:"].includes(url.protocol) ||
      url.username ||
      url.password ||
      url.pathname !== "/" ||
      url.search ||
      url.hash
    )
      throw new Error("Enter an HTTP(S) origin only, without a path or credentials.");
    return url.origin;
  }
  async function request(path, body) {
    const headers = { Accept: "application/json" };
    if (body) headers["Content-Type"] = "application/json";
    if (system === "scopeweaver") {
      const token = localStorage.getItem("artex_token");
      if (token) headers.Authorization = `Bearer ${token}`;
    }
    const response = await fetch(prefix + path, {
      method: body ? "POST" : "GET",
      headers,
      credentials: "same-origin",
      body: body ? JSON.stringify(body) : undefined,
    });
    if (response.status === 401) throw new Error("Sign in to ScopeWeaver in another tab, then reload this handoff.");
    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Request failed (${response.status}): ${text.slice(0, 300)}`);
    }
    const raw = await response.text();
    if (new TextEncoder().encode(raw).byteLength > limit)
      throw new Error("Source snapshot exceeds 8 MiB. Narrow the selection.");
    return JSON.parse(raw);
  }
  function redact(value, depth = 0) {
    if (depth > 100) throw new Error("Snapshot nesting exceeds safe limits.");
    if (Array.isArray(value)) return value.map((item) => redact(item, depth + 1));
    if (!value || typeof value !== "object") return value;
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [
        key,
        /^(authorization|proxy.authorization|cookie|set.cookie|password|passwd|secret|api.key|access.token|refresh.token|private.key)$/i.test(
          key,
        )
          ? "[masked]"
          : redact(item, depth + 1),
      ]),
    );
  }
  function build() {
    if (!envelope) throw new Error("No source snapshot loaded.");
    const result = {
      ...envelope,
      title: $("title").value.trim(),
      goal: $("goal").value.trim(),
      intent: $("intent").value.trim(),
      human_input: $("human-input").value.trim(),
      template: $("template").value,
    };
    if (!receiving && !$("include-graph").checked)
      result.items = result.items.map((item) => ({
        ...item,
        data:
          system === "scopeweaver"
            ? { task: item.data.task, constraints: item.data.constraints }
            : { project: item.data.project },
      }));
    checkSize(result);
    return result;
  }
  function refresh() {
    if (!envelope) return;
    try {
      $("preview").textContent = JSON.stringify(build(), null, 2);
    } catch (error) {
      status(error.message, true);
    }
  }
  function render() {
    $("source").textContent = `${label(envelope.source.system)} · ${envelope.source.origin}`;
    $("items").replaceChildren(
      ...envelope.items.map((item) => {
        const li = document.createElement("li");
        li.textContent = item.data.task?.name || item.data.project?.title || item.id;
        const small = document.createElement("small");
        const graphs = Array.isArray(item.data.graphs) ? item.data.graphs : [];
        const nodes =
          graphs.reduce((n, graph) => n + (Array.isArray(graph.nodes) ? graph.nodes.length : 0), 0) ||
          item.data.facts?.length ||
          0;
        small.textContent = `ID ${item.id} · ${nodes} facts / graph nodes`;
        li.append(small);
        return li;
      }),
    );
    $("heading").textContent = receiving ? `Review in ${label(system)}` : `Handoff to ${label(other)}`;
    $("subtitle").textContent =
      `${envelope.items.length} source item${envelope.items.length === 1 ? "" : "s"}. One reviewed destination draft.`;
    const createLabel = system === "cairn" ? "Create stopped project" : "Create paused task";
    $("send").textContent = receiving ? createLabel : "Send for review";
    $("send").disabled = completed;
    $("download").disabled = false;
    $("destination-label").hidden = receiving;
    $("destination").required = !receiving;
    $("file-label").hidden = !receiving;
    $("graph-control").hidden = receiving;
    refresh();
  }
  function accept(data, sourceOrigin = null) {
    checkSize(data);
    const known = ["version", "id", "source", "title", "goal", "intent", "human_input", "template", "items"];
    if (
      !data ||
      typeof data !== "object" ||
      Object.keys(data).some((key) => !known.includes(key)) ||
      data.version !== 1 ||
      !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(data.id) ||
      data.source?.system !== other ||
      origin(data.source.origin) !== data.source.origin ||
      (sourceOrigin && data.source.origin !== sourceOrigin) ||
      !Array.isArray(data.items) ||
      !data.items.length ||
      data.items.length > 100
    )
      throw new Error("Invalid or incompatible handoff document.");
    for (const key of ["title", "goal", "intent", "human_input", "template"])
      if (typeof data[key] !== "string") throw new Error("Invalid handoff fields.");
    const ids = new Set();
    for (const item of data.items) {
      if (
        !item ||
        typeof item.id !== "string" ||
        !item.id.trim() ||
        ids.has(item.id) ||
        !item.data ||
        typeof item.data !== "object" ||
        Array.isArray(item.data)
      )
        throw new Error("Invalid handoff item.");
      ids.add(item.id);
    }
    if (![...$("template").options].some((option) => option.value === data.template)) {
      const option = document.createElement("option");
      option.value = data.template;
      option.textContent = `Source template: ${data.template}`;
      $("template").append(option);
    }
    $("template").value = data.template;
    envelope = redact(data);
    receiving = true;
    completed = false;
    for (const [id, key] of [
      ["title", "title"],
      ["goal", "goal"],
      ["intent", "intent"],
      ["human-input", "human_input"],
    ])
      $(id).value = envelope[key];
    $("reviewed").checked = false;
    $("receive").hidden = true;
    render();
    status("Snapshot received. Review the data and instructions before creating the draft.");
  }
  try {
    templates = JSON.parse(localStorage.getItem("context-handoff.templates.v1") || "{}");
  } catch {
    templates = {};
  }
  if (!templates || typeof templates !== "object" || Array.isArray(templates)) templates = {};
  function addTemplate(name) {
    const option = document.createElement("option");
    option.value = `saved:${name}`;
    option.textContent = `Saved: ${name}`;
    $("template").append(option);
  }
  Object.keys(templates).slice(0, 50).forEach(addTemplate);
  $("template").addEventListener("change", () => {
    const key = $("template").value;
    const template = key.startsWith("saved:") ? templates[key.slice(6)] : presets[key];
    if (template && typeof template.goal === "string" && typeof template.intent === "string") {
      $("goal").value = template.goal;
      $("intent").value = template.intent;
    }
    refresh();
  });
  $("save-template").addEventListener("click", () => {
    const name = $("template-name").value.trim();
    if (!name || !$("goal").value.trim() || !$("intent").value.trim())
      return status("Enter a template name, goal and intent first.", true);
    try {
      if (Object.keys(templates).length >= 50 && !Object.hasOwn(templates, name))
        throw new Error("Maximum 50 saved templates.");
      const exists = Object.hasOwn(templates, name);
      templates = { ...templates, [name]: { goal: $("goal").value, intent: $("intent").value } };
      localStorage.setItem("context-handoff.templates.v1", JSON.stringify(templates));
      if (!exists) addTemplate(name);
      $("template").value = `saved:${name}`;
      status("Template saved in this browser.");
    } catch (error) {
      status(error.message, true);
    }
  });
  $("form").addEventListener("input", refresh);
  $("include-graph").addEventListener("change", refresh);
  $("download").addEventListener("click", () => {
    try {
      const data = build();
      const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = `handoff-${data.id}.json`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (error) {
      status(error.message, true);
    }
  });
  $("file").addEventListener("change", async () => {
    try {
      const file = $("file").files[0];
      if (!file) return;
      if (file.size > limit) throw new Error("File exceeds 8 MiB.");
      accept(JSON.parse(await file.text()));
    } catch (error) {
      status(error.message, true);
    }
  });
  $("form").addEventListener("submit", async (event) => {
    event.preventDefault();
    if (completed) return;
    try {
      const data = build();
      if (receiving) {
        $("send").disabled = true;
        status("Creating a draft. No workers will start…");
        const result = await request("/handoffs", data);
        completed = true;
        $("result").href =
          system === "cairn"
            ? `/#/projects/${encodeURIComponent(result.id)}`
            : `/function/tasks/detail?id=${encodeURIComponent(result.id)}`;
        $("result").hidden = false;
        status(`${result.duplicate ? "Already imported" : "Created"}: ${result.id}. No start action was sent.`);
        if (peer)
          peer.postMessage({ type: "handoff:receipt", channel: expectedChannel, id: result.id }, expectedOrigin);
        return;
      }
      expectedOrigin = origin($("destination").value.trim());
      expectedChannel = uuid();
      const path = other === "cairn" ? "/static/handoff.html" : "/handoff.html";
      const target = new URL(path, expectedOrigin);
      target.search = new URLSearchParams({
        system: other,
        source: location.origin,
        channel: expectedChannel,
      }).toString();
      popup = window.open(target.href, "_blank");
      if (!popup) throw new Error("Allow popups or download the handoff file instead.");
      envelope = data;
      $("send").disabled = true;
      status("Destination opened. Click Receive there, then review and create the draft.");
      clearTimeout(timeout);
      timeout = setTimeout(() => {
        popup = null;
        $("send").disabled = false;
        status("Transfer expired. Try again, or use the downloaded file.", true);
      }, 300000);
    } catch (error) {
      $("send").disabled = completed;
      status(error.message, true);
    }
  });
  window.addEventListener("message", (event) => {
    try {
      const message = event.data;
      if (!message || event.origin !== expectedOrigin || message.channel !== expectedChannel) return;
      if (!receiving && event.source === popup && message.type === "handoff:ready")
        popup.postMessage({ type: "handoff:data", channel: expectedChannel, payload: envelope }, expectedOrigin);
      if (receiving && event.source === peer && message.type === "handoff:data" && !envelope) {
        accept(message.payload, event.origin);
        clearTimeout(timeout);
      }
      if (!receiving && event.source === popup && message.type === "handoff:receipt") {
        clearTimeout(timeout);
        completed = true;
        status(`Imported in ${label(other)} as ${message.id}. No start action was sent.`);
      }
    } catch (error) {
      status(error.message, true);
    }
  });
  $("receive").addEventListener("click", () => {
    if (!peer) return status("The source window is no longer connected. Import the handoff file instead.", true);
    peer.postMessage({ type: "handoff:ready", channel: expectedChannel }, expectedOrigin);
    status("Waiting for the reviewed source snapshot…");
    timeout = setTimeout(() => status("No snapshot arrived. Check the source tab or import a file.", true), 30000);
  });
  async function init() {
    $("back").href = system === "cairn" ? "/" : "/function/tasks";
    const target = new URL(location.origin);
    target.port = other === "cairn" ? "8000" : "8787";
    $("destination").value = target.origin;
    const ids = [...new Set((params.get("ids") || "").split(",").filter(Boolean))];
    if (ids.length) {
      if (ids.length > 100 || ids.some((id) => !/^[a-zA-Z0-9_-]{1,100}$/.test(id)))
        throw new Error("Select between 1 and 100 valid items.");
      receiving = false;
      status("Loading source snapshots…");
      const items = [];
      for (const id of ids) {
        const path =
          system === "cairn" ? `/projects/${encodeURIComponent(id)}` : `/tasks/${encodeURIComponent(id)}/handoff`;
        items.push({ id, data: redact(await request(path)) });
        checkSize(items);
      }
      envelope = {
        version: 1,
        id: uuid(),
        source: { system, origin: location.origin },
        title: "",
        goal: "",
        intent: "",
        human_input: "",
        template: "custom",
        items,
      };
      $("title").value =
        `Handoff: ${ids.length} ${system === "cairn" ? "project" : "task"}${ids.length === 1 ? "" : "s"}`;
      render();
      status("Choose a template or write a goal and intent, then review the exact payload.");
    } else {
      $("destination-label").hidden = true;
      status("Import a handoff file, or receive a snapshot from the source workspace.");
      if (params.has("source") && params.has("channel") && window.opener) {
        expectedOrigin = origin(params.get("source"));
        expectedChannel = params.get("channel");
        if (!/^[a-f0-9-]{36}$/.test(expectedChannel)) throw new Error("Invalid transfer channel.");
        peer = window.opener;
        $("source").textContent = `Source requesting transfer: ${expectedOrigin}`;
        $("receive").hidden = false;
      }
    }
  }
  init().catch((error) => status(error.message, true));
}
setupHandoff();
