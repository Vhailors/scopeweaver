function setupHandoff() {
  const $ = (id) => document.getElementById(id);
  const params = new URLSearchParams(location.search);
  const system = params.get("system") === "cairn" ? "cairn" : "scopeweaver";
  const other = system === "cairn" ? "scopeweaver" : "cairn";
  const label = (value) => (value === "cairn" ? "Cairn" : "ScopeWeaver");
  const prefix = system === "cairn" ? "" : "/api";
  const limit = 8 * 1024 * 1024;
  const directFindings = system === "scopeweaver" && params.has("finding_ids");
  const presets = {
    review: {
      goal: "Produce a clear, evidence-backed summary of the selected context.",
      intent:
        "Review the selected evidence, separate established facts from open questions, and preserve source references.",
    },
    plan: {
      goal: "Prepare a human-reviewed plan from the selected context.",
      intent: "Identify gaps, dependencies, constraints and proposed next steps. Do not execute actions.",
    },
    followup: {
      goal: "Resolve the questions described in the human input.",
      intent: "Use the selected source snapshot as reference and identify what needs human confirmation.",
    },
  };
  let envelope = null;
  let receiving = true;
  let completed = false;
  let busy = false;
  let popup = null;
  let pendingPayload = null;
  let peer = null;
  let receiveRequested = false;
  let timeout = null;
  let expectedChannel = null;
  let expectedOrigin = null;
  let templates = {};
  let inventory = [];
  let checked = new Set();
  let autoTitle = "";
  function uuid() {
    if (crypto.randomUUID) return crypto.randomUUID();
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    const hex = [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
    return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20)].join("-");
  }
  function status(text, error = false) {
    $("status").textContent = text;
    $("status").dataset.error = String(error);
  }
  function checkSize(data) {
    if (new TextEncoder().encode(JSON.stringify(data)).byteLength > limit)
      throw new Error("Snapshot exceeds 8 MiB. Select fewer findings or items.");
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
      throw new Error("Enter an HTTP(S) origin without a path or credentials.");
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
    if (!response.ok) throw new Error(`Request failed (${response.status}): ${(await response.text()).slice(0, 300)}`);
    const raw = await response.text();
    if (new TextEncoder().encode(raw).byteLength > limit)
      throw new Error("Source exceeds 8 MiB. Choose specific findings instead.");
    return JSON.parse(raw);
  }
  function redact(value, depth = 0) {
    if (depth > 100) throw new Error("Snapshot nesting exceeds safe limits.");
    if (Array.isArray(value)) return value.map((item) => redact(item, depth + 1));
    if (!value || typeof value !== "object") return value;
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [
        key,
        /^(authorization|proxy[._-]?authorization|cookie|set[._-]?cookie|password|passwd|secret|api[._-]?key|access[._-]?token|refresh[._-]?token|private[._-]?key)$/i.test(
          key,
        )
          ? "[masked]"
          : redact(item, depth + 1),
      ]),
    );
  }
  function focused() {
    return !receiving && $("context-mode").value === "findings";
  }
  function focusedData(finding, task, assets, constraints, anchors = {}) {
    const clean = { ...finding };
    delete clean.TaskDescription;
    delete clean.task_description;
    clean.TrafficBindings = null;
    const parent = {};
    if (task?.id != null) parent.id = String(task.id);
    if (task?.name) parent.name = task.name;
    return { finding: clean, task: parent, assets, constraints, node_anchors: anchors };
  }
  function collectFindings() {
    const found = new Map();
    function add(finding, data) {
      const id = String(finding.ID ?? finding.finding_id ?? finding.id ?? "");
      if (!id || found.has(id)) return;
      found.set(id, {
        id,
        data,
        name: finding.Name || finding.name || finding.VulnClass || finding.vulnclass || `Finding ${id}`,
        severity: finding.Severity || finding.severity || "",
      });
    }
    for (const item of envelope.items) {
      const data = item.data;
      if (data.finding)
        add(
          data.finding,
          focusedData(data.finding, data.task, data.assets || [], data.constraints || [], data.node_anchors || {}),
        );
      for (const graph of data.graphs || []) {
        for (const finding of graph.findings || []) {
          const taskID = String(finding.TaskID ?? finding.task_id ?? graph.task_id ?? data.task?.id ?? "");
          const nodeID = String(finding.NodeID ?? finding.node_id ?? "");
          const anchorIDs = graph.node_anchors?.[nodeID] || [];
          const assetIDs = new Set([...(finding.AssetIDs || finding.asset_ids || []), ...anchorIDs].map(String));
          const assets = (graph.assets || []).filter((asset) => assetIDs.has(String(asset.id ?? asset.ID)));
          const task = { id: taskID, name: String(data.task?.id) === taskID ? data.task.name : "" };
          add(
            finding,
            focusedData(
              finding,
              task,
              assets,
              data.constraints?.[taskID] || [],
              nodeID && anchorIDs.length ? { [nodeID]: anchorIDs } : {},
            ),
          );
        }
      }
    }
    inventory = [...found.values()];
    checked = new Set(inventory.length <= 100 ? inventory.map((item) => item.id) : []);
    $("finding-choices").replaceChildren(
      ...inventory.map((item) => {
        const row = document.createElement("label");
        row.className = "finding-choice";
        const box = document.createElement("input");
        box.type = "checkbox";
        box.dataset.findingId = item.id;
        box.checked = checked.has(item.id);
        box.setAttribute("aria-label", `Include finding ${item.id}: ${item.name}`);
        const text = document.createElement("span");
        text.textContent = item.name;
        const small = document.createElement("small");
        small.textContent = `Finding ${item.id} · ${item.severity || "severity not set"}`;
        text.append(small);
        box.addEventListener("change", () => {
          if (box.checked) checked.add(item.id);
          else checked.delete(item.id);
          updateTitle();
          render();
        });
        row.append(box, text);
        return row;
      }),
    );
  }
  function sourceItems() {
    if (focused()) {
      if (!checked.size) throw new Error("Check at least one finding to hand off.");
      if (checked.size > 100) throw new Error("Select at most 100 findings per handoff.");
      return inventory
        .filter((item) => checked.has(item.id))
        .map((item) => ({ id: `finding:${item.id}`, data: item.data }));
    }
    if (!receiving && !$("include-graph").checked)
      return envelope.items.map((item) => ({
        ...item,
        data:
          system === "scopeweaver"
            ? { task: item.data.task, constraints: item.data.constraints }
            : { project: item.data.project },
      }));
    return envelope.items;
  }
  function updateTitle() {
    if (receiving) return;
    const next = focused()
      ? `Review ${checked.size || "selected"} finding${checked.size === 1 ? "" : "s"}`
      : `Handoff: ${envelope.items.length} ${system === "cairn" ? "project" : "task"}${envelope.items.length === 1 ? "" : "s"}`;
    if (!$("title").value || $("title").value === autoTitle) $("title").value = next;
    autoTitle = next;
  }
  function build() {
    if (!envelope) throw new Error("Choose source tasks/findings or receive a handoff first.");
    const result = {
      ...envelope,
      title: $("title").value.trim(),
      goal: $("goal").value.trim(),
      intent: $("intent").value.trim(),
      human_input: $("human-input").value.trim(),
      template: $("template").value,
      items: sourceItems(),
    };
    checkSize(result);
    return result;
  }
  function refresh() {
    $("save-template").disabled =
      !$("template-name").value.trim() || !$("goal").value.trim() || !$("intent").value.trim();
    if (!envelope) return;
    $("composer").disabled = busy || completed;
    $("file").disabled = busy;
    $("cancel-transfer").hidden = receiving || !busy || completed;
    $("context-mode").disabled = busy || completed;
    $("include-graph").disabled = busy || completed;
    $("findings-all").disabled = busy || completed || inventory.length > 100;
    $("findings-none").disabled = busy || completed;
    for (const input of $("finding-choices").querySelectorAll("input")) input.disabled = busy || completed;
    try {
      $("preview").textContent = JSON.stringify(build(), null, 2);
      if ($("status").dataset.error === "true" && !busy && !completed)
        status("Ready for review. Saving a template is optional.");
      $("send").disabled = completed || busy;
      $("download").disabled = false;
    } catch (error) {
      $("preview").textContent = error.message;
      $("send").disabled = true;
      $("download").disabled = true;
      status(error.message, true);
    }
  }
  function render() {
    $("composer").hidden = false;
    $("composer").disabled = false;
    $("empty-state").hidden = true;
    $("source").textContent = `${label(envelope.source.system)} · ${envelope.source.origin}`;
    const items = focused()
      ? inventory.filter((item) => checked.has(item.id)).map((item) => ({ id: `finding:${item.id}`, data: item.data }))
      : envelope.items;
    $("items").replaceChildren(
      ...items.map((item) => {
        const li = document.createElement("li");
        li.textContent =
          item.data.finding?.Name ||
          item.data.finding?.name ||
          item.data.task?.name ||
          item.data.project?.title ||
          item.id;
        const small = document.createElement("small");
        small.textContent = `Source ID ${item.id}`;
        li.append(small);
        return li;
      }),
    );
    $("heading").textContent = receiving ? `Review in ${label(system)}` : `Handoff to ${label(other)}`;
    $("subtitle").textContent =
      `${items.length} selected source item${items.length === 1 ? "" : "s"}. No template name is needed to send.`;
    const createLabel = system === "cairn" ? "Create stopped project" : "Create paused task";
    $("send").textContent = receiving ? createLabel : "Send for review";
    $("destination-label").hidden = receiving;
    $("destination").required = !receiving;
    $("destination").disabled = receiving;
    $("file-label").hidden = !receiving;
    $("findings-section").hidden = receiving || !inventory.length;
    $("mode-label").hidden = directFindings;
    $("findings-picker").hidden = !focused();
    $("finding-count").textContent = `${checked.size} of ${inventory.length} findings checked · maximum 100`;
    $("findings-all").disabled = inventory.length > 100;
    $("graph-control").hidden = receiving || focused();
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
    receiveRequested = false;
    envelope = redact(data);
    receiving = true;
    completed = false;
    busy = false;
    for (const [id, key] of [
      ["title", "title"],
      ["goal", "goal"],
      ["intent", "intent"],
      ["human-input", "human_input"],
    ])
      $(id).value = envelope[key];
    $("result").hidden = true;
    $("reviewed").checked = false;
    $("receive").hidden = true;
    render();
    status(
      "Received. Review the selected data and instructions, then create the draft. Saving a template is optional.",
    );
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
  $("goal").value = presets.review.goal;
  $("intent").value = presets.review.intent;
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
    if (!name || !$("goal").value.trim() || !$("intent").value.trim()) {
      $("template-status").textContent =
        "A name is only needed to save a reusable template. You can send without saving.";
      return;
    }
    try {
      if (Object.keys(templates).length >= 50 && !Object.hasOwn(templates, name))
        throw new Error("Maximum 50 saved templates.");
      const exists = Object.hasOwn(templates, name);
      templates = { ...templates, [name]: { goal: $("goal").value, intent: $("intent").value } };
      localStorage.setItem("context-handoff.templates.v1", JSON.stringify(templates));
      if (!exists) addTemplate(name);
      $("template").value = `saved:${name}`;
      $("template-status").textContent = "Template saved in this browser. You can now send this handoff.";
      refresh();
    } catch (error) {
      $("template-status").textContent = error.message;
    }
  });
  $("form").addEventListener("input", refresh);
  $("include-graph").addEventListener("change", refresh);
  $("context-mode").addEventListener("change", () => {
    updateTitle();
    render();
    status(
      focused()
        ? "Choose the specific findings to send. Other task findings and full graphs are excluded."
        : "Selected task context will be sent. Saving a template is optional.",
    );
  });
  for (const [id, all] of [
    ["findings-all", true],
    ["findings-none", false],
  ])
    $(id).addEventListener("click", () => {
      checked = new Set(all ? inventory.map((item) => item.id) : []);
      for (const input of $("finding-choices").querySelectorAll("input")) input.checked = all;
      updateTitle();
      render();
    });
  $("cancel-transfer").addEventListener("click", () => {
    if (popup && !popup.closed) popup.close();
    popup = null;
    $("reviewed").checked = false;
    pendingPayload = null;
    clearTimeout(timeout);
    busy = false;
    envelope = { ...envelope, id: uuid() };
    refresh();
    status("Transfer canceled. Edit the selection or instructions, then send again.");
  });
  $("download").addEventListener("click", () => {
    try {
      const data = build();
      const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = `handoff-${data.id}.json`;
      link.click();
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
    if (completed || busy) return;
    try {
      const data = build();
      if (receiving) {
        busy = true;
        refresh();
        status("Creating a draft. No workers will start…");
        const result = await request("/handoffs", data);
        completed = true;
        busy = false;
        refresh();
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
      const target = new URL(other === "cairn" ? "/static/handoff.html" : "/handoff.html", expectedOrigin);
      target.search = new URLSearchParams({
        system: other,
        source: location.origin,
        channel: expectedChannel,
      }).toString();
      popup = window.open(target.href, "_blank");
      if (!popup) throw new Error("Allow popups or download the handoff file instead.");
      pendingPayload = data;
      busy = true;
      refresh();
      status("Destination opened. Click Receive there, review, then create the draft. No template needs to be saved.");
      clearTimeout(timeout);
      timeout = setTimeout(() => {
        popup = null;
        busy = false;
        refresh();
        status("Transfer expired. Try again or download the handoff file.", true);
      }, 300000);
    } catch (error) {
      busy = false;
      refresh();
      status(error.message, true);
    }
  });
  window.addEventListener("message", (event) => {
    try {
      const message = event.data;
      if (!message || event.origin !== expectedOrigin || message.channel !== expectedChannel) return;
      if (!receiving && event.source === popup && message.type === "handoff:ready")
        popup.postMessage({ type: "handoff:data", channel: expectedChannel, payload: pendingPayload }, expectedOrigin);
      if (receiving && receiveRequested && event.source === peer && message.type === "handoff:data" && !envelope) {
        accept(message.payload, event.origin);
        clearTimeout(timeout);
      }
      if (!receiving && event.source === popup && message.type === "handoff:receipt") {
        clearTimeout(timeout);
        completed = true;
        busy = false;
        refresh();
        status(`Imported in ${label(other)} as ${message.id}. No start action was sent.`);
      }
    } catch (error) {
      status(error.message, true);
    }
  });
  $("receive").addEventListener("click", () => {
    if (!peer) return status("Source window disconnected. Import the handoff file instead.", true);
    receiveRequested = true;
    peer.postMessage({ type: "handoff:ready", channel: expectedChannel }, expectedOrigin);
    status("Waiting for the reviewed source snapshot…");
    timeout = setTimeout(() => status("No snapshot arrived. Check the source tab or import a file.", true), 30000);
  });
  async function init() {
    const scopeBack = directFindings ? "/function/findings" : "/function/tasks";
    $("back").href = system === "cairn" ? "/" : scopeBack;
    const target = new URL(location.origin);
    target.port = other === "cairn" ? "8000" : "8787";
    $("destination").value = target.origin;
    const scope = new URL(location.origin);
    if (system !== "scopeweaver") scope.port = "8787";
    $("choose-findings").href = new URL("/function/findings", scope).href;
    $("choose-tasks").href = new URL("/function/tasks", scope).href;
    const key = directFindings ? "finding_ids" : "ids";
    const ids = [...new Set((params.get(key) || "").split(",").filter(Boolean))];
    if (ids.length) {
      if (
        ids.length > 100 ||
        ids.some((id) => !/^[a-zA-Z0-9_-]{1,100}$/.test(id)) ||
        (directFindings && ids.some((id) => !/^[1-9][0-9]*$/.test(id)))
      )
        throw new Error("Select 1–100 valid source items.");
      receiving = false;
      status("Loading the selected source context…");
      let items = [];
      if (directFindings)
        items = redact(await request(`/findings/handoff?ids=${encodeURIComponent(ids.join(","))}`)).items;
      else
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
        template: "review",
        items,
      };
      collectFindings();
      $("context-mode").value = directFindings ? "findings" : "tasks";
      updateTitle();
      render();
      status(
        directFindings
          ? "Review the checked findings and send. A template name is not required."
          : "Ready to send once. To send only specific findings, change Handoff contents on the left.",
      );
    } else {
      $("destination-label").hidden = true;
      $("destination").disabled = true;
      status("Receive from a source workspace or import a file. To send specific findings, use the link above.");
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
  init().catch((error) =>
    status(`${error.message} Use the Tasks or Findings links above to choose a smaller selection.`, true),
  );
}
setupHandoff();
