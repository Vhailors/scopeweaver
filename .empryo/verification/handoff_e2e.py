import json
import os
import subprocess
from urllib.parse import urlsplit
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from uuid import uuid4

from playwright.sync_api import sync_playwright, expect

SCOPE = os.getenv("HANDOFF_SCOPE", "http://127.0.0.1:18788")
CAIRN = os.getenv("HANDOFF_CAIRN", "http://127.0.0.1:18000")
OUT = Path(__file__).parent
for endpoint in (SCOPE, CAIRN):
    address = urlsplit(endpoint)
    assert address.hostname in ("127.0.0.1", "localhost")
    assert address.port not in (8000, 8787, 8797)
TOKEN = ""
RUN = uuid4().hex[:6]
report = {"scope": SCOPE, "cairn": CAIRN, "checks": []}


def api(base, path, data=None, expected=200):
    headers = {"Content-Type": "application/json"}
    if base == SCOPE and TOKEN:
        headers["Authorization"] = "Bearer " + TOKEN
    req = Request(base + path, data=json.dumps(data).encode() if data is not None else None, headers=headers)
    try:
        with urlopen(req, timeout=30) as response:
            status, raw = response.status, response.read()
    except HTTPError as error:
        status, raw = error.code, error.read()
    assert status in (expected if isinstance(expected, tuple) else (expected,)), (path, status, raw[:500])
    return json.loads(raw)


def envelope(source, index=0):
    return {"version": 1, "id": str(uuid4()), "source": {"system": source, "origin": CAIRN if source == "cairn" else SCOPE}, "title": f"Handoff fixture {index} [{RUN}]", "goal": "Review the supplied inventory without executing actions.", "intent": "Summarize the evidence and open questions.", "human_input": "Human review only. Preserve source relationships.", "template": "review", "items": [{"id": f"fixture-{index}", "data": {"project": {"id": f"fixture-{index}", "title": "Reference fixture"}, "facts": [{"id": "origin", "description": "Harmless source context"}, {"id": "goal", "description": "Review only"}], "intents": [{"id": "i1", "from_fact_ids": ["origin"], "to_fact_id": "goal", "description": "Review context"}], "api_key": "must-be-masked"}}]}


auth = api(SCOPE, "/api/auth/status")
if auth["initialized"]:
    TOKEN = api(SCOPE, "/api/auth/login", {"username": "ARTEX", "password": "Handoff-E2E-local-only-2026"})["token"]
else:
    TOKEN = api(SCOPE, "/api/auth/init", {"password": "Handoff-E2E-local-only-2026"})["token"]

ids = []
for i in range(1, 6):
    data = envelope("cairn", i)
    result = api(SCOPE, "/api/handoffs", data, 201)
    ids.append(str(result["id"]))
    duplicate = api(SCOPE, "/api/handoffs", data)
    assert str(duplicate["id"]) == ids[-1] and duplicate["duplicate"]
    api(SCOPE, f"/api/tasks/{ids[-1]}/constraints", {"kind": "deny", "text": "No execution: review only"})
    tid = int(ids[-1])
    assets = api(SCOPE, "/api/assets", {"task_id": tid, "assets": [{"type": "root_domain", "domain": f"handoff-{RUN}-{i}.invalid"}]})
    assert not assets["errors"], assets
    api(SCOPE, "/api/assets", {"assets": [{"type": "root_domain", "domain": f"anchor-only-{RUN}-{i}.invalid"}]})
    fixture_sql = f"WITH added AS (INSERT INTO exploration_nodes(exploration_id,kind,payload,priority,state,origin) SELECT exploration_id,'fact','{{\"text\":\"Harmless linked evidence\"}}'::jsonb,0,'confirmed','human' FROM tasks WHERE id={tid} RETURNING id,exploration_id) INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id) SELECT added.exploration_id,(SELECT min(id) FROM exploration_nodes WHERE exploration_id=added.exploration_id),'yields',added.id FROM added;"
    fixture_sql += f"INSERT INTO exploration_anchors(node_id,asset_id) SELECT n.id,a.id FROM exploration_nodes n JOIN tasks t ON t.exploration_id=n.exploration_id CROSS JOIN assets a WHERE t.id={tid} AND n.kind='fact' AND a.domain='anchor-only-{RUN}-{i}.invalid' ON CONFLICT DO NOTHING; INSERT INTO findings(task_id,vulnclass,name,severity,summary,evidence,report) VALUES ({tid},'inventory-note','Documentation note','low','Harmless fixture','No traffic','Review fixture report.');"
    subprocess.run(["docker", "exec", "scopeweaver-handoff-verify", "psql", "-U", "handoff", "-d", "handoff", "-c", fixture_sql], check=True, capture_output=True)
    exported = api(SCOPE, f"/api/tasks/{tid}/handoff")
    assert exported["graphs"][0]["edges"]
    assert len(exported["graphs"][0]["assets"]) >= 2
    assert exported["graphs"][0]["node_anchors"]
    assert exported["graphs"][0]["findings"][0]["Report"] == "Review fixture report."
    assert exported["graphs"][0]["findings"][0]["TrafficBindings"] is None
    assert exported["constraints"][str(tid)]
    task = api(SCOPE, f"/api/tasks/{ids[-1]}")
    assert task["paused"] is True, task
report["checks"].append("Five atomically paused tasks; duplicate requests return the original IDs")

bad = envelope("scopeweaver")
bad["version"] = 2
api(CAIRN, "/handoffs", bad, 400)
bad = envelope("cairn")
bad["source"]["origin"] = "javascript:alert(1)"
api(SCOPE, "/api/handoffs", bad, 400)
report["checks"].append("Invalid versions and source origins rejected")

for base, path, src in ((SCOPE, "/api/handoffs", "cairn"), (CAIRN, "/handoffs", "scopeweaver")):
    headers = {"Content-Type": "text/plain"}
    if base == SCOPE:
        headers["Authorization"] = "Bearer " + TOKEN
    try:
        urlopen(Request(base + path, data=json.dumps(envelope(src)).encode(), headers=headers))
        raise AssertionError("text/plain JSON must be rejected")
    except HTTPError as error:
        assert error.code == 415
    shared = envelope(src, 77)
    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(lambda _: api(base, path, shared, (200, 201)), range(5)))
    assert len({str(result["id"]) for result in results}) == 1
    assert sum(bool(result.get("duplicate")) for result in results) == 4
report["checks"].append("Non-JSON requests rejected; concurrent retries create one draft in each system")

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(viewport={"width": 1360, "height": 1000})
    context.add_init_script("if (location.origin === " + json.dumps(SCOPE) + ") localStorage.setItem('artex_token', " + json.dumps(TOKEN) + "); Object.defineProperty(crypto, 'randomUUID', {value: undefined});")
    context.add_cookies([{"name": "artex_token", "value": TOKEN, "url": SCOPE}])
    requests = []
    errors = []
    context.on("request", lambda request: requests.append(request.url))
    context.on("page", lambda page: page.on("pageerror", lambda error: errors.append(str(error))))
    source = context.new_page()
    source.goto(SCOPE + "/function/tasks", wait_until="networkidle")
    for task_id in ids:
        row = source.locator("tbody tr").filter(has=source.locator('a[href*="id=' + task_id + '"]'))
        if row.count() != 1:
            row = source.locator("tbody tr").filter(has_text=f"Handoff fixture {ids.index(task_id) + 1} [{RUN}]")
        expect(row).to_have_count(1)
        row.get_by_role("checkbox").check()
    source.get_by_role("button", name="Handoff to Cairn", exact=True).click()
    expect(source.locator("#items li")).to_have_count(5)
    source.locator("#template").select_option("plan")
    source.locator("#human-input").fill("Summarize these five contexts. Do not launch workers.")
    source.locator("#template-name").fill("Evidence review")
    source.locator("#save-template").click()
    source.locator("#goal").fill("Temporary edit")
    source.locator("#template").select_option("custom")
    source.locator("#template").select_option("saved:Evidence review")
    expect(source.locator("#goal")).to_have_value("Prepare a human-reviewed plan from the selected context.")
    source.locator("#include-graph").uncheck()
    metadata = json.loads(source.locator("#preview").text_content())
    assert "graphs" not in metadata["items"][0]["data"]
    assert metadata["items"][0]["data"]["constraints"]
    source.locator("#include-graph").check()
    source.locator("#destination").fill(CAIRN)
    source.locator("#reviewed").check()
    preview = json.loads(source.locator("#preview").text_content())
    assert len(preview["items"]) == 5
    source.screenshot(path=str(OUT / "handoff-source-desktop.png"), full_page=True)
    source.set_viewport_size({"width": 390, "height": 844})
    assert source.evaluate("document.documentElement.scrollWidth <= innerWidth")
    source.screenshot(path=str(OUT / "handoff-source-mobile.png"), full_page=True)
    source.set_viewport_size({"width": 1360, "height": 1000})
    with source.expect_popup() as opened:
        source.locator("#send").click()
    receiver = opened.value
    receiver.wait_for_load_state("networkidle")
    receiver.evaluate("""(payload) => { const p = new URLSearchParams(location.search); for (const [origin, source] of [["http://untrusted.invalid", window.opener], [p.get("source"), window]]) window.dispatchEvent(new MessageEvent("message", {origin, source, data: {type: "handoff:data", channel: p.get("channel"), payload}})); }""", preview)
    expect(receiver.locator("#items li")).to_have_count(0)
    receiver.locator("#receive").click()
    expect(receiver.locator("#items li")).to_have_count(5)
    transferred = json.loads(receiver.locator("#preview").text_content())
    assert transferred["items"] == preview["items"]
    assert transferred["template"] == preview["template"]
    receiver.screenshot(path=str(OUT / "handoff-receiver-desktop.png"), full_page=True)
    receiver.locator("#reviewed").check()
    receiver.locator("#send").click()
    expect(receiver.locator("#result")).to_be_visible()
    pid = receiver.locator("#result").get_attribute("href").rsplit("/", 1)[-1]
    project = api(CAIRN, f"/projects/{pid}")
    assert project["project"]["status"] == "stopped"
    assert not project["project"]["bootstrap_enabled"]
    saved = json.loads(project["facts"][0]["description"].split("\n", 1)[1]) if project["facts"][0]["id"] == "origin" else json.loads(next(f["description"] for f in project["facts"] if f["id"] == "origin").split("\n", 1)[1])
    assert saved["items"] == preview["items"]
    duplicate = api(CAIRN, "/handoffs", transferred)
    assert duplicate["duplicate"] and duplicate["id"] == pid
    expect(source.locator("#status")).to_contain_text("Imported in Cairn")
    report["checks"].append("Native task selection → five-item popup transfer → stopped Cairn project; graph, asset, constraint and report snapshots preserved")
    report["checks"].append("Templates saved; mobile has no horizontal overflow; insecure-HTTP UUID fallback works")

    receiver.locator("#result").click()
    receiver.wait_for_load_state("networkidle")
    receiver.get_by_role("link", name="Handoff to ScopeWeaver", exact=True).click()
    expect(receiver.locator("#items li")).to_have_count(1)
    receiver.locator("#template").select_option("review")
    receiver.locator("#destination").fill(SCOPE)
    receiver.locator("#reviewed").check()
    with receiver.expect_popup() as returned:
        receiver.locator("#send").click()
    destination = returned.value
    destination.wait_for_load_state("networkidle")
    destination.locator("#receive").click()
    expect(destination.locator("#items li")).to_have_count(1)
    destination.locator("#reviewed").check()
    destination.locator("#send").click()
    expect(destination.locator("#result")).to_be_visible()
    tid = destination.locator("#result").get_attribute("href").rsplit("=", 1)[-1]
    assert api(SCOPE, f"/api/tasks/{tid}")["paused"] is True
    report["checks"].append("Native Cairn project → ScopeWeaver popup → paused task")

    offline = context.new_page()
    offline.goto(CAIRN + "/static/handoff.html?system=cairn")
    file_data = envelope("scopeweaver", 99)
    file_data["title"] = "<img src=x onerror=alert(1)>"
    file_data["items"][0]["data"]["project"]["title"] = file_data["title"]
    offline.locator("#file").set_input_files({"name": "handoff.json", "mimeType": "application/json", "buffer": json.dumps(file_data).encode()})
    expect(offline.locator("#items li")).to_have_count(1)
    assert "must-be-masked" not in offline.locator("#preview").text_content()
    assert "[masked]" in offline.locator("#preview").text_content()
    assert offline.locator("img").count() == 0
    report["checks"].append("Offline import, secret-field masking and text-only rendering verified")
    assert not [url for url in requests if any(action in url for action in ("/resume", "/start", "/bootstrap"))]
    assert not errors, errors
    report["checks"].append("No start/resume/bootstrap requests or browser errors")
    browser.close()

report["status"] = "PASS"
(OUT / "handoff-e2e.json").write_text(json.dumps(report, indent=2))
print(json.dumps(report, indent=2))
