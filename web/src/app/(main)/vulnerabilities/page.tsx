"use client";

import { useEffect, useState } from "react";
import { AlertTriangle, Bell, Download, Loader2, Plus, RefreshCw, ShieldCheck } from "lucide-react";
import { useI18n } from "@/i18n";
import { http } from "@/lib/api";

type Component = { ecosystem: string; name: string; version: string };
type Inventory = { packages: Component[]; source: string; warnings: string[] };
type Project = {
  id: string;
  name: string;
  inventory: Inventory;
  inventory_hash: string;
  daily: boolean;
  approved_at: string;
};
type Summary = {
  id: string;
  status: string;
  inventory_hash: string;
  created_at: string;
  findings: number;
  changes: { new: number; changed: number; no_longer_observed: number };
};
type Finding = {
  key: string;
  id: string;
  package: Component;
  title: string;
  evidence: string;
  cvss: number | null;
  known_exploited: boolean;
  fixed_versions: string[];
  references: string[];
  url: string;
};
type Run = Omit<Summary, "findings"> & {
  findings: Finding[];
  decisions: Decision[];
  inventory: Inventory;
  checked: number;
  error: string;
  warnings: string[];
  attribution: string;
  coverage: string;
};
type Decision = {
  id: string;
  finding_key: string;
  package_version: string;
  inventory_hash: string;
  status: string;
  reason: string;
};
type Detail = { project: Project; runs: Summary[]; decisions: Decision[]; last_successful: Run | null };
type Entry = { project: Project; latest: Summary | null; unread: boolean };
type Preview = { inventory: Inventory; inventory_hash: string; input: Record<string, unknown> };
const button =
  "inline-flex min-h-10 items-center justify-center gap-2 rounded-md border border-border px-3 text-sm hover:bg-muted disabled:cursor-not-allowed disabled:opacity-50";
const input =
  "w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";
const root = "/vulnerability-review";
const pending = (status?: string) => status === "running" || status === "queued";

function ReviewDecision({
  finding,
  decision,
  disabled,
  save,
}: {
  finding: Finding;
  decision?: Decision;
  disabled: boolean;
  save: (status: string, reason: string) => Promise<void>;
}) {
  const { t } = useI18n();
  const [status, setStatus] = useState("open");
  const [reason, setReason] = useState("");
  const labels = {
    open: t("vulnerability.open"),
    accepted_risk: t("vulnerability.acceptedRisk"),
    resolved: t("vulnerability.resolved"),
    dismissed: t("vulnerability.dismissed"),
  };
  return (
    <article className="border-border border-b py-5">
      <div className="flex flex-wrap justify-between gap-3">
        <div>
          <a className="font-mono text-sm underline" href={finding.url} target="_blank" rel="noopener noreferrer">
            {finding.id}
          </a>
          <h3 className="mt-2 font-semibold">{finding.title}</h3>
          <p className="mt-1 break-all font-mono text-muted-foreground text-xs">
            {finding.package.ecosystem} / {finding.package.name} @ {finding.package.version}
          </p>
        </div>
        <span className="text-sm">
          CVSS {finding.cvss ?? t("common.unknown")}
          {finding.known_exploited && (
            <strong className="mt-1 block text-destructive">{t("vulnerability.knownExploited")}</strong>
          )}
        </span>
      </div>
      <p className="mt-3 text-muted-foreground text-sm">{finding.evidence}</p>
      {finding.fixed_versions.length > 0 && (
        <p className="mt-2 text-sm">
          {t("vulnerability.fixes")}: {finding.fixed_versions.join(", ")}
        </p>
      )}
      {decision && (
        <p className="mt-3 rounded-md bg-muted p-3 text-sm">
          {t("vulnerability.decision")}: {labels[decision.status as keyof typeof labels] ?? decision.status}.{" "}
          {decision.reason}
        </p>
      )}
      <details className="mt-3">
        <summary className="cursor-pointer font-medium text-sm">{t("vulnerability.evidence")}</summary>
        <div className="mt-3 space-y-3">
          <ul className="space-y-2">
            {finding.references.slice(0, 15).map((url) => (
              <li key={url}>
                <a className="break-all text-xs underline" href={url} target="_blank" rel="noopener noreferrer">
                  {url}
                </a>
              </li>
            ))}
          </ul>
          <form
            className="grid gap-3"
            onSubmit={(event) => {
              event.preventDefault();
              void save(status, reason);
            }}
          >
            <label className="grid gap-2 text-sm">
              {t("vulnerability.decision")}
              <select
                aria-label={t("vulnerability.decision")}
                className={input}
                value={status}
                onChange={(event) => setStatus(event.target.value)}
                disabled={disabled}
              >
                {Object.entries(labels).map(([value, text]) => (
                  <option key={value} value={value}>
                    {text}
                  </option>
                ))}
              </select>
            </label>
            <label className="grid gap-2 text-sm">
              {t("vulnerability.reason")}
              <textarea
                className={input}
                rows={3}
                minLength={3}
                maxLength={2000}
                required
                value={reason}
                onChange={(event) => setReason(event.target.value)}
                disabled={disabled}
              />
            </label>
            <button type="submit" className={button} disabled={disabled || reason.trim().length < 3}>
              {t("common.save")}
            </button>
          </form>
        </div>
      </details>
    </article>
  );
}

export default function VulnerabilitiesPage() {
  const { t, locale } = useI18n();
  const [entries, setEntries] = useState<Entry[]>([]);
  const [selected, setSelected] = useState("");
  const [runID, setRunID] = useState("");
  const [detail, setDetail] = useState<Detail | null>(null);
  const [run, setRun] = useState<Run | null>(null);
  const [tick, setTick] = useState(0);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [form, setForm] = useState<"new" | "replace" | null>(null);
  const [name, setName] = useState("");
  const [raw, setRaw] = useState("");
  const [lockfile, setLockfile] = useState("");
  const [preview, setPreview] = useState<Preview | null>(null);
  const [approved, setApproved] = useState(false);
  const [daily, setDaily] = useState(false);
  const [query, setQuery] = useState("");
  const refresh = () => setTick((value) => value + 1);
  const timestamp = (value: string) => new Date(value).toLocaleString(locale);
  const statusLabel = (value: string) =>
    ({
      queued: t("vulnerability.queued"),
      running: t("vulnerability.running"),
      succeeded: t("vulnerability.succeeded"),
      partial: t("vulnerability.partial"),
      failed: t("vulnerability.failed"),
      cancelled: t("vulnerability.cancelled"),
    })[value] ?? value;
  useEffect(() => {
    let live = true;
    void (async () => {
      try {
        const list = await http<Entry[]>(`${root}/projects?refresh=${tick}`);
        if (!live) return;
        setEntries(list);
        if (!selected) {
          setSelected(list[0]?.project.id ?? "");
          return;
        }
        const next = await http<Detail>(`${root}/projects/${selected}`);
        const id = runID || next.runs[0]?.id;
        const report = id ? await http<Run>(`${root}/projects/${selected}/runs/${id}`) : null;
        if (live) {
          setDetail(next);
          setRun(report);
        }
      } catch (cause) {
        if (live) setError(cause instanceof Error ? cause.message : t("common.failedToLoad"));
      } finally {
        if (live) setLoading(false);
      }
    })();
    return () => {
      live = false;
    };
  }, [selected, runID, tick, t]);
  const latest = detail?.runs[0]?.status;
  useEffect(() => {
    const timer = window.setInterval(() => setTick((value) => value + 1), pending(latest) ? 2500 : 30000);
    return () => window.clearInterval(timer);
  }, [latest]);
  async function perform(action: () => Promise<void>) {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await action();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : t("common.failed"));
    } finally {
      setBusy(false);
    }
  }
  function invalidate() {
    setPreview(null);
    setApproved(false);
  }
  function openForm(mode: "new" | "replace") {
    setForm(mode);
    setName(mode === "replace" ? (detail?.project.name ?? "") : "");
    setRaw("");
    setLockfile("");
    setDaily(mode === "replace" ? (detail?.project.daily ?? false) : false);
    invalidate();
  }
  async function previewInput() {
    await perform(async () => {
      let source: Record<string, unknown>;
      if (lockfile) source = { lockfile_content: lockfile };
      else {
        let packages: unknown;
        try {
          packages = JSON.parse(raw);
        } catch {
          throw new Error(t("vulnerability.parseError"));
        }
        if (!Array.isArray(packages)) throw new Error(t("vulnerability.parseError"));
        source = { packages };
      }
      const value = await http<Omit<Preview, "input">>(`${root}/inventory/preview`, {
        method: "POST",
        body: JSON.stringify(source),
      });
      setPreview({ ...value, input: source });
      setApproved(false);
    });
  }
  async function saveInventory() {
    if (!preview || !approved) return;
    await perform(async () => {
      const project = await http<Project>(form === "replace" ? `${root}/projects/${selected}` : `${root}/projects`, {
        method: form === "replace" ? "PATCH" : "POST",
        body: JSON.stringify({
          ...preview.input,
          name,
          daily,
          approve_external_lookup: true,
          expected_inventory_hash: preview.inventory_hash,
        }),
      });
      setSelected(project.id);
      setRunID("");
      setDetail(null);
      setRun(null);
      setForm(null);
      refresh();
      const queued = await http<Run>(`${root}/projects/${project.id}/runs`, { method: "POST" });
      setRunID(queued.id);
      refresh();
    });
  }
  function exportRun() {
    if (!run) return;
    const url = URL.createObjectURL(
      new Blob([JSON.stringify({ report: run, decisions: run.decisions }, null, 2)], { type: "application/json" }),
    );
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `dependency-review-${run.id}.json`;
    anchor.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  const current = detail?.project;
  const stale = Boolean(run && current && run.inventory_hash !== current.inventory_hash);
  const canReview = Boolean(run && !stale && (run.status === "succeeded" || run.status === "partial"));
  return (
    <div className="mx-auto w-full max-w-7xl space-y-6 p-4 sm:p-6">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <ShieldCheck className="size-6" />
            <h1 className="font-semibold text-2xl tracking-tight">{t("vulnerability.title")}</h1>
          </div>
          <p className="mt-2 max-w-2xl text-muted-foreground text-sm">{t("vulnerability.subtitle")}</p>
        </div>
        <button type="button" className={button} disabled={busy} onClick={() => openForm("new")}>
          <Plus className="size-4" />
          {t("vulnerability.newInventory")}
        </button>
      </header>
      <div className="flex gap-3 rounded-lg border border-border bg-muted/30 p-4 text-sm">
        <AlertTriangle className="mt-0.5 size-4 shrink-0" />
        <p>{t("vulnerability.coverage")}</p>
      </div>
      {error && (
        <div
          role="alert"
          className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-destructive/30 p-4 text-destructive text-sm"
        >
          <p>{error}</p>
          <button type="button" className={button} onClick={refresh}>
            {t("common.retry")}
          </button>
        </div>
      )}
      {notice && (
        <p role="status" className="rounded-md bg-muted p-3 text-sm">
          {notice}
        </p>
      )}
      {form && (
        <section className="space-y-4 rounded-lg border border-border p-4">
          <div className="flex items-center justify-between">
            <h2 className="font-semibold">
              {t(form === "new" ? "vulnerability.newInventory" : "vulnerability.replace")}
            </h2>
            <button type="button" className={button} disabled={busy} onClick={() => setForm(null)}>
              {t("common.close")}
            </button>
          </div>
          <label className="grid gap-2 text-sm">
            {t("common.name")}
            <input
              className={input}
              value={name}
              maxLength={120}
              onChange={(event) => setName(event.target.value)}
              disabled={busy}
            />
          </label>
          <label className="grid gap-2 text-sm">
            {t("vulnerability.exactPackages")}
            <textarea
              className={`${input} font-mono text-xs`}
              rows={7}
              value={raw}
              onChange={(event) => {
                setRaw(event.target.value);
                setLockfile("");
                invalidate();
              }}
              disabled={busy || Boolean(lockfile)}
            />
          </label>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              className={button}
              disabled={busy || Boolean(lockfile)}
              onClick={() => {
                setRaw(JSON.stringify([{ ecosystem: "npm", name: "lodash", version: "4.17.20" }], null, 2));
                invalidate();
              }}
            >
              {t("vulnerability.publicExample")}
            </button>
            {lockfile && (
              <button
                type="button"
                className={button}
                disabled={busy}
                onClick={() => {
                  setLockfile("");
                  invalidate();
                }}
              >
                {t("common.close")}
              </button>
            )}
          </div>
          <label className="grid gap-2 text-sm">
            {t("vulnerability.lockfile")}
            <input
              key={form + selected}
              type="file"
              accept=".json,application/json"
              disabled={busy}
              onChange={(event) => {
                const chosen = event.target.files?.[0];
                if (!chosen) return;
                if (chosen.size > 1024 * 1024) {
                  setError(t("vulnerability.sizeError"));
                  return;
                }
                void chosen
                  .text()
                  .then((text) => {
                    setLockfile(text);
                    invalidate();
                  })
                  .catch(() => setError(t("vulnerability.readError")));
              }}
            />
          </label>
          <p className="text-muted-foreground text-xs">{t("vulnerability.lockHint")}</p>
          <button
            type="button"
            className={button}
            onClick={() => void previewInput()}
            disabled={busy || (!raw && !lockfile)}
          >
            {t("vulnerability.preview")}
          </button>
          {preview && (
            <div className="space-y-4 border-border border-t pt-4">
              <h3 className="font-medium">{t("vulnerability.disclosure")}</h3>
              {preview.inventory.warnings.map((warning) => (
                <p key={warning} className="text-destructive text-sm">
                  {warning}
                </p>
              ))}
              <pre className="max-h-64 overflow-auto rounded-md bg-muted p-3 text-xs">
                {JSON.stringify(preview.inventory.packages, null, 2)}
              </pre>
              <label className="flex items-start gap-3 text-sm">
                <input
                  type="checkbox"
                  checked={approved}
                  onChange={(event) => setApproved(event.target.checked)}
                  disabled={busy}
                  className="mt-1 size-4 shrink-0"
                />
                <span>{t("vulnerability.consent")}</span>
              </label>
              <label className="flex items-start gap-3 text-sm">
                <input
                  type="checkbox"
                  checked={daily}
                  onChange={(event) => setDaily(event.target.checked)}
                  disabled={busy}
                  className="mt-1 size-4 shrink-0"
                />
                <span>{t("vulnerability.daily")}</span>
              </label>
              <button
                type="button"
                className={button}
                disabled={busy || !approved || !name.trim()}
                onClick={() => void saveInventory()}
              >
                {busy && <Loader2 className="size-4 animate-spin" />}
                {t("vulnerability.saveReview")}
              </button>
            </div>
          )}
        </section>
      )}
      {loading && (
        <p role="status" className="flex items-center gap-2 text-sm">
          <Loader2 className="size-4 animate-spin" />
          {t("common.loading")}
        </p>
      )}
      {!loading && entries.length === 0 && !error && (
        <p className="rounded-lg border border-border border-dashed p-8 text-muted-foreground text-sm">
          {t("vulnerability.empty")}
        </p>
      )}
      {entries.length > 0 && (
        <div className="grid grid-cols-1 items-start gap-6 lg:grid-cols-[220px_minmax(0,1fr)]">
          <label className="grid gap-2 text-sm lg:hidden">
            {t("vulnerability.inventories")}
            <select
              aria-label={t("vulnerability.inventories")}
              className={input}
              value={selected}
              disabled={busy}
              onChange={(event) => {
                if (event.target.value === selected) {
                  refresh();
                  return;
                }
                setSelected(event.target.value);
                setRunID("");
                setDetail(null);
                setRun(null);
                setForm(null);
              }}
            >
              {entries.map((entry) => (
                <option key={entry.project.id} value={entry.project.id}>
                  {entry.project.name}
                  {entry.unread ? ` · ${t("vulnerability.unread")}` : ""}
                </option>
              ))}
            </select>
          </label>
          <aside className="hidden max-h-[70vh] min-w-0 space-y-2 overflow-y-auto pr-1 lg:block">
            <h2 className="font-medium text-muted-foreground text-xs uppercase tracking-wide">
              {t("vulnerability.inventories")}
            </h2>
            {entries.map((entry) => (
              <button
                type="button"
                key={entry.project.id}
                disabled={busy}
                className={`w-full rounded-lg border p-3 text-left hover:bg-muted ${selected === entry.project.id ? "border-primary bg-muted" : "border-transparent"}`}
                onClick={() => {
                  if (entry.project.id === selected) {
                    refresh();
                    return;
                  }
                  setSelected(entry.project.id);
                  setRunID("");
                  setDetail(null);
                  setRun(null);
                  setForm(null);
                }}
              >
                <span className="flex items-center justify-between gap-2">
                  <span className="truncate font-medium text-sm">{entry.project.name}</span>
                  {entry.unread && <Bell className="size-3.5 shrink-0" aria-label={t("vulnerability.unread")} />}
                </span>
                <span className="mt-1 block text-muted-foreground text-xs">
                  {entry.project.inventory.packages.length} ·{" "}
                  {entry.latest ? statusLabel(entry.latest.status) : t("common.none")}
                </span>
              </button>
            ))}
          </aside>
          {detail && (
            <section className="min-w-0 space-y-5">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <h2 className="break-words font-semibold text-xl">{current?.name}</h2>
                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    className={button}
                    disabled={busy || pending(latest)}
                    onClick={() =>
                      void perform(async () => {
                        const next = await http<Run>(`${root}/projects/${selected}/runs`, { method: "POST" });
                        setRunID(next.id);
                        refresh();
                      })
                    }
                  >
                    <RefreshCw className={`size-4 ${pending(latest) ? "animate-spin" : ""}`} />
                    {t("vulnerability.reviewNow")}
                  </button>
                  <button
                    type="button"
                    className={button}
                    disabled={busy}
                    onClick={() =>
                      void perform(async () => {
                        await http(`${root}/projects/${selected}/acknowledge`, { method: "POST" });
                        refresh();
                      })
                    }
                  >
                    {t("vulnerability.markRead")}
                  </button>
                </div>
              </div>
              <details className="rounded-lg border border-border p-4">
                <summary className="cursor-pointer font-medium text-sm">{t("vulnerability.inventory")}</summary>
                <div className="mt-4 space-y-3">
                  <p className="text-muted-foreground text-xs">
                    {t("vulnerability.approved")}: {current && timestamp(current.approved_at)}
                  </p>
                  <p className="break-all font-mono text-xs">
                    {t("vulnerability.snapshot")}: {current?.inventory_hash}
                  </p>
                  <p className="text-muted-foreground text-xs">{t("vulnerability.daily")}</p>
                  <div className="flex flex-wrap gap-2">
                    <button type="button" className={button} disabled={busy} onClick={() => openForm("replace")}>
                      {t("vulnerability.replace")}
                    </button>
                    <button
                      type="button"
                      className={button}
                      disabled={busy}
                      onClick={() =>
                        void perform(async () => {
                          await http(`${root}/projects/${selected}`, {
                            method: "PATCH",
                            body: JSON.stringify({ daily: !current?.daily }),
                          });
                          refresh();
                        })
                      }
                    >
                      {t(current?.daily ? "vulnerability.disableDaily" : "vulnerability.enableDaily")}
                    </button>
                  </div>
                  {current?.inventory.warnings.map((warning) => (
                    <p key={warning} className="text-sm">
                      {warning}
                    </p>
                  ))}
                  <pre className="max-h-64 overflow-auto bg-muted p-3 text-xs">
                    {JSON.stringify(current?.inventory.packages, null, 2)}
                  </pre>
                </div>
              </details>
              <details className="rounded-lg border border-border p-4">
                <summary className="cursor-pointer font-medium text-sm">{t("vulnerability.history")}</summary>
                <div className="mt-3 divide-y divide-border">
                  {detail.runs.map((item) => (
                    <button
                      type="button"
                      key={item.id}
                      disabled={busy}
                      className="block w-full py-3 text-left hover:bg-muted"
                      onClick={() => setRunID(item.id)}
                    >
                      <span className="block text-sm">
                        {timestamp(item.created_at)} · {statusLabel(item.status)}
                      </span>
                      <span className="mt-1 block text-muted-foreground text-xs">
                        {t("vulnerability.changes", {
                          new: item.changes.new,
                          changed: item.changes.changed,
                          missing: item.changes.no_longer_observed,
                        })}
                      </span>
                    </button>
                  ))}
                </div>
              </details>
              {!run && <p className="py-6 text-muted-foreground text-sm">{t("vulnerability.noRun")}</p>}
              {run && (
                <>
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <p className="text-sm">
                      {statusLabel(run.status)} · {timestamp(run.created_at)}
                    </p>
                    <div className="flex gap-2">
                      {pending(run.status) && (
                        <button
                          type="button"
                          className={button}
                          disabled={busy}
                          onClick={() =>
                            void perform(async () => {
                              await http(`${root}/projects/${selected}/runs/${run.id}/cancel`, { method: "POST" });
                              refresh();
                            })
                          }
                        >
                          {t("common.cancel")}
                        </button>
                      )}
                      <button type="button" className={button} onClick={exportRun}>
                        <Download className="size-4" />
                        JSON
                      </button>
                    </div>
                  </div>
                  {stale && (
                    <p className="rounded-md border border-destructive/30 p-3 text-sm">{t("vulnerability.older")}</p>
                  )}
                  {run.error && (
                    <p role="alert" className="text-destructive text-sm">
                      {run.error}
                    </p>
                  )}
                  {run.warnings.map((warning) => (
                    <p key={warning} className="text-muted-foreground text-sm">
                      {warning}
                    </p>
                  ))}
                  {["failed", "partial"].includes(run.status) &&
                    detail.last_successful &&
                    detail.last_successful.id !== run.id && (
                      <button
                        type="button"
                        className={button}
                        disabled={busy}
                        onClick={() => setRunID(detail.last_successful?.id ?? "")}
                      >
                        {t("vulnerability.previous")}
                      </button>
                    )}
                  <div className="grid grid-cols-3 gap-3 border-border border-y py-4">
                    {[
                      { label: t("vulnerability.checked"), value: `${run.checked}/${run.inventory.packages.length}` },
                      { label: t("vulnerability.matchCount"), value: run.findings.length },
                      {
                        label: t("vulnerability.knownExploited"),
                        value: run.findings.filter((finding) => finding.known_exploited).length,
                      },
                    ].map((item) => (
                      <div key={item.label}>
                        <p className="font-semibold text-2xl tabular-nums">{item.value}</p>
                        <p className="mt-1 text-muted-foreground text-xs">{item.label}</p>
                      </div>
                    ))}
                  </div>
                  {run.status === "succeeded" && run.findings.length === 0 && (
                    <p className="rounded-md bg-muted p-4 text-sm">{t("vulnerability.noFindings")}</p>
                  )}
                  {run.findings.length > 0 && (
                    <label className="grid gap-2 text-sm">
                      {t("common.search")}
                      <input className={input} value={query} onChange={(event) => setQuery(event.target.value)} />
                    </label>
                  )}
                  <div>
                    {run.findings
                      .filter((finding) =>
                        `${finding.id} ${finding.title} ${finding.package.name}`
                          .toLowerCase()
                          .includes(query.toLowerCase()),
                      )
                      .map((finding) => (
                        <ReviewDecision
                          key={`${run.id}/${finding.key}/${finding.package.version}`}
                          finding={finding}
                          decision={run.decisions.find(
                            (decision) =>
                              decision.finding_key === finding.key &&
                              decision.package_version === finding.package.version &&
                              decision.inventory_hash === run.inventory_hash,
                          )}
                          disabled={busy || !canReview}
                          save={async (status, reason) => {
                            await perform(async () => {
                              await http(`${root}/projects/${selected}/findings/${finding.key}`, {
                                method: "PUT",
                                body: JSON.stringify({ run_id: run.id, status, reason }),
                              });
                              refresh();
                              setNotice(t("vulnerability.decisionSaved"));
                            });
                          }}
                        />
                      ))}
                  </div>
                  <p className="text-muted-foreground text-xs">{t("vulnerability.unknownMatch")}</p>
                </>
              )}
            </section>
          )}
        </div>
      )}
      <footer className="space-y-2 border-border border-t pt-4 text-muted-foreground text-xs">
        <p>
          <a className="underline" href="https://cve.now/llms.txt" target="_blank" rel="noopener noreferrer">
            {t("vulnerability.attribution")}
          </a>
        </p>
        <p>{t("vulnerability.sharedAdmin")}</p>
      </footer>
    </div>
  );
}
