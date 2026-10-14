"use client";

import { translate as swt } from "@/i18n/runtime";
import { useI18n } from "@/i18n";
import * as React from "react";
import { toast } from "sonner";
import { PlusIcon, RefreshCwIcon, ServerIcon, ShieldCheckIcon, Trash2Icon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Checkbox } from "@/components/ui/checkbox";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from "@/components/ui/sheet";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import type { MessageKey } from "@/i18n";
import type { MCPCatalogState, MCPCatalogStatus, MCPProviderKind, MCPServer, MCPTool, Agent } from "@/lib/types";

type Transport = "stdio" | "http" | "sse";
type FormState = {
  name: string;
  transport: Transport;
  command: string;
  args: string;
  url: string;
  env: string;
  insecure: boolean;
  providerKind: MCPProviderKind;
  sourceRevision: string;
};
const emptyForm: FormState = {
  name: "",
  transport: "stdio",
  command: "",
  args: "",
  url: "",
  env: "",
  insecure: false,
  providerKind: "",
  sourceRevision: "",
};

const catalogStatusKeys: Record<MCPCatalogState, MessageKey> = {
  not_configured: "interface.mcpCatalogStatusNotConfigured",
  disabled: "interface.mcpCatalogStatusDisabled",
  not_discovered: "interface.mcpCatalogStatusNotDiscovered",
  discovered: "interface.mcpCatalogStatusDiscovered",
  stale: "interface.mcpCatalogStatusStale",
  unavailable: "interface.mcpCatalogStatusUnavailable",
};

function parseProviderKind(value: string): MCPProviderKind {
  if (value === "yeepforge" || value === "adstrike") return value;

  return "";
}

export default function MCPPage() {
  "use no memo";
  const { t: swt, locale: swLocale, fmt } = useI18n();

  const [servers, setServers] = React.useState<MCPServer[]>([]);
  const [agents, setAgents] = React.useState<Agent[]>([]);
  const [visibility, setVisibility] = React.useState<Record<number, string[]>>({});

  const [open, setOpen] = React.useState(false);
  const [editing, setEditing] = React.useState<MCPServer | null>(null); // null = add mode
  const [tab, setTab] = React.useState<"config" | "tools">("config");
  const [form, setForm] = React.useState<FormState>(emptyForm);
  const [saving, setSaving] = React.useState(false);
  const [tools, setTools] = React.useState<MCPTool[]>([]);
  const [toolsLoading, setToolsLoading] = React.useState(false);
  const [refreshing, setRefreshing] = React.useState(false);
  // null until the stored value is known; absent setting means off.
  const [reportsEnabled, setReportsEnabled] = React.useState<boolean | null>(null);
  const [savingReports, setSavingReports] = React.useState(false);
  const current = editing ? (servers.find((s) => s.id === editing.id) ?? editing) : null;
  const tagged = form.providerKind !== "";

  const load = React.useCallback(() => {
    api
      .settings()
      .then((s) => setReportsEnabled(s.security_reports_enabled === true))
      .catch((e: Error) => toast.error(swt("interface.mcpSecurityReportsSaveFailed") + e.message));
    api.agents().then(setAgents).catch(() => {});
    api
      .mcpServers()
      .then((ss) => {
        setServers(ss);
        ss.forEach((s) =>
          api
            .resourceVisibility("mcp", s.id)
            .then((ids) => setVisibility((v) => ({ ...v, [s.id]: ids })))
            .catch(() => {}),
        );
      })
      .catch(() => {});
  }, [swt]);
  React.useEffect(() => {
    load();
  }, [load]);

  function setF(patch: Partial<FormState>) {
    setForm((f) => ({ ...f, ...patch }));
  }

  function parseEnv(text: string): Record<string, string> {
    const out: Record<string, string> = {};
    for (const line of text.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const idx = trimmed.indexOf("=");
      if (idx > 0) {
        const key = trimmed.slice(0, idx).trim();
        if (key) out[key] = trimmed.slice(idx + 1).trim();
      }
    }
    return out;
  }
  function envToText(env: Record<string, string> | undefined): string {
    return Object.entries(env ?? {})
      .map(([k, v]) => `${k}=${v}`)
      .join("\n");
  }

  function openAdd() {
    setEditing(null);
    setForm(emptyForm);
    setTools([]);
    setTab("config");
    setOpen(true);
  }

  function openEdit(s: MCPServer) {
    setEditing(s);
    setForm({
      name: s.name,
      transport: s.transport,
      command: s.command ?? "",
      args: (s.args ?? []).join(" "),
      url: s.url ?? "",
      env: envToText(s.env),
      insecure: s.insecure ?? false,
      providerKind: s.provider_kind ?? "",
      sourceRevision: s.source_revision ?? "",
    });
    setTab("config");
    setOpen(true);
    loadTools(s.id);
  }

  async function loadTools(id: number) {
    setToolsLoading(true);
    try {
      setTools(await api.mcpTools(id));
    } catch {
      setTools([]);
    } finally {
      setToolsLoading(false);
    }
  }

  async function saveForm() {
    if (!form.name.trim()) {
      toast.error(swt("interface.m1446"));
      return;
    }
    if (form.transport === "stdio" && !form.command.trim()) {
      toast.error(swt("interface.m1447"));
      return;
    }
    if (form.transport !== "stdio" && !form.url.trim()) {
      toast.error(swt("interface.m1448"));
      return;
    }
    setSaving(true);
    try {
      const base =
        form.transport !== "stdio"
          ? {
              transport: form.transport,
              url: form.url.trim(),
              command: "",
              args: [] as string[],
              env: parseEnv(form.env), // In remote mode, env represents request headers.
              insecure: form.insecure,
            }
          : {
              transport: "stdio" as const,
              command: form.command.trim(),
              args: form.args.trim() ? form.args.trim().split(/\s+/) : [],
              env: parseEnv(form.env),
              insecure: false,
            };
      // Kind is sent unchanged so the server matches identity; tagged rows start disabled.
      await api.saveMcpServer({
        ...(editing ? { id: editing.id } : {}),
        name: form.name.trim(),
        enabled: editing ? editing.enabled : !tagged,
        provider_kind: form.providerKind,
        source_revision: form.sourceRevision.trim(),
        ...base,
      });
      toast.success(editing ? swt("interface.m0377") : swt("interface.m1449"));
      if (!editing) setOpen(false);
      load();
    } catch (e) {
      toast.error(swt("interface.m1450") + (e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  async function refreshCatalog(id: number) {
    setRefreshing(true);

    try {
      const status = await api.refreshMcpCatalog(id);
      toast.success(swt("interface.mcpCatalogRefreshed", { count: status.cache?.tools.length ?? 0 }));
    } catch (e) {
      toast.error(swt("interface.mcpCatalogRefreshFailed") + (e instanceof Error ? e.message : ""));
    } finally {
      setRefreshing(false);
      load();
    }
  }

  async function toggleReports(next: boolean) {
    setSavingReports(true);

    try {
      const saved = await api.setSettings({ security_reports_enabled: next });
      setReportsEnabled(saved.security_reports_enabled === true);
      toast.success(swt("interface.mcpSecurityReportsSaved"));
    } catch (e) {
      toast.error(swt("interface.mcpSecurityReportsSaveFailed") + (e instanceof Error ? e.message : ""));
    } finally {
      setSavingReports(false);
    }
  }

  function setProviderKind(value: string) {
    const kind = parseProviderKind(value);
    setF(kind ? { providerKind: kind, transport: "stdio", insecure: false } : { providerKind: kind });
  }

  async function refreshTools() {
    if (!editing) return;

    if (editing.provider_kind) {
      await refreshCatalog(editing.id);

      return;
    }

    setRefreshing(true);
    try {
      const t = await api.refreshMcpServer(editing.id);
      setTools(t);
      toast.success(swt("interface.m1451", { p0: t.length }));
      load();
    } catch (e) {
      toast.error(swt("interface.m1452") + (e as Error).message);
    } finally {
      setRefreshing(false);
    }
  }

  async function removeServer(s: MCPServer) {
    try {
      await api.deleteMcpServer(s.id);
      toast.success(swt("interface.m1422", { p0: s.name }));
      setOpen(false);
      load();
    } catch (e) {
      toast.error(swt("interface.m0110") + (e as Error).message);
    }
  }

  async function toggleEnabled(s: MCPServer) {
    try {
      await api.saveMcpServer({ ...s, enabled: !s.enabled });
      load();
    } catch (e) {
      toast.error(swt("interface.m0801") + (e as Error).message);
    }
  }

  async function toggleVisibility(serverId: number, agentId: string, agentName: string) {
    const on = (visibility[serverId] ?? []).includes(agentId);
    try {
      await api.toggleVisibility(agentId, "mcp", serverId, !on);
      toast.success(swt("interface.m1453", { p0: on ? swt("interface.m0063") : swt("interface.m1454"), p1: agentName }));
      load();
    } catch (e) {
      toast.error(swt("interface.m0801") + (e as Error).message);
    }
  }

  function renderForm() {
    return (
      <div className="grid gap-4 py-4">
        <div className="grid gap-2">
          <Label htmlFor="m-provider-kind">{swt("interface.mcpProviderKind")}</Label>
          {editing ? (
            <Input
              id="m-provider-kind"
              className="font-mono"
              readOnly
              aria-describedby="m-provider-kind-hint"
              value={form.providerKind || swt("interface.mcpProviderKindGeneric")}
            />
          ) : (
            <NativeSelect
              id="m-provider-kind"
              className="w-full"
              aria-describedby="m-provider-kind-hint"
              value={form.providerKind}
              onChange={(e) => setProviderKind(e.target.value)}
            >
              <NativeSelectOption value="">{swt("interface.mcpProviderKindGeneric")}</NativeSelectOption>
              <NativeSelectOption value="yeepforge">YeepForge</NativeSelectOption>
              <NativeSelectOption value="adstrike">AdStrike</NativeSelectOption>
            </NativeSelect>
          )}
          <p id="m-provider-kind-hint" className="text-muted-foreground text-xs">
            {swt("interface.mcpProviderKindHint")}
          </p>
        </div>
        <div className="grid gap-2">
          <Label>{swt("interface.m1455")}</Label>
          <div className="flex flex-wrap gap-2">
            <Button
              type="button"
              variant={form.transport === "stdio" ? "default" : "outline"}
              onClick={() => setF({ transport: "stdio" })}
            >
              {swt("interface.m1456")}</Button>
            <Button
              type="button"
              variant={form.transport === "http" ? "default" : "outline"}
              disabled={tagged}
              onClick={() => setF({ transport: "http" })}
            >
              {swt("interface.m1457")}</Button>
            <Button
              type="button"
              variant={form.transport === "sse" ? "default" : "outline"}
              disabled={tagged}
              onClick={() => setF({ transport: "sse" })}
            >
              {swt("interface.m1458")}</Button>
          </div>
        </div>
        <div className="grid gap-2">
          <Label htmlFor="m-name">{swt("interface.m0868")}</Label>
          <Input
            id="m-name"
            placeholder="filesystem"
            value={form.name}
            onChange={(e) => setF({ name: e.target.value })}
          />
        </div>
        {form.transport === "stdio" ? (
          <>
            <div className="grid gap-2">
              <Label htmlFor="m-cmd">{swt("interface.m1459")}</Label>
              <Input
                id="m-cmd"
                className="font-mono"
                placeholder="npx"
                value={form.command}
                onChange={(e) => setF({ command: e.target.value })}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="m-args">{swt("interface.m1460")}</Label>
              <Input
                id="m-args"
                className="font-mono"
                placeholder="-y @modelcontextprotocol/server-filesystem /data"
                value={form.args}
                onChange={(e) => setF({ args: e.target.value })}
              />
            </div>
            {tagged && (
              <div className="grid gap-2">
                <Label htmlFor="m-source-revision">{swt("interface.mcpSourceRevision")}</Label>
                <Input
                  id="m-source-revision"
                  className="font-mono"
                  autoComplete="off"
                  spellCheck={false}
                  aria-describedby="m-source-revision-hint"
                  value={form.sourceRevision}
                  onChange={(e) => setF({ sourceRevision: e.target.value })}
                />
                <p id="m-source-revision-hint" className="text-muted-foreground text-xs">
                  {swt("interface.mcpSourceRevisionHint")}
                </p>
              </div>
            )}
          </>
        ) : (
          <div className="grid gap-2">
            <Label htmlFor="m-url">{swt("interface.m1461")}</Label>
            <Input
              id="m-url"
              className="font-mono"
              placeholder="https://mcp.example.com/mcp"
              value={form.url}
              onChange={(e) => setF({ url: e.target.value })}
            />
            <label className="flex items-center gap-2 text-sm">
              <Checkbox
                checked={form.insecure}
                onCheckedChange={(v) => setF({ insecure: v === true })}
              />
              {swt("interface.m1462")}</label>
          </div>
        )}
        <div className="grid gap-2">
          <Label htmlFor="m-env">
            {form.transport !== "stdio"
              ? swt("interface.m1463")
              : swt("interface.m1464")}
          </Label>
          <Textarea
            id="m-env"
            className="font-mono"
            placeholder={
              form.transport !== "stdio" ? "Authorization=Bearer xxxx" : "API_KEY=xxxx\nFOO=bar"
            }
            value={form.env}
            onChange={(e) => setF({ env: e.target.value })}
          />
        </div>
      </div>
    );
  }

  function renderTools() {
    return (
      <div className="flex flex-col gap-3 py-4">
        <div className="flex items-center justify-between">
          <span className="text-muted-foreground text-sm">{tools.length} {swt("interface.m0464")}</span>
          <Button size="sm" variant="outline" disabled={refreshing} onClick={refreshTools}>
            <RefreshCwIcon className={refreshing ? "animate-spin" : ""} /> {swt("interface.m0225")}</Button>
        </div>
        {toolsLoading ? (
          <p className="text-muted-foreground text-sm">{swt("interface.m0260")}</p>
        ) : tools.length === 0 ? (
          <p className="text-muted-foreground text-sm">{swt("interface.m1465")}</p>
        ) : (
          <div className="flex flex-col divide-y">
            {tools.map((t) => (
              <div key={t.name} className="py-2.5">
                <code className="font-mono text-sm">{t.name}</code>
                {t.description && (
                  <p className="text-muted-foreground mt-0.5 text-xs leading-relaxed">
                    {t.description}
                  </p>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    );
  }

  function catalogRow(label: string, value: React.ReactNode) {
    return (
      <div className="grid gap-0.5">
        <span className="text-muted-foreground text-xs">{label}</span>
        <span className="text-sm">{value}</span>
      </div>
    );
  }

  function renderCatalog(status: MCPCatalogStatus) {
    const names = status.cache ? status.cache.tools : [];

    return (
      <div className="flex flex-col gap-4 py-4">
        <div className="flex items-start justify-between gap-3">
          <p className="text-muted-foreground text-xs">{swt("interface.mcpCatalogRefreshHint")}</p>
          <Button size="sm" variant="outline" disabled={refreshing} onClick={refreshTools}>
            <RefreshCwIcon className={refreshing ? "animate-spin" : ""} /> {swt("interface.m0225")}</Button>
        </div>
        <div className="grid gap-3 rounded-lg border p-3" data-testid="mcp-catalog-status" data-status={status.status}>
          {catalogRow(
            swt("interface.mcpCatalogStatusLabel"),
            <Badge variant={status.status === "unavailable" ? "destructive" : "outline"}>
              {swt(catalogStatusKeys[status.status])}
            </Badge>,
          )}
          {catalogRow(swt("interface.mcpCatalogProvenance"), swt("interface.mcpCatalogProvenanceUnverified"))}
          {catalogRow(
            swt("interface.mcpCatalogExpectedRevision"),
            <code className="break-all font-mono text-xs">
              {status.expected_source_revision || swt("interface.mcpCatalogNotSet")}
            </code>,
          )}
          {catalogRow(
            swt("interface.mcpCatalogObservedRevision"),
            <code className="break-all font-mono text-xs">
              {status.cache?.observed_revision || swt("interface.mcpCatalogNotReported")}
            </code>,
          )}
          {catalogRow(
            swt("interface.mcpCatalogExecutableDigest"),
            <code className="break-all font-mono text-xs">
              {status.cache?.executable_sha256 || swt("interface.mcpCatalogNotMeasured")}
            </code>,
          )}
          {catalogRow(
            swt("interface.mcpCatalogDiscoveredAt"),
            status.cache ? fmt.dateTime(status.cache.discovered_at) : swt("interface.mcpCatalogNever"),
          )}
        </div>
        <div className="grid gap-2">
          <span className="font-medium text-sm">{swt("interface.mcpCatalogCachedNamesTitle")}</span>
          <p className="text-muted-foreground text-xs">{swt("interface.mcpCatalogNotCallable")}</p>
          {names.length === 0 ? (
            <p className="text-muted-foreground text-sm">{swt("interface.mcpCatalogEmpty")}</p>
          ) : (
            <div className="flex flex-wrap gap-2" data-testid="mcp-catalog-names">
              {names.map((t) => (
                <Badge key={t.name} variant="secondary" className="font-mono">
                  {t.name}
                </Badge>
              ))}
            </div>
          )}
        </div>
      </div>
    );
  }

  function renderCardSummary(s: MCPServer) {
    if (!s.catalog) {
      return (
        <p className="text-muted-foreground text-sm">
          {s.tools && s.tools.length > 0 ? swt("interface.m1468", { p0: s.tools.length }) : swt("interface.m1469")}
        </p>
      );
    }

    return (
      <div className="grid gap-1" data-catalog-status={s.catalog.status}>
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm">
            {swt("interface.mcpCatalogCardStatus", { status: swt(catalogStatusKeys[s.catalog.status]) })}
          </span>
          <Badge variant="secondary">{swt("interface.mcpCatalogOnly")}</Badge>
        </div>
        <span className="text-muted-foreground text-xs">{swt("interface.mcpCatalogEnabledMeaning")}</span>
      </div>
    );
  }

  function toolsTabLabel() {
    if (current?.catalog) return swt("interface.mcpCatalogTab");

    return `${swt("interface.m1474")} ${tools.length ? `（${tools.length}）` : ""}`;
  }

  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">MCP</h1>
        <p className="text-muted-foreground text-sm">{swt("interface.m1466")}</p>
      </div>

      <Card className="gap-3">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <ShieldCheckIcon className="size-4" />
            {swt("interface.mcpSecurityReportsTitle")}
          </CardTitle>
          <CardDescription id="security-reports-description">
            {swt("interface.mcpSecurityReportsDescription")}
            <br />
            {swt("interface.mcpSecurityReportsBoundary")}
          </CardDescription>
        </CardHeader>
        <CardContent className="flex items-center justify-between gap-4">
          <Label htmlFor="security-reports-enabled" className="font-normal text-muted-foreground text-sm">
            {reportsEnabled ? swt("interface.mcpSecurityReportsOn") : swt("interface.mcpSecurityReportsOff")}
          </Label>
          <Switch
            id="security-reports-enabled"
            aria-describedby="security-reports-description"
            checked={reportsEnabled === true}
            disabled={reportsEnabled === null || savingReports}
            onCheckedChange={toggleReports}
          />
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <button
          type="button"
          onClick={openAdd}
          className="text-foreground/70 border-foreground/70 hover:bg-muted/60 hover:shadow-sm flex min-h-[116px] flex-col items-center justify-center gap-2 rounded-xl border border-dashed transition"
        >
          <PlusIcon className="size-6" />
          <span className="text-sm">{swt("interface.m1467")}</span>
        </button>

        {servers.map((s) => (
          <Card
            key={s.id}
            data-provider-kind={s.provider_kind || undefined}
            onClick={() => openEdit(s)}
            className="hover:border-primary/60 cursor-pointer gap-3 transition hover:shadow-sm"
          >
            <CardHeader>
              <div className="flex min-w-0 items-center gap-2">
                <ServerIcon className="text-muted-foreground size-4 shrink-0" />
                <CardTitle className="truncate text-base">{s.name}</CardTitle>
                <Badge variant="outline" className="uppercase">
                  {s.transport}
                </Badge>
                <div className="ml-auto flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
                  <Switch
                    checked={s.enabled}
                    onCheckedChange={() => toggleEnabled(s)}
                    aria-label={swt("interface.m1174")}
                  />
                  <Button
                    size="icon"
                    variant="outline"
                    aria-label={swt("interface.m0101")}
                    onClick={() => removeServer(s)}
                  >
                    <Trash2Icon className="text-destructive" />
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent className="grid gap-3">
              {renderCardSummary(s)}
              <div className="grid gap-2" onClick={(e) => e.stopPropagation()}>
                <span className="text-muted-foreground text-xs">{swt("interface.m1470")}</span>
                <div className="flex flex-wrap gap-x-4 gap-y-2">
                  {agents.map((a) => (
                    <label key={a.key} className="flex items-center gap-2 text-sm">
                      <Checkbox
                        checked={(visibility[s.id] ?? []).includes(a.id)}
                        onCheckedChange={() => toggleVisibility(s.id, a.id, a.name)}
                      />
                      {a.name}
                    </label>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent
          side="right"
          className="w-full data-[side=right]:sm:max-w-lg"
        >
          <SheetHeader>
            <SheetTitle>{editing ? editing.name : swt("interface.m1471")}</SheetTitle>
            <SheetDescription>
              {swt("interface.m1472")}</SheetDescription>
          </SheetHeader>

          {editing ? (
            <Tabs
              value={tab}
              onValueChange={(v) => setTab(v as "config" | "tools")}
              className="flex min-h-0 flex-1 flex-col px-4"
            >
              <TabsList>
                <TabsTrigger value="config">{swt("interface.m1473")}</TabsTrigger>
                <TabsTrigger value="tools">{toolsTabLabel()}</TabsTrigger>
              </TabsList>
              <TabsContent value="config" className="-mx-4 min-h-0 flex-1 overflow-y-auto px-4">
                {renderForm()}
                <div className="flex flex-col items-start gap-2 pt-2 pb-6">
                  <Button data-testid="mcp-save" onClick={saveForm} disabled={saving}>
                    {swt("interface.m0273")}</Button>
                  {tagged && <p className="text-muted-foreground text-xs">{swt("interface.mcpCatalogSaveNote")}</p>}
                </div>
              </TabsContent>
              <TabsContent value="tools" className="min-h-0 flex-1 overflow-y-auto">
                {current?.catalog ? renderCatalog(current.catalog) : renderTools()}
              </TabsContent>
            </Tabs>
          ) : (
            <div className="flex min-h-0 flex-1 flex-col overflow-y-auto px-4">
              {renderForm()}
              <div className="flex flex-col items-start gap-2 pt-2 pb-6">
                <Button data-testid="mcp-save" onClick={saveForm} disabled={saving}>
                  <PlusIcon /> {swt("interface.m0611")}</Button>
                {tagged && <p className="text-muted-foreground text-xs">{swt("interface.mcpCatalogSaveNote")}</p>}
              </div>
            </div>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}
