"use client";

import * as React from "react";

import { InfoIcon, ShieldCheckIcon, UploadIcon } from "lucide-react";
import { toast } from "sonner";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import type { MessageKey } from "@/i18n";
import { useI18n } from "@/i18n";
import { api } from "@/lib/api";
import type { AssessmentCompleteness, AssessmentProducer, AssessmentReportSummary } from "@/lib/types";

// Matches the server's total request limit; larger files are never sent.
const MAX_REPORT_BYTES = 1 << 20;

const PRODUCERS: readonly { value: AssessmentProducer; name: string }[] = [
  { value: "yeepforge", name: "YeepForge" },
  { value: "adstrike", name: "AdStrike" },
  { value: "confirmesc", name: "confirmesc" },
];

const COMPLETENESS: Record<AssessmentCompleteness, { label: MessageKey; guidance: MessageKey }> = {
  unknown: { label: "interface.assessmentCompletenessUnknown", guidance: "interface.assessmentGuidanceUnknown" },
  has_errors: { label: "interface.assessmentCompletenessHasErrors", guidance: "interface.assessmentGuidanceHasErrors" },
  no_observations: {
    label: "interface.assessmentCompletenessNoObservations",
    guidance: "interface.assessmentGuidanceNoObservations",
  },
};

function producerName(producer: AssessmentProducer): string {
  return PRODUCERS.find((p) => p.value === producer)?.name ?? producer;
}

function Detail({ label, value, title }: { label: string; value: string; title?: string }) {
  return (
    <div className="min-w-0">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="break-all font-mono" title={title}>
        {value}
      </dd>
    </div>
  );
}

function HistoryEntry({ report }: { report: AssessmentReportSummary }) {
  const { t: swt, fmt } = useI18n();
  const completeness = COMPLETENESS[report.completeness];

  return (
    <li
      className="flex flex-col gap-3 rounded-lg border p-3"
      data-testid="assessment-history-entry"
      data-assessment-id={report.assessment_id}
      data-producer={report.producer}
    >
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium text-sm">{producerName(report.producer)}</span>
        <Badge variant="outline">{swt("interface.assessmentProducerReported")}</Badge>
        <Badge
          variant={report.completeness === "has_errors" ? "destructive" : "secondary"}
          data-completeness={report.completeness}
        >
          {swt(completeness.label)}
        </Badge>
        <span className="ml-auto text-muted-foreground text-xs">{fmt.dateTime(report.imported_at)}</span>
      </div>
      <p className="text-sm">
        {swt("interface.assessmentObservations", { count: report.observation_count })}
        {" · "}
        {swt("interface.assessmentExportErrors", { count: report.error_count })}
      </p>
      <div className="flex flex-col gap-1 text-muted-foreground text-xs">
        <p>{swt("interface.assessmentNotConfirmed")}</p>
        <p>{swt(completeness.guidance)}</p>
      </div>
      <dl className="grid gap-x-4 gap-y-2 text-xs sm:grid-cols-2">
        <Detail label={swt("interface.assessmentProfile")} value={report.parser_profile} />
        <Detail label={swt("interface.assessmentParserVersion")} value={String(report.parser_version)} />
        <Detail label={swt("interface.assessmentSourceRevision")} value={report.parser_source_revision} />
        <Detail
          label={swt("interface.assessmentProvenance")}
          value={swt("interface.assessmentUnverified")}
          title={swt("interface.assessmentUnverifiedHint")}
        />
        <Detail label={swt("interface.assessmentOriginalDigest")} value={report.original_sha256} />
        <Detail label={swt("interface.assessmentSanitizedDigest")} value={report.sanitized_sha256} />
        <Detail
          label={swt("interface.assessmentObservedAt")}
          value={report.observed_at ? fmt.dateTime(report.observed_at) : swt("interface.assessmentNotReported")}
        />
        {report.recommended_skill && (
          <Detail
            label={swt("interface.assessmentLibrarySkill")}
            value={report.recommended_skill}
            title={swt("interface.assessmentLibrarySkillHint")}
          />
        )}
      </dl>
      <p className="text-muted-foreground text-xs">{swt("interface.assessmentUnverifiedHint")}</p>
    </li>
  );
}

export function AssessmentReportImport({ taskId }: { taskId: string }) {
  const { t: swt } = useI18n();
  const fileRef = React.useRef<HTMLInputElement>(null);

  const [enabled, setEnabled] = React.useState<boolean | null>(null);
  const [producer, setProducer] = React.useState<AssessmentProducer>("yeepforge");
  const [hasFile, setHasFile] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState("");

  const [reports, setReports] = React.useState<readonly AssessmentReportSummary[]>([]);
  const [nextBefore, setNextBefore] = React.useState(0);
  const [historyLoading, setHistoryLoading] = React.useState(true);
  const [historyError, setHistoryError] = React.useState("");

  const loadHistory = React.useCallback(
    async (before?: number) => {
      setHistoryLoading(true);

      try {
        const page = await api.assessmentReports(taskId, before);
        setReports((current) => (before === undefined ? page.reports : [...current, ...page.reports]));
        setNextBefore(page.has_more ? page.next_before : 0);
        setHistoryError("");
      } catch (err) {
        setHistoryError(swt("interface.assessmentHistoryLoadFailed") + (err instanceof Error ? err.message : ""));
      } finally {
        setHistoryLoading(false);
      }
    },
    [taskId, swt],
  );

  React.useEffect(() => {
    let active = true;
    api
      .settings()
      .then((settings) => {
        if (active) setEnabled(settings.security_reports_enabled === true);
      })
      .catch(() => {
        // The server enforces the setting on every import; do not invent a disabled state.
        if (active) setEnabled(true);
      });
    void loadHistory();

    return () => {
      active = false;
    };
  }, [loadHistory]);

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const input = fileRef.current;
    const file = input?.files?.[0];

    if (!input || !file) return;
    setBusy(true);
    setError("");

    try {
      if (file.size > MAX_REPORT_BYTES) throw new Error(swt("interface.assessmentTooLarge"));

      const text = await file.text().catch(() => {
        throw new Error(swt("interface.assessmentReadFailed"));
      });

      const result = await api.importAssessmentReportText(taskId, producer, text);
      toast.success(
        result.duplicate
          ? swt("interface.assessmentDuplicate")
          : swt("interface.assessmentImported", { count: result.observation_count }),
      );
      await loadHistory();
    } catch (err) {
      const message = swt("interface.assessmentImportFailed") + (err instanceof Error ? err.message : "");
      setError(message);
      toast.error(message);
    } finally {
      // Drop the selected file so its bytes and name are not kept by the page.
      input.value = "";
      setHasFile(false);
      setBusy(false);
    }
  }

  const intakeDisabled = enabled !== true || busy;

  return (
    <Card data-testid="assessment-reports">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-sm">
          <ShieldCheckIcon className="size-4" /> {swt("interface.assessmentTitle")}
        </CardTitle>
        <CardDescription>{swt("interface.assessmentDescription")}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <Alert>
          <InfoIcon />
          <AlertDescription>{swt("interface.assessmentDroppedNotice")}</AlertDescription>
        </Alert>
        {enabled === false && (
          <Alert data-testid="assessment-disabled">
            <InfoIcon />
            <AlertDescription>{swt("interface.assessmentDisabledNotice")}</AlertDescription>
          </Alert>
        )}
        <form className="flex flex-col gap-2" onSubmit={submit}>
          <fieldset
            className="grid gap-3 sm:grid-cols-[minmax(0,12rem)_minmax(0,1fr)_auto] sm:items-end"
            disabled={intakeDisabled}
          >
            <div className="flex min-w-0 flex-col gap-1.5">
              <Label htmlFor="assessment-producer">{swt("interface.assessmentProducerLabel")}</Label>
              <NativeSelect
                id="assessment-producer"
                className="w-full"
                data-testid="assessment-producer"
                value={producer}
                onChange={(e) => {
                  const next = PRODUCERS.find((p) => p.value === e.target.value);

                  if (next) setProducer(next.value);
                }}
              >
                {PRODUCERS.map((p) => (
                  <NativeSelectOption key={p.value} value={p.value}>
                    {p.name}
                  </NativeSelectOption>
                ))}
              </NativeSelect>
            </div>
            <div className="flex min-w-0 flex-col gap-1.5">
              <Label htmlFor="assessment-file">{swt("interface.assessmentFileLabel")}</Label>
              <Input
                id="assessment-file"
                ref={fileRef}
                type="file"
                accept="application/json,.json"
                data-testid="assessment-file"
                onChange={(e) => {
                  setHasFile((e.target.files?.length ?? 0) > 0);
                  setError("");
                }}
              />
            </div>
            <Button type="submit" data-testid="assessment-import" disabled={intakeDisabled || !hasFile}>
              <UploadIcon />
              {busy ? swt("interface.assessmentImporting") : swt("interface.assessmentImportAction")}
            </Button>
          </fieldset>
          <p className="text-muted-foreground text-xs">{swt("interface.assessmentFileHint")}</p>
          {error && (
            <p role="alert" className="text-destructive text-sm" data-testid="assessment-error">
              {error}
            </p>
          )}
        </form>
        <section className="flex flex-col gap-2">
          <h3 className="font-medium text-sm">{swt("interface.assessmentHistoryTitle")}</h3>
          {historyError && (
            <p role="alert" className="text-destructive text-sm">
              {historyError}
            </p>
          )}
          <ul className="flex flex-col gap-3" data-testid="assessment-history" aria-busy={historyLoading}>
            {reports.map((report) => (
              <HistoryEntry key={report.assessment_id} report={report} />
            ))}
          </ul>
          {!historyLoading && !historyError && reports.length === 0 && (
            <p className="rounded-md border border-dashed py-6 text-center text-muted-foreground text-sm">
              {swt("interface.assessmentHistoryEmpty")}
            </p>
          )}
          {nextBefore > 0 && (
            <Button
              variant="outline"
              size="sm"
              className="self-start"
              disabled={historyLoading}
              onClick={() => void loadHistory(nextBefore)}
            >
              {swt("interface.assessmentLoadMore")}
            </Button>
          )}
        </section>
      </CardContent>
    </Card>
  );
}
