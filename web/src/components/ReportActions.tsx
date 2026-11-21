import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "../api";
import { downloadText } from "../lib/csv";
import { defang, shortenMiddle } from "../lib/format";
import type { CveInfo, FeedbackLabel, Report } from "../model";
import { LEVEL_BG } from "./LevelBadge";
import { ReportDiff } from "./ReportDiff";
import { Button, FIELD, SectionTitle } from "./ui";

const FEEDBACK: { label: FeedbackLabel; text: string }[] = [
  { label: "false_positive", text: "False positive" },
  { label: "false_negative", text: "False negative" },
];

/** CVEs found on the host with CISA KEV and EPSS context. Context only, never a verdict input. */
function Vulnerabilities({ cves }: { cves: CveInfo[] }) {
  if (cves.length === 0) return null;
  return (
    <section aria-label="Vulnerabilities" className="border-b border-line">
      <SectionTitle>Vulnerabilities</SectionTitle>
      <ul className="pb-2">
        {cves.map((c) => (
          <li key={c.id} className="px-4 py-1.5">
            <div className="flex flex-wrap items-center gap-2">
              <a
                href={`https://nvd.nist.gov/vuln/detail/${c.id}`}
                target="_blank"
                rel="noopener noreferrer"
                className="mono text-xs text-accent-text hover:underline"
              >
                {c.id}
              </a>
              {c.kev && <span className="mono rounded border border-malicious px-1.5 text-[11px] leading-5 text-malicious">KEV</span>}
              {c.ransomware && <span className="mono rounded border border-suspicious px-1.5 text-[11px] leading-5 text-suspicious">Ransomware</span>}
              {c.epss !== null && c.epss !== undefined && (
                <span className="mono ml-auto text-[11px] text-muted" title="Probability of exploitation in the next 30 days (EPSS)">
                  EPSS {(c.epss * 100).toFixed(1)}%
                </span>
              )}
            </div>
            {c.kev_name && <p className="mt-0.5 text-[11px] text-muted">{c.kev_name}</p>}
          </li>
        ))}
      </ul>
    </section>
  );
}

/** CVEs, earlier reports sharing an indicator, feedback, watchlist and STIX export for one report. */
export function ReportActions({ report, onOpen }: { report: Report; onOpen: (id: string) => void }) {
  const qc = useQueryClient();
  const watch = useQuery({ queryKey: ["watchlist"], queryFn: api.watchlist });
  const watching = watch.data?.entries.some((e) => e.ioc === report.ioc) ?? false;
  const watchAdd = useMutation({ mutationFn: () => api.watchAdd(report.id), onSuccess: (s) => qc.setQueryData(["watchlist"], s) });
  const feedback = useMutation({
    mutationFn: (label: FeedbackLabel) => api.feedback(report.id, label),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["stats"] }),
  });
  const [caseId, setCaseId] = useState("");
  const cases = useQuery({ queryKey: ["cases"], queryFn: () => api.cases() });
  const refreshCases = () => void qc.invalidateQueries({ queryKey: ["cases"] });
  const addToCase = useMutation({ mutationFn: (id: string) => api.caseAdd(id, report.id), onSuccess: refreshCases });
  const newCase = useMutation({
    mutationFn: async () => api.caseAdd((await api.caseCreate(`Investigation: ${defang(report.ioc)}`)).id, report.id),
    onSuccess: refreshCases,
  });
  const exp = useMutation({
    mutationFn: async (kind: "md" | "html" | "misp") => ({
      kind,
      text: await api.download(kind === "misp" ? `/api/reports/${report.id}/misp` : `/api/reports/${report.id}/export?format=${kind}`),
    }),
    onSuccess: ({ kind, text }) => {
      const ext = kind === "misp" ? "misp.json" : kind;
      const type = kind === "html" ? "text/html" : kind === "md" ? "text/markdown" : "application/json";
      downloadText(`verdikt-${report.id}.${ext}`, text, type);
    },
  });
  const stix = useMutation({
    mutationFn: () => api.stix(report.id),
    onSuccess: (text) => downloadText(`verdikt-${report.id}.stix.json`, text, "application/stix+json"),
  });

  return (
    <>
      <ReportDiff key={report.id} reportId={report.id} />
      <Vulnerabilities cves={report.cves} />
      <section aria-label="Report actions" className="border-b border-line">
        <SectionTitle>Seen before</SectionTitle>
        {report.seen_before.length === 0 ? (
          <p className="px-4 pb-3 text-sm text-muted">No earlier report shares this indicator or its infrastructure.</p>
        ) : (
          <ul className="pb-2">
            {report.seen_before.map((s) => (
              <li key={s.report_id}>
                <button
                  type="button"
                  onClick={() => onOpen(s.report_id)}
                  className="flex w-full items-start gap-2 px-4 py-1.5 text-left hover:bg-panel2"
                  title={`Shared: ${s.shared.map(defang).join(", ")}`}
                >
                  <span aria-hidden="true" className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${LEVEL_BG[s.level]}`} />
                  <span className="min-w-0">
                    <span className="mono block truncate text-xs">{shortenMiddle(s.ioc, 28)}</span>
                    <span className="mono block truncate text-[11px] text-muted">
                      {s.level} · shares {s.shared.map((v) => shortenMiddle(defang(v), 18)).join(", ")}
                    </span>
                  </span>
                </button>
              </li>
            ))}
          </ul>
        )}

        <div className="flex flex-wrap items-center gap-2 border-t border-line px-4 py-3">
          {FEEDBACK.map((f) => (
            <Button key={f.label} size="sm" disabled={feedback.isPending} onClick={() => feedback.mutate(f.label)}>
              {f.text}
            </Button>
          ))}
          <Button size="sm" disabled={watching || watchAdd.isPending} onClick={() => watchAdd.mutate()}>
            {watching ? "Watching" : "Watch"}
          </Button>
          <Button size="sm" disabled={stix.isPending} onClick={() => stix.mutate()}>
            Export STIX
          </Button>
          <Button size="sm" disabled={exp.isPending} onClick={() => exp.mutate("misp")}>
            Export MISP
          </Button>
          <Button size="sm" disabled={exp.isPending} onClick={() => exp.mutate("md")}>
            Report (Markdown)
          </Button>
          <Button size="sm" disabled={exp.isPending} onClick={() => exp.mutate("html")}>
            Report (HTML)
          </Button>
          <div className="flex w-full items-center gap-2">
            <label htmlFor="add-case" className="sr-only">
              Add to case
            </label>
            <select
              id="add-case"
              value={caseId}
              onChange={(e) => setCaseId(e.target.value)}
              className={`${FIELD} h-7 min-w-0 flex-1 py-0 text-xs`}
            >
              <option value="">Add to case…</option>
              {cases.data?.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.title}
                </option>
              ))}
            </select>
            <Button size="sm" disabled={!caseId || addToCase.isPending} onClick={() => addToCase.mutate(caseId)}>
              Add
            </Button>
            <Button size="sm" disabled={newCase.isPending} onClick={() => newCase.mutate()}>
              New case
            </Button>
          </div>
          <p className="w-full text-xs text-muted" role="status" aria-live="polite">
            {feedback.isSuccess && "Feedback recorded."}
            {feedback.isError && `Could not save feedback: ${feedback.error.message}`}
            {watchAdd.isError && `Could not watch: ${watchAdd.error.message}`}
            {stix.isError && `Could not export: ${stix.error.message}`}
            {exp.isError && `Could not export: ${exp.error.message}`}
            {addToCase.isSuccess && "Added to the case."}
            {newCase.isSuccess && "Case created with this report."}
            {(addToCase.isError || newCase.isError) && `Could not add to a case: ${(addToCase.error ?? newCase.error)?.message}`}
          </p>
        </div>
      </section>
    </>
  );
}
