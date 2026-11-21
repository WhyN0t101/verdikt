import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api";
import { downloadText } from "../lib/csv";
import { defang, shortenMiddle } from "../lib/format";
import type { CveInfo, FeedbackLabel, Report } from "../model";
import { LEVEL_BG } from "./LevelBadge";

const FEEDBACK: { label: FeedbackLabel; text: string }[] = [
  { label: "false_positive", text: "False positive" },
  { label: "false_negative", text: "False negative" },
];
const BTN = "rounded border border-line-strong px-2 py-1 text-xs hover:border-accent disabled:opacity-50";

/** CVEs found on the host with CISA KEV and EPSS context. Context only, never a verdict input. */
function Vulnerabilities({ cves }: { cves: CveInfo[] }) {
  if (cves.length === 0) return null;
  return (
    <section aria-label="Vulnerabilities" className="border-b border-line">
      <h2 className="label px-4 py-2.5">Vulnerabilities</h2>
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
              {c.kev && <span className="label border border-malicious px-1 text-malicious">KEV</span>}
              {c.ransomware && <span className="label border border-suspicious px-1 text-suspicious">Ransomware</span>}
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
  const stix = useMutation({
    mutationFn: () => api.stix(report.id),
    onSuccess: (text) => downloadText(`verdikt-${report.id}.stix.json`, text, "application/stix+json"),
  });

  return (
    <>
      <Vulnerabilities cves={report.cves} />
      <section aria-label="Report actions" className="border-b border-line">
        <h2 className="label px-4 py-2.5">Seen before</h2>
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
            <button key={f.label} type="button" disabled={feedback.isPending} onClick={() => feedback.mutate(f.label)} className={BTN}>
              {f.text}
            </button>
          ))}
          <button type="button" disabled={watching || watchAdd.isPending} onClick={() => watchAdd.mutate()} className={BTN}>
            {watching ? "Watching" : "Watch"}
          </button>
          <button type="button" disabled={stix.isPending} onClick={() => stix.mutate()} className={BTN}>
            Export STIX
          </button>
          <p className="w-full text-xs text-muted" role="status" aria-live="polite">
            {feedback.isSuccess && "Feedback recorded."}
            {feedback.isError && `Could not save feedback: ${feedback.error.message}`}
            {watchAdd.isError && `Could not watch: ${watchAdd.error.message}`}
            {stix.isError && `Could not export: ${stix.error.message}`}
          </p>
        </div>
      </section>
    </>
  );
}
