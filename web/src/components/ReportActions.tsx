import { useMutation } from "@tanstack/react-query";
import { api } from "../api";
import { defang, shortenMiddle } from "../lib/format";
import type { FeedbackLabel, Report } from "../model";
import { LEVEL_BG } from "./LevelBadge";

const FEEDBACK: { label: FeedbackLabel; text: string }[] = [
  { label: "false_positive", text: "False positive" },
  { label: "false_negative", text: "False negative" },
];

function download(name: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "application/stix+json" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

/** Earlier reports sharing an indicator, analyst feedback and STIX export for one report. */
export function ReportActions({ report, onOpen }: { report: Report; onOpen: (id: string) => void }) {
  const feedback = useMutation({ mutationFn: (label: FeedbackLabel) => api.feedback(report.id, label) });
  const stix = useMutation({ mutationFn: () => api.stix(report.id), onSuccess: (text) => download(`verdikt-${report.id}.stix.json`, text) });

  return (
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
          <button
            key={f.label}
            type="button"
            disabled={feedback.isPending}
            onClick={() => feedback.mutate(f.label)}
            className="rounded border border-line-strong px-2 py-1 text-xs hover:border-accent disabled:opacity-50"
          >
            {f.text}
          </button>
        ))}
        <button
          type="button"
          disabled={stix.isPending}
          onClick={() => stix.mutate()}
          className="rounded border border-line-strong px-2 py-1 text-xs hover:border-accent disabled:opacity-50"
        >
          Export STIX
        </button>
        <p className="w-full text-xs text-muted" role="status" aria-live="polite">
          {feedback.isSuccess && "Feedback recorded."}
          {feedback.isError && `Could not save feedback: ${feedback.error.message}`}
          {stix.isError && `Could not export: ${stix.error.message}`}
        </p>
      </div>
    </section>
  );
}
