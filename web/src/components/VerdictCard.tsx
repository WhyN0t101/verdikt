import { useState } from "react";
import { defang, formatDuration, typeTag } from "../lib/format";
import type { Report } from "../model";
import { LEVEL_BG, LEVEL_BORDER, LevelBadge } from "./LevelBadge";

function CopyButton({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className="label rounded border border-line px-1.5 py-0.5 hover:border-accent"
      onClick={() => {
        navigator.clipboard
          .writeText(text)
          .then(() => {
            setDone(true);
            setTimeout(() => setDone(false), 1500);
          })
          .catch(() => setDone(false));
      }}
      aria-label="Copy defanged IOC"
    >
      {done ? "Copied" : "Copy defanged"}
    </button>
  );
}

/** One square per source; filled squares are the sources that agree with the verdict. */
function Confidence({ report }: { report: Report }) {
  return (
    <span className="flex items-center gap-2">
      <span className="flex gap-0.5" aria-hidden="true">
        {Array.from({ length: report.total }, (_, i) => (
          <span key={i} className={`h-2.5 w-2.5 rounded-[2px] ${i < report.agreeing ? LEVEL_BG[report.level] : "border border-line-strong"}`} />
        ))}
      </span>
      <span className="mono text-xs text-muted">
        {report.agreeing}/{report.total} sources agree
      </span>
    </span>
  );
}

/** Verdict overlay on the viewport: the answer first, the evidence one glance below. */
export function VerdictHud({ report }: { report: Report }) {
  return (
    <section aria-label="Verdict" className={`hud w-full max-w-md border-l-4 p-4 ${LEVEL_BORDER[report.level]}`}>
      <LevelBadge level={report.level} size="lg" />
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <span className="mono min-w-0 break-all text-base">{report.ioc}</span>
        <span className="label rounded border border-line px-1.5 py-0.5">{typeTag(report.ioc_type)}</span>
        <CopyButton text={defang(report.ioc)} />
      </div>
      <div className="mt-3">
        <Confidence report={report} />
      </div>
      {report.reasons.length > 0 && (
        <ul className="mt-3 space-y-1 border-t border-line pt-3">
          {report.reasons.map((r, i) => (
            <li key={i} className="mono text-xs text-muted">
              {r}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

/** Key/value readout for the right column. */
export function Diagnostics({ report }: { report: Report | null }) {
  const geo = report?.geo.find((g) => g.role === "ioc");
  const rows: [string, string][] = report
    ? [
        ["Target", report.ioc],
        ["Type", typeTag(report.ioc_type)],
        ["ASN", geo?.asn ? `AS${geo.asn}${geo.as_org ? ` ${geo.as_org}` : ""}` : "-"],
        ["Country", geo?.country ?? "-"],
        ["Lookup", formatDuration(report.duration_ms)],
      ]
    : [];
  return (
    <section aria-label="Diagnostics" className="border-b border-line">
      <h2 className="label px-4 py-2.5">Diagnostics</h2>
      {report ? (
        <dl className="px-4 pb-3">
          {rows.map(([k, v]) => (
            <div key={k} className="flex items-baseline justify-between gap-4 py-1">
              <dt className="label shrink-0">{k}</dt>
              <dd className="mono min-w-0 truncate text-xs" title={v}>
                {v}
              </dd>
            </div>
          ))}
        </dl>
      ) : (
        <p className="px-4 pb-3 text-sm text-muted">Target, ASN and country appear after a check.</p>
      )}
    </section>
  );
}
