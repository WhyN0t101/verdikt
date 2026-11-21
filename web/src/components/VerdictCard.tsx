import { useState } from "react";
import { defang, formatDuration, typeTag } from "../lib/format";
import type { Report } from "../model";
import { LEVEL_BG, LEVEL_BORDER, LevelBadge } from "./LevelBadge";
import { Button, Chip, SectionTitle } from "./ui";

function CopyButton({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <Button
      size="sm"
      aria-label="Copy defanged IOC"
      onClick={() => {
        navigator.clipboard
          .writeText(text)
          .then(() => {
            setDone(true);
            setTimeout(() => setDone(false), 1500);
          })
          .catch(() => setDone(false));
      }}
    >
      {done ? "Copied" : "Copy defanged"}
    </Button>
  );
}

/** One segment per source; filled segments are the sources that agree with the verdict. */
function Confidence({ report }: { report: Report }) {
  return (
    <div>
      <div className="flex gap-1" aria-hidden="true">
        {Array.from({ length: report.total }, (_, i) => (
          <span key={i} className={`h-1.5 flex-1 rounded-full ${i < report.agreeing ? LEVEL_BG[report.level] : "bg-line-strong"}`} />
        ))}
      </div>
      <p className="mono mt-1.5 text-xs text-muted">
        {report.agreeing} of {report.total} sources agree · {report.confidence} confidence
      </p>
    </div>
  );
}

/** Verdict overlay on the viewport: the answer in display type, the evidence one glance below. */
export function VerdictHud({ report, onRecheck, busy }: { report: Report; onRecheck: () => void; busy: boolean }) {
  return (
    <section aria-label="Verdict" className={`hud verdict-in w-full max-w-md border-l-4 p-5 ${LEVEL_BORDER[report.level]}`}>
      <LevelBadge level={report.level} size="xl" />
      <div className="mt-3 flex items-start gap-2">
        <span className="mono min-w-0 flex-1 break-all text-sm">{report.ioc}</span>
        <Chip>{typeTag(report.ioc_type)}</Chip>
      </div>
      <div className="mt-4">
        <Confidence report={report} />
      </div>
      {report.reasons.length > 0 && (
        <ul className="mt-4 space-y-1 border-t border-line pt-3">
          {report.reasons.map((r, i) => (
            <li key={i} className="text-sm text-muted">
              {r}
            </li>
          ))}
        </ul>
      )}
      <div className="mt-4 flex flex-wrap gap-2">
        <CopyButton text={defang(report.ioc)} />
        <Button size="sm" disabled={busy} onClick={onRecheck} title="Query every source again, ignoring cached answers. Uses source quota.">
          Re-check, skip cache
        </Button>
      </div>
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
        ["Evidence", `${report.confidence} confidence`],
        ["Lookup", formatDuration(report.duration_ms)],
      ]
    : [];
  return (
    <section aria-label="Diagnostics" className="border-b border-line pb-1">
      <SectionTitle>Diagnostics</SectionTitle>
      {report ? (
        <dl className="px-4 pb-2 pt-1">
          {rows.map(([k, v]) => (
            <div key={k} className="flex items-baseline justify-between gap-4 py-1">
              <dt className="shrink-0 text-xs text-muted">{k}</dt>
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
