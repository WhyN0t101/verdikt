import { useState } from "react";
import { defang, formatDuration, typeTag } from "../lib/format";
import type { Report } from "../model";
import { LevelBadge } from "./LevelBadge";

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

export function VerdictCard({ report }: { report: Report }) {
  const geo = report.geo.find((g) => g.role === "ioc");
  const rows: [string, string][] = [
    ["Confidence", `${report.agreeing}/${report.total} sources`],
    ["ASN", geo?.asn ? `AS${geo.asn}${geo.as_org ? ` ${geo.as_org}` : ""}` : "-"],
    ["Country", geo?.country ?? "-"],
    ["Lookup", formatDuration(report.duration_ms)],
  ];
  return (
    <section aria-label="Verdict" className="rounded-md border border-line bg-panel p-4">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <LevelBadge level={report.level} size="lg" />
        <span className="mono min-w-0 break-all text-base">{report.ioc}</span>
        <span className="label rounded border border-line px-1.5 py-0.5">{typeTag(report.ioc_type)}</span>
        <CopyButton text={defang(report.ioc)} />
      </div>
      <dl className="mt-4 grid grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-4">
        {rows.map(([k, v]) => (
          <div key={k}>
            <dt className="label">{k}</dt>
            <dd className="mono mt-0.5 truncate text-sm" title={v}>
              {v}
            </dd>
          </div>
        ))}
      </dl>
      {report.reasons.length > 0 && (
        <div className="mt-4 border-t border-line pt-3">
          <h3 className="label">Reasons</h3>
          <ul className="mt-1.5 space-y-1 text-sm">
            {report.reasons.map((r) => (
              <li key={r} className="mono text-[13px]">
                {r}
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
