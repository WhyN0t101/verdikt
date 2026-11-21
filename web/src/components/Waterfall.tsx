import { formatDuration } from "../lib/format";
import type { Report } from "../model";
import { LEVEL_BG } from "./LevelBadge";

/** One lane per source: where its request started and how long it took, on a shared time axis. */
export function Waterfall({ report }: { report: Report | null }) {
  if (!report || report.results.length === 0) return null;
  const total = Math.max(report.duration_ms, ...report.results.map((r) => r.started_ms + r.duration_ms), 1);
  return (
    <section aria-label="Timeline" className="border-b border-line">
      <h2 className="label flex justify-between px-4 py-2.5">
        <span>Timeline</span>
        <span>{formatDuration(total)}</span>
      </h2>
      <ol className="space-y-1.5 px-4 pb-4">
        {report.results.map((r) => {
          const left = (r.started_ms / total) * 100;
          const width = Math.max((r.duration_ms / total) * 100, 1.5);
          const failed = r.status !== "ok" && r.status !== "not_found";
          const label = r.cached ? "cached" : formatDuration(r.duration_ms);
          return (
            <li key={r.source} className="mono text-xs" title={`${r.source}: ${label}${failed ? `, ${r.status.replace("_", " ")}` : ""}`}>
              <div className="flex justify-between">
                <span>{r.source}</span>
                <span className="text-muted">{label}</span>
              </div>
              <div className="relative mt-1 h-1.5 border-b border-line-strong" aria-hidden="true">
                <div
                  className={`absolute top-0 h-full rounded-[2px] ${failed ? "hatch text-unknown" : LEVEL_BG[r.level]}`}
                  style={{ left: `${Math.min(left, 100 - width)}%`, width: `${width}%` }}
                />
              </div>
            </li>
          );
        })}
      </ol>
    </section>
  );
}
