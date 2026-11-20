import { clock } from "../lib/format";
import type { Report } from "../model";
import { LEVEL_BORDER, LEVEL_TEXT } from "./LevelBadge";

/** One line per source answer, left border = row level. */
export function LogStream({ report }: { report: Report | null }) {
  const rows = report ? [...report.results].sort((a, b) => a.fetched_at.localeCompare(b.fetched_at)) : [];
  return (
    <section aria-label="Source log" className="rounded-md border border-line bg-panel">
      <h2 className="label border-b border-line px-3 py-2">Source log</h2>
      {rows.length === 0 ? (
        <p className="p-3 text-sm text-muted">Source answers appear here as a check completes.</p>
      ) : (
        <ol className="max-h-80 overflow-y-auto">
          {rows.map((r) => (
            <li key={r.source} className={`mono border-l-2 px-3 py-1.5 text-xs ${LEVEL_BORDER[r.level]}`}>
              <span className="text-muted">[{clock(r.fetched_at)}]</span>{" "}
              <span className="uppercase">{r.source}</span>{" "}
              <span className={LEVEL_TEXT[r.level]}>{r.status === "ok" ? r.level.toUpperCase() : r.status.toUpperCase()}</span>
              <div className="text-muted">{r.summary}</div>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}
