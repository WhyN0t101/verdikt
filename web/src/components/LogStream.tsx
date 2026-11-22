import { clock } from "../lib/format";
import type { Report } from "../model";
import { LEVEL_BORDER, LEVEL_TEXT } from "./LevelBadge";
import { SectionTitle } from "./ui";

/** One line per source answer, left border = row level. */
export function LogStream({ report }: { report: Report | null }) {
  const rows = report ? [...report.results].sort((a, b) => a.fetched_at.localeCompare(b.fetched_at)) : [];
  return (
    <section aria-label="Source log" className="border-b border-line">
      <SectionTitle>Source log</SectionTitle>
      {rows.length === 0 ? (
        <p className="px-4 pb-3 text-sm text-muted">Source answers appear here as a check completes.</p>
      ) : (
        <ol className="max-h-96 overflow-y-auto pb-2">
          {rows.map((r) => (
            <li key={r.source} className={`mono my-1 ml-4 mr-2 border-l-2 px-3 py-1 text-xs ${LEVEL_BORDER[r.level]}`}>
              <span className="text-muted">[{clock(r.fetched_at)}]</span>{" "}
              <span className="uppercase">{r.source}</span>{" "}
              <span className={LEVEL_TEXT[r.level]}>{r.status === "ok" ? r.level.toUpperCase() : r.status.toUpperCase()}</span>
              <div className="feed-text text-muted">{r.summary}</div>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}
