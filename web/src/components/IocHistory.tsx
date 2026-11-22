import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { ago } from "../lib/format";
import { changesText, hasStory } from "../lib/historyPanel";
import type { Level } from "../model";
import { LevelBadge } from "./LevelBadge";
import { Button, Note, SectionTitle } from "./ui";

interface Props {
  reportId: string;
  onOpen: (reportId: string) => void;
  onOpenCase: (caseId: string) => void;
}

/** Everything stored about this exact indicator: earlier reports, the cases it is in, and its watch. */
export function IocHistory({ reportId, onOpen, onOpenCase }: Props) {
  const q = useQuery({ queryKey: ["history", reportId], queryFn: () => api.history(reportId) });
  if (q.isError) {
    return (
      <div className="border-b border-line px-4 py-3">
        <Note tone="error">{`Could not load the indicator history: ${q.error.message}`}</Note>
      </div>
    );
  }
  const d = q.data;
  if (!d || !hasStory(d)) return null;
  return (
    <section aria-label="Indicator history" className="border-b border-line pb-3">
      <SectionTitle right={changesText(d.changes)}>Indicator history</SectionTitle>
      <div className="space-y-3 px-4 text-sm">
        <details open={d.reports.length > 1}>
          <summary className="cursor-pointer text-muted hover:text-ink">
            {d.reports.length} report{d.reports.length === 1 ? "" : "s"} of this indicator
          </summary>
          <ol aria-label="Reports of this indicator" className="mt-2 ml-1 border-l border-line-strong">
            {d.reports.map((r) => {
              const current = r.id === d.report_id;
              return (
                <li key={r.id} aria-current={current ? "true" : undefined} className="relative flex flex-wrap items-center gap-2 py-1 pl-4">
                  <span aria-hidden="true" className="absolute top-3 -left-[3px] h-1.5 w-1.5 rounded-full bg-line-strong" />
                  <span className="mono w-20 shrink-0 whitespace-nowrap text-xs text-muted" title={r.created_at}>
                    {ago(r.created_at)}
                  </span>
                  <LevelBadge level={r.level as Level} />
                  {current ? (
                    <span className="text-xs text-muted">This report</span>
                  ) : (
                    <Button variant="ghost" size="sm" onClick={() => onOpen(r.id)} aria-label={`Open the report from ${ago(r.created_at)}`}>
                      Open
                    </Button>
                  )}
                </li>
              );
            })}
          </ol>
          {d.truncated && <p className="mt-1 text-xs text-muted">Showing the newest {d.reports.length}.</p>}
        </details>

        {d.cases.length > 0 && (
          <div>
            <h3 className="text-xs font-medium text-muted">In cases</h3>
            <ul className="mt-1 flex flex-wrap gap-1.5">
              {d.cases.map((c) => (
                <li key={c.id} className="min-w-0">
                  <Button variant="secondary" size="sm" onClick={() => onOpenCase(c.id)} className="max-w-full" title="Open this case">
                    <span className="feed-text truncate">{c.title}</span>
                    <span className="mono text-muted">{c.report_count}</span>
                  </Button>
                </li>
              ))}
            </ul>
          </div>
        )}

        {d.watched && (
          <div>
            <h3 className="text-xs font-medium text-muted">Watching{d.watched_since ? ` since ${ago(d.watched_since)}` : ""}</h3>
            {d.events.length === 0 ? (
              <p className="mt-1 text-xs text-muted">No verdict change seen yet.</p>
            ) : (
              <ul className="mt-1 space-y-1">
                {d.events.map((ev) => (
                  <li key={ev.id} className="flex flex-wrap items-center gap-1.5">
                    <span className="mono w-20 shrink-0 whitespace-nowrap text-xs text-muted" title={ev.at}>
                      {ago(ev.at)}
                    </span>
                    <LevelBadge level={ev.from_level as Level} />
                    <span className="text-xs text-muted">to</span>
                    <LevelBadge level={ev.to_level as Level} />
                    <Button variant="ghost" size="sm" onClick={() => onOpen(ev.report_id)} aria-label={`Open the report where it changed to ${ev.to_level}`}>
                      What changed
                    </Button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}

        <p className="text-xs text-muted">
          Matches this exact indicator. A URL and its host are separate indicators. Reports older than 90 days are removed unless they are in a case.
        </p>
      </div>
    </section>
  );
}
