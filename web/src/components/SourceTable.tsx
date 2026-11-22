import { useEffect, useRef } from "react";
import { provenanceText, safeHref } from "../lib/provenance";
import type { Report, SourceInfo, SourceResult } from "../model";
import { LEVEL_BORDER, LevelBadge } from "./LevelBadge";

interface Props {
  report: Report | null;
  /** enabled sources, shown as skeleton rows while a check is running */
  pending: SourceInfo[] | null;
  /** a verdict reason asked for this row: open its "Why this counted" and move focus there */
  focus?: { name: string; n: number } | null;
}

function Skeleton({ name }: { name: string }) {
  return (
    <tr className="border-t border-line">
      <td className="mono px-3 py-2">{name}</td>
      <td colSpan={3} className="px-3 py-2">
        <div className="pixel h-3 w-40 rounded-sm" role="status" aria-label={`${name} loading`} />
      </td>
    </tr>
  );
}

const ROLE_TEXT: Record<string, string> = {
  strong: "Strong source: counts towards the verdict and can back a SAFE verdict.",
  weak: "Counts towards the verdict but cannot back SAFE on its own.",
  feed: "List-only feed: a listing counts, but \"not listed\" carries no weight.",
  context: "Context only: shown for the analyst, never changes the verdict.",
  "no answer": "No usable answer: an error, rate limit or missing record. It is never counted as clean.",
};

/** Why this row counted the way it did: its role, weight, and the rules that matched. */
function Why({ r, focusKey }: { r: SourceResult; focusKey: number | null }) {
  const ref = useRef<HTMLDetailsElement>(null);
  useEffect(() => {
    const d = ref.current;
    if (focusKey === null || !d) return;
    d.open = true;
    d.querySelector("summary")?.focus();
    d.scrollIntoView({ block: "nearest" }); // no smooth scrolling, so reduced motion is respected
  }, [focusKey]);
  if (!r.role) return null;
  return (
    <details ref={ref} className="mt-1 text-xs">
      <summary className="cursor-pointer text-muted hover:text-ink">Why this counted</summary>
      <div className="mt-1 space-y-1 text-muted">
        <p>{ROLE_TEXT[r.role] ?? r.role}</p>
        <p className="mono">Weight in confidence: {r.weight}</p>
        {r.fired.length > 0 ? (
          <ul className="mono text-ink">
            {r.fired.map((f) => (
              <li key={f}>{f}</li>
            ))}
          </ul>
        ) : (
          <p>No rule matched.</p>
        )}
      </div>
    </details>
  );
}

export function SourceTable({ report, pending, focus = null }: Props) {
  return (
    <section aria-label="Sources" className="overflow-auto bg-panel">
      <table className="w-full min-w-[520px] text-left text-sm">
        <thead>
          <tr className="sticky top-0 bg-panel text-xs text-muted">
            <th className="px-3 py-2 font-normal">Source</th>
            <th className="px-3 py-2 font-normal">Level</th>
            <th className="px-3 py-2 font-normal">Result</th>
            <th className="px-3 py-2 text-right font-normal">Link</th>
          </tr>
        </thead>
        <tbody>
          {pending
            ? pending.map((s) => <Skeleton key={s.name} name={s.name} />)
            : report?.results.map((r) => (
                <tr key={r.source} className="border-t border-line align-top hover:bg-panel2">
                  <td className={`mono border-l-2 px-3 py-2 ${r.status === "ok" ? LEVEL_BORDER[r.level] : "border-transparent"}`}>
                    {r.source}
                    {r.cached && <span className="label ml-2 border border-line px-1">cached</span>}
                  </td>
                  <td className="px-3 py-2">
                    {r.status === "ok" ? (
                      <LevelBadge level={r.level} />
                    ) : (
                      <span className="label">{r.status.replace("_", " ")}</span>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    <span className="mono feed-text text-[13px]">{r.summary}</span>
                    {r.tags.length > 0 && (
                      <span className="mt-1 flex flex-wrap gap-1">
                        {r.tags.map((t) => (
                          <span key={t} className="label feed-text rounded border border-line px-1 normal-case">
                            {t}
                          </span>
                        ))}
                      </span>
                    )}
                    <p className="mono mt-1 text-xs text-muted">{provenanceText(r)}</p>
                    <Why r={r} focusKey={focus?.name === r.source ? focus.n : null} />
                  </td>
                  <td className="px-3 py-2 text-right">
                    {safeHref(r.link) && (
                      <a
                        href={safeHref(r.link) ?? undefined}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-accent-text underline-offset-2 hover:underline"
                        aria-label={`Open ${r.source} page`}
                      >
                        Open
                      </a>
                    )}
                  </td>
                </tr>
              ))}
        </tbody>
      </table>
    </section>
  );
}
