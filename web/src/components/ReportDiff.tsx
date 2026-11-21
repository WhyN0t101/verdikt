import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { changeKinds, confidenceChange, levelMoved, metricValue } from "../lib/diffText";
import { ago } from "../lib/format";
import type { Level, SourceChange } from "../model";
import { LevelBadge } from "./LevelBadge";
import { Chip, Note, SectionTitle } from "./ui";

/** Feed text is attacker-controlled: plain text node, bidi-isolated, clamped (full text in the tooltip). */
function FeedText({ children }: { children: string }) {
  return (
    <span className="feed-text mono line-clamp-2 text-xs" title={children}>
      {children}
    </span>
  );
}

function LevelMove({ from, to }: { from: Level | null; to: Level | null }) {
  return (
    <span className="flex flex-wrap items-center gap-1.5">
      {from && <LevelBadge level={from} />}
      {from && to && <span className="text-xs text-muted">to</span>}
      {to && <LevelBadge level={to} />}
    </span>
  );
}

function Row({ c }: { c: SourceChange }) {
  const kinds = changeKinds(c);
  return (
    <li className="space-y-1 border-t border-line py-2 first:border-t-0">
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="mono text-xs font-medium">{c.source}</span>
        {kinds.map((k) => (
          <Chip key={k}>{k}</Chip>
        ))}
      </div>
      {(c.level_from !== c.level_to || c.change !== "changed") && <LevelMove from={c.level_from} to={c.level_to} />}
      {c.status_from !== c.status_to && (
        <p className="mono text-xs">
          Status {c.status_from ?? "none"} to {c.status_to ?? "none"}
        </p>
      )}
      {c.no_answer && <p className="text-xs font-medium">No answer, not a clean result.</p>}
      {c.summary_from !== c.summary_to && (
        <div className="space-y-0.5">
          {c.summary_from && (
            <p className="flex gap-1.5">
              <span className="w-8 shrink-0 text-xs text-muted">Was</span>
              <FeedText>{c.summary_from}</FeedText>
            </p>
          )}
          {c.summary_to && (
            <p className="flex gap-1.5">
              <span className="w-8 shrink-0 text-xs text-muted">Now</span>
              <FeedText>{c.summary_to}</FeedText>
            </p>
          )}
        </div>
      )}
      {c.metrics.map((m) => (
        <p key={m.key} className="mono text-xs">
          <span className="feed-text">{m.key}</span>: {metricValue(m.from)} to {metricValue(m.to)}
        </p>
      ))}
    </li>
  );
}

function Reasons({ label, sign, items }: { label: string; sign: string; items: string[] }) {
  if (items.length === 0) return null;
  return (
    <div>
      <h3 className="text-xs font-medium text-muted">{label}</h3>
      <ul className="mt-0.5 space-y-0.5">
        {items.map((r) => (
          <li key={r} className="flex gap-1.5">
            <span aria-hidden="true" className="mono w-3 shrink-0 text-xs text-muted">
              {sign}
            </span>
            <FeedText>{r}</FeedText>
          </li>
        ))}
      </ul>
    </div>
  );
}

/** What moved since the previous report of the same indicator. Hidden when there is no earlier report. */
export function ReportDiff({ reportId }: { reportId: string }) {
  const q = useQuery({ queryKey: ["diff", reportId], queryFn: () => api.diff(reportId) });
  if (q.isError) {
    return (
      <div className="border-b border-line px-4 py-3">
        <Note tone="error">{`Could not load the changes: ${q.error.message}`}</Note>
      </div>
    );
  }
  const d = q.data;
  if (!d || d.previous_id === null) return null;
  return (
    <section aria-label="Changes" className="border-b border-line pb-2">
      <SectionTitle>Changes since {d.previous_at ? ago(d.previous_at) : "the last check"}</SectionTitle>
      <details open={levelMoved(d)} className="px-4 text-sm">
        <summary className="cursor-pointer text-muted hover:text-ink">
          {levelMoved(d) ? (
            <span className="inline-flex flex-wrap items-center gap-1.5 align-middle">
              <LevelMove from={d.level_from} to={d.level_to} />
            </span>
          ) : d.changed ? (
            "Verdict unchanged, details changed"
          ) : (
            "Nothing changed"
          )}
        </summary>
        <div className="mt-2 space-y-3">
          <p className="mono text-xs text-muted">{confidenceChange(d)}</p>
          {d.sources.length > 0 && (
            <ul aria-label="Source changes">
              {d.sources.map((c) => (
                <Row key={`${c.source}-${c.change}`} c={c} />
              ))}
            </ul>
          )}
          <Reasons label="Reasons added" sign="+" items={d.reasons_added} />
          <Reasons label="Reasons removed" sign="-" items={d.reasons_removed} />
          {!d.changed && <p className="text-xs text-muted">No source or reason changed.</p>}
        </div>
      </details>
    </section>
  );
}
