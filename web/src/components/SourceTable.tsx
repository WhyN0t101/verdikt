import type { Report, SourceInfo } from "../model";
import { LEVEL_BORDER, LevelBadge } from "./LevelBadge";

interface Props {
  report: Report | null;
  /** enabled sources, shown as skeleton rows while a check is running */
  pending: SourceInfo[] | null;
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

export function SourceTable({ report, pending }: Props) {
  return (
    <section aria-label="Sources" className="overflow-auto bg-panel">
      <table className="w-full min-w-[520px] text-left text-sm">
        <thead>
          <tr className="label sticky top-0 bg-panel">
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
                <tr key={r.source} className="border-t border-line align-top">
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
                    <span className="mono text-[13px]">{r.summary}</span>
                    {r.tags.length > 0 && (
                      <span className="mt-1 flex flex-wrap gap-1">
                        {r.tags.map((t) => (
                          <span key={t} className="label rounded border border-line px-1 normal-case">
                            {t}
                          </span>
                        ))}
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2 text-right">
                    {r.link && (
                      <a
                        href={r.link}
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
