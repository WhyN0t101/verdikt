import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { sourceState, usageText } from "../lib/sources";
import { Chip, Panel } from "./ui";

/** Every registered source: on or off and why, which indicator types it takes, and today's use. */
export function SourcesPanel({ className = "" }: { className?: string }) {
  const q = useQuery({ queryKey: ["sources"], queryFn: api.sources });
  const list = q.data ?? [];
  const on = list.filter((s) => s.enabled).length;
  return (
    <Panel title={q.data ? `Sources, ${on} of ${list.length} enabled` : "Sources"} label="Source list" className={className}>
      {q.isError && (
        <p role="alert" className="text-xs text-malicious">
          Could not load the sources: {q.error.message}
        </p>
      )}
      {q.isPending && <div className="pixel h-24" role="status" aria-label="Loading sources" />}
      {q.data && (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[520px] text-left text-sm">
            <thead>
              <tr className="text-xs text-muted">
                <th className="pb-2 font-normal">Source</th>
                <th className="pb-2 font-normal">Status</th>
                <th className="pb-2 font-normal">Indicator types</th>
                <th className="pb-2 text-right font-normal">Used</th>
              </tr>
            </thead>
            <tbody>
              {list.map((s) => {
                const st = sourceState(s);
                return (
                  <tr key={s.name} className="border-t border-line align-top">
                    <td className="mono py-1.5 text-[13px]">{s.name}</td>
                    <td className="py-1.5">
                      <Chip tone={s.enabled ? "accent" : "plain"}>{st.label}</Chip>
                      {st.hint && <span className="ml-2 text-xs text-muted">{st.hint}</span>}
                    </td>
                    <td className="mono py-1.5 text-xs text-muted">{s.supports.join(" ")}</td>
                    <td className="mono py-1.5 text-right text-xs">{usageText(s)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <p className="mt-3 text-xs text-muted">Keys are read from .env and never shown here.</p>
    </Panel>
  );
}
