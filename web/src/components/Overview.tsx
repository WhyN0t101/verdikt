import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { api } from "../api";
import { ago, shortenMiddle } from "../lib/format";
import type { Level } from "../model";
import { ActivityChart } from "./ActivityChart";
import { LEVEL_BG, LevelBadge } from "./LevelBadge";

function Panel({ title, label, children }: { title: string; label: string; children: ReactNode }) {
  return (
    <section aria-label={label} className="border border-line bg-panel">
      <h2 className="label border-b border-line px-4 py-2.5">{title}</h2>
      <div className="p-4">{children}</div>
    </section>
  );
}

const pct = (n: number, of: number) => (of === 0 ? "-" : `${Math.round((n / of) * 100)}%`);
const BTN = "rounded border border-line-strong px-3 py-1.5 text-sm hover:border-accent disabled:opacity-50";

export function Overview({ onCheck }: { onCheck: (ioc: string) => void }) {
  const qc = useQueryClient();
  const stats = useQuery({ queryKey: ["stats"], queryFn: () => api.stats(30) });
  const watch = useQuery({ queryKey: ["watchlist"], queryFn: api.watchlist });
  const feeds = useQuery({ queryKey: ["feeds"], queryFn: api.feeds });

  const recheck = useMutation({
    mutationFn: api.recheck,
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["watchlist"] });
      void qc.invalidateQueries({ queryKey: ["stats"] });
    },
  });
  const remove = useMutation({
    mutationFn: api.watchRemove,
    onSuccess: (state) => qc.setQueryData(["watchlist"], state),
  });
  const update = useMutation({
    mutationFn: api.feedsUpdate,
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["feeds"] }),
  });

  const s = stats.data;
  const fb = s?.feedback;
  const judged = fb ? fb.false_positive + fb.false_negative + fb.correct : 0;

  return (
    <div className="grid gap-4 p-5 lg:grid-cols-2">
      <Panel title={`Checks per day${s ? ` (${s.total} in ${s.days} days)` : ""}`} label="Activity">
        {s ? <ActivityChart data={s.by_day} /> : <div className="pixel h-24" role="status" aria-label="Loading activity" />}
      </Panel>

      <Panel title="Source health, last 30 days" label="Source health">
        {s && s.sources.length === 0 && <p className="text-sm text-muted">Source statistics appear after the first check.</p>}
        {s && s.sources.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[420px] text-left text-sm">
              <thead>
                <tr className="label">
                  <th className="pb-2 font-normal">Source</th>
                  <th className="pb-2 font-normal">Answered</th>
                  <th className="pb-2 font-normal">Errors</th>
                  <th className="pb-2 font-normal">Limited</th>
                  <th className="pb-2 font-normal">Cached</th>
                  <th className="pb-2 text-right font-normal">Avg ms</th>
                </tr>
              </thead>
              <tbody className="mono text-[13px]">
                {s.sources.map((h) => (
                  <tr key={h.source} className="border-t border-line">
                    <td className="py-1.5">{h.source}</td>
                    <td>{pct(h.ok, h.checks)}</td>
                    <td className={h.errors > 0 ? "text-malicious" : ""}>{h.errors}</td>
                    <td className={h.rate_limited > 0 ? "text-suspicious" : ""}>{h.rate_limited}</td>
                    <td>{pct(h.cached, h.checks)}</td>
                    <td className="text-right">{h.avg_ms || "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <Panel title="Watchlist" label="Watchlist">
        <div className="mb-3 flex flex-wrap items-center gap-3">
          <button type="button" className={BTN} disabled={recheck.isPending || (watch.data?.entries.length ?? 0) === 0} onClick={() => recheck.mutate()}>
            {recheck.isPending ? "Re-checking…" : "Re-check all"}
          </button>
          <span className="text-xs text-muted" role="status" aria-live="polite">
            {recheck.isSuccess && (recheck.data.length === 0 ? "No verdict changed." : `${recheck.data.length} verdict(s) changed.`)}
            {recheck.isError && `Re-check failed: ${recheck.error.message}`}
            {!recheck.isSuccess && !recheck.isError && "A re-check skips the cache and uses source quota."}
          </span>
        </div>
        {watch.data && watch.data.entries.length === 0 && <p className="text-sm text-muted">Nothing watched yet. Open a report and choose Watch.</p>}
        <ul>
          {watch.data?.entries.map((e) => (
            <li key={e.ioc} className="flex items-center gap-3 border-t border-line py-1.5 first:border-t-0">
              <span className="mono min-w-0 flex-1 truncate text-[13px]" title={e.ioc}>
                {shortenMiddle(e.ioc, 34)}
              </span>
              {e.last_level ? <LevelBadge level={e.last_level as Level} /> : <span className="label">not checked</span>}
              <button
                type="button"
                onClick={() => remove.mutate(e.ioc)}
                aria-label={`Stop watching ${e.ioc}`}
                className="rounded border border-line px-2 py-0.5 text-xs text-muted hover:border-accent"
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
        {watch.data && watch.data.events.length > 0 && (
          <div className="mt-3 border-t border-line pt-3">
            <h3 className="label mb-1.5">Recent changes</h3>
            <ul className="mono space-y-1 text-xs">
              {watch.data.events.slice(0, 6).map((ev) => (
                <li key={ev.id}>
                  {ago(ev.at)} · {shortenMiddle(ev.ioc, 26)}: {ev.from_level} → {ev.to_level}
                </li>
              ))}
            </ul>
          </div>
        )}
      </Panel>

      <Panel title="Recurring infrastructure" label="Recurring infrastructure">
        {s && s.recurring.length === 0 && <p className="text-sm text-muted">No indicator has shown up in more than one report yet.</p>}
        <ul>
          {s?.recurring.map((r) => (
            <li key={r.value} className="flex items-center gap-3 border-t border-line py-1.5 first:border-t-0">
              <span aria-hidden="true" className={`h-2 w-2 shrink-0 rounded-full ${LEVEL_BG[r.last_level as Level]}`} />
              <span className="mono min-w-0 flex-1 truncate text-[13px]" title={r.value}>
                {shortenMiddle(r.value, 34)}
              </span>
              <span className="label">
                {r.reports} reports · {r.kind}
              </span>
              <button type="button" onClick={() => onCheck(r.value)} aria-label={`Check ${r.value}`} className="rounded border border-line px-2 py-0.5 text-xs hover:border-accent">
                Check
              </button>
            </li>
          ))}
        </ul>
      </Panel>

      <Panel title="Verdict feedback" label="Feedback">
        {judged === 0 ? (
          <p className="text-sm text-muted">No feedback yet. Mark a report as a false positive or false negative to see how the rules are doing.</p>
        ) : (
          <dl className="grid grid-cols-3 gap-4">
            {(
              [
                ["Correct", fb?.correct ?? 0],
                ["False positive", fb?.false_positive ?? 0],
                ["False negative", fb?.false_negative ?? 0],
              ] as const
            ).map(([k, v]) => (
              <div key={k}>
                <dt className="label">{k}</dt>
                <dd className="mono mt-1 text-lg">{v}</dd>
              </div>
            ))}
          </dl>
        )}
      </Panel>

      <Panel title="Local data feeds" label="Local feeds">
        <div className="mb-3 flex flex-wrap items-center gap-3">
          <button type="button" className={BTN} disabled={update.isPending} onClick={() => update.mutate()}>
            {update.isPending ? "Downloading…" : "Update feeds"}
          </button>
          <span className="text-xs text-muted" role="status" aria-live="polite">
            {update.isSuccess && `${update.data.filter((u) => u.ok).length}/${update.data.length} feeds updated.`}
            {update.isError && `Update failed: ${update.error.message}`}
            {!update.isSuccess && !update.isError && "About 14 MB of public lists, matched on this machine."}
          </span>
        </div>
        {feeds.data && feeds.data.length === 0 && <p className="text-sm text-muted">No feeds yet. Update them once to enable blocklists, top sites, KEV and EPSS.</p>}
        <ul className="mono space-y-1 text-xs">
          {feeds.data?.map((f) => (
            <li key={f.name} className="flex justify-between gap-4">
              <span>{f.name}</span>
              <span className="text-muted">
                {f.count.toLocaleString()} entries · {ago(f.fetched_at)}
              </span>
            </li>
          ))}
        </ul>
      </Panel>
    </div>
  );
}
