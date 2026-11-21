import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import { ago, shortenMiddle } from "../lib/format";
import type { JobStatus, Level } from "../model";
import { ActivityChart } from "./ActivityChart";
import { LEVEL_BG, LevelBadge } from "./LevelBadge";
import { Button, FIELD, Panel } from "./ui";

function Tile({ label, value, tone }: { label: string; value: string | number; tone?: string }) {
  return (
    <div className="rounded-lg border border-line bg-panel px-4 py-3">
      <div className="text-xs text-muted">{label}</div>
      <div className={`mt-1 text-3xl font-semibold tabular-nums tracking-tight ${tone ?? ""}`}>{value}</div>
    </div>
  );
}

const pct = (n: number, of: number) => (of === 0 ? "-" : `${Math.round((n / of) * 100)}%`);

export function Overview({ onCheck }: { onCheck: (ioc: string) => void }) {
  const qc = useQueryClient();
  const stats = useQuery({ queryKey: ["stats"], queryFn: () => api.stats(30) });
  const watch = useQuery({ queryKey: ["watchlist"], queryFn: api.watchlist });
  const feeds = useQuery({ queryKey: ["feeds"], queryFn: api.feeds });
  // poll once a second while a background job runs, otherwise leave the list alone
  const sched = useQuery({
    queryKey: ["scheduler"],
    queryFn: api.scheduler,
    refetchInterval: (q) => (q.state.data?.some((j) => j.running) ? 1000 : false),
  });
  const watchJob = sched.data?.find((j) => j.name === "watch");
  const watchRunning = watchJob?.running ?? false;
  // progress arrives as "3/50"; empty until the first entry finishes
  const [done, total] = (watchJob?.progress ?? "").split("/").map(Number);
  const watchPct = done !== undefined && total ? Math.min(100, Math.round((done / total) * 100)) : 0;
  const wasRunning = useRef(false);
  useEffect(() => {
    if (wasRunning.current && !watchRunning) {
      void qc.invalidateQueries({ queryKey: ["watchlist"] });
      void qc.invalidateQueries({ queryKey: ["stats"] });
    }
    wasRunning.current = watchRunning;
  }, [watchRunning, qc]);
  const [importName, setImportName] = useState("");
  const runJob = useMutation({
    mutationFn: api.schedulerRun,
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["scheduler"] });
      void qc.invalidateQueries({ queryKey: ["watchlist"] });
      void qc.invalidateQueries({ queryKey: ["feeds"] });
    },
  });
  const importFeed = useMutation({
    mutationFn: async (file: File) => api.feedsImport(importName.trim(), await file.text()),
    onSuccess: () => {
      setImportName("");
      void qc.invalidateQueries({ queryKey: ["feeds"] });
    },
  });
  const forget = useMutation({ mutationFn: api.feedsForget, onSuccess: (list) => qc.setQueryData(["feeds"], list) });

  // start returns at once with the live status; the poll above shows progress
  const recheck = useMutation({
    mutationFn: () => api.schedulerStart("watch"),
    onSuccess: (job) => qc.setQueryData(["scheduler"], (all: JobStatus[] | undefined) => all?.map((j) => (j.name === job.name ? job : j))),
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

  const sum = (k: "malicious" | "suspicious") => s?.by_day.reduce((n, d) => n + d[k], 0) ?? 0;

  return (
    <div className="mx-auto w-full max-w-7xl space-y-4 p-5">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Tile label={`Checks, ${s?.days ?? 30} days`} value={s?.total ?? "-"} />
        <Tile label="Malicious" value={s ? sum("malicious") : "-"} tone="text-malicious" />
        <Tile label="Suspicious" value={s ? sum("suspicious") : "-"} tone="text-suspicious" />
        <Tile label="Watched indicators" value={watch.data?.entries.length ?? "-"} />
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
      <Panel title={`Checks per day${s ? ` (${s.total} in ${s.days} days)` : ""}`} label="Activity">
        {s ? <ActivityChart data={s.by_day} /> : <div className="pixel h-24" role="status" aria-label="Loading activity" />}
      </Panel>

      <Panel title="Source health, last 30 days" label="Source health">
        {s && s.sources.length === 0 && <p className="text-sm text-muted">Source statistics appear after the first check.</p>}
        {s && s.sources.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[420px] text-left text-sm">
              <thead>
                <tr className="text-xs text-muted">
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
          <Button size="sm" disabled={recheck.isPending || watchRunning || (watch.data?.entries.length ?? 0) === 0} onClick={() => recheck.mutate()}>
            {watchRunning ? "Re-checking…" : "Re-check all"}
          </Button>
          <span className="text-xs text-muted" role="status" aria-live="polite">
            {watchRunning && `Checked ${watchJob?.progress || "0"} entries so far.`}
            {!watchRunning && recheck.isSuccess && (watchJob?.last_ok === false ? `Re-check failed: ${watchJob.last_detail}` : watchJob?.last_detail.startsWith("0 verdict") ? "No verdict changed." : watchJob?.last_detail)}
            {recheck.isError && `Re-check failed: ${recheck.error.message}`}
            {!watchRunning && !recheck.isSuccess && !recheck.isError && "A re-check skips the cache and uses source quota."}
          </span>
        </div>
        {watchRunning && (
          <div
            role="progressbar"
            aria-label="Re-check progress"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={watchPct}
            className="mb-3 h-1.5 border border-line-strong"
          >
            <div className="hatch h-full text-accent-text" style={{ width: `${watchPct}%` }} />
          </div>
        )}
        {watch.data && watch.data.entries.length === 0 && <p className="text-sm text-muted">Nothing watched yet. Open a report and choose Watch.</p>}
        <ul>
          {watch.data?.entries.map((e) => (
            <li key={e.ioc} className="flex items-center gap-3 border-t border-line py-1.5 first:border-t-0">
              <span className="mono min-w-0 flex-1 truncate text-[13px]" title={e.ioc}>
                {shortenMiddle(e.ioc, 34)}
              </span>
              {e.last_level ? <LevelBadge level={e.last_level as Level} /> : <span className="label">not checked</span>}
              <Button variant="ghost" size="sm" onClick={() => remove.mutate(e.ioc)} aria-label={`Stop watching ${e.ioc}`}>
                Remove
              </Button>
            </li>
          ))}
        </ul>
        {watch.data && watch.data.events.length > 0 && (
          <div className="mt-3 border-t border-line pt-3">
            <h3 className="mb-1.5 text-xs font-medium text-muted">Recent changes</h3>
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
              <Button size="sm" onClick={() => onCheck(r.value)} aria-label={`Check ${r.value}`}>
                Check
              </Button>
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
                <dt className="text-xs text-muted">{k}</dt>
                <dd className="mono mt-1 text-lg">{v}</dd>
              </div>
            ))}
          </dl>
        )}
      </Panel>

      <Panel title="Scheduler" label="Scheduler">
        <p className="mb-3 text-xs text-muted">
          Background jobs run only while verdikt ui is open and are off unless set in .env (VERDIKT_WATCH_EVERY_HOURS, VERDIKT_FEEDS_EVERY_HOURS).
        </p>
        <ul className="space-y-3">
          {sched.data?.map((j) => (
            <li key={j.name} className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm">
              <span className="mono w-14">{j.name}</span>
              <span className="label">{j.every_hours > 0 ? `every ${j.every_hours} h` : "off"}</span>
              <span className="text-xs text-muted">
                {j.last_run ? `last ${ago(j.last_run)}: ${j.last_detail}` : "not run yet"}
                {j.next_run && ` · next ${ago(j.next_run).replace(" ago", "")}`}
              </span>
              <Button size="sm" className="ml-auto" disabled={runJob.isPending} onClick={() => runJob.mutate(j.name)} aria-label={`Run the ${j.name} job now`}>
                Run now
                </Button>
            </li>
          ))}
        </ul>
        {runJob.isError && (
          <p role="alert" className="mt-2 text-xs text-malicious">
            {runJob.error.message}
          </p>
        )}
      </Panel>

      <Panel title="Local data feeds" label="Local feeds">
        <div className="mb-3 flex flex-wrap items-center gap-3">
          <Button size="sm" disabled={update.isPending} onClick={() => update.mutate()}>
            {update.isPending ? "Downloading…" : "Update feeds"}
          </Button>
          <span className="text-xs text-muted" role="status" aria-live="polite">
            {update.isSuccess && `${update.data.filter((u) => u.ok).length}/${update.data.length} feeds updated.`}
            {update.isError && `Update failed: ${update.error.message}`}
            {!update.isSuccess && !update.isError && "About 14 MB of public lists, matched on this machine."}
          </span>
        </div>
        {feeds.data && feeds.data.length === 0 && <p className="text-sm text-muted">No feeds yet. Update them once to enable blocklists, top sites, KEV and EPSS.</p>}
        <ul className="mono space-y-1 text-xs">
          {feeds.data?.map((f) => (
            <li key={f.name} className="flex items-center justify-between gap-4">
              <span>{f.name}</span>
              <span className="text-muted">
                {f.count.toLocaleString()} entries · {ago(f.fetched_at)}
              </span>
              {f.name.startsWith("import:") && (
                <Button variant="ghost" size="sm" onClick={() => forget.mutate(f.name.slice("import:".length))} aria-label={`Forget imported list ${f.name.slice("import:".length)}`}>
                  Forget
                </Button>
              )}
            </li>
          ))}
        </ul>
        <div className="mt-4 space-y-2 border-t border-line pt-3">
          <h3 className="text-sm font-medium">Import MISP or STIX file</h3>
          <div className="flex flex-wrap items-center gap-2">
            <label htmlFor="import-name" className="sr-only">
              Name for the imported list
            </label>
            <input
              id="import-name"
              value={importName}
              onChange={(e) => setImportName(e.target.value)}
              placeholder="list-name"
              className={`${FIELD} mono w-40`}
            />
            <label htmlFor="import-file" className="sr-only">
              MISP event or STIX bundle file
            </label>
            <input
              id="import-file"
              type="file"
              accept=".json,application/json"
              disabled={!importName.trim() || importFeed.isPending}
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) importFeed.mutate(file);
                e.target.value = "";
              }}
              className="text-xs"
            />
          </div>
          <p className="text-xs text-muted" role="status" aria-live="polite">
            {importFeed.isSuccess && `Imported ${importFeed.data.count} indicator(s) from a ${importFeed.data.format} file as ${importFeed.data.name}.`}
            {importFeed.isError && `Import failed: ${importFeed.error.message}`}
            {!importFeed.isSuccess && !importFeed.isError && "Imported indicators count as blocklisted. MISP: only attributes marked to_ids."}
          </p>
        </div>
      </Panel>
      </div>
    </div>
  );
}
