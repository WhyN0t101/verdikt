import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import { ago, shortenMiddle } from "../lib/format";
import { parseProgress } from "../lib/progress";
import { describeWatch } from "../lib/watchText";
import type { JobStatus, Level } from "../model";
import { ActivityChart } from "./ActivityChart";
import { LEVEL_BG, LevelBadge } from "./LevelBadge";
import { SourcesPanel } from "./SourcesPanel";
import { Button, FIELD, Panel } from "./ui";

function Tile({ label, value, tone }: { label: string; value: string | number; tone?: string }) {
  return (
    <div className="rounded-lg border border-line bg-panel px-4 py-3">
      <div className="text-xs text-muted">{label}</div>
      <div className={`mt-1 text-3xl font-semibold tabular-nums tracking-tight ${tone ?? ""}`}>{value}</div>
    </div>
  );
}

/** Determinate when the job reports "done/total", otherwise the stepped pixel bar. */
function JobBar({ progress, label }: { progress: string; label: string }) {
  const frac = parseProgress(progress);
  return (
    <div
      role="progressbar"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={frac === null ? undefined : Math.round(frac * 100)}
      className="h-1.5 border border-line-strong"
    >
      {frac === null ? <div className="pixel h-full w-full" /> : <div className="hatch h-full text-accent-text" style={{ width: `${frac * 100}%` }} />}
    </div>
  );
}

const pct = (n: number, of: number) => (of === 0 ? "-" : `${Math.round((n / of) * 100)}%`);

export function Overview({ onCheck, onOpen }: { onCheck: (ioc: string) => void; onOpen: (reportId: string) => void }) {
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
  // when any background job finishes, what it changed must be fetched again
  const wasRunning = useRef<Record<string, boolean>>({});
  useEffect(() => {
    const now = Object.fromEntries((sched.data ?? []).map((j) => [j.name, j.running]));
    const finished = Object.entries(wasRunning.current).some(([name, was]) => was && !now[name]);
    wasRunning.current = now;
    if (finished) {
      for (const key of ["watchlist", "stats", "feeds"]) void qc.invalidateQueries({ queryKey: [key] });
    }
  }, [sched.data, qc]);
  const [importName, setImportName] = useState("");
  const [allAttrs, setAllAttrs] = useState(false);
  // one path for every job button: start returns at once with the live status and the poll above shows progress
  const startJob = useMutation({
    mutationFn: api.schedulerStart,
    onSuccess: (job) => qc.setQueryData(["scheduler"], (all: JobStatus[] | undefined) => all?.map((j) => (j.name === job.name ? job : j))),
  });
  const importFeed = useMutation({
    mutationFn: async (file: File) => api.feedsImport(importName.trim(), await file.text(), allAttrs),
    onSuccess: () => {
      setImportName("");
      void qc.invalidateQueries({ queryKey: ["feeds"] });
    },
  });
  const forget = useMutation({ mutationFn: api.feedsForget, onSuccess: (list) => qc.setQueryData(["feeds"], list) });

  const remove = useMutation({
    mutationFn: api.watchRemove,
    onSuccess: (state) => qc.setQueryData(["watchlist"], state),
  });
  const update = useMutation({
    mutationFn: api.feedsUpdate,
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["feeds"] }),
  });

  // the headline above is only for a re-check started here; the detail text comes from the job itself
  const watchChecked = startJob.isSuccess && startJob.variables === "watch";
  const watchEvidence = watchJob ? describeWatch(watchJob.last_detail, watchJob.last_ok).evidence : null;

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

      <SourcesPanel className="lg:col-span-2" />

      <Panel title="Source health, last 30 days" label="Source health">
        {s && s.sources.length === 0 && <p className="text-sm text-muted">Source statistics appear after the first check.</p>}
        {s && s.sources.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[420px] text-left text-sm">
              <thead>
                <tr className="text-xs text-muted">
                  <th className="pb-2 font-normal">Source</th>
                  <th className="pb-2 font-normal">Answered</th>
                  <th className="pb-2 font-normal">Not found</th>
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
                    <td>{h.not_found}</td>
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

      <Panel title={`Watchlist${watch.data ? `, ${watch.data.entries.length} of ${watch.data.max_entries}` : ""}`} label="Watchlist">
        <div className="mb-3 flex flex-wrap items-center gap-3">
          <Button size="sm" disabled={startJob.isPending || watchRunning || (watch.data?.entries.length ?? 0) === 0} onClick={() => startJob.mutate("watch")}>
            {watchRunning ? "Re-checking…" : "Re-check all"}
          </Button>
          <span className="text-xs text-muted" role="status" aria-live="polite">
            {watchRunning && (parseProgress(watchJob?.progress ?? "") === null ? "Starting…" : `Checked ${watchJob?.progress} entries so far.`)}
            {!watchRunning && watchChecked && watchJob && describeWatch(watchJob.last_detail, watchJob.last_ok).text}
            {startJob.isError && `Re-check failed: ${startJob.error.message}`}
            {!watchRunning && !watchChecked && !startJob.isError && "A re-check skips the cache and uses source quota."}
          </span>
        </div>
        {watchRunning && <JobBar progress={watchJob?.progress ?? ""} label="Re-check progress" />}
        {!watchRunning && watchChecked && watchEvidence && (
          <p className="mt-3 border-l-2 border-accent pl-2 text-xs" role="status">
            {watchEvidence}
          </p>
        )}
        {watch.data && watch.data.entries.length === 0 && <p className="text-sm text-muted">Nothing watched yet. Open a report and choose Watch.</p>}
        <ul>
          {watch.data?.entries.map((e) => (
            <li key={e.ioc} className="border-t border-line py-1.5 first:border-t-0">
              <div className="flex items-center gap-3">
                <span className="mono min-w-0 flex-1 truncate text-[13px]" title={e.ioc}>
                  {shortenMiddle(e.ioc, 34)}
                </span>
                {e.last_level ? <LevelBadge level={e.last_level as Level} /> : <span className="label">not checked</span>}
                <Button variant="ghost" size="sm" onClick={() => remove.mutate(e.ioc)} aria-label={`Stop watching ${e.ioc}`}>
                  Remove
                </Button>
              </div>
              <p className="mono mt-0.5 flex flex-wrap items-center gap-x-2 text-[11px] text-muted">
                <span>added {ago(e.added_at)}</span>
                <span>{e.last_checked_at ? `checked ${ago(e.last_checked_at)}` : "not checked yet"}</span>
                {e.last_report_id && (
                  <button
                    type="button"
                    onClick={() => onOpen(e.last_report_id ?? "")}
                    aria-label={`Open the last report for ${e.ioc}`}
                    className="text-accent-text underline-offset-2 hover:underline"
                  >
                    last report
                  </button>
                )}
              </p>
            </li>
          ))}
        </ul>
        {watch.data && watch.data.events.length > 0 && (
          <div className="mt-3 border-t border-line pt-3">
            <h3 className="mb-1.5 text-xs font-medium text-muted">Recent changes</h3>
            <ul className="mono space-y-1 text-xs">
              {watch.data.events.slice(0, 6).map((ev) => (
                <li key={ev.id} className="flex items-center gap-2">
                  <span className="min-w-0 flex-1">
                    {ago(ev.at)} · {shortenMiddle(ev.ioc, 26)}: {ev.from_level} → {ev.to_level}
                  </span>
                  <Button variant="ghost" size="sm" onClick={() => onOpen(ev.report_id)} aria-label={`What changed for ${ev.ioc}`}>
                    What changed
                  </Button>
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
            <li key={j.name} className="space-y-1.5">
              <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm">
                <span className="mono w-14">{j.name}</span>
                <span className="label">{j.every_hours > 0 ? `every ${j.every_hours} h` : "off"}</span>
                <span className="text-xs text-muted">
                  {j.running ? "running…" : j.last_run ? `last ${ago(j.last_run)}${j.last_ok === false ? " (failed)" : ""}: ${j.last_detail}` : "not run yet"}
                  {!j.running && j.next_run && ` · next ${ago(j.next_run).replace(" ago", "")}`}
                </span>
                <Button size="sm" className="ml-auto" disabled={startJob.isPending || j.running} onClick={() => startJob.mutate(j.name)} aria-label={`Run the ${j.name} job now`}>
                  Run now
                </Button>
              </div>
              {j.running && <JobBar progress={j.progress} label={`${j.name} job progress`} />}
            </li>
          ))}
        </ul>
        {startJob.isError && (
          <p role="alert" className="mt-2 text-xs text-malicious">
            {startJob.error.message}
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
            {!update.isSuccess && !update.isError && "About 15 MB of public lists (it varies), matched on this machine."}
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
          <label className="flex items-center gap-2 text-xs">
            <input type="checkbox" checked={allAttrs} onChange={(e) => setAllAttrs(e.target.checked)} />
            Include MISP attributes not marked for IDS (to_ids)
          </label>
          <p className="text-xs text-muted" role="status" aria-live="polite">
            {importFeed.isSuccess && `Imported ${importFeed.data.count} indicator(s) from a ${importFeed.data.format} file as ${importFeed.data.name}.`}
            {importFeed.isError && `Import failed: ${importFeed.error.message}`}
            {!importFeed.isSuccess && !importFeed.isError && "Imported indicators count as blocklisted. MISP: only attributes marked to_ids, unless the box above is ticked."}
          </p>
        </div>
      </Panel>
      </div>
    </div>
  );
}
