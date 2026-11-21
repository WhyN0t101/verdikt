import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { api } from "../api";
import { PICK_LABEL, type PickMode, pickReports, watchPlan } from "../lib/batchActions";
import type { Report } from "../model";
import { Button, FIELD, Note } from "./ui";

const NEW_CASE = "new";
const errorText = (e: unknown) => (e instanceof Error ? e.message : "request failed");
const stamp = () => new Date().toISOString().slice(0, 16).replace("T", " ");

/** After a batch run: record the bad results in a case and/or put them on the watchlist. */
export function BatchTriage({ reports }: { reports: Report[] }) {
  const qc = useQueryClient();
  const cases = useQuery({ queryKey: ["cases"], queryFn: () => api.cases() });
  const watch = useQuery({ queryKey: ["watchlist"], queryFn: api.watchlist });
  const [mode, setMode] = useState<PickMode>("bad");
  const [target, setTarget] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [result, setResult] = useState<{ text: string; failed: boolean } | null>(null);
  const stop = useRef(false);

  const picked = pickReports(reports, mode);
  const max = watch.data?.max_entries ?? 0;
  const watched = watch.data?.entries.map((e) => e.ioc) ?? [];
  const plan = watchPlan(picked, watched, max);

  async function addToCase() {
    stop.current = false;
    setResult(null);
    let added = 0;
    try {
      // the title carries no indicator, so nothing raw can leak into an export
      const caseId = target === NEW_CASE ? (await api.caseCreate(`Batch triage, ${stamp()}`)).id : target;
      for (const r of picked) {
        if (stop.current) break;
        setBusy(`Adding ${added + 1} of ${picked.length}`);
        await api.caseAdd(caseId, r.id);
        added++;
      }
      setResult({ text: `${added} added to the case${added < picked.length ? `, ${picked.length - added} not added` : ""}.`, failed: false });
    } catch (e) {
      setResult({ text: `${added} added, then it stopped: ${errorText(e)}`, failed: true });
    } finally {
      setBusy(null);
      void qc.invalidateQueries({ queryKey: ["cases"] });
    }
  }

  async function watchAll() {
    stop.current = false;
    setResult(null);
    let added = 0;
    try {
      for (const r of plan.toAdd) {
        if (stop.current) break;
        setBusy(`Watching ${added + 1} of ${plan.toAdd.length}`);
        qc.setQueryData(["watchlist"], await api.watchAdd(r.id));
        added++;
      }
      const parts = [`${added} added`];
      if (plan.skippedAlready) parts.push(`${plan.skippedAlready} already watched`);
      if (plan.skippedCap) parts.push(`${plan.skippedCap} skipped: watchlist is full (${max})`);
      setResult({ text: `${parts.join(", ")}.`, failed: false });
    } catch (e) {
      setResult({ text: `${added} added, then it stopped: ${errorText(e)}`, failed: true });
    } finally {
      setBusy(null);
    }
  }

  if (reports.length === 0) return null;
  const none = picked.length === 0;
  return (
    <section aria-label="Triage actions" className="space-y-3 border-t border-line px-4 py-3">
      <div className="flex flex-wrap items-center gap-3">
        <label htmlFor="triage-mode" className="text-xs text-muted">
          Which results
        </label>
        <select id="triage-mode" value={mode} onChange={(e) => setMode(e.target.value as PickMode)} disabled={busy !== null} className={`${FIELD} h-8 w-auto py-0`}>
          {(Object.keys(PICK_LABEL) as PickMode[]).map((m) => (
            <option key={m} value={m}>
              {PICK_LABEL[m]}
            </option>
          ))}
        </select>
        <span className="mono text-xs text-muted">{picked.length} selected</span>
        {busy && (
          <>
            <span className="text-xs text-muted" role="status" aria-live="polite">
              {busy}
            </span>
            <Button size="sm" onClick={() => (stop.current = true)}>
              Stop
            </Button>
          </>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <label htmlFor="triage-case" className="sr-only">
          Case to add to
        </label>
        <select id="triage-case" value={target} onChange={(e) => setTarget(e.target.value)} disabled={busy !== null} className={`${FIELD} h-8 w-auto max-w-56 py-0`}>
          <option value="">Choose a case…</option>
          <option value={NEW_CASE}>New case</option>
          {cases.data?.map((c) => (
            <option key={c.id} value={c.id}>
              {c.title}
            </option>
          ))}
        </select>
        <Button size="sm" variant="primary" disabled={none || !target || busy !== null} onClick={() => void addToCase()}>
          Add {picked.length} to case
        </Button>
        <Button size="sm" disabled={plan.toAdd.length === 0 || busy !== null || !watch.data} onClick={() => void watchAll()}>
          Watch {plan.toAdd.length}
        </Button>
      </div>

      {watch.data && !none && (
        <p className="text-xs text-muted">
          Watchlist: {watched.length} of {max} used. Adding {plan.toAdd.length} leaves {Math.max(0, max - watched.length - plan.toAdd.length)}.
          {plan.skippedAlready > 0 && ` ${plan.skippedAlready} already watched.`}
          {plan.skippedCap > 0 && ` ${plan.skippedCap} will be skipped: the list is full.`} A re-check spends source quota on every entry.
        </p>
      )}
      {none && <p className="text-xs text-muted">No checked result matches. Pick another level, or check the indicators first.</p>}
      {result && <Note tone={result.failed ? "error" : "muted"}>{result.text}</Note>}
    </section>
  );
}
