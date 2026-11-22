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

  /** One sequential loop for both actions: counter text, Stop, and the first error ends it. */
  async function runEach<T>(items: T[], step: (item: T) => Promise<unknown>, verb: string) {
    stop.current = false;
    setResult(null);
    let done = 0;
    let failure: string | null = null;
    try {
      for (const item of items) {
        if (stop.current) break;
        setBusy(`${verb} ${done + 1} of ${items.length}`);
        await step(item);
        done++;
      }
    } catch (e) {
      failure = errorText(e);
    } finally {
      setBusy(null);
    }
    return { done, failure };
  }

  async function addToCase() {
    let caseId = target;
    const created = target === NEW_CASE;
    if (created) {
      try {
        // the title carries no indicator, so nothing raw can leak into an export
        caseId = (await api.caseCreate(`Batch triage, ${stamp()}`)).id;
      } catch (e) {
        setResult({ text: `Could not create the case: ${errorText(e)}`, failed: true });
        return;
      }
    }
    const { done, failure } = await runEach(picked, (r) => api.caseAdd(caseId, r.id), "Adding");
    let left = "";
    if (created && done === 0) {
      // nothing went in: do not leave an empty case behind
      left = await api.caseDelete(caseId).then(
        () => "",
        () => " An empty case was left behind; delete it on the Cases page.",
      );
    } else if (created) {
      await qc.refetchQueries({ queryKey: ["cases"] });
      setTarget(caseId); // a second click adds to this case instead of creating another
    }
    void qc.invalidateQueries({ queryKey: ["cases"] });
    void qc.invalidateQueries({ queryKey: ["history"] });
    setResult(
      failure
        ? { text: `${done} added, then it stopped: ${failure}.${left}`, failed: true }
        : { text: `${done} added to the case${done < picked.length ? `, ${picked.length - done} not added` : ""}.`, failed: false },
    );
  }

  async function watchAll() {
    const { done, failure } = await runEach(plan.toAdd, async (r) => qc.setQueryData(["watchlist"], await api.watchAdd(r.id)), "Watching");
    void qc.invalidateQueries({ queryKey: ["history"] });
    if (failure) return setResult({ text: `${done} added, then it stopped: ${failure}.`, failed: true });
    const parts = [`${done} added`];
    if (plan.skippedAlready) parts.push(`${plan.skippedAlready} already watched`);
    if (plan.skippedCap) parts.push(`${plan.skippedCap} skipped: watchlist is full (${max})`);
    setResult({ text: `${parts.join(", ")}.`, failed: false });
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
        {!target && !none && <span className="text-xs text-muted">Choose a case first.</span>}
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
