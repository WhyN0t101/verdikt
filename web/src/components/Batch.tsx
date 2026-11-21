import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { api } from "../api";
import { downloadText, toCsv } from "../lib/csv";
import { shortenMiddle, typeTag } from "../lib/format";
import type { Extraction, IOCType, Report } from "../model";
import { BatchTriage } from "./BatchTriage";
import { LevelBadge } from "./LevelBadge";
import { Button, FIELD } from "./ui";

type Row = {
  value: string;
  type: IOCType;
  state: "pending" | "running" | "done" | "error";
  report?: Report;
  error?: string;
};

const CSV_HEADER = ["ioc", "type", "level", "confidence", "agreeing", "total", "report_id", "reasons"];

/** Paste a ticket or a list: extract the indicators, check them one by one, export the table. */
export function Batch({ onOpen }: { onOpen: (id: string) => void }) {
  const qc = useQueryClient();
  const [text, setText] = useState("");
  const [found, setFound] = useState<Extraction | null>(null);
  const [rows, setRows] = useState<Row[]>([]);
  const [running, setRunning] = useState(false);
  const stop = useRef(false);

  const extract = useMutation({
    mutationFn: () => api.extract(text),
    onSuccess: (e) => {
      setFound(e);
      setRows(e.items.map((i) => ({ value: i.value, type: i.type, state: "pending" })));
    },
  });

  const patch = (i: number, change: Partial<Row>) => setRows((all) => all.map((r, j) => (j === i ? { ...r, ...change } : r)));

  async function runAll() {
    stop.current = false;
    setRunning(true);
    // one at a time: the per-source rate limiters and daily budgets are the real limit
    for (let i = 0; i < rows.length && !stop.current; i++) {
      const row = rows[i];
      if (!row || row.state === "done") continue;
      patch(i, { state: "running", error: undefined });
      try {
        patch(i, { state: "done", report: await api.check(row.value) });
      } catch (e) {
        patch(i, { state: "error", error: e instanceof Error ? e.message : "failed" });
      }
    }
    setRunning(false);
    void qc.invalidateQueries({ queryKey: ["reports"] });
    void qc.invalidateQueries({ queryKey: ["sources"] });
    void qc.invalidateQueries({ queryKey: ["stats"] });
  }

  const done = rows.filter((r) => r.state === "done").length;

  function exportCsv() {
    const body = rows
      .filter((r): r is Row & { report: Report } => r.report !== undefined)
      .map(({ report: p }) => [p.ioc, p.ioc_type, p.level, p.confidence, String(p.agreeing), String(p.total), p.id, p.reasons.join(" | ")]);
    downloadText("verdikt-batch.csv", toCsv([CSV_HEADER, ...body]), "text/csv");
  }

  return (
    <div className="mx-auto w-full max-w-5xl space-y-4 p-5">
      <section aria-label="Paste text" className="rounded-lg border border-line bg-panel">
        <h2 className="border-b border-line px-4 py-3 text-sm font-semibold">Paste a ticket, an email or a list</h2>
        <div className="space-y-3 p-4">
          <label htmlFor="batch-text" className="sr-only">
            Text containing indicators
          </label>
          <textarea
            id="batch-text"
            value={text}
            onChange={(e) => setText(e.target.value)}
            rows={6}
            spellCheck={false}
            placeholder="Any text. IPs, domains, URLs and hashes are found, including defanged ones like hxxp://evil[.]com."
            className={`${FIELD} mono resize-y p-3 text-[13px]`}
          />
          <div className="flex flex-wrap items-center gap-3">
            <Button variant="primary" disabled={!text.trim() || extract.isPending || running} onClick={() => extract.mutate()}>
              Extract indicators
            </Button>
            {extract.isError && (
              <span role="alert" className="text-sm text-malicious">
                {extract.error.message}
              </span>
            )}
          </div>
        </div>
      </section>

      {found && (
        <section aria-label="Batch results" className="rounded-lg border border-line bg-panel">
          <div className="flex flex-wrap items-center gap-3 border-b border-line px-4 py-2.5">
            <h2 className="mr-auto text-sm font-semibold">
              {rows.length} indicator{rows.length === 1 ? "" : "s"} found · {done} checked
            </h2>
            {running ? (
              <Button size="sm" onClick={() => (stop.current = true)}>
                Stop
              </Button>
            ) : (
              <Button size="sm" variant="primary" disabled={rows.length === 0 || done === rows.length} onClick={() => void runAll()}>
                Check all {rows.length - done}
              </Button>
            )}
            <Button size="sm" disabled={done === 0} onClick={exportCsv}>
              Export CSV
            </Button>
          </div>

          {rows.length === 0 && <p className="p-4 text-sm text-muted">No indicators found in that text.</p>}
          {found.truncated && <p className="border-b border-line px-4 py-2 text-sm">Only the first {rows.length} indicators are listed.</p>}
          {rows.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[560px] text-left text-sm">
                <thead>
                  <tr className="text-xs text-muted">
                    <th className="px-4 py-2 font-normal">Indicator</th>
                    <th className="px-2 py-2 font-normal">Type</th>
                    <th className="px-2 py-2 font-normal">Verdict</th>
                    <th className="px-2 py-2 font-normal">Confidence</th>
                    <th className="px-4 py-2 text-right font-normal">Report</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => (
                    <tr key={r.value} className="border-t border-line">
                      <td className="mono px-4 py-1.5 text-[13px]" title={r.value}>
                        {shortenMiddle(r.value, 40)}
                      </td>
                      <td className="label px-2">{typeTag(r.type)}</td>
                      <td className="px-2">
                        {r.state === "done" && r.report && <LevelBadge level={r.report.level} />}
                        {r.state === "pending" && <span className="label">waiting</span>}
                        {r.state === "running" && <span className="pixel inline-block h-3 w-20" role="status" aria-label={`Checking ${r.value}`} />}
                        {r.state === "error" && <span className="text-malicious">{r.error}</span>}
                      </td>
                      <td className="mono px-2 text-[13px]">{r.report?.confidence ?? ""}</td>
                      <td className="px-4 text-right">
                        {r.report && (
                          <Button variant="ghost" size="sm" onClick={() => onOpen(r.report?.id ?? "")} aria-label={`Open report for ${r.value}`}>
                            Open
                          </Button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {!running && <BatchTriage reports={rows.flatMap((r) => (r.report ? [r.report] : []))} />}

          {found.skipped.length > 0 && (
            <details className="border-t border-line px-4 py-3 text-sm">
              <summary className="cursor-pointer text-muted">{found.skipped.length} skipped (internal or invalid)</summary>
              <ul className="mono mt-2 space-y-1 text-xs">
                {found.skipped.map((s) => (
                  <li key={s.value}>
                    {s.value}: {s.reason}
                  </li>
                ))}
              </ul>
            </details>
          )}
        </section>
      )}
    </div>
  );
}
