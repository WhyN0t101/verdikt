import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Suspense, lazy, useCallback, useEffect, useRef, useState } from "react";
import { api } from "./api";
import { CommandBar } from "./components/CommandBar";
import { EmptyState } from "./components/EmptyState";
import { HistoryList } from "./components/HistoryList";
import { LogStream } from "./components/LogStream";
import { MapView } from "./components/MapView";
import { RawJson } from "./components/RawJson";
import { SourceTable } from "./components/SourceTable";
import { VerdictCard } from "./components/VerdictCard";
import { formatDuration, formatQuota } from "./lib/format";
import type { Report } from "./model";

// Cytoscape is the largest dependency; load it only when the Graph tab opens.
const GraphView = lazy(() => import("./components/GraphView").then((m) => ({ default: m.GraphView })));

type Tab = "map" | "graph" | "raw";
const TABS: { id: Tab; label: string; key: string }[] = [
  { id: "map", label: "Map", key: "1" },
  { id: "graph", label: "Graph", key: "2" },
  { id: "raw", label: "Raw JSON", key: "3" },
];

type Theme = "dark" | "light";

function initialTheme(): Theme {
  try {
    const saved = localStorage.getItem("verdikt-theme");
    if (saved === "dark" || saved === "light") return saved;
  } catch {
    /* storage can be blocked; fall through */
  }
  return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

export default function App() {
  const qc = useQueryClient();
  const input = useRef<HTMLInputElement>(null);
  const [value, setValue] = useState("");
  const [report, setReport] = useState<Report | null>(null);
  const [tab, setTab] = useState<Tab>("map");
  const [theme, setTheme] = useState<Theme>(initialTheme);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem("verdikt-theme", theme);
    } catch {
      /* ignore */
    }
  }, [theme]);

  const history = useQuery({ queryKey: ["reports"], queryFn: api.reports });
  const sources = useQuery({ queryKey: ["sources"], queryFn: api.sources });

  const check = useMutation({
    mutationFn: (ioc: string) => api.check(ioc),
    onSuccess: (r) => {
      setReport(r);
      void qc.invalidateQueries({ queryKey: ["reports"] });
      void qc.invalidateQueries({ queryKey: ["sources"] });
    },
  });

  const run = useCallback(
    (ioc: string) => {
      setValue(ioc);
      check.mutate(ioc);
    },
    [check],
  );

  const open = useCallback(async (id: string) => {
    const r = await api.report(id);
    setReport(r);
    setValue(r.ioc);
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        input.current?.focus();
        input.current?.select();
        return;
      }
      const typing = e.target instanceof HTMLElement && ["INPUT", "TEXTAREA"].includes(e.target.tagName);
      if (e.key === "Escape") {
        setValue("");
        input.current?.focus();
      } else if (!typing && !e.ctrlKey && !e.metaKey && !e.altKey) {
        const t = TABS.find((x) => x.key === e.key);
        if (t) setTab(t.id);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const vt = sources.data?.find((s) => s.name === "virustotal");
  const enabled = sources.data?.filter((s) => s.enabled) ?? [];
  const noKeys = sources.data !== undefined && enabled.length <= 1;

  return (
    <div className="relative flex min-h-full flex-col">
      <header className="flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-line bg-panel px-4 py-2.5">
        <div className="flex items-center gap-2">
          <span aria-hidden="true" className="grid h-7 w-7 place-items-center rounded-lg bg-violet-600 font-mono text-sm font-bold text-white" style={{ background: "var(--violet-600)" }}>
            v
          </span>
          <span className="text-base font-bold tracking-tight">verdikt</span>
        </div>
        <CommandBar ref={input} value={value} pending={check.isPending} onChange={setValue} onSubmit={() => check.mutate(value)} />
        <div className="mono flex items-center gap-3 text-xs text-muted">
          {report && <span title="Last lookup">{formatDuration(report.duration_ms)}</span>}
          {vt && (
            <span title="VirusTotal requests used today">
              VT {formatQuota(vt.used_today, vt.daily_budget)}
            </span>
          )}
          <button
            type="button"
            className="rounded border border-line px-2 py-1 hover:border-accent"
            onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
            aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
          >
            {theme === "dark" ? "Light" : "Dark"}
          </button>
        </div>
      </header>

      <div className="mono border-b border-line px-4 py-1.5 text-xs text-muted" aria-label="Breadcrumb">
        verdikt / check / <span className="text-ink">{report?.ioc ?? "-"}</span>
      </div>

      <div className="grid flex-1 gap-4 p-4 lg:grid-cols-[15rem_minmax(0,1fr)] xl:grid-cols-[15rem_minmax(0,1fr)_19rem]">
        <aside className="rounded-md border border-line bg-panel py-2 lg:max-h-[calc(100vh-7rem)] lg:overflow-y-auto">
          <h2 className="label px-3 pb-2">History</h2>
          <HistoryList items={history.data ?? []} activeId={report?.id ?? null} onSelect={(id) => void open(id)} />
        </aside>

        <main className="min-w-0 space-y-4">
          {noKeys && (
            <p className="rounded-md border border-line-strong bg-panel p-3 text-sm" role="note">
              Only keyless sources are enabled. Add API keys to .env to enable more (see .env.example).
            </p>
          )}
          {check.isError && (
            <p role="alert" className="rounded-md border border-malicious bg-panel p-3 text-sm text-malicious">
              {check.error.message}
            </p>
          )}
          {!report && !check.isPending && <EmptyState />}
          {(report || check.isPending) && (
            <>
              {report && !check.isPending && <VerdictCard report={report} />}
              {check.isPending && <div className="pixel h-28 rounded-md" role="status" aria-label="Checking" />}
              <SourceTable report={check.isPending ? null : report} pending={check.isPending ? enabled : null} />
              {report && !check.isPending && (
                <section aria-label="Visualisations">
                  <div role="tablist" className="mb-3 flex gap-1 border-b border-line">
                    {TABS.map((t) => (
                      <button
                        key={t.id}
                        role="tab"
                        type="button"
                        aria-selected={tab === t.id}
                        onClick={() => setTab(t.id)}
                        className={`-mb-px border-b-2 px-3 py-2 text-sm ${tab === t.id ? "border-accent text-ink" : "border-transparent text-muted"}`}
                      >
                        {t.label} <span className="label">{t.key}</span>
                      </button>
                    ))}
                  </div>
                  {tab === "map" && <MapView geo={report.geo} onPivot={run} />}
                  {tab === "graph" && (
                    <Suspense fallback={<div className="pixel h-24 rounded-md" role="status" aria-label="Loading graph" />}>
                      <GraphView
                        graph={report.graph}
                        rootId={report.graph.nodes[0]?.id ?? ""}
                        theme={theme}
                        sources={sources.data ?? []}
                        pending={check.isPending}
                        onPivot={run}
                      />
                    </Suspense>
                  )}
                  {tab === "raw" && <RawJson id={report.id} />}
                </section>
              )}
            </>
          )}
        </main>

        <div className="space-y-4 lg:col-span-2 xl:col-span-1">
          <LogStream report={check.isPending ? null : report} />
        </div>
      </div>
    </div>
  );
}
