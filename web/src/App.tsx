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
import { Diagnostics, VerdictHud } from "./components/VerdictCard";
import { Waterfall } from "./components/Waterfall";
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
  const [openError, setOpenError] = useState<string | null>(null);

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
      setOpenError(null);
      setReport(r);
      void qc.invalidateQueries({ queryKey: ["reports"] });
      void qc.invalidateQueries({ queryKey: ["sources"] });
    },
  });

  const run = useCallback(
    (ioc: string) => {
      if (check.isPending) return; // a late answer to the first check must not replace the second
      setValue(ioc);
      check.mutate(ioc);
    },
    [check],
  );

  const open = useCallback(async (id: string) => {
    try {
      const r = await api.report(id);
      setOpenError(null);
      setReport(r);
      setValue(r.ioc);
    } catch (e) {
      setOpenError(e instanceof Error ? e.message : "could not open the report");
    }
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
  // keyless sources (InternetDB, OTX, ...) are always on, so test for any key-gated source
  const noKeys = sources.data !== undefined && !enabled.some((s) => s.requires_key);

  const showReport = report !== null && !check.isPending;
  const quotas = sources.data?.filter((s) => s.daily_budget !== null) ?? [];

  return (
    <div className="relative flex min-h-full flex-col lg:h-full">
      <header className="flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-line bg-panel px-4 py-2.5">
        <div className="flex items-center gap-2">
          <svg aria-hidden="true" viewBox="0 0 32 32" className="h-7 w-7">
            <rect width="32" height="32" rx="7" fill="var(--violet-600)" />
            <path d="M8.5 10l7.5 13 7.5-13" stroke="#fff" strokeWidth="3.4" fill="none" strokeLinejoin="miter" />
            <path d="M3.5 10h6M22.5 10h6" stroke="#fff" strokeWidth="1.6" />
          </svg>
          <span className="text-lg font-bold tracking-tight">verdikt</span>
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


      <div className="grid min-h-0 flex-1 lg:grid-cols-[14rem_minmax(0,1fr)] xl:grid-cols-[14rem_minmax(0,1fr)_20rem]">
        <aside className="border-b border-line bg-panel py-2 lg:overflow-y-auto lg:border-b-0 lg:border-r">
          <h2 className="label px-4 pb-2 pt-1">History</h2>
          <HistoryList items={history.data ?? []} activeId={report?.id ?? null} onSelect={(id) => void open(id)} />
        </aside>

        <main className="flex min-h-0 min-w-0 flex-col">
          {(noKeys || openError || check.isError) && (
            <div className="space-y-px">
              {noKeys && (
                <p className="border-b border-line bg-panel px-4 py-2 text-sm" role="note">
                  Only keyless sources are enabled. Add API keys to .env to enable more (see .env.example).
                </p>
              )}
              {openError && (
                <p role="alert" className="border-b border-malicious bg-panel px-4 py-2 text-sm text-malicious">
                  {openError}
                </p>
              )}
              {check.isError && (
                <p role="alert" className="border-b border-malicious bg-panel px-4 py-2 text-sm text-malicious">
                  {check.error.message}
                </p>
              )}
            </div>
          )}

          <section aria-label="Visualisations" className="frame min-h-[26rem] flex-1 overflow-hidden">
            {tab !== "map" && showReport ? null : <MapView geo={showReport ? report.geo : []} onPivot={run} />}
            {showReport && tab === "graph" && (
              <div className="absolute inset-0 z-[1] bg-bg">
                <Suspense fallback={<div className="pixel m-4 h-24" role="status" aria-label="Loading graph" />}>
                  <GraphView
                    graph={report.graph}
                    rootId={report.graph.nodes[0]?.id ?? ""}
                    theme={theme}
                    sources={sources.data ?? []}
                    pending={check.isPending}
                    onPivot={run}
                  />
                </Suspense>
              </div>
            )}
            {showReport && tab === "raw" && (
              <div className="absolute inset-0 z-[1] bg-bg">
                <RawJson id={report.id} />
              </div>
            )}
            {check.isPending && <div className="sweep" role="status" aria-label="Checking" />}
            {!report && !check.isPending && <EmptyState />}

            {showReport && (
              <>
                <div className="absolute left-4 top-4 z-10 w-[calc(100%-2rem)] max-w-md">
                  <VerdictHud report={report} />
                </div>
                <div role="tablist" className="hud absolute right-4 top-4 z-10 flex">
                  {TABS.map((t) => (
                    <button
                      key={t.id}
                      role="tab"
                      type="button"
                      aria-selected={tab === t.id}
                      onClick={() => setTab(t.id)}
                      className={`border-b-2 px-3 py-1.5 text-sm ${tab === t.id ? "border-accent text-ink" : "border-transparent text-muted"}`}
                    >
                      {t.label} <span className="label">{t.key}</span>
                    </button>
                  ))}
                </div>
                {tab === "map" && (
                  <p className="mono absolute bottom-4 left-4 z-10 max-w-sm text-xs text-muted">
                    {report.geo.length === 0
                      ? "No location for this indicator. Locations need an IP and the GeoLite2 databases (set VERDIKT_GEOIP_DIR in .env)."
                      : "Locations are approximate: cloud, CDN and VPN addresses resolve to the provider's registered location, not the operator's."}
                  </p>
                )}
              </>
            )}
          </section>

          {(check.isPending || report) && (
            <div className="max-h-[36%] shrink-0 overflow-auto border-t border-line">
              <SourceTable report={check.isPending ? null : report} pending={check.isPending ? enabled : null} />
            </div>
          )}
        </main>

        <div className="border-t border-line bg-panel lg:col-span-2 lg:overflow-y-auto xl:col-span-1 xl:border-l xl:border-t-0">
          <Diagnostics report={showReport ? report : null} />
          <Waterfall report={showReport ? report : null} />
          <LogStream report={check.isPending ? null : report} />
          {quotas.length > 0 && (
            <section aria-label="Daily quota">
              <h2 className="label px-4 py-2.5">Daily quota</h2>
              <ul className="space-y-2 px-4 pb-4">
                {quotas.map((s) => {
                  const pct = Math.min(100, (s.used_today / (s.daily_budget ?? 1)) * 100);
                  return (
                    <li key={s.name}>
                      <div className="mono flex justify-between text-xs">
                        <span>{s.name}</span>
                        <span className="text-muted">{formatQuota(s.used_today, s.daily_budget)}</span>
                      </div>
                      <div className="mt-1 h-1.5 border border-line-strong" aria-hidden="true">
                        <div className="hatch h-full text-accent-text" style={{ width: `${pct}%` }} />
                      </div>
                    </li>
                  );
                })}
              </ul>
            </section>
          )}
        </div>
      </div>
    </div>
  );
}
