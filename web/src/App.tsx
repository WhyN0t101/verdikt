import { keepPreviousData, useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Suspense, lazy, useCallback, useEffect, useRef, useState } from "react";
import { api } from "./api";
import { CommandBar } from "./components/CommandBar";
import { EmptyState } from "./components/EmptyState";
import { HistoryFilters } from "./components/HistoryFilters";
import { HistoryList } from "./components/HistoryList";
import { LevelBadge } from "./components/LevelBadge";
import { Batch } from "./components/Batch";
import { Cases } from "./components/Cases";
import { Logo } from "./components/Logo";
import { Button, Segmented, SectionTitle } from "./components/ui";
import { LogStream } from "./components/LogStream";
import { MapView } from "./components/MapView";
import { Overview } from "./components/Overview";
import { RawJson } from "./components/RawJson";
import { SourceTable } from "./components/SourceTable";
import { ReportActions } from "./components/ReportActions";
import { Diagnostics, VerdictHud } from "./components/VerdictCard";
import { Waterfall } from "./components/Waterfall";
import { downloadText } from "./lib/csv";
import { formatDuration, formatQuota } from "./lib/format";
import { type HistoryFilter, NO_FILTER, PAGE_SIZE, historyCsv, isFiltered, reportParams } from "./lib/historyQuery";
import type { Report } from "./model";

// Cytoscape is the largest dependency; load it only when the Graph tab opens.
const GraphView = lazy(() => import("./components/GraphView").then((m) => ({ default: m.GraphView })));

type Tab = "map" | "graph" | "raw";
const TABS: { id: Tab; label: string; key: string }[] = [
  { id: "map", label: "Map", key: "1" },
  { id: "graph", label: "Graph", key: "2" },
  { id: "raw", label: "Raw JSON", key: "3" },
];

type View = "check" | "overview" | "batch" | "cases";
const VIEWS: { id: View; label: string }[] = [
  { id: "check", label: "Check" },
  { id: "overview", label: "Overview" },
  { id: "batch", label: "Batch" },
  { id: "cases", label: "Cases" },
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

function Readout({ label, value }: { label: string; value: string }) {
  return (
    <div className="leading-none">
      <div className="text-[11px] text-muted">{label}</div>
      <div className="mono mt-1.5 text-[13px] font-medium">{value}</div>
    </div>
  );
}

export default function App() {
  const qc = useQueryClient();
  const input = useRef<HTMLInputElement>(null);
  const reportRef = useRef<string | null>(null);
  const [value, setValue] = useState("");
  const [report, setReport] = useState<Report | null>(null);
  const [tab, setTab] = useState<Tab>("map");
  const [view, setView] = useState<View>("check");
  const [theme, setTheme] = useState<Theme>(initialTheme);
  const [openError, setOpenError] = useState<string | null>(null);
  // a counter so asking for the same row twice moves focus again; tied to a report so a new report never steals focus
  const [focusSource, setFocusSource] = useState<{ id: string; name: string; n: number } | null>(null);
  const [openCaseId, setOpenCaseId] = useState<string | null>(null);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem("verdikt-theme", theme);
    } catch {
      /* ignore */
    }
  }, [theme]);

  const [filter, setFilter] = useState<HistoryFilter>(NO_FILTER);
  const changeFilter = useCallback((change: Partial<HistoryFilter>) => setFilter((f) => ({ ...f, ...change })), []);
  // pages of PAGE_SIZE; a full page means there may be more. A new report can shift rows by one between pages.
  const history = useInfiniteQuery({
    queryKey: ["reports", filter],
    queryFn: ({ pageParam }) => api.reports(reportParams(filter, pageParam)),
    initialPageParam: 0,
    placeholderData: keepPreviousData, // no empty flash (and no "No report matches.") while a new filter loads
    getNextPageParam: (last, all) => (last.length === PAGE_SIZE ? all.length * PAGE_SIZE : undefined),
  });
  const historyItems = history.data?.pages.flat() ?? [];
  const sources = useQuery({ queryKey: ["sources"], queryFn: api.sources });

  const check = useMutation({
    mutationFn: ({ ioc, fresh }: { ioc: string; fresh: boolean }) => api.check(ioc, fresh),
    onSuccess: (r) => {
      setOpenError(null);
      setReport(r);
      void qc.invalidateQueries({ queryKey: ["reports"] });
      void qc.invalidateQueries({ queryKey: ["sources"] });
    },
  });

  const run = useCallback(
    (ioc: string, fresh = false) => {
      if (check.isPending) return; // a late answer to the first check must not replace the second
      setValue(ioc);
      setView("check");
      check.mutate({ ioc, fresh });
    },
    [check],
  );

  const open = useCallback(async (id: string) => {
    try {
      const r = await api.report(id);
      setOpenError(null);
      setReport(r);
      setValue(r.ioc);
      setView("check");
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
      const typing = e.target instanceof HTMLElement && ["INPUT", "TEXTAREA", "SELECT"].includes(e.target.tagName);
      if (e.key === "Escape") {
        if (e.target === input.current) setValue("");
        else input.current?.focus();
      } else if (!typing && !e.ctrlKey && !e.metaKey && !e.altKey) {
        const t = TABS.find((x) => x.key === e.key);
        if (t) setTab(t.id);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // deep link: #/report/<id>/<tab> mirrors the open report and tab, so reload and back/forward work
  useEffect(() => {
    const fromHash = () => {
      const m = /^#\/report\/([^/]+)(?:\/(map|graph|raw))?$/.exec(location.hash);
      if (!m) return;
      if (m[2]) setTab(m[2] as Tab);
      if (m[1] && m[1] !== reportRef.current) void open(decodeURIComponent(m[1]));
    };
    fromHash();
    window.addEventListener("hashchange", fromHash);
    return () => window.removeEventListener("hashchange", fromHash);
  }, [open]);
  useEffect(() => {
    reportRef.current = report?.id ?? null;
    if (!report) return;
    const next = `#/report/${encodeURIComponent(report.id)}/${tab}`;
    if (location.hash !== next) location.hash = next;
  }, [report, tab]);

  const showSource = (name: string) => report && setFocusSource((f) => ({ id: report.id, name, n: (f?.n ?? 0) + 1 }));
  const openCase = (id: string) => {
    setOpenCaseId(id);
    setView("cases");
  };

  const vt = sources.data?.find((s) => s.name === "virustotal");
  const enabled = sources.data?.filter((s) => s.enabled) ?? [];
  // keyless sources (InternetDB, OTX, ...) are always on, so test for any key-gated source
  const noKeys = sources.data !== undefined && !enabled.some((s) => s.requires_key);

  const showReport = report !== null && !check.isPending;
  const quotas = sources.data?.filter((s) => s.daily_budget !== null) ?? [];

  return (
    <div className="relative flex min-h-full flex-col lg:h-full">
      <header className="flex flex-wrap items-center gap-x-5 gap-y-3 border-b border-line bg-panel px-5 py-3">
        <Logo />
        <Segmented role="nav" label="Views" items={VIEWS} value={view} onChange={setView} />
        <CommandBar ref={input} value={value} pending={check.isPending} onChange={setValue} onSubmit={() => run(value)} />
        <div className="ml-auto flex items-center gap-4 sm:ml-0">
          {report && <Readout label="Last check" value={formatDuration(report.duration_ms)} />}
          {vt && <Readout label="VirusTotal" value={formatQuota(vt.used_today, vt.daily_budget)} />}
          <Button
            className="w-9 px-0"
            onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
            aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
          >
            <svg aria-hidden="true" viewBox="0 0 20 20" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round">
              {theme === "dark" ? (
                <>
                  <circle cx="10" cy="10" r="3.5" />
                  <path d="M10 2.5v2M10 15.5v2M2.5 10h2M15.5 10h2M4.7 4.7l1.4 1.4M13.9 13.9l1.4 1.4M4.7 15.3l1.4-1.4M13.9 6.1l1.4-1.4" />
                </>
              ) : (
                <path d="M16.5 11.5A6.5 6.5 0 0 1 8.5 3.5a6.5 6.5 0 1 0 8 8z" />
              )}
            </svg>
                    </Button>
        </div>
      </header>


      {view === "overview" && (
        <div className="min-h-0 flex-1 overflow-auto">
          <Overview onCheck={(ioc) => run(ioc)} onOpen={(id) => void open(id)} />
        </div>
      )}
      {view === "cases" && (
        <div className="min-h-0 flex-1 overflow-auto">
          <Cases key={openCaseId ?? "list"} initialId={openCaseId} onOpen={(id) => void open(id)} />
        </div>
      )}
      {view === "batch" && (
        <div className="min-h-0 flex-1 overflow-auto">
          <Batch onOpen={(id) => void open(id)} />
        </div>
      )}

      <div hidden={view !== "check"} className="grid min-h-0 flex-1 lg:grid-cols-[14rem_minmax(0,1fr)] xl:grid-cols-[14rem_minmax(0,1fr)_20rem]">
        <aside className="order-3 border-t border-line bg-panel py-2 lg:order-none lg:overflow-y-auto lg:border-r lg:border-t-0">
          <h2 className="px-4 pb-2 pt-2 text-sm font-semibold">History</h2>
          <HistoryFilters filter={filter} onChange={changeFilter} count={historyItems.length} onClear={() => setFilter(NO_FILTER)} />
          <HistoryList items={historyItems} activeId={report?.id ?? null} onSelect={(id) => void open(id)} filtered={isFiltered(filter)} />
          {historyItems.length > 0 && (
            <div className="flex flex-wrap gap-2 px-3 pt-3">
              {(history.hasNextPage || (history.data?.pages.length ?? 0) > 1) && (
                // aria-disabled, not disabled: a disabled button drops keyboard focus, which is the point of keeping it mounted
                <Button
                  size="sm"
                  aria-disabled={!history.hasNextPage || history.isFetchingNextPage}
                  className="aria-disabled:cursor-not-allowed aria-disabled:opacity-50"
                  onClick={() => history.hasNextPage && !history.isFetchingNextPage && void history.fetchNextPage()}
                >
                  {history.isFetchingNextPage ? "Loading…" : history.hasNextPage ? "Load more" : "No more reports"}
                </Button>
              )}
              <Button size="sm" variant="ghost" onClick={() => downloadText("verdikt-history.csv", historyCsv(historyItems), "text/csv")}>
                Export list as CSV
              </Button>
            </div>
          )}
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
                {tab === "map" ? (
                  <div className="absolute bottom-4 left-4 z-10 w-[calc(100%-2rem)] max-w-md">
                    <VerdictHud report={report} onRecheck={() => run(report.ioc, true)} busy={check.isPending} onShowSource={showSource} />
                  </div>
                ) : (
                  <section aria-label="Verdict" className="hud absolute left-4 top-14 z-10 flex items-center gap-3 px-3 py-2 sm:top-4">
                    <LevelBadge level={report.level} />
                    <span className="mono text-xs">{report.ioc}</span>
                  </section>
                )}
                <Segmented
                  role="tab"
                  label="Visualisation"
                  className="hud absolute right-4 top-4 z-10"
                  items={TABS.map((t) => ({ id: t.id, label: t.label, hint: t.key }))}
                  value={tab}
                  onChange={setTab}
                />
                {tab === "map" && (
                  <p className="mono absolute left-4 top-14 z-10 max-w-sm text-xs text-muted sm:top-4">
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
              <SourceTable report={check.isPending ? null : report} pending={check.isPending ? enabled : null} focus={focusSource?.id === report?.id ? focusSource : null} />
            </div>
          )}
        </main>

        <div className="order-2 border-t border-line bg-panel lg:order-none lg:col-span-2 lg:overflow-y-auto xl:col-span-1 xl:border-l xl:border-t-0">
          <Diagnostics report={showReport ? report : null} />
          {showReport && report && <ReportActions report={report} onOpen={(id) => void open(id)} onOpenCase={openCase} />}
          <Waterfall report={showReport ? report : null} />
          <LogStream report={check.isPending ? null : report} />
          {quotas.length > 0 && (
            <section aria-label="Daily quota">
              <SectionTitle>Daily quota</SectionTitle>
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
