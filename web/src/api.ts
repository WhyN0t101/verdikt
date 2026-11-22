import type { CaseDetail, CaseSummary, Extraction, FeedImport, IOCType, JobStatus, FeedInfo, FeedUpdate, FeedbackLabel, Level, IocHistory, Report, ReportDiff, ReportSummary, SourceInfo, Stats, WatchState } from "./model";

// The server injects a per-run token into the served page; the browser never sees API keys.
function token(): string {
  return document.querySelector<HTMLMetaElement>('meta[name="verdikt-token"]')?.content ?? "";
}

class ApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request(path: string, init?: RequestInit): Promise<Response> {
  // the API only accepts JSON POSTs, so even an empty POST carries `{}`
  const body = init?.body ?? (init?.method === "POST" ? "{}" : undefined);
  const res = await fetch(path, {
    ...init,
    body,
    headers: { "x-verdikt-token": token(), ...(body ? { "content-type": "application/json" } : {}) },
  });
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { detail?: unknown };
    const detail = typeof body.detail === "string" ? body.detail : `request failed (${res.status})`;
    throw new ApiError(res.status, detail);
  }
  return res;
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  return (await (await request(path, init)).json()) as T;
}

export const api = {
  check: (ioc: string, noCache = false) =>
    call<Report>("/api/check", { method: "POST", body: JSON.stringify({ ioc, no_cache: noCache }) }),
  reports: (p: { q?: string; level?: Level; type?: IOCType; limit?: number; offset?: number } = {}) => {
    const query = new URLSearchParams({ limit: String(p.limit ?? 100) });
    if (p.q) query.set("q", p.q);
    if (p.level) query.set("level", p.level);
    if (p.type) query.set("type", p.type);
    if (p.offset) query.set("offset", String(p.offset));
    return call<ReportSummary[]>(`/api/reports?${query}`);
  },
  history: (id: string) => call<IocHistory>(`/api/reports/${encodeURIComponent(id)}/history`),
  diff: (id: string, against?: string) =>
    call<ReportDiff>(`/api/reports/${encodeURIComponent(id)}/diff${against ? `?against=${encodeURIComponent(against)}` : ""}`),
  report: (id: string, raw = false) => call<Report>(`/api/reports/${encodeURIComponent(id)}?raw=${raw}`),
  sources: () => call<SourceInfo[]>("/api/sources"),
  feedback: (id: string, label: FeedbackLabel, note?: string) =>
    call<unknown>(`/api/reports/${encodeURIComponent(id)}/feedback`, { method: "POST", body: JSON.stringify(note ? { label, note } : { label }) }),
  stats: (days = 30) => call<Stats>(`/api/stats?days=${days}`),
  watchlist: () => call<WatchState>("/api/watchlist"),
  watchAdd: (reportId: string) =>
    call<WatchState>("/api/watchlist", { method: "POST", body: JSON.stringify({ report_id: reportId }) }),
  watchRemove: (ioc: string) => call<WatchState>(`/api/watchlist?ioc=${encodeURIComponent(ioc)}`, { method: "DELETE" }),
  feeds: () => call<FeedInfo[]>("/api/feeds"),
  feedsUpdate: () => call<FeedUpdate[]>("/api/feeds/update", { method: "POST" }),
  extract: (text: string) => call<Extraction>("/api/extract", { method: "POST", body: JSON.stringify({ text }) }),
  cases: (tag?: string) => call<CaseSummary[]>(`/api/cases${tag ? `?tag=${encodeURIComponent(tag)}` : ""}`),
  caseGet: (id: string) => call<CaseDetail>(`/api/cases/${encodeURIComponent(id)}`),
  caseCreate: (title: string, tags: string[] = []) =>
    call<CaseDetail>("/api/cases", { method: "POST", body: JSON.stringify({ title, tags }) }),
  casePatch: (id: string, change: { title?: string; notes?: string; tags?: string[] }) =>
    call<CaseDetail>(`/api/cases/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify(change) }),
  caseDelete: (id: string) => call<CaseSummary[]>(`/api/cases/${encodeURIComponent(id)}`, { method: "DELETE" }),
  caseAdd: (id: string, reportId: string) =>
    call<CaseDetail>(`/api/cases/${encodeURIComponent(id)}/reports`, { method: "POST", body: JSON.stringify({ report_id: reportId }) }),
  caseRemove: (id: string, reportId: string) =>
    call<CaseDetail>(`/api/cases/${encodeURIComponent(id)}/reports/${encodeURIComponent(reportId)}`, { method: "DELETE" }),
  scheduler: () => call<JobStatus[]>("/api/scheduler"),
  schedulerStart: (name: string) => call<JobStatus>(`/api/scheduler/${encodeURIComponent(name)}/start`, { method: "POST" }),
  feedsImport: (name: string, content: string, allAttributes = false) =>
    call<FeedImport>("/api/feeds/import", { method: "POST", body: JSON.stringify({ name, content, all_attributes: allAttributes }) }),
  feedsForget: (name: string) => call<FeedInfo[]>(`/api/feeds/import?name=${encodeURIComponent(name)}`, { method: "DELETE" }),
  /** A file the API builds (report or case export, MISP event): text, fetched with the token header. */
  download: async (path: string) => (await request(path)).text(),
  /** STIX bundle as text; the endpoint needs the token header, so a plain link cannot fetch it. */
  stix: async (id: string) => (await request(`/api/reports/${encodeURIComponent(id)}/stix`)).text(),
};
