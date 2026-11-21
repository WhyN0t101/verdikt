import type { FeedbackLabel, Report, ReportSummary, SourceInfo } from "./model";

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
  const res = await fetch(path, {
    ...init,
    headers: { "x-verdikt-token": token(), ...(init?.body ? { "content-type": "application/json" } : {}) },
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
  reports: () => call<ReportSummary[]>("/api/reports?limit=100"),
  report: (id: string, raw = false) => call<Report>(`/api/reports/${encodeURIComponent(id)}?raw=${raw}`),
  sources: () => call<SourceInfo[]>("/api/sources"),
  feedback: (id: string, label: FeedbackLabel) =>
    call<unknown>(`/api/reports/${encodeURIComponent(id)}/feedback`, { method: "POST", body: JSON.stringify({ label }) }),
  /** STIX bundle as text; the endpoint needs the token header, so a plain link cannot fetch it. */
  stix: async (id: string) => (await request(`/api/reports/${encodeURIComponent(id)}/stix`)).text(),
};
