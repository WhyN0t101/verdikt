import type { Report, ReportSummary, SourceInfo } from "./model";

// The server injects a per-run token into the served page; the browser never sees API keys.
function token(): string {
  return document.querySelector<HTMLMetaElement>('meta[name="verdikt-token"]')?.content ?? "";
}

export class ApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: { "x-verdikt-token": token(), ...(init?.body ? { "content-type": "application/json" } : {}) },
  });
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { detail?: unknown };
    const detail = typeof body.detail === "string" ? body.detail : `request failed (${res.status})`;
    throw new ApiError(res.status, detail);
  }
  return (await res.json()) as T;
}

export const api = {
  check: (ioc: string, noCache = false) =>
    call<Report>("/api/check", { method: "POST", body: JSON.stringify({ ioc, no_cache: noCache }) }),
  reports: () => call<ReportSummary[]>("/api/reports?limit=100"),
  report: (id: string, raw = false) => call<Report>(`/api/reports/${encodeURIComponent(id)}?raw=${raw}`),
  sources: () => call<SourceInfo[]>("/api/sources"),
};
