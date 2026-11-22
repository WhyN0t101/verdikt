import { ago, clock } from "./format";

/** "live, fetched 14:02:11" or "cached, fetched 5 h ago", then the row's role and weight. */
export function provenanceText(r: { cached: boolean; fetched_at: string; role: string; weight: number }, now: number = Date.now()): string {
  const fetched = r.cached ? `cached, fetched ${ago(r.fetched_at, now)}` : `live, fetched ${clock(r.fetched_at)}`;
  return r.role ? `${fetched} · ${r.role} · weight ${r.weight}` : fetched;
}

/** The source a verdict reason talks about: reasons start with "<source>: ". Longest name wins. */
export function reasonToSource(reason: string, rows: { source: string }[]): string | null {
  const hits = rows.filter((r) => reason.startsWith(`${r.source}: `));
  return hits.reduce<string | null>((best, r) => (best === null || r.source.length > best.length ? r.source : best), null);
}

/** A link only when it is plain http(s); anything else (javascript:, data:, relative) is dropped. */
export function safeHref(url: string | null | undefined): string | null {
  if (!url) return null;
  try {
    const u = new URL(url);
    return u.protocol === "https:" || u.protocol === "http:" ? u.href : null;
  } catch {
    return null;
  }
}
