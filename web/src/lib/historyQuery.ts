import type { IOCType, Level, ReportSummary } from "../model";
import { toCsv } from "./csv";

export const PAGE_SIZE = 50;
export const Q_MAX = 200; // the API rejects a longer search text
export const IOC_TYPES: IOCType[] = ["ip", "domain", "url", "md5", "sha1", "sha256"];

export interface HistoryFilter {
  q: string;
  level: Level | "";
  type: IOCType | "";
}

export const NO_FILTER: HistoryFilter = { q: "", level: "", type: "" };

export const isFiltered = (f: HistoryFilter) => f.q !== "" || f.level !== "" || f.type !== "";

/** Arguments for `api.reports`: empty filters are left out and the text is trimmed and capped. */
export function reportParams(f: HistoryFilter, offset: number, limit = PAGE_SIZE) {
  const q = f.q.trim().slice(0, Q_MAX);
  return { limit, offset, ...(q && { q }), ...(f.level && { level: f.level }), ...(f.type && { type: f.type }) };
}

/** The loaded history rows as CSV text (formula cells are neutralised by `toCsv`). */
export function historyCsv(items: ReportSummary[]): string {
  return toCsv([["ioc", "type", "level", "created_at", "id"], ...items.map((i) => [i.ioc, i.ioc_type, i.level, i.created_at, i.id])]);
}
