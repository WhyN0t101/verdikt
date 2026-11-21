/** Pure helpers for the batch triage bar: which results to act on, and what the watchlist can take. */
export type PickMode = "bad" | "malicious" | "all";

export const PICK_LABEL: Record<PickMode, string> = {
  bad: "Malicious and suspicious",
  malicious: "Malicious only",
  all: "All checked",
};

const LEVELS: Record<PickMode, readonly string[] | null> = {
  bad: ["malicious", "suspicious"],
  malicious: ["malicious"],
  all: null,
};

export function pickReports<T extends { level: string }>(reports: T[], mode: PickMode): T[] {
  const levels = LEVELS[mode];
  return levels ? reports.filter((r) => levels.includes(r.level)) : reports;
}

export interface WatchPlan<T> {
  toAdd: T[];
  skippedAlready: number;
  skippedCap: number;
}

/** Split the picked reports into what fits, what is already watched, and what the cap rejects. */
export function watchPlan<T extends { ioc: string }>(picked: T[], watched: string[], max: number): WatchPlan<T> {
  const have = new Set(watched);
  const fresh = picked.filter((r) => !have.has(r.ioc));
  const free = Math.max(0, max - watched.length);
  return { toAdd: fresh.slice(0, free), skippedAlready: picked.length - fresh.length, skippedCap: Math.max(0, fresh.length - free) };
}
