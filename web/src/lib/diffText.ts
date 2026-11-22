import type { MetricChange, ReportDiff, SourceChange } from "../model";

/** Short names for what changed in one source row, in reading order. */
export function changeKinds(c: SourceChange): string[] {
  if (c.change === "added") return ["Added"];
  if (c.change === "removed") return ["Removed"];
  const kinds: string[] = [];
  if (c.level_from !== c.level_to) kinds.push("Level");
  if (c.status_from !== c.status_to) kinds.push("Status");
  if (c.summary_from !== c.summary_to) kinds.push("Summary");
  if (c.metrics.length > 0) kinds.push("Metric");
  return kinds;
}

/** A metric value as text; a value missing in the older report reads "none". */
export function metricValue(v: MetricChange["from"]): string {
  return v === null ? "none" : typeof v === "boolean" ? (v ? "yes" : "no") : String(v);
}

export function confidenceChange(d: ReportDiff): string {
  const now = `${d.agreeing_to} of ${d.total_to} sources agree`;
  const counts = d.agreeing_from === null || d.total_from === null || (d.agreeing_from === d.agreeing_to && d.total_from === d.total_to) ? now : `${d.agreeing_from} of ${d.total_from} to ${now}`;
  const label = d.confidence_from && d.confidence_from !== d.confidence_to ? `${d.confidence_from} to ${d.confidence_to}` : d.confidence_to;
  return `${counts}, ${label} confidence`;
}

/** True when the verdict itself moved: the block opens by default then. */
export const levelMoved = (d: ReportDiff): boolean => d.level_from !== null && d.level_from !== d.level_to;
