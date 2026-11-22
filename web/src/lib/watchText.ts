// scheduler.py writes: "<n> verdict change(s)[, <n> evidence change(s)][, <n> notification(s)]"
const DETAIL = /^(\d+) verdict change\(s\)(?:, (\d+) evidence change\(s\))?(?:, (\d+) notification\(s\))?$/;

export interface WatchSummary {
  /** the headline: what happened to the verdicts */
  text: string;
  /** set when sources answered differently while the verdict stayed the same */
  evidence: string | null;
  failed: boolean;
}

/** The watch job's detail line as sentences; an unknown format is shown as it is. */
export function describeWatch(detail: string, ok: boolean | null): WatchSummary {
  if (ok === false) return { text: `Re-check ${detail.startsWith("failed") ? detail : `failed: ${detail}`}`, evidence: null, failed: true };
  const m = DETAIL.exec(detail);
  if (!m) return { text: detail, evidence: null, failed: false };
  const verdicts = Number(m[1]);
  const evidence = Number(m[2] ?? 0);
  const sent = Number(m[3] ?? 0);
  const parts = [verdicts === 0 ? "No verdict changed." : `${verdicts} verdict change(s).`];
  if (sent > 0) parts.push(`${sent} notification(s) sent.`);
  return {
    text: parts.join(" "),
    evidence: evidence > 0 ? `${evidence} evidence change(s): a source answered differently while the verdict stayed the same. Open the entry's last report to see which.` : null,
    failed: false,
  };
}
