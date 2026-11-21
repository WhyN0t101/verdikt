const PROGRESS = /^\s*(\d+)\s*\/\s*(\d+)\s*$/;

/** Job progress "3/50" as a fraction 0..1, or null while unknown (empty, malformed or total 0). */
export function parseProgress(text: string): number | null {
  const m = PROGRESS.exec(text);
  const done = Number(m?.[1]);
  const total = Number(m?.[2]);
  if (!m || !(total > 0)) return null;
  return Math.min(1, done / total);
}
