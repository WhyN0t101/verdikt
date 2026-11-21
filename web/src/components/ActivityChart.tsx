import { LEVEL_LABEL } from "../lib/format";
import type { DayCount } from "../model";

const LEVELS = ["safe", "unknown", "suspicious", "malicious"] as const; // bottom to top: danger on top
const W = 560;
const H = 150;
const PAD = { l: 28, r: 4, t: 8, b: 20 };

function lastDays(n: number): string[] {
  const days: string[] = [];
  for (let i = n - 1; i >= 0; i--) days.push(new Date(Date.now() - i * 86_400_000).toISOString().slice(0, 10));
  return days;
}

/** Checks per day, stacked by verdict. Level is also in the legend text and the data table. */
export function ActivityChart({ data, windowDays = 14 }: { data: DayCount[]; windowDays?: number }) {
  const days = lastDays(windowDays);
  const byDay = new Map(data.map((d) => [d.day, d]));
  const rows = days.map((day) => byDay.get(day) ?? { day, malicious: 0, suspicious: 0, safe: 0, unknown: 0 });
  const totals = rows.map((r) => r.malicious + r.suspicious + r.safe + r.unknown);
  const max = Math.max(1, ...totals);
  const slot = (W - PAD.l - PAD.r) / days.length;
  const bar = Math.max(4, slot - 6);
  const y = (n: number) => PAD.t + (H - PAD.t - PAD.b) * (1 - n / max);

  if (totals.every((t) => t === 0)) {
    return <p className="text-sm text-muted">No checks in the last {windowDays} days.</p>;
  }

  return (
    <figure className="m-0">
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`Checks per day for the last ${windowDays} days, by verdict`} className="block w-full">
        <line x1={PAD.l} x2={W - PAD.r} y1={y(0)} y2={y(0)} stroke="var(--border-strong)" />
        <text x={PAD.l - 6} y={y(max) + 4} textAnchor="end" fontSize="10" fill="var(--muted)" fontFamily="var(--font-mono)">
          {max}
        </text>
        <text x={PAD.l - 6} y={y(0)} textAnchor="end" fontSize="10" fill="var(--muted)" fontFamily="var(--font-mono)">
          0
        </text>
        {rows.map((r, i) => {
          let acc = 0;
          const x = PAD.l + i * slot + (slot - bar) / 2;
          return (
            <g key={r.day}>
              <title>{`${r.day}: ${LEVELS.map((l) => `${r[l]} ${l}`).join(", ")}`}</title>
              {LEVELS.map((l) => {
                const n = r[l];
                if (n === 0) return null;
                const top = y(acc + n);
                const height = y(acc) - top;
                acc += n;
                // 2px surface gap between stacked segments
                return <rect key={l} x={x} y={top} width={bar} height={Math.max(0, height - 2)} style={{ fill: `var(--lvl-${l})` }} />;
              })}
              {(rows.length - 1 - i) % 4 === 0 && (
                <text x={x + bar / 2} y={H - 5} textAnchor="middle" fontSize="10" fill="var(--muted)" fontFamily="var(--font-mono)">
                  {r.day.slice(5)}
                </text>
              )}
            </g>
          );
        })}
      </svg>
      <figcaption className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs">
        {[...LEVELS].reverse().map((l) => (
          <span key={l} className="flex items-center gap-1.5">
            <span aria-hidden="true" className="h-2.5 w-2.5 rounded-[2px]" style={{ background: `var(--lvl-${l})` }} />
            {LEVEL_LABEL[l]}
          </span>
        ))}
      </figcaption>
      <details className="mt-2 text-xs">
        <summary className="cursor-pointer text-muted">Data table</summary>
        <table className="mono mt-2 w-full text-left">
          <thead>
            <tr className="text-muted">
              <th className="font-normal">Day</th>
              {[...LEVELS].reverse().map((l) => (
                <th key={l} className="font-normal">
                  {LEVEL_LABEL[l]}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows
              .filter((r) => r.malicious + r.suspicious + r.safe + r.unknown > 0)
              .map((r) => (
                <tr key={r.day}>
                  <td>{r.day}</td>
                  {[...LEVELS].reverse().map((l) => (
                    <td key={l}>{r[l]}</td>
                  ))}
                </tr>
              ))}
          </tbody>
        </table>
      </details>
    </figure>
  );
}
