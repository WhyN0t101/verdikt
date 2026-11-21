import { useMemo, useState } from "react";
import land from "../data/land.json";
import { defang, LEVEL_LABEL } from "../lib/format";
import { greatCircle, project } from "../lib/geo";
import type { GeoPoint } from "../model";

const W = 720;
const H = 360;

// Land is a precomputed dot grid (Natural Earth, 2 degree cells): no tiles, no map requests.
const LAND_PATH = (() => {
  const { step, dots } = land as { step: number; dots: number[] };
  const parts: string[] = [];
  for (let i = 0; i < dots.length; i += 2) {
    const p = project((dots[i] as number) + step / 2, (dots[i + 1] as number) - step / 2, W, H);
    parts.push(`M${p.x.toFixed(1)} ${p.y.toFixed(1)}h0`);
  }
  return parts.join("");
})();

interface Props {
  geo: GeoPoint[];
  onPivot: (ip: string) => void;
}

/** Fills its (positioned) parent. With no points it is the bare dot-matrix world. */
export function MapView({ geo, onPivot }: Props) {
  const [hover, setHover] = useState<GeoPoint | null>(null);
  const origin = geo.find((g) => g.role === "ioc");
  const related = geo.filter((g) => g.role !== "ioc");

  const arcs = useMemo(() => {
    if (!origin) return [];
    return related.flatMap((r) =>
      greatCircle([origin.lon, origin.lat], [r.lon, r.lat]).map((seg) =>
        seg
          .map(([lon, lat]) => {
            const p = project(lon, lat, W, H);
            return `${p.x.toFixed(1)},${p.y.toFixed(1)}`;
          })
          .join(" "),
      ),
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [geo]);

  const c = origin ? project(origin.lon, origin.lat, W, H) : { x: W / 2, y: H / 2 };
  const shown = hover ?? origin ?? null;

  return (
    <div className="absolute inset-0">
      <svg viewBox={`0 0 ${W} ${H}`} role="group" aria-label="World map of the indicator and related IPs" className="block h-full w-full overflow-visible">
        <defs>
          <filter id="glow" x="-100%" y="-100%" width="300%" height="300%">
            <feGaussianBlur stdDeviation="3" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        {/* concentric range rings centred on the indicator, and a crosshair lattice */}
        <g fill="none" stroke="var(--grid)" strokeWidth="1">
          {[60, 120, 180, 240, 300, 420, 560].map((r) => (
            <circle key={r} cx={c.x} cy={c.y} r={r} />
          ))}
        </g>
        <g stroke="var(--grid)" strokeWidth="1">
          {[-1, 0, 1, 2, 3, 4, 5, 6, 7].flatMap((i) =>
            [-1, 0, 1, 2, 3, 4, 5].map((j) => {
              const x = 60 + i * 100;
              const y = 40 + j * 70;
              return <path key={`${i}-${j}`} d={`M${x - 3} ${y}h6M${x} ${y - 3}v6`} />;
            }),
          )}
        </g>
        <path d={LAND_PATH} stroke="var(--land)" strokeWidth="2.6" strokeLinecap="round" fill="none" />
        {arcs.map((pts) => (
          <polyline key={pts} points={pts} fill="none" stroke="var(--violet-300)" strokeWidth="1.4" />
        ))}
        {origin && (
          <g aria-hidden="true">
            <circle className="pulse" cx={c.x} cy={c.y} r="5" fill="none" stroke="var(--lvl-info)" strokeWidth="1" />
            <path d={`M${c.x - 14} ${c.y}h8M${c.x + 6} ${c.y}h8M${c.x} ${c.y - 14}v8M${c.x} ${c.y + 6}v8`} stroke="var(--lvl-info)" strokeWidth="1" />
          </g>
        )}
        {geo.map((g, idx) => {
          const p = project(g.lon, g.lat, W, H);
          const isOrigin = g.role === "ioc";
          const n = isOrigin ? null : related.indexOf(g) + 1;
          return (
            <g
              key={g.ip}
              tabIndex={0}
              role="button"
              aria-label={`${defang(g.ip)}, ${g.country ?? "unknown country"}, ${LEVEL_LABEL[g.level]}${isOrigin ? "" : ". Activate to check this IP"}`}
              style={{ cursor: isOrigin ? "default" : "pointer", outline: "none" }}
              onMouseEnter={() => setHover(g)}
              onMouseLeave={() => setHover(null)}
              onFocus={() => setHover(g)}
              onBlur={() => setHover(null)}
              onClick={() => !isOrigin && onPivot(g.ip)}
              onKeyDown={(e) => {
                if ((e.key === "Enter" || e.key === " ") && !isOrigin) {
                  e.preventDefault();
                  onPivot(g.ip);
                }
              }}
              data-idx={idx}
            >
              <circle cx={p.x} cy={p.y} r="12" fill="transparent" />
              {isOrigin && <circle cx={p.x} cy={p.y} r="9" fill="none" strokeWidth="1" style={{ stroke: `var(--lvl-${g.level})` }} />}
              <circle cx={p.x} cy={p.y} r={isOrigin ? 4.5 : 3.5} style={{ fill: `var(--lvl-${g.level})` }} filter="url(#glow)" stroke="var(--panel)" strokeWidth="1.5" />
              {n !== null && (
                <g>
                  <path d={`M${p.x + 4} ${p.y - 4}l8 -8`} stroke="var(--violet-300)" strokeWidth="1" />
                  <rect x={p.x + 12} y={p.y - 22} width="13" height="13" fill="var(--panel)" stroke="var(--violet-300)" />
                  <text x={p.x + 18.5} y={p.y - 12.2} textAnchor="middle" fontSize="8.5" fill="var(--text)" fontFamily="var(--font-mono)">
                    {n}
                  </text>
                </g>
              )}
            </g>
          );
        })}
      </svg>
      {shown && (
        <div role="status" className="hud mono pointer-events-none absolute bottom-4 right-6 z-10 max-w-72 px-3 py-2 text-xs">
          <div>{defang(shown.ip)}</div>
          <div className="text-muted">
            {shown.asn ? `AS${shown.asn} ` : ""}
            {shown.as_org ?? ""}
          </div>
          <div className="text-muted">
            {[shown.city, shown.country].filter(Boolean).join(", ") || "location unknown"} · {LEVEL_LABEL[shown.level]}
          </div>
        </div>
      )}
    </div>
  );
}
