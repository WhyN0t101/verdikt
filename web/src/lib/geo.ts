export interface XY {
  x: number;
  y: number;
}

export type LonLat = [number, number];

/** Equirectangular projection into a `w` x `h` box (lon -180..180, lat 90..-90). */
export function project(lon: number, lat: number, w: number, h: number): XY {
  return { x: ((lon + 180) / 360) * w, y: ((90 - lat) / 180) * h };
}

const rad = (d: number) => (d * Math.PI) / 180;
const deg = (r: number) => (r * 180) / Math.PI;

/**
 * Great-circle points from a to b, split into segments wherever the path wraps the
 * antimeridian so a flat map never draws a line across the whole world.
 */
export function greatCircle(a: LonLat, b: LonLat, steps = 48): LonLat[][] {
  const [lo1, la1, lo2, la2] = [rad(a[0]), rad(a[1]), rad(b[0]), rad(b[1])];
  const d =
    2 *
    Math.asin(Math.sqrt(Math.sin((la2 - la1) / 2) ** 2 + Math.cos(la1) * Math.cos(la2) * Math.sin((lo2 - lo1) / 2) ** 2));
  if (d === 0) return [[a, b]];
  const points: LonLat[] = [];
  for (let i = 0; i <= steps; i++) {
    const f = i / steps;
    const A = Math.sin((1 - f) * d) / Math.sin(d);
    const B = Math.sin(f * d) / Math.sin(d);
    const x = A * Math.cos(la1) * Math.cos(lo1) + B * Math.cos(la2) * Math.cos(lo2);
    const y = A * Math.cos(la1) * Math.sin(lo1) + B * Math.cos(la2) * Math.sin(lo2);
    const z = A * Math.sin(la1) + B * Math.sin(la2);
    points.push([deg(Math.atan2(y, x)), deg(Math.atan2(z, Math.hypot(x, y)))]);
  }
  const segments: LonLat[][] = [[points[0] as LonLat]];
  for (let i = 1; i < points.length; i++) {
    const p = points[i] as LonLat;
    const prev = points[i - 1] as LonLat;
    if (Math.abs(p[0] - prev[0]) > 180) segments.push([]);
    (segments[segments.length - 1] as LonLat[]).push(p);
  }
  return segments.filter((s) => s.length > 1);
}
