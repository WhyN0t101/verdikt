// One-off: rasterise Natural Earth land (via world-atlas, dev dependency) into a dot grid.
// Output is committed; the app makes no network requests for its map.
import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { feature } from "topojson-client";

const require = createRequire(import.meta.url);
const topo = JSON.parse(readFileSync(require.resolve("world-atlas/land-110m.json"), "utf8"));
const land = feature(topo, topo.objects.land);
const polys = [];
for (const f of land.features ?? [land]) {
  const g = f.geometry;
  if (g.type === "Polygon") polys.push(g.coordinates);
  else if (g.type === "MultiPolygon") polys.push(...g.coordinates);
}

function inRing(x, y, ring) {
  let inside = false;
  for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
    const [xi, yi] = ring[i];
    const [xj, yj] = ring[j];
    if (yi > y !== yj > y && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi) inside = !inside;
  }
  return inside;
}
// even-odd over all rings handles holes
const inPoly = (x, y, rings) => rings.reduce((acc, r) => (inRing(x, y, r) ? !acc : acc), false);

const STEP = 2;
const dots = [];
for (let lat = 84; lat >= -58; lat -= STEP) {
  for (let lon = -180; lon < 180; lon += STEP) {
    if (polys.some((p) => inPoly(lon + STEP / 2, lat - STEP / 2, p))) dots.push(lon, lat);
  }
}
writeFileSync(new URL("../src/data/land.json", import.meta.url), JSON.stringify({ step: STEP, dots }));
console.log(`${dots.length / 2} land dots`);
