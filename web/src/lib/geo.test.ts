import { describe, expect, it } from "vitest";
import { greatCircle, project } from "./geo";

describe("project", () => {
  it("maps corners and centre", () => {
    expect(project(-180, 90, 360, 180)).toEqual({ x: 0, y: 0 });
    expect(project(180, -90, 360, 180)).toEqual({ x: 360, y: 180 });
    expect(project(0, 0, 360, 180)).toEqual({ x: 180, y: 90 });
  });
});

describe("greatCircle", () => {
  it("keeps endpoints", () => {
    const seg = greatCircle([10, 20], [50, 40]);
    expect(seg).toHaveLength(1);
    const pts = seg[0] ?? [];
    expect(pts[0]?.[0]).toBeCloseTo(10);
    expect(pts[0]?.[1]).toBeCloseTo(20);
    expect(pts.at(-1)?.[0]).toBeCloseTo(50);
    expect(pts.at(-1)?.[1]).toBeCloseTo(40);
  });
  it("splits at the antimeridian", () => {
    expect(greatCircle([170, 0], [-170, 0]).length).toBe(2);
  });
  it("stays on the equator between equatorial points", () => {
    for (const p of greatCircle([0, 0], [60, 0])[0] ?? []) expect(p[1]).toBeCloseTo(0);
  });
  it("handles identical points", () => {
    expect(greatCircle([5, 5], [5, 5])).toHaveLength(1);
  });
});
