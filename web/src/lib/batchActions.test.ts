import { describe, expect, it } from "vitest";
import { pickReports, watchPlan } from "./batchActions";

const r = (ioc: string, level: string) => ({ ioc, level });
const rows = [r("a", "malicious"), r("b", "suspicious"), r("c", "unknown"), r("d", "safe")];

describe("pickReports", () => {
  it.each([
    ["bad", ["a", "b"]],
    ["malicious", ["a"]],
    ["all", ["a", "b", "c", "d"]],
  ] as const)("%s", (mode, want) => expect(pickReports(rows, mode).map((x) => x.ioc)).toEqual(want));

  it("empty input", () => expect(pickReports([], "bad")).toEqual([]));
});

describe("watchPlan", () => {
  const picked = [r("a", "malicious"), r("b", "malicious"), r("c", "malicious")];

  it("adds everything when there is room", () =>
    expect(watchPlan(picked, [], 50)).toEqual({ toAdd: picked, skippedAlready: 0, skippedCap: 0 }));

  it("skips what is already watched", () => {
    const plan = watchPlan(picked, ["b", "x"], 50);
    expect(plan.toAdd.map((x) => x.ioc)).toEqual(["a", "c"]);
    expect(plan.skippedAlready).toBe(1);
  });

  it("stops at the cap and counts the rest", () => {
    const plan = watchPlan(picked, ["x", "y"], 3); // one slot free
    expect(plan.toAdd.map((x) => x.ioc)).toEqual(["a"]);
    expect(plan.skippedCap).toBe(2);
  });

  it("full watchlist adds nothing", () => {
    const plan = watchPlan(picked, ["x", "y", "z"], 3);
    expect(plan).toEqual({ toAdd: [], skippedAlready: 0, skippedCap: 3 });
  });

  it("exactly full after adding is fine", () => expect(watchPlan(picked, ["x"], 4).skippedCap).toBe(0));
});
