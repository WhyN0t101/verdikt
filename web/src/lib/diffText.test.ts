import { describe, expect, it } from "vitest";
import type { ReportDiff, SourceChange } from "../model";
import { changeKinds, confidenceChange, levelMoved, metricValue } from "./diffText";

const row = (p: Partial<SourceChange>): SourceChange => ({
  source: "virustotal",
  change: "changed",
  status_from: "ok",
  status_to: "ok",
  level_from: "safe",
  level_to: "safe",
  summary_from: "x",
  summary_to: "x",
  no_answer: false,
  metrics: [],
  ...p,
});

describe("changeKinds", () => {
  it("added and removed", () => {
    expect(changeKinds(row({ change: "added" }))).toEqual(["Added"]);
    expect(changeKinds(row({ change: "removed" }))).toEqual(["Removed"]);
  });
  it("lists every difference in reading order", () =>
    expect(
      changeKinds(row({ level_to: "malicious", status_to: "error", summary_to: "y", metrics: [{ key: "malicious", from: 0, to: 7 }] })),
    ).toEqual(["Level", "Status", "Summary", "Metric"]));
  it("nothing changed gives no kind", () => expect(changeKinds(row({}))).toEqual([]));
});

describe("metricValue", () => {
  it.each([
    [null, "none"],
    [true, "yes"],
    [false, "no"],
    [0, "0"],
    [7.5, "7.5"],
  ] as const)("%j", (v, want) => expect(metricValue(v)).toBe(want));
});

const diff = (p: Partial<ReportDiff>): ReportDiff => ({
  report_id: "b",
  previous_id: "a",
  previous_at: "2026-11-20T10:00:00Z",
  changed: true,
  level_from: "suspicious",
  level_to: "malicious",
  agreeing_from: 2,
  agreeing_to: 4,
  total_from: 6,
  total_to: 6,
  confidence_from: "medium",
  confidence_to: "high",
  sources: [],
  reasons_added: [],
  reasons_removed: [],
  ...p,
});

describe("confidenceChange", () => {
  it("shows before and after", () => expect(confidenceChange(diff({}))).toBe("2 of 6 to 4 of 6 sources agree"));
  it("unchanged counts read once", () => expect(confidenceChange(diff({ agreeing_from: 4 }))).toBe("4 of 6 sources agree"));
  it("no previous report", () => expect(confidenceChange(diff({ agreeing_from: null, total_from: null }))).toBe("4 of 6 sources agree"));
});

describe("levelMoved", () => {
  it("true when the level differs", () => expect(levelMoved(diff({}))).toBe(true));
  it("false when equal or no previous", () => {
    expect(levelMoved(diff({ level_from: "malicious" }))).toBe(false);
    expect(levelMoved(diff({ level_from: null }))).toBe(false);
  });
});
