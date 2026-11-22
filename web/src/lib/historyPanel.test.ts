import { describe, expect, it } from "vitest";
import type { IocHistory } from "../model";
import { changesText, hasStory } from "./historyPanel";

const rep = (id: string) => ({ id, ioc: "1.2.3.4", ioc_type: "ip", level: "safe", created_at: "2026-11-22T10:00:00Z" });
const hist = (p: Partial<IocHistory>): IocHistory => ({
  report_id: "a",
  ioc: "1.2.3.4",
  reports: [rep("a")],
  truncated: false,
  changes: 0,
  cases: [],
  watched: false,
  watched_since: null,
  events: [],
  ...p,
});

describe("hasStory", () => {
  it("a first-time indicator has none", () => expect(hasStory(hist({}))).toBe(false));
  it("earlier reports", () => expect(hasStory(hist({ reports: [rep("a"), rep("b")] }))).toBe(true));
  it("in a case", () =>
    expect(hasStory(hist({ cases: [{ id: "c", title: "t", tags: [], created_at: "", updated_at: "", report_count: 1 }] }))).toBe(true));
  it("watched", () => expect(hasStory(hist({ watched: true }))).toBe(true));
});

describe("changesText", () => {
  it.each([
    [0, ""],
    [1, "1 verdict change"],
    [2, "2 verdict changes"],
  ])("%d", (n, want) => expect(changesText(n)).toBe(want));
});
