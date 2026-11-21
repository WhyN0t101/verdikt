import { describe, expect, it } from "vitest";
import { Q_MAX, NO_FILTER, historyCsv, isFiltered, reportParams } from "./historyQuery";

describe("reportParams", () => {
  it("leaves empty filters out", () => expect(reportParams(NO_FILTER, 0)).toEqual({ limit: 50, offset: 0 }));

  it("trims and keeps set filters", () =>
    expect(reportParams({ q: "  evil.com ", level: "malicious", type: "domain" }, 50)).toEqual({
      limit: 50,
      offset: 50,
      q: "evil.com",
      level: "malicious",
      type: "domain",
    }));

  it("blank text is no filter", () => expect(reportParams({ ...NO_FILTER, q: "   " }, 0)).not.toHaveProperty("q"));

  it("caps the text at the API maximum", () =>
    expect(reportParams({ ...NO_FILTER, q: "a".repeat(Q_MAX + 10) }, 0).q).toHaveLength(Q_MAX));

  it("keeps special characters for the API to encode", () =>
    expect(reportParams({ ...NO_FILTER, q: "100%_&#" }, 0).q).toBe("100%_&#"));
});

describe("isFiltered", () => {
  it("is false for no filter", () => expect(isFiltered(NO_FILTER)).toBe(false));
  it.each([{ q: "x" }, { level: "safe" }, { type: "ip" }] as const)("is true for %j", (p) => expect(isFiltered({ ...NO_FILTER, ...p })).toBe(true));
});

describe("historyCsv", () => {
  const row = { id: "r1", ioc: "=cmd|' /C calc'!A0", ioc_type: "domain", level: "malicious", created_at: "2026-11-21T10:00:00Z" };

  it("has a header and one line per row", () => {
    const lines = historyCsv([row, { ...row, id: "r2", ioc: "8.8.8.8" }]).trim().split(/\r?\n/);
    expect(lines).toHaveLength(3);
    expect(lines[0]).toBe("ioc,type,level,created_at,id");
  });

  it("neutralises formula cells", () => expect(historyCsv([row])).not.toMatch(/^=|\n=/));
});
