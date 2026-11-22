import { describe, expect, it } from "vitest";
import { clock } from "./format";
import { provenanceText, reasonToSource, safeHref } from "./provenance";

const NOW = Date.parse("2026-11-22T12:00:00Z");
const row = (p: object) => ({ cached: false, fetched_at: "2026-11-22T11:59:30Z", role: "strong", weight: 3, ...p });

describe("provenanceText", () => {
  it("live answer shows the fetch clock time", () =>
    expect(provenanceText(row({}), NOW)).toBe(`live, fetched ${clock("2026-11-22T11:59:30Z")} · strong · weight 3`));

  it.each([
    ["2026-11-22T11:59:40Z", "just now"],
    ["2026-11-22T07:00:00Z", "5 h ago"],
    ["2026-11-20T12:00:00Z", "2 d ago"],
  ])("cached %s -> %s", (at, age) =>
    expect(provenanceText(row({ cached: true, fetched_at: at }), NOW)).toBe(`cached, fetched ${age} · strong · weight 3`));

  it("no role: no role or weight part", () => expect(provenanceText(row({ cached: true, role: "" }), NOW)).toBe("cached, fetched just now"));
});

describe("reasonToSource", () => {
  const rows = [{ source: "virustotal" }, { source: "urlscan" }, { source: "urlhaus" }, { source: "url" }];

  it("finds the row a reason names", () => expect(reasonToSource("virustotal: malicious 2 >= 2 -> suspicious", rows)).toBe("virustotal"));
  it("unknown source gives null", () => expect(reasonToSource("nobody: x", rows)).toBeNull());
  it("a reason without the prefix gives null", () => expect(reasonToSource("2 of 5 sources agree", rows)).toBeNull());
  it("a source name that is a prefix of another does not match it", () => expect(reasonToSource("urlhaus: listed", rows)).toBe("urlhaus"));
  it("longest name wins", () => expect(reasonToSource("url: x", [{ source: "u" }, { source: "url" }])).toBe("url"));
});

describe("safeHref", () => {
  it.each(["https://example.invalid/vt/1.2.3.4", "http://example.invalid/x"])("keeps %s", (u) => expect(safeHref(u)).toBe(new URL(u).href));
  it.each(["javascript:alert(1)", "data:text/html,<script>", "/relative/path", "", "not a url", null, undefined])("drops %s", (u) =>
    expect(safeHref(u)).toBeNull());
});
