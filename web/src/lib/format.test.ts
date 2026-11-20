import { describe, expect, it } from "vitest";
import { clock, defang, formatDuration, formatQuota, shortenMiddle, typeTag } from "./format";

describe("defang", () => {
  it.each([
    ["http://evil.com/a", "hxxp://evil[.]com/a"],
    ["https://evil.com", "hxxps://evil[.]com"],
    ["1.2.3.4", "1[.]2[.]3[.]4"],
    ["abc123", "abc123"],
  ])("%s", (raw, want) => expect(defang(raw)).toBe(want));
});

describe("formatters", () => {
  it("duration", () => {
    expect(formatDuration(420)).toBe("420 ms");
    expect(formatDuration(1234)).toBe("1.2 s");
  });
  it("quota", () => {
    expect(formatQuota(412, 500)).toBe("412/500");
    expect(formatQuota(3, null)).toBe("3");
  });
  it("shortenMiddle keeps both ends", () => {
    const s = shortenMiddle("a".repeat(64), 20);
    expect(s).toHaveLength(20);
    expect(s).toContain("…");
    expect(shortenMiddle("short", 20)).toBe("short");
  });
  it("typeTag", () => expect(typeTag("domain")).toBe("DOM"));
  it("clock is HH:MM:SS", () => expect(clock("2026-01-01T14:03:15")).toBe("14:03:15"));
});
