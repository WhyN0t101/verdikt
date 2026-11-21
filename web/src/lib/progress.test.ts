import { describe, expect, it } from "vitest";
import { parseProgress } from "./progress";

describe("parseProgress", () => {
  it.each([
    ["3/50", 0.06],
    ["0/5", 0],
    ["50/50", 1],
    ["60/50", 1], // clamped
    [" 3 / 50 ", 0.06],
  ])("%j -> %d", (text, want) => expect(parseProgress(text)).toBeCloseTo(want));

  it.each(["", "3/0", "x/y", "-1/5", "1/2/3", "3", "3/"])("%j -> null", (text) =>
    expect(parseProgress(text)).toBeNull(),
  );
});
