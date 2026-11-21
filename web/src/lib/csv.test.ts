import { describe, expect, it } from "vitest";
import { safeCell, toCsv } from "./csv";

describe("safeCell", () => {
  it.each([
    ["=HYPERLINK(1)", "'=HYPERLINK(1)"],
    ["+1", "'+1"],
    ["-2", "'-2"],
    ["@SUM(1)", "'@SUM(1)"],
    ["\tx", "'\tx"],
    ["1.2.3.4", "1.2.3.4"],
    ["http://a.example", "http://a.example"],
  ])("%s", (input, want) => expect(safeCell(input)).toBe(want));
});

describe("toCsv", () => {
  it("quotes commas, quotes and newlines", () => {
    expect(toCsv([["a,b", 'say "hi"', "line\nbreak"]])).toBe('"a,b","say ""hi""","line\nbreak"\n');
  });
  it("neutralises formulas before quoting", () => {
    expect(toCsv([["=1+1,2"]])).toBe("\"'=1+1,2\"\n");
  });
  it("joins rows", () => {
    expect(toCsv([["a", "b"], ["c", "d"]])).toBe("a,b\nc,d\n");
  });
});
