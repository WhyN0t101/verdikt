import { describe, expect, it } from "vitest";
import { describeWatch } from "./watchText";

describe("describeWatch", () => {
  it("nothing changed", () => expect(describeWatch("0 verdict change(s)", true)).toEqual({ text: "No verdict changed.", evidence: null, failed: false }));

  it("evidence-only changes are not hidden behind 'No verdict changed.'", () => {
    const s = describeWatch("0 verdict change(s), 2 evidence change(s)", true);
    expect(s.text).toBe("No verdict changed.");
    expect(s.evidence).toContain("2 evidence change(s)");
  });

  it("verdict and evidence changes", () => {
    const s = describeWatch("1 verdict change(s), 3 evidence change(s)", true);
    expect(s.text).toBe("1 verdict change(s).");
    expect(s.evidence).toContain("3 evidence change(s)");
  });

  it("notifications", () => expect(describeWatch("1 verdict change(s), 2 notification(s)", true).text).toBe("1 verdict change(s). 2 notification(s) sent."));

  it("a failed job shows the detail", () => expect(describeWatch("failed: ValueError", false)).toEqual({ text: "Re-check failed: ValueError", evidence: null, failed: true }));

  it("an unknown format is shown as it is", () => expect(describeWatch("something new", true).text).toBe("something new"));
});
