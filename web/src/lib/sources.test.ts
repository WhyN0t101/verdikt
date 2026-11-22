import { describe, expect, it } from "vitest";
import { sourceState, usageText } from "./sources";

describe("sourceState", () => {
  it("enabled has no hint", () => expect(sourceState({ name: "virustotal", enabled: true, requires_key: true })).toEqual({ label: "Enabled", hint: "" }));

  it("a disabled keyed source needs a key", () => {
    const s = sourceState({ name: "abuseipdb", enabled: false, requires_key: true });
    expect(s.label).toBe("Needs a key");
    expect(s.hint).not.toMatch(/[A-Za-z0-9]{24,}/); // never anything key-like
  });

  it.each([
    ["crtsh", false, "VERDIKT_CRTSH"],
    ["passivedns", true, "VERDIKT_VT_RESOLUTIONS"],
    ["localfeeds", false, "Update feeds"],
  ])("%s is Off and says how to turn it on", (name, requires_key, text) => {
    const s = sourceState({ name, enabled: false, requires_key });
    expect(s.label).toBe("Off");
    expect(s.hint).toContain(text);
  });

  it("an unknown keyless source that is off is opt-in", () =>
    expect(sourceState({ name: "future", enabled: false, requires_key: false })).toEqual({ label: "Off", hint: "opt-in" }));
});

describe("usageText", () => {
  it("with a budget", () => expect(usageText({ used_today: 12, daily_budget: 500 })).toBe("12/500 today"));
  it("without a budget", () => expect(usageText({ used_today: 7, daily_budget: null })).toBe("7 today"));
});
