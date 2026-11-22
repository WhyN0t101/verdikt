import type { SourceInfo } from "../model";

// Sources that are off for a reason other than a missing key. The names are env settings, not secrets.
const OFF_HINT: Record<string, string> = {
  crtsh: "opt-in: set VERDIKT_CRTSH in .env",
  passivedns: "needs the VirusTotal key and VERDIKT_VT_RESOLUTIONS in .env",
  localfeeds: "turns on after Update feeds (Overview) or an imported list",
};

export interface SourceState {
  label: "Enabled" | "Needs a key" | "Off";
  hint: string;
}

/** Why a source is on or off, in words (the list never shows a key). */
export function sourceState(s: Pick<SourceInfo, "name" | "enabled" | "requires_key">): SourceState {
  if (s.enabled) return { label: "Enabled", hint: "" };
  const hint = OFF_HINT[s.name];
  if (hint) return { label: "Off", hint };
  return s.requires_key ? { label: "Needs a key", hint: "add its API key to .env (see .env.example)" } : { label: "Off", hint: "opt-in" };
}

/** Daily use: "12/500 today" for a source with a budget, "7 today" without one. */
export const usageText = (s: Pick<SourceInfo, "used_today" | "daily_budget">): string =>
  s.daily_budget === null ? `${s.used_today} today` : `${s.used_today}/${s.daily_budget} today`;
