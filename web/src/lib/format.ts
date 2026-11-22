import type { IOCType, Level } from "../model";

/** `http://evil.com` -> `hxxp://evil[.]com`. Copy buttons and notifications defang by default. */
export function defang(value: string): string {
  const out = value.replaceAll(".", "[.]");
  const schemes: [string, string][] = [
    ["https://", "hxxps://"],
    ["http://", "hxxp://"],
    ["ftp://", "fxp://"],
  ];
  for (const [from, to] of schemes) {
    if (out.toLowerCase().startsWith(from)) return to + out.slice(from.length);
  }
  return out;
}

export const LEVEL_ORDER: Level[] = ["malicious", "suspicious", "unknown", "safe"];

export const LEVEL_LABEL: Record<Level, string> = {
  malicious: "Malicious",
  suspicious: "Suspicious",
  safe: "Safe",
  unknown: "Unknown",
  info: "Info",
};

/** Glyph shown next to every level so colour is never the only signal. */
export const LEVEL_ICON: Record<Level, string> = {
  malicious: "✕",
  suspicious: "!",
  safe: "✓",
  unknown: "?",
  info: "i",
};

const TYPE_TAG: Record<IOCType, string> = {
  ip: "IP",
  domain: "DOM",
  url: "URL",
  md5: "MD5",
  sha1: "SHA1",
  sha256: "SHA256",
};
export const typeTag = (t: IOCType): string => TYPE_TAG[t];
export const IOC_TYPES = Object.keys(TYPE_TAG) as IOCType[];

/** Relative age for lists, e.g. `5 min ago`, `3 h ago`, `2 d ago`. */
export function ago(iso: string, now: number = Date.now()): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "-";
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

export function formatDuration(ms: number): string {
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`;
}

/** Quota readout, e.g. `412/500`; sources without a daily cap show usage only. */
export function formatQuota(used: number, budget: number | null): string {
  return budget === null ? `${used}` : `${used}/${budget}`;
}

export function shortenMiddle(value: string, max = 28): string {
  if (value.length <= max) return value;
  const keep = max - 1;
  const head = Math.ceil(keep * 0.6);
  return `${value.slice(0, head)}…${value.slice(value.length - (keep - head))}`;
}

/** Clock time for a log line, e.g. `14:03:15`. */
export function clock(iso: string): string {
  const d = new Date(iso);
  return [d.getHours(), d.getMinutes(), d.getSeconds()].map((n) => String(n).padStart(2, "0")).join(":");
}
