import { LEVEL_ICON, LEVEL_LABEL } from "../lib/format";
import type { Level } from "../model";

export const LEVEL_TEXT: Record<Level, string> = {
  malicious: "text-malicious",
  suspicious: "text-suspicious",
  safe: "text-safe",
  unknown: "text-unknown",
  info: "text-info",
};

export const LEVEL_BG: Record<Level, string> = {
  malicious: "bg-malicious",
  suspicious: "bg-suspicious",
  safe: "bg-safe",
  unknown: "bg-unknown",
  info: "bg-info",
};

export const LEVEL_BORDER: Record<Level, string> = {
  malicious: "border-malicious",
  suspicious: "border-suspicious",
  safe: "border-safe",
  unknown: "border-unknown",
  info: "border-info",
};

/** Level is always icon + text, never colour alone. */
export function LevelBadge({ level, size = "sm" }: { level: Level; size?: "sm" | "lg" | "xl" }) {
  const big = size === "lg";
  const huge = size === "xl";
  return (
    <span
      className={`inline-flex items-center gap-1.5 font-semibold ${LEVEL_TEXT[level]} ${huge ? "font-sans text-4xl tracking-tight" : `font-mono uppercase tracking-wider ${big ? "text-lg" : "text-xs"}`}`}
    >
      <span
        aria-hidden="true"
        className={`grid place-items-center rounded-sm border ${LEVEL_BORDER[level]} ${huge ? "h-9 w-9 rounded-md border-2 text-xl" : big ? "h-6 w-6 text-sm" : "h-4 w-4 text-[10px]"}`}
      >
        {LEVEL_ICON[level]}
      </span>
      {LEVEL_LABEL[level]}
    </span>
  );
}
