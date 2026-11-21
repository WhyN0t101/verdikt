import { LEVEL_LABEL, LEVEL_ORDER, shortenMiddle, typeTag } from "../lib/format";
import type { IOCType, Level, ReportSummary } from "../model";
import { LEVEL_BG } from "./LevelBadge";

interface Props {
  items: ReportSummary[];
  activeId: string | null;
  onSelect: (id: string) => void;
}

export function HistoryList({ items, activeId, onSelect }: Props) {
  if (items.length === 0) {
    return <p className="px-3 py-2 text-sm text-muted">Nothing checked yet. Paste an indicator to start.</p>;
  }
  return (
    <nav aria-label="History" className="space-y-4">
      {LEVEL_ORDER.map((level) => {
        const group = items.filter((i) => i.level === level);
        if (group.length === 0) return null;
        return (
          <div key={level}>
            <h3 className="px-3 pb-1 text-xs font-medium text-muted">
              {LEVEL_LABEL[level]} <span className="text-muted">({group.length})</span>
            </h3>
            <ul>
              {group.map((i) => (
                <li key={i.id}>
                  <button
                    type="button"
                    onClick={() => onSelect(i.id)}
                    aria-current={i.id === activeId ? "true" : undefined}
                    title={i.ioc}
                    className={`flex w-full items-center gap-2 px-3 py-1.5 text-left hover:bg-panel2 ${i.id === activeId ? "bg-panel2" : ""}`}
                  >
                    <span aria-hidden="true" className={`h-2 w-2 shrink-0 rounded-full ${LEVEL_BG[level as Level]}`} />
                    <span className="mono min-w-0 flex-1 truncate text-[13px]">{shortenMiddle(i.ioc, 26)}</span>
                    <span className="mono shrink-0 text-[10px] text-muted">{typeTag(i.ioc_type as IOCType)}</span>
                  </button>
                </li>
              ))}
            </ul>
          </div>
        );
      })}
    </nav>
  );
}
