import { useEffect, useState } from "react";
import { LEVEL_LABEL, LEVEL_ORDER, typeTag } from "../lib/format";
import { IOC_TYPES, type HistoryFilter, Q_MAX, isFiltered } from "../lib/historyQuery";
import type { IOCType, Level } from "../model";
import { Button, FIELD } from "./ui";

interface Props {
  filter: HistoryFilter;
  onChange: (change: Partial<HistoryFilter>) => void;
  /** rows loaded so far, shown as the result count while a filter is on */
  count: number;
  onClear: () => void;
}

const DEBOUNCE_MS = 250;

/** Search box and two selects above the history list. The sidebar is narrow, so they stack. */
export function HistoryFilters({ filter, onChange, count, onClear }: Props) {
  const [text, setText] = useState(filter.q);

  // wait for a pause in typing before asking the API
  useEffect(() => {
    if (text.trim() === filter.q) return;
    const t = setTimeout(() => onChange({ q: text.trim() }), DEBOUNCE_MS);
    return () => clearTimeout(t);
  }, [text, filter.q, onChange]);

  const active = isFiltered(filter) || text !== "";
  return (
    <div className="space-y-2 px-3 pb-3">
      <label htmlFor="history-q" className="sr-only">
        Search history
      </label>
      <input
        id="history-q"
        type="search"
        value={text}
        maxLength={Q_MAX}
        onChange={(e) => setText(e.target.value)}
        placeholder="Search"
        spellCheck={false}
        autoComplete="off"
        className={`${FIELD} mono h-8 py-0 text-[13px]`}
      />
      <div className="flex gap-2">
        <label htmlFor="history-level" className="sr-only">
          Verdict
        </label>
        <select id="history-level" value={filter.level} onChange={(e) => onChange({ level: e.target.value as Level | "" })} className={`${FIELD} h-8 min-w-0 flex-1 py-0 text-xs`}>
          <option value="">Verdict</option>
          {LEVEL_ORDER.map((l) => (
            <option key={l} value={l}>
              {LEVEL_LABEL[l]}
            </option>
          ))}
        </select>
        <label htmlFor="history-type" className="sr-only">
          Indicator type
        </label>
        <select id="history-type" value={filter.type} onChange={(e) => onChange({ type: e.target.value as IOCType | "" })} className={`${FIELD} h-8 min-w-0 flex-1 py-0 text-xs`}>
          <option value="">Type</option>
          {IOC_TYPES.map((t) => (
            <option key={t} value={t}>
              {typeTag(t)}
            </option>
          ))}
        </select>
      </div>
      {active && (
        <div className="flex items-center justify-between gap-2">
          <p className="text-xs text-muted" role="status" aria-live="polite">
            {count === 0 ? "No report matches." : `${count} loaded.`}
          </p>
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              setText("");
              onClear();
            }}
          >
            Clear
          </Button>
        </div>
      )}
    </div>
  );
}
