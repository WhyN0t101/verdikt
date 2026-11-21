import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "../api";
import { downloadText } from "../lib/csv";
import { ago, shortenMiddle, typeTag } from "../lib/format";
import type { CaseDetail, IOCType, Level } from "../model";
import { LEVEL_BG } from "./LevelBadge";

const BTN = "rounded border border-line-strong px-2.5 py-1 text-xs hover:border-accent disabled:opacity-50";

function Detail({ id, onOpen, onGone }: { id: string; onOpen: (reportId: string) => void; onGone: () => void }) {
  const q = useQuery({ queryKey: ["case", id], queryFn: () => api.caseGet(id) });
  if (q.isPending) return <div className="pixel m-4 h-24" role="status" aria-label="Loading case" />;
  if (q.isError) return <p className="p-4 text-sm text-malicious">Could not load the case: {q.error.message}</p>;
  // the form fields start from the stored case; the parent keys this component by case id
  return <Editor id={id} data={q.data} onOpen={onOpen} onGone={onGone} />;
}

function Editor({
  id,
  data,
  onOpen,
  onGone,
}: {
  id: string;
  data: CaseDetail;
  onOpen: (reportId: string) => void;
  onGone: () => void;
}) {
  const qc = useQueryClient();
  const [notes, setNotes] = useState(data.notes);
  const [tags, setTags] = useState(data.tags.join(", "));
  const [title, setTitle] = useState(data.title);

  const refresh = (c: CaseDetail) => {
    qc.setQueryData(["case", id], c);
    void qc.invalidateQueries({ queryKey: ["cases"] });
  };
  const save = useMutation({
    mutationFn: () =>
      api.casePatch(id, {
        title,
        notes,
        tags: tags
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean),
      }),
    onSuccess: refresh,
  });
  const remove = useMutation({ mutationFn: (reportId: string) => api.caseRemove(id, reportId), onSuccess: refresh });
  const del = useMutation({
    mutationFn: () => api.caseDelete(id),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["cases"] });
      onGone();
    },
  });
  const exp = useMutation({
    mutationFn: async (format: "md" | "html") => ({
      format,
      text: await api.download(`/api/cases/${encodeURIComponent(id)}/export?format=${format}`),
    }),
    onSuccess: ({ format, text }) =>
      downloadText(`verdikt-case-${id.slice(0, 8)}.${format}`, text, format === "md" ? "text/markdown" : "text/html"),
  });

  return (
    <section aria-label="Case detail" className="space-y-4 p-4">
      <div>
        <label htmlFor="case-title" className="label">
          Title
        </label>
        <input
          id="case-title"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          className="mt-1 w-full border border-line-strong bg-bg px-3 py-2 text-sm outline-none focus:border-accent"
        />
      </div>
      <div>
        <label htmlFor="case-tags" className="label">
          Tags (comma separated)
        </label>
        <input
          id="case-tags"
          value={tags}
          onChange={(e) => setTags(e.target.value)}
          className="mono mt-1 w-full border border-line-strong bg-bg px-3 py-2 text-[13px] outline-none focus:border-accent"
        />
      </div>
      <div>
        <label htmlFor="case-notes" className="label">
          Notes
        </label>
        <textarea
          id="case-notes"
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          rows={6}
          className="mt-1 w-full resize-y border border-line-strong bg-bg p-3 text-sm outline-none focus:border-accent"
        />
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <button type="button" className={BTN} disabled={save.isPending} onClick={() => save.mutate()}>
          Save case
        </button>
        <button type="button" className={BTN} disabled={exp.isPending} onClick={() => exp.mutate("md")}>
          Export Markdown
        </button>
        <button type="button" className={BTN} disabled={exp.isPending} onClick={() => exp.mutate("html")}>
          Export HTML
        </button>
        <button type="button" className={`${BTN} ml-auto text-malicious`} disabled={del.isPending} onClick={() => del.mutate()}>
          Delete case
        </button>
        <p className="w-full text-xs text-muted" role="status" aria-live="polite">
          {save.isSuccess && "Case saved."}
          {save.isError && `Could not save: ${save.error.message}`}
          {exp.isError && `Could not export: ${exp.error.message}`}
        </p>
      </div>

      <div>
        <h3 className="label mb-2">Reports ({data.reports.length})</h3>
        {data.reports.length === 0 && <p className="text-sm text-muted">No reports yet. Open a report and choose Add to case.</p>}
        <ul>
          {data.reports.map((r) => (
            <li key={r.id} className="flex items-center gap-3 border-t border-line py-1.5">
              <span aria-hidden="true" className={`h-2 w-2 shrink-0 rounded-full ${LEVEL_BG[r.level as Level]}`} />
              <span className="mono min-w-0 flex-1 truncate text-[13px]" title={r.ioc}>
                {shortenMiddle(r.ioc, 40)}
              </span>
              <span className="label">{typeTag(r.ioc_type as IOCType)}</span>
              <button type="button" className={BTN} onClick={() => onOpen(r.id)} aria-label={`Open report for ${r.ioc}`}>
                Open
              </button>
              <button type="button" className={BTN} onClick={() => remove.mutate(r.id)} aria-label={`Remove ${r.ioc} from the case`}>
                Remove
              </button>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}

/** Investigations: a case groups reports with notes and tags, and exports as one document. */
export function Cases({ onOpen }: { onOpen: (reportId: string) => void }) {
  const qc = useQueryClient();
  const [tag, setTag] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [title, setTitle] = useState("");
  const all = useQuery({ queryKey: ["cases"], queryFn: () => api.cases() });
  const tags = [...new Set((all.data ?? []).flatMap((c) => c.tags))].sort();
  const shown = (all.data ?? []).filter((c) => !tag || c.tags.includes(tag));

  const create = useMutation({
    mutationFn: () => api.caseCreate(title.trim()),
    onSuccess: (c) => {
      setTitle("");
      setSelected(c.id);
      void qc.invalidateQueries({ queryKey: ["cases"] });
    },
  });

  return (
    <div className="grid min-h-0 gap-4 p-5 lg:grid-cols-[20rem_minmax(0,1fr)]">
      <section aria-label="Cases" className="border border-line bg-panel">
        <h2 className="label border-b border-line px-4 py-2.5">Investigations</h2>
        <form
          className="flex gap-2 border-b border-line p-3"
          onSubmit={(e) => {
            e.preventDefault();
            if (title.trim()) create.mutate();
          }}
        >
          <label htmlFor="new-case" className="sr-only">
            New case title
          </label>
          <input
            id="new-case"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="New case title"
            className="min-w-0 flex-1 border border-line-strong bg-bg px-2 py-1.5 text-sm outline-none focus:border-accent"
          />
          <button type="submit" className={BTN} disabled={!title.trim() || create.isPending}>
            Create
          </button>
        </form>
        {create.isError && (
          <p role="alert" className="px-3 py-2 text-xs text-malicious">
            {create.error.message}
          </p>
        )}
        {tags.length > 0 && (
          <div className="flex flex-wrap gap-1.5 border-b border-line px-3 py-2">
            {tags.map((t) => (
              <button
                key={t}
                type="button"
                aria-pressed={tag === t}
                onClick={() => setTag(tag === t ? null : t)}
                className={`label border px-1.5 py-0.5 normal-case ${tag === t ? "border-accent text-ink" : "border-line"}`}
              >
                {t}
              </button>
            ))}
          </div>
        )}
        {all.data && shown.length === 0 && <p className="p-4 text-sm text-muted">No cases yet. Create one, then add reports to it.</p>}
        <ul>
          {shown.map((c) => (
            <li key={c.id}>
              <button
                type="button"
                onClick={() => setSelected(c.id)}
                aria-current={selected === c.id ? "true" : undefined}
                className={`block w-full px-4 py-2 text-left hover:bg-panel2 ${selected === c.id ? "bg-panel2" : ""}`}
              >
                <span className="block truncate text-sm">{c.title}</span>
                <span className="label block">
                  {c.report_count} report{c.report_count === 1 ? "" : "s"} · {ago(c.updated_at)}
                  {c.tags.length > 0 && ` · ${c.tags.join(", ")}`}
                </span>
              </button>
            </li>
          ))}
        </ul>
      </section>

      <div className="border border-line bg-panel">
        {selected ? (
          <Detail key={selected} id={selected} onOpen={onOpen} onGone={() => setSelected(null)} />
        ) : (
          <p className="p-6 text-sm text-muted">Select a case to read and edit its notes, or create a new one.</p>
        )}
      </div>
    </div>
  );
}
