import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "../api";
import { downloadText } from "../lib/csv";
import { ago, shortenMiddle, typeTag } from "../lib/format";
import type { CaseDetail, IOCType, Level } from "../model";
import { LevelBadge } from "./LevelBadge";
import { Button, FIELD } from "./ui";

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
        <label htmlFor="case-title" className="text-xs text-muted">
          Title
        </label>
        <input
          id="case-title"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          className={`${FIELD} mt-1`}
        />
      </div>
      <div>
        <label htmlFor="case-tags" className="text-xs text-muted">
          Tags (comma separated)
        </label>
        <input
          id="case-tags"
          value={tags}
          onChange={(e) => setTags(e.target.value)}
          className={`${FIELD} mono mt-1`}
        />
      </div>
      <div>
        <label htmlFor="case-notes" className="text-xs text-muted">
          Notes
        </label>
        <textarea
          id="case-notes"
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          rows={6}
          className={`${FIELD} mt-1 resize-y`}
        />
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <Button size="sm" disabled={save.isPending} onClick={() => save.mutate()}>
          Save case
        </Button>
        <Button size="sm" disabled={exp.isPending} onClick={() => exp.mutate("md")}>
          Export Markdown
        </Button>
        <Button size="sm" disabled={exp.isPending} onClick={() => exp.mutate("html")}>
          Export HTML
        </Button>
        <Button variant="danger" size="sm" className="ml-auto" disabled={del.isPending} onClick={() => del.mutate()}>
          Delete case
        </Button>
        <p className="w-full text-xs text-muted" role="status" aria-live="polite">
          {save.isSuccess && "Case saved."}
          {save.isError && `Could not save: ${save.error.message}`}
          {exp.isError && `Could not export: ${exp.error.message}`}
        </p>
      </div>

      <div>
        <h3 className="mb-2 text-sm font-medium">Timeline, {data.reports.length} report{data.reports.length === 1 ? "" : "s"}</h3>
        {data.reports.length === 0 && <p className="text-sm text-muted">No reports yet. Open a report and choose Add to case.</p>}
        <ul>
          {[...data.reports]
            .sort((a, b) => a.created_at.localeCompare(b.created_at))
            .map((r) => (
              <li key={r.id} className="flex items-center gap-3 border-t border-line py-2">
                <span className="mono w-20 shrink-0 text-xs text-muted" title={r.created_at}>
                  {ago(r.created_at)}
                </span>
                <span className="w-28 shrink-0">
                  <LevelBadge level={r.level as Level} />
                </span>
                <span className="mono min-w-0 flex-1 truncate text-[13px]" title={r.ioc}>
                  {shortenMiddle(r.ioc, 40)}
                </span>
                <span className="label">{typeTag(r.ioc_type as IOCType)}</span>
                <Button size="sm" onClick={() => onOpen(r.id)} aria-label={`Open report for ${r.ioc}`}>
                  Open
                </Button>
                <Button size="sm" variant="ghost" onClick={() => remove.mutate(r.id)} aria-label={`Remove ${r.ioc} from the case`}>
                  Remove
                </Button>
              </li>
            ))}
        </ul>
      </div>
    </section>
  );
}

/** Investigations: a case groups reports with notes and tags, and exports as one document. */
export function Cases({ onOpen, initialId = null }: { onOpen: (reportId: string) => void; initialId?: string | null }) {
  const qc = useQueryClient();
  const [tag, setTag] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(initialId);
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
      <section aria-label="Cases" className="rounded-lg border border-line bg-panel">
        <h2 className="border-b border-line px-4 py-3 text-sm font-semibold">Investigations</h2>
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
            className={`${FIELD} min-w-0 flex-1`}
          />
          <Button type="submit" size="sm" disabled={!title.trim() || create.isPending}>
            Create
          </Button>
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
                <span className="feed-text block truncate text-sm">{c.title}</span>
                <span className="label block">
                  {c.report_count} report{c.report_count === 1 ? "" : "s"} · {ago(c.updated_at)}
                  {c.tags.length > 0 && ` · ${c.tags.join(", ")}`}
                </span>
              </button>
            </li>
          ))}
        </ul>
      </section>

      <div className="rounded-lg border border-line bg-panel">
        {selected ? (
          <Detail key={selected} id={selected} onOpen={onOpen} onGone={() => setSelected(null)} />
        ) : (
          <p className="p-6 text-sm text-muted">Select a case to read and edit its notes, or create a new one.</p>
        )}
      </div>
    </div>
  );
}
