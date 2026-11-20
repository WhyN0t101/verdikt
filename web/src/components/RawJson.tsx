import { useQuery } from "@tanstack/react-query";
import { api } from "../api";

/** Full stored report including vendor `raw` payloads, rendered as text only. */
export function RawJson({ id }: { id: string }) {
  const q = useQuery({ queryKey: ["report-raw", id], queryFn: () => api.report(id, true) });
  if (q.isPending) return <div className="pixel h-24 rounded-md" role="status" aria-label="Loading raw JSON" />;
  if (q.isError) return <p className="text-sm text-malicious">Could not load the raw report: {q.error.message}</p>;
  return (
    <pre className="mono max-h-[28rem] overflow-auto rounded-md border border-line bg-panel p-3 text-xs">
      {JSON.stringify(q.data, null, 2)}
    </pre>
  );
}
