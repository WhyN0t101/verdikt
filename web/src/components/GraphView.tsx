import cytoscape from "cytoscape";
import fcose from "cytoscape-fcose";
import { useEffect, useRef, useState } from "react";
import { LEVEL_LABEL, formatQuota, shortenMiddle } from "../lib/format";
import type { Graph, GraphNode, SourceInfo } from "../model";

cytoscape.use(fcose);

const SHAPES: Record<string, cytoscape.Css.NodeShape> = {
  ip: "ellipse",
  domain: "round-rectangle",
  url: "diamond",
  hash: "hexagon",
  malware: "octagon",
  asn: "barrel",
};
const PIVOTABLE = new Set(["ip", "domain", "url", "hash"]);

const css = (name: string) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

interface Props {
  graph: Graph;
  rootId: string;
  /** re-read colours when the theme changes */
  theme: string;
  sources: SourceInfo[];
  pending: boolean;
  onPivot: (value: string) => void;
}

export function GraphView({ graph, rootId, theme, sources, pending, onPivot }: Props) {
  const host = useRef<HTMLDivElement>(null);
  const [selected, setSelected] = useState<GraphNode | null>(null);

  useEffect(() => {
    if (!host.current) return;
    const level = (l: string) => css(`--lvl-${l}`);
    const cy = cytoscape({
      container: host.current,
      elements: [
        ...graph.nodes.map((n) => ({
          data: { id: n.id, label: shortenMiddle(n.label, 24), kind: n.kind, level: n.level, full: n.label, root: n.id === rootId },
        })),
        ...graph.edges.map((e, i) => ({ data: { id: `e${i}`, source: e.source, target: e.target, label: e.label } })),
      ],
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)",
            "font-family": css("--font-mono"),
            "font-size": 10,
            color: css("--text"),
            "text-valign": "bottom",
            "text-margin-y": 5,
            "background-color": css("--panel-2"),
            "border-width": 2,
            "border-color": (n: cytoscape.NodeSingular) => level(n.data("level") as string),
            shape: (n: cytoscape.NodeSingular) => SHAPES[n.data("kind") as string] ?? "ellipse",
            width: 26,
            height: 26,
          },
        },
        { selector: "node[?root]", style: { width: 36, height: 36, "border-width": 3 } },
        { selector: "node:selected", style: { "overlay-color": css("--violet-500"), "overlay-opacity": 0.25, "overlay-padding": 6 } },
        {
          selector: "edge",
          style: {
            width: 1,
            "line-color": css("--violet-300"),
            "target-arrow-color": css("--violet-300"),
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            label: "data(label)",
            "font-size": 8,
            "font-family": css("--font-mono"),
            color: css("--muted"),
            "text-rotation": "autorotate",
            "text-background-color": css("--panel"),
            "text-background-opacity": 1,
            "text-background-padding": "2px",
          },
        },
      ],
      layout: { name: "fcose", animate: false, randomize: true, nodeRepulsion: () => 9000, idealEdgeLength: () => 90 } as cytoscape.LayoutOptions,
      wheelSensitivity: 0.3,
      minZoom: 0.4,
      maxZoom: 3,
    });
    cy.on("tap", "node", (evt) => {
      const id = evt.target.id() as string;
      setSelected(graph.nodes.find((n) => n.id === id) ?? null);
    });
    cy.on("tap", (evt) => {
      if (evt.target === cy) setSelected(null);
    });
    return () => cy.destroy();
  }, [graph, rootId, theme]);

  const budget = sources.find((s) => s.name === "virustotal");
  const canPivot = selected !== null && PIVOTABLE.has(selected.kind) && selected.id !== rootId;

  return (
    <div className="absolute inset-0">
      <div
        ref={host}
        role="img"
        aria-label={`Relationship graph with ${graph.nodes.length} nodes and ${graph.edges.length} edges`}
        className="h-full w-full"
      />
      <aside className="hud absolute bottom-4 right-6 w-64 p-3 text-sm" aria-live="polite">
        <h3 className="label">Selected node</h3>
        {selected ? (
          <div className="mt-2 space-y-2">
            <p className="mono break-all text-[13px]">{selected.label}</p>
            <p className="label">
              {selected.kind} · {LEVEL_LABEL[selected.level]}
            </p>
            {canPivot ? (
              <button
                type="button"
                disabled={pending}
                onClick={() => onPivot(selected.label)}
                className="h-9 w-full rounded-md bg-accent px-3 text-sm font-medium text-on-accent disabled:opacity-50"
              >
                Check this IOC
              </button>
            ) : (
              <p className="text-muted">{selected.id === rootId ? "This is the current indicator." : "Only IPs, domains, URLs and hashes can be checked."}</p>
            )}
            {budget && (
              <p className="text-xs text-muted">
                Each check spends source quota. VirusTotal today: <span className="mono">{formatQuota(budget.used_today, budget.daily_budget)}</span>
              </p>
            )}
          </div>
        ) : (
          <p className="mt-2 text-muted">Select a node to check it. Related nodes are unchecked, so they show as unknown.</p>
        )}
      </aside>
    </div>
  );
}
