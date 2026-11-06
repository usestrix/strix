import { useEffect, useMemo, useState } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  type Edge,
  type Node,
} from "@xyflow/react";
import dagre from "@dagrejs/dagre";
import { AlertTriangle, Route, Shield } from "lucide-react";
import { fetchAttackPath } from "@/data/serverSource";
import type {
  AttackPathEdge,
  AttackPathNode as GraphNode,
  AttackPathPayload,
} from "@/types/attack-path";
import AttackPathNode, { type AttackPathNodeData } from "@/components/AttackPathNode";

import "@xyflow/react/dist/style.css";

const NODE_W = 220;
const NODE_H = 72;
const nodeTypes = { attackPathNode: AttackPathNode };

function isLateralEdge(edge: AttackPathEdge): boolean {
  return (edge.labels ?? []).includes("MODELED_LATERAL");
}

function layoutGraph(
  nodes: GraphNode[],
  edges: AttackPathEdge[],
  showLateral: boolean,
  bfsPairs: Set<string>,
  dijkstraPairs: Set<string>
): { rfNodes: Node[]; rfEdges: Edge[] } {
  const visibleEdges = edges.filter((e) => showLateral || !isLateralEdge(e));
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: "LR", nodesep: 40, ranksep: 70 });

  const rfNodes: Node[] = [];
  for (const node of nodes) {
    const id = String(node.id);
    g.setNode(id, { width: NODE_W, height: NODE_H });
    const data: AttackPathNodeData = {
      name: node.name,
      type: node.type,
      zone: node.zone,
      impact: node.impact,
      provenance: node.provenance,
      isEntry: !!node.is_entry_point,
      isCrown: !!node.is_crown_jewel,
    };
    rfNodes.push({
      id,
      type: "attackPathNode",
      position: { x: 0, y: 0 },
      data,
    });
  }

  const rfEdges: Edge[] = [];
  for (const edge of visibleEdges) {
    const id = `${edge.from}->${edge.to}`;
    g.setEdge(String(edge.from), String(edge.to));
    const simulated = edge.provenance === "simulated";
    const onBfs = bfsPairs.has(`${edge.from}->${edge.to}`);
    const onDijkstra = dijkstraPairs.has(`${edge.from}->${edge.to}`);
    const tags: string[] = [];
    if (onBfs) tags.push("BFS");
    if (onDijkstra) tags.push("DJ");
    if (!onBfs && !onDijkstra) tags.push(simulated ? "sim" : "finding");
    // Sky = BFS, rose = Dijkstra-only, teal when both; keep finding/sim colors otherwise.
    let stroke = simulated ? "#b45309" : "#34d399";
    let strokeWidth = simulated ? 1.25 : 1.75;
    if (onBfs && onDijkstra) {
      stroke = "#2dd4bf";
      strokeWidth = 2.75;
    } else if (onBfs) {
      stroke = "#38bdf8";
      strokeWidth = 2.5;
    } else if (onDijkstra) {
      stroke = "#fb7185";
      strokeWidth = 2.5;
    }
    rfEdges.push({
      id,
      source: String(edge.from),
      target: String(edge.to),
      animated: onBfs || onDijkstra || !simulated,
      label: `${((edge.probability ?? 0) * 100).toFixed(0)}% · ${tags.join("+")}`,
      labelStyle: {
        fill: onBfs || onDijkstra ? "#e2e8f0" : "#aaa",
        fontSize: 10,
      },
      style: {
        stroke,
        strokeWidth,
        strokeDasharray: simulated && !onBfs && !onDijkstra ? "5 4" : undefined,
      },
    });
  }

  dagre.layout(g);
  for (const node of rfNodes) {
    const pos = g.node(node.id);
    if (pos) {
      node.position = { x: pos.x - NODE_W / 2, y: pos.y - NODE_H / 2 };
    }
  }
  return { rfNodes, rfEdges };
}

function defensePriority(edges: AttackPathEdge[], nodes: GraphNode[]): AttackPathEdge[] {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  return [...edges]
    .filter((e) => e.provenance === "from_finding")
    .sort((a, b) => {
      const aCrown = byId.get(a.to)?.is_crown_jewel ? 1 : 0;
      const bCrown = byId.get(b.to)?.is_crown_jewel ? 1 : 0;
      if (aCrown !== bCrown) return bCrown - aCrown;
      return (b.probability ?? 0) - (a.probability ?? 0);
    });
}

interface AttackPathViewProps {
  runName: string | null;
}

export default function AttackPathView({ runName }: AttackPathViewProps) {
  const [payload, setPayload] = useState<AttackPathPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  // Product default: simulated lateral OFF in the UI.
  const [showSimulatedLateral, setShowSimulatedLateral] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setPayload(null);
    setError(null);
    setShowSimulatedLateral(false);
    fetchAttackPath(runName)
      .then((data) => {
        if (!cancelled) setPayload(data);
      })
      .catch((e: unknown) => {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : "Could not load attack-path data.");
        }
      });
    return () => {
      cancelled = true;
    };
  }, [runName]);

  const graph = payload?.graph ?? null;
  const bfsPairs = useMemo(() => {
    const pairs = new Set<string>();
    for (const edge of payload?.meta?.modeled_paths?.bfs_edges ?? []) {
      if (edge.from != null && edge.to != null) pairs.add(`${edge.from}->${edge.to}`);
    }
    return pairs;
  }, [payload?.meta?.modeled_paths?.bfs_edges]);
  const dijkstraPairs = useMemo(() => {
    const pairs = new Set<string>();
    for (const edge of payload?.meta?.modeled_paths?.dijkstra_edges ?? []) {
      if (edge.from != null && edge.to != null) pairs.add(`${edge.from}->${edge.to}`);
    }
    return pairs;
  }, [payload?.meta?.modeled_paths?.dijkstra_edges]);
  const layout = useMemo(() => {
    if (!graph) return { rfNodes: [] as Node[], rfEdges: [] as Edge[] };
    return layoutGraph(
      graph.nodes ?? [],
      graph.edges ?? [],
      showSimulatedLateral,
      bfsPairs,
      dijkstraPairs
    );
  }, [graph, showSimulatedLateral, bfsPairs, dijkstraPairs]);

  const priority = useMemo(() => {
    if (!graph) return [] as AttackPathEdge[];
    return defensePriority(graph.edges ?? [], graph.nodes ?? []).slice(0, 8);
  }, [graph]);

  const hasLateral = useMemo(
    () => (graph?.edges ?? []).some(isLateralEdge),
    [graph]
  );

  if (error) {
    return (
      <div className="flex h-full items-center justify-center p-8 text-sm text-red-300">
        {error}
      </div>
    );
  }

  if (!payload) {
    return (
      <div className="flex h-full items-center justify-center p-8 text-sm text-[#888]">
        Loading modeled attack-path…
      </div>
    );
  }

  if (!payload.available || !graph) {
    return (
      <div className="mx-auto flex max-w-2xl flex-col gap-3 p-8">
        <div className="flex items-center gap-2 text-[#ededed]">
          <Route className="h-5 w-5 text-[#888]" />
          <h2 className="text-lg font-medium">Attack path</h2>
        </div>
        <p className="rounded-lg border border-[rgba(255,255,255,0.08)] bg-[#141414] p-4 text-sm leading-relaxed text-[#bbb]">
          {payload.reason ??
            "No modeled attack-path artifacts for this run. Generate them with the DSA backend after the scan."}
        </p>
        <p className="text-xs text-[#777]">
          This view never invents paths. When artifacts are missing the UI degrades
          gracefully — it does not imply confirmed multi-hop exploits.
        </p>
      </div>
    );
  }

  const disclaimer =
    payload.disclaimer ||
    graph.disclaimer ||
    "MODELED ATTACK GRAPH — not a confirmed multi-hop exploit chain. Nodes/edges marked provenance=from_finding come from Strix finding fields (target/endpoint/severity). Nodes/edges marked provenance=simulated are explicit modeling assumptions (threat-model scaffolding), NOT pentest proof.";

  return (
    <div className="flex h-full min-h-0 flex-col gap-3 p-4 md:p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2 text-[#ededed]">
            <Route className="h-5 w-5 text-emerald-400" />
            <h2 className="text-lg font-medium">Attack path</h2>
          </div>
          <p className="mt-1 max-w-3xl text-xs leading-relaxed text-[#999]">{disclaimer}</p>
        </div>
        <div className="flex flex-wrap items-center gap-3 text-xs text-[#aaa]">
          <span className="rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-1 text-emerald-300">
            FROM FINDING = Strix field-derived
          </span>
          <span className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-1 text-amber-300">
            SIMULATED = modeling assumption
          </span>
          <span className="rounded border border-sky-500/30 bg-sky-500/10 px-2 py-1 text-sky-300">
            BFS = modeled fewest-hop (not confirmed pivot)
          </span>
          <span className="rounded border border-rose-500/30 bg-rose-500/10 px-2 py-1 text-rose-300">
            DJ = modeled max path-product / Dijkstra −log(p)
          </span>
        </div>
      </div>

      {(graph.warnings?.length ?? 0) > 0 && (
        <div className="flex gap-2 rounded-lg border border-amber-500/20 bg-amber-500/5 px-3 py-2 text-xs text-amber-100/90">
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 flex-none" />
          <ul className="list-disc space-y-0.5 pl-4">
            {graph.warnings!.map((w) => (
              <li key={w}>{w}</li>
            ))}
          </ul>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-4 text-xs text-[#bbb]">
        <label className="flex cursor-pointer items-center gap-2">
          <input
            type="checkbox"
            className="accent-amber-500"
            checked={showSimulatedLateral}
            disabled={!hasLateral}
            onChange={(e) => setShowSimulatedLateral(e.target.checked)}
          />
          Show simulated lateral edges
          <span className="text-[#777]">(off by default; never confirmed pivots)</span>
        </label>
        {payload.meta?.engine?.skipped_reason && (
          <span className="text-[#888]">Engine note: {payload.meta.engine.skipped_reason}</span>
        )}
        {payload.meta?.engine?.invoked && (
          <span className="text-[#888]">
            C++ engine invoked
            {payload.meta.engine.returncode != null
              ? ` (exit ${payload.meta.engine.returncode})`
              : ""}
          </span>
        )}
      </div>

      <div className="grid min-h-0 flex-1 grid-cols-1 gap-3 lg:grid-cols-[1fr_280px]">
        <div className="min-h-[320px] overflow-hidden rounded-lg border border-[rgba(255,255,255,0.08)] bg-[#0d0d0d]">
          <ReactFlow
            nodes={layout.rfNodes}
            edges={layout.rfEdges}
            nodeTypes={nodeTypes}
            fitView
            proOptions={{ hideAttribution: true }}
            nodesDraggable={false}
            nodesConnectable={false}
            elementsSelectable={false}
          >
            <Background gap={18} color="#1f1f1f" />
            <Controls showInteractive={false} />
            <MiniMap
              pannable
              zoomable
              maskColor="rgba(0,0,0,0.55)"
              nodeColor={(n) =>
                (n.data as AttackPathNodeData | undefined)?.provenance === "simulated"
                  ? "#b45309"
                  : "#059669"
              }
            />
          </ReactFlow>
        </div>

        <aside className="flex min-h-0 flex-col gap-3 overflow-auto">
          <section className="rounded-lg border border-[rgba(255,255,255,0.08)] bg-[#141414] p-3">
            <div className="mb-2 flex items-center gap-1.5 text-sm font-medium text-[#ededed]">
              <Shield className="h-4 w-4 text-emerald-400" />
              Defense priority
            </div>
            <p className="mb-2 text-[11px] leading-relaxed text-[#888]">
              Ranked from finding-backed exploit steps (severity/CVSS weights). Simulated edges are
              excluded — they are modeling assumptions, not confirmed pivots.
            </p>
            {priority.length === 0 ? (
              <p className="text-xs text-[#777]">No from_finding exploit-step edges in this graph.</p>
            ) : (
              <ol className="space-y-2">
                {priority.map((edge) => {
                  const from = graph.nodes.find((n) => n.id === edge.from);
                  const to = graph.nodes.find((n) => n.id === edge.to);
                  return (
                    <li
                      key={`${edge.from}-${edge.to}-${edge.title ?? ""}`}
                      className="rounded border border-[rgba(255,255,255,0.06)] bg-[#101010] px-2 py-1.5 text-[11px]"
                    >
                      <div className="font-medium text-[#ddd]">
                        {from?.name ?? edge.from} → {to?.name ?? edge.to}
                      </div>
                      <div className="mt-0.5 text-[#888]">
                        p={(edge.probability ?? 0).toFixed(2)} · {edge.protocol ?? "TCP"}
                        {edge.title ? ` · ${edge.title}` : ""}
                      </div>
                      {(edge.finding_ids?.length ?? 0) > 0 && (
                        <div className="mt-0.5 text-[10px] text-emerald-400/80">
                          findings: {edge.finding_ids!.join(", ")}
                        </div>
                      )}
                    </li>
                  );
                })}
              </ol>
            )}
          </section>

          {payload.analysis_text && (
            <section className="rounded-lg border border-[rgba(255,255,255,0.08)] bg-[#141414] p-3">
              <div className="mb-2 text-sm font-medium text-[#ededed]">Engine summary</div>
              <pre className="max-h-56 overflow-auto whitespace-pre-wrap text-[10px] leading-relaxed text-[#999]">
                {payload.analysis_text.slice(0, 4000)}
              </pre>
            </section>
          )}
        </aside>
      </div>
    </div>
  );
}
