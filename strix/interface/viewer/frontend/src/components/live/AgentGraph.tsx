"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  useReactFlow,
  type Node,
  type Edge,
} from "@xyflow/react";
import dagre from "@dagrejs/dagre";
import AgentNodeComponent from "./AgentNode";
import GraphSkeleton from "./GraphSkeleton";
import type { AgentNode } from "@/types/events";

import "@xyflow/react/dist/style.css";

const NODE_WIDTH = 260;
const NODE_HEIGHT = 80;

const nodeTypes = { agentNode: AgentNodeComponent };

function getLayoutedElements(
  agents: Map<string, AgentNode>,
  selectedAgentId: string | null
) {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: "TB", nodesep: 60, ranksep: 80 });

  const nodes: Node[] = [];
  const edges: Edge[] = [];

  for (const [id, agent] of agents) {
    g.setNode(id, { width: NODE_WIDTH, height: NODE_HEIGHT });
    nodes.push({
      id,
      type: "agentNode",
      position: { x: 0, y: 0 },
      data: { ...agent, isSelected: id === selectedAgentId },
    });

    if (agent.parentId && agents.has(agent.parentId)) {
      const edgeId = `${agent.parentId}->${id}`;
      g.setEdge(agent.parentId, id);
      edges.push({
        id: edgeId,
        source: agent.parentId,
        target: id,
        style: { stroke: "#2a2a2a", strokeWidth: 1.5 },
      });
    }
  }

  dagre.layout(g);

  for (const node of nodes) {
    const pos = g.node(node.id);
    if (pos) {
      node.position = {
        x: pos.x - NODE_WIDTH / 2,
        y: pos.y - NODE_HEIGHT / 2,
      };
    }
  }

  return { nodes, edges };
}

const ZOOM_DURATION = 300;


/** Centers viewport on the root node (no parentId) at a fixed zoom — only once on first load */
function CenterOnRoot({ nodes }: { nodes: Node[] }) {
  const { setCenter } = useReactFlow();
  const hasCentered = useRef(false);
  useEffect(() => {
    if (nodes.length > 0 && !hasCentered.current) {
      const root = nodes.find((n) => !(n.data as Record<string, unknown>).parentId);
      const target = root ?? nodes[0];
      hasCentered.current = true;
      const cx = target.position.x + NODE_WIDTH / 2;
      const cy = target.position.y + NODE_HEIGHT / 2;
      setTimeout(() => setCenter(cx, cy, { zoom: 0.85, duration: 400 }), 60);
    }
  }, [nodes, setCenter]);
  return null;
}

function SmoothControls() {
  const { zoomIn, zoomOut, fitView } = useReactFlow();
  return (
    <Controls
      position="bottom-right"
      showZoom={false}
      showFitView={false}
      showInteractive={false}
      className="!bg-transparent !border-none !shadow-none"
    >
      <div className="flex flex-col overflow-hidden rounded-lg border border-[#222]">
        <button onClick={() => zoomIn({ duration: ZOOM_DURATION })} className="flex items-center justify-center w-7 h-7 bg-[#111] text-white hover:bg-[#2a2a2a] transition-colors" title="Zoom in">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-3.5 h-3.5"><path d="M12 5v14M5 12h14" /></svg>
        </button>
        <button onClick={() => zoomOut({ duration: ZOOM_DURATION })} className="flex items-center justify-center w-7 h-7 bg-[#111] text-white hover:bg-[#2a2a2a] border-y border-[#222] transition-colors" title="Zoom out">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-3.5 h-3.5"><path d="M5 12h14" /></svg>
        </button>
        <button onClick={() => fitView({ padding: 0.3, duration: ZOOM_DURATION })} className="flex items-center justify-center w-7 h-7 bg-[#111] text-white hover:bg-[#2a2a2a] transition-colors" title="Fit view">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-3.5 h-3.5"><path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7" /></svg>
        </button>
      </div>
    </Controls>
  );
}

interface AgentGraphProps {
  agents: Map<string, AgentNode>;
  selectedAgentId: string | null;
  onSelectAgent: (id: string | null) => void;
  eventsLoaded?: boolean;
  eventsEmpty?: boolean;
  scanCompleted?: boolean;
}

export default function AgentGraph({
  agents,
  selectedAgentId,
  onSelectAgent,
  eventsLoaded,
  eventsEmpty,
  scanCompleted,
}: AgentGraphProps) {
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);

  useEffect(() => {
    if (agents.size === 0) return;
    const { nodes: ln, edges: le } = getLayoutedElements(agents, selectedAgentId);
    setNodes(ln);
    setEdges(le);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [agents.size, setNodes, setEdges]);

  // Sync agent data (status, name, etc.) into existing nodes without re-layout
  useEffect(() => {
    if (agents.size === 0) return;
    setNodes((nds) =>
      nds.map((n) => {
        const agent = agents.get(n.id);
        if (!agent) return n;
        return { ...n, data: { ...agent, isSelected: n.id === selectedAgentId } };
      })
    );
  }, [agents, selectedAgentId, setNodes]);

  const nodeClickedRef = useRef(false);

  const onNodeClick = useCallback(
    (_: React.MouseEvent, node: Node) => {
      nodeClickedRef.current = true;
      onSelectAgent(node.id);
    },
    [onSelectAgent]
  );

  const onPaneClick = useCallback(() => {
    if (nodeClickedRef.current) {
      nodeClickedRef.current = false;
      return;
    }
    onSelectAgent(null);
  }, [onSelectAgent]);

  // Convex responded, zero events — show empty state (not skeleton)
  if (agents.size === 0 && eventsLoaded && eventsEmpty) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-center px-4">
        <div className="w-10 h-10 mb-3 rounded-full bg-[#111] flex items-center justify-center">
          {scanCompleted ? (
            <svg className="w-5 h-5 text-[#444]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 6A2.25 2.25 0 0 1 6 3.75h2.25A2.25 2.25 0 0 1 10.5 6v2.25a2.25 2.25 0 0 1-2.25 2.25H6a2.25 2.25 0 0 1-2.25-2.25V6ZM3.75 15.75A2.25 2.25 0 0 1 6 13.5h2.25a2.25 2.25 0 0 1 2.25 2.25V18a2.25 2.25 0 0 1-2.25 2.25H6A2.25 2.25 0 0 1 3.75 18v-2.25ZM13.5 6a2.25 2.25 0 0 1 2.25-2.25H18A2.25 2.25 0 0 1 20.25 6v2.25A2.25 2.25 0 0 1 18 10.5h-2.25a2.25 2.25 0 0 1-2.25-2.25V6ZM13.5 15.75a2.25 2.25 0 0 1 2.25-2.25H18a2.25 2.25 0 0 1 2.25 2.25V18A2.25 2.25 0 0 1 18 20.25h-2.25a2.25 2.25 0 0 1-2.25-2.25v-2.25Z" />
            </svg>
          ) : (
            <div className="w-2 h-2 rounded-full bg-blue-500 animate-pulse" />
          )}
        </div>
        <p className="text-sm text-[#555]">
          {scanCompleted
            ? "Agent trace data is not available for this pentest"
            : "Waiting for agent data\u2026"}
        </p>
      </div>
    );
  }

  const showGraph = agents.size > 0;

  return (
    <div className="relative h-full">
      {/* Skeleton overlay — fades out when graph is ready */}
      <div
        className={`absolute inset-0 z-10 transition-opacity duration-500 ${
          showGraph ? "opacity-0 pointer-events-none" : "opacity-100"
        }`}
      >
        <GraphSkeleton />
      </div>

      {/* Graph — fades in */}
      <div
        className={`h-full transition-opacity duration-500 ${
          showGraph ? "opacity-100" : "opacity-0"
        }`}
      >
    <ReactFlow
      nodes={nodes}
      edges={edges}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      onNodeClick={onNodeClick}
      onPaneClick={onPaneClick}
      nodeTypes={nodeTypes}
      nodesConnectable={false}
      edgesFocusable={false}
      edgesReconnectable={false}
      minZoom={0.15}
      maxZoom={1.5}
      proOptions={{ hideAttribution: true }}
      className="bg-black"
    >
      <Background color="#111" gap={20} />
      <CenterOnRoot nodes={nodes} />
      <SmoothControls />
      <MiniMap
        position="bottom-left"
        nodeColor={(n) => {
          const status = (n.data as Record<string, unknown>)?.status as string;
          if (status === "running") return "#3b82f6";
          if (status === "completed") return "#10b981";
          if (status === "failed" || status === "error") return "#ef4444";
          return "#555";
        }}
        maskColor="rgba(0,0,0,0.8)"
        style={{ width: 80, height: 50 }}
        className="!bg-[#0a0a0a] !border-[#222]"
      />
    </ReactFlow>
      </div>
    </div>
  );
}
