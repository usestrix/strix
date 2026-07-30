"use client";

import { memo } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import type { AgentNode as AgentNodeData } from "@/types/events";

const STATUS_STYLES: Record<string, string> = {
  running: "bg-blue-500",
  completed: "bg-emerald-500",
  failed: "bg-red-500",
  error: "bg-red-500",
};

function AgentNodeComponent({ data, selected }: NodeProps) {
  const agent = data as unknown as AgentNodeData & { isSelected: boolean };

  return (
    <div
      className={`w-[260px] rounded-lg border px-4 py-3 transition-colors ${
        agent.isSelected || selected
          ? "border-white/30 bg-[#0a0a0a]"
          : "border-[#222] bg-black hover:border-[#333]"
      }`}
    >
      <Handle type="target" position={Position.Top} isConnectable={false} className={`!w-1.5 !h-1.5 !border-0 ${agent.parentId ? "!bg-[#444]" : "!bg-transparent"}`} />

      <div className="flex items-center gap-2">
        <span className="relative flex h-2 w-2 shrink-0">
          <span
            className={`absolute inline-flex h-full w-full rounded-full opacity-75 ${STATUS_STYLES[agent.status] ?? "bg-gray-500"} ${
              agent.status === "running" ? "animate-ping" : ""
            }`}
          />
          <span
            className={`relative inline-flex h-2 w-2 rounded-full ${STATUS_STYLES[agent.status] ?? "bg-gray-500"}`}
          />
        </span>
        <span className="text-sm font-semibold text-white leading-snug line-clamp-3">
          {agent.name}
        </span>
      </div>

      <Handle type="source" position={Position.Bottom} isConnectable={false} className={`!w-1.5 !h-1.5 !border-0 ${agent.children && agent.children.length > 0 ? "!bg-[#444]" : "!bg-transparent"}`} />
    </div>
  );
}

export default memo(AgentNodeComponent);
