import { memo } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import { cn } from "@/lib/utils";

export interface AttackPathNodeData {
  name: string;
  type: string;
  zone: string;
  impact: number;
  provenance: string;
  isEntry: boolean;
  isCrown: boolean;
  [key: string]: unknown;
}

function AttackPathNode({ data }: NodeProps) {
  const d = data as AttackPathNodeData;
  const simulated = d.provenance === "simulated";
  return (
    <div
      className={cn(
        "w-[220px] rounded-lg border bg-[#141414] px-2.5 py-2 text-left shadow-sm",
        d.isCrown
          ? "border-amber-400/55"
          : simulated
            ? "border-amber-500/35"
            : "border-[rgba(255,255,255,0.12)]"
      )}
    >
      <Handle type="target" position={Position.Left} className="!bg-[#555] !w-1.5 !h-1.5" />
      <div className="mb-1 flex flex-wrap gap-1">
        <span
          className={cn(
            "rounded border px-1 py-[1px] text-[9px] font-semibold tracking-wide",
            simulated
              ? "border-amber-500/30 bg-amber-500/15 text-amber-300"
              : "border-emerald-500/30 bg-emerald-500/15 text-emerald-300"
          )}
        >
          {simulated ? "SIMULATED" : "FROM FINDING"}
        </span>
        {d.isCrown && (
          <span className="rounded border border-amber-400/40 bg-amber-400/10 px-1 py-[1px] text-[9px] font-semibold text-amber-200">
            CROWN (MODELED)
          </span>
        )}
        {d.isEntry && (
          <span className="rounded border border-sky-400/30 bg-sky-400/10 px-1 py-[1px] text-[9px] font-semibold text-sky-200">
            ENTRY
          </span>
        )}
      </div>
      <div className="truncate text-[12px] font-medium text-[#ededed]" title={d.name}>
        {d.name}
      </div>
      <div className="mt-0.5 text-[10px] text-[#888]">
        {d.type} · {d.zone} · impact {d.impact}
      </div>
      <Handle type="source" position={Position.Right} className="!bg-[#555] !w-1.5 !h-1.5" />
    </div>
  );
}

export default memo(AttackPathNode);
