"use client";

import type { ToolRendererProps } from "@/types/events";
import { TruncatedText } from "./ToolCard";

function ScanStartInfo({ args }: ToolRendererProps) {
  const rawTargets = args.targets;
  const targets = Array.isArray(rawTargets) ? rawTargets : [];
  const targetNames = targets.map((t) => (typeof t === "object" && t ? (t.original as string) ?? null : null)).filter(Boolean) as string[];

  return (
    <div>
      <div className="flex items-center gap-2">
        <span className="text-emerald-400/80 font-semibold text-sm">Starting penetration test</span>
        {targetNames.length === 1 && <span className="text-[#888] text-[13px]">on {targetNames[0]}</span>}
      </div>
      {targetNames.length > 1 && (
        <div className="mt-1.5 space-y-0.5">
          {targetNames.map((t, i) => (
            <div key={i} className="text-[13px] text-[#888]"><span className="text-[#555] mr-1">•</span>{t}</div>
          ))}
        </div>
      )}
    </div>
  );
}

function SubagentStartInfo({ args }: ToolRendererProps) {
  const name = (args.name as string) ?? "Unknown Agent";
  const task = (args.task as string) ?? "";

  return (
    <div>
      <div className="flex items-center gap-2">
        <span className="text-[#888] text-[13px]">subagent</span>
        <span className="text-purple-400 font-semibold text-sm">{name}</span>
      </div>
      {task && <div className="mt-1.5"><TruncatedText text={task} maxLines={15} /></div>}
    </div>
  );
}

export default function ScanInfoRenderer(props: ToolRendererProps) {
  if (props.toolName === "subagent_start_info") return <SubagentStartInfo {...props} />;
  return <ScanStartInfo {...props} />;
}
