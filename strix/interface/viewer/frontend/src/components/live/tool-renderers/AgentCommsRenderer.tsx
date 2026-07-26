"use client";

import type { ToolRendererProps } from "@/types/events";
import { TruncatedText } from "./ToolCard";

export default function AgentCommsRenderer({ toolName, args }: ToolRendererProps) {
  if (toolName === "create_agent") {
    const name = (args.name as string) ?? (args.agent_name as string) ?? "";
    const task = (args.task as string) ?? "";
    return (
      <div>
        <div className="flex items-center gap-2">
          <span className="text-cyan-400/80 font-semibold text-sm">spawning</span>
          {name && <span className="text-cyan-400 font-semibold text-sm">{name}</span>}
        </div>
        {task && <div className="mt-1.5"><TruncatedText text={task} maxLines={15} /></div>}
      </div>
    );
  }

  if (toolName === "agent_finish") {
    const summary = (args.result_summary as string) ?? "";
    const success = args.success as boolean | undefined;
    const rawFindings = args.findings;
    const findings = Array.isArray(rawFindings) ? rawFindings as string[] : undefined;
    return (
      <div>
        <span className={`font-semibold text-sm ${success === false ? "text-red-400/80" : "text-emerald-400/80"}`}>
          {success === false ? "Agent failed" : "Agent completed"}
        </span>
        {summary && <div className="mt-1.5"><TruncatedText text={summary} maxLines={20} /></div>}
        {findings && findings.length > 0 && (
          <div className="mt-1.5 space-y-0.5">
            {findings.map((f, i) => (
              <div key={i} className="text-[13px] text-[#888]"><span className="text-red-400/50 mr-1">•</span>{typeof f === "string" ? f : JSON.stringify(f)}</div>
            ))}
          </div>
        )}
      </div>
    );
  }

  if (toolName === "send_message_to_agent") {
    const message = (args.message as string) ?? "";
    const agentId = (args.target_agent_id as string) ?? (args.agent_id as string) ?? "";
    return (
      <div>
        <div className="flex items-center gap-2">
          <span className="text-cyan-400/80 font-semibold text-sm">message</span>
          {agentId && <span className="text-[#888] text-[13px]">to {agentId.slice(0, 16)}</span>}
        </div>
        {message && <div className="mt-1.5"><TruncatedText text={message} maxLines={20} /></div>}
      </div>
    );
  }

  if (toolName === "wait_for_message") {
    const reason = (args.reason as string) ?? "";
    return (
      <div className="flex items-center gap-2">
        <span className="text-cyan-400/80 font-semibold text-sm">waiting</span>
        {reason && <span className="text-[#888] text-[13px] truncate">{reason}</span>}
      </div>
    );
  }

  if (toolName === "stop_agent") {
    const targetAgentId = (args.target_agent_id as string) ?? "";
    const cascade = args.cascade !== false;
    const reason = (args.reason as string) ?? "";
    return (
      <div>
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-red-400/80 font-semibold text-sm">stopping</span>
          {targetAgentId && <span className="text-[#888] text-[13px]">{targetAgentId.slice(0, 16)}</span>}
          {cascade && <span className="text-[#555] text-[13px] italic">+ descendants</span>}
        </div>
        {reason && <div className="mt-1.5 text-[#888] text-[13px]">{reason}</div>}
      </div>
    );
  }

  if (toolName === "view_agent_graph") {
    return (
      <span className="text-cyan-400/80 font-semibold text-sm">viewing agents graph</span>
    );
  }

  return (
    <span className="text-cyan-400/80 font-semibold text-sm">{toolName.replace(/_/g, " ")}</span>
  );
}
