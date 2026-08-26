"use client";

import type { ToolRendererProps } from "@/types/events";
import { Crosshair, AlertTriangle, Plus, Save } from "lucide-react";
import { TruncatedText } from "./ToolCard";

interface Amendment {
  agent_name?: string;
  content?: string;
  recorded_at?: string;
}

const ACTION_LABELS: Record<string, { label: string; Icon: typeof Crosshair }> = {
  get_threat_model: { label: "Threat model", Icon: Crosshair },
  save_threat_model: { label: "Threat model saved", Icon: Save },
  amend_threat_model: { label: "Threat model amended", Icon: Plus },
};

/** A git sha is noise past its first bytes, and "unversioned" is not a revision. */
function shortRevision(revision: unknown): string {
  const value = typeof revision === "string" ? revision.trim() : "";
  if (!value || value === "unversioned") return "";
  return value.slice(0, 8);
}

export default function ThreatModelRenderer({ toolName, args, result }: ToolRendererProps) {
  const action = ACTION_LABELS[toolName] ?? { label: "Threat model", Icon: Crosshair };
  const ActionIcon = action.Icon;
  const target = (args.target as string) ?? "";
  const res = result as Record<string, unknown> | string | null;

  const header = (
    <div className="flex items-center gap-2 flex-wrap">
      <ActionIcon className="w-3.5 h-3.5 text-blue-400/60" />
      <span className="text-blue-400/80 font-semibold text-sm">{action.label}</span>
      {target && <span className="text-[#666] font-mono text-xs">{target}</span>}
    </div>
  );

  if (typeof res === "string" && res.trim()) {
    return <div>{header}<div className="mt-1.5 text-[#888] text-[13px]">{res.trim()}</div></div>;
  }

  const structured = res && typeof res === "object" ? res : null;

  if (structured && !structured.success) {
    return (
      <div>
        {header}
        <div className="mt-1.5 text-red-400/70 text-[13px]">
          {(structured.error as string) ?? "Threat model call failed"}
        </div>
      </div>
    );
  }

  if (toolName === "get_threat_model") {
    if (structured && !structured.found) {
      return (
        <div>
          {header}
          <div className="mt-1.5 text-[#555] text-xs">No model cached for this target yet</div>
        </div>
      );
    }
    const rawAmendments = structured?.amendments;
    const amendments: Amendment[] = Array.isArray(rawAmendments) ? (rawAmendments as Amendment[]) : [];
    const cachedRevision = shortRevision(structured?.cached_revision);
    return (
      <div>
        {header}
        {structured?.stale === true && (
          <div className="mt-1.5 flex items-center gap-1.5 text-yellow-400/80 text-xs">
            <AlertTriangle className="w-3 h-3 shrink-0" />
            <span>stale{cachedRevision ? ` — written at ${cachedRevision}` : ""}</span>
          </div>
        )}
        {amendments.length > 0 && (
          <div className="mt-2">
            <span className="text-amber-400/70 text-xs font-semibold">
              {amendments.length} amendment{amendments.length === 1 ? "" : "s"}
            </span>
            <span className="text-[#555] text-xs"> — later statements win</span>
            <div className="mt-1 space-y-1">
              {/* On a public share link the amendment body is stripped, so the
                  author line has to stand on its own. */}
              {amendments.map((amendment, i) => (
                <div key={i} className="text-xs leading-snug">
                  <span className="text-[#666]">{amendment.agent_name ?? "unknown agent"}</span>
                  {amendment.content && (
                    <span className="text-[#999]">: {amendment.content}</span>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
        {typeof structured?.content === "string" && structured.content.trim() && (
          <div className="mt-2">
            <TruncatedText text={structured.content} maxLines={14} />
          </div>
        )}
      </div>
    );
  }

  if (toolName === "amend_threat_model") {
    const addendum = (args.addendum as string) ?? "";
    const count = structured?.amendment_count as number | undefined;
    return (
      <div>
        {header}
        {count != null && (
          <div className="mt-1.5 text-[#666] text-xs">{count} amendment{count === 1 ? "" : "s"} on this model</div>
        )}
        {addendum && <div className="mt-1.5"><TruncatedText text={addendum} maxLines={10} /></div>}
      </div>
    );
  }

  const cleared = (structured?.amendments_cleared as number | undefined) ?? 0;
  const revision = shortRevision(structured?.revision);
  const content = (args.content as string) ?? "";
  return (
    <div>
      {header}
      {revision && <div className="mt-1.5 text-[#666] font-mono text-xs">at {revision}</div>}
      {/* Saving folds amendments away — the one destructive thing this tool does. */}
      {cleared > 0 && (
        <div className="mt-1.5 flex items-center gap-1.5 text-yellow-400/80 text-xs">
          <AlertTriangle className="w-3 h-3 shrink-0" />
          <span>cleared {cleared} amendment{cleared === 1 ? "" : "s"}</span>
        </div>
      )}
      {content && <div className="mt-2"><TruncatedText text={content} maxLines={14} /></div>}
    </div>
  );
}
