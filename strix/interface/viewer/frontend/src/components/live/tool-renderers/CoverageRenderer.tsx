"use client";

import type { ToolRendererProps } from "@/types/events";
import { CheckCircle2, CircleSlash, HelpCircle, AlertTriangle, Circle, ClipboardList } from "lucide-react";

interface CoverageEntry {
  entry_id?: string;
  surface?: string;
  risk_area?: string;
  outcome?: string;
  evidence?: string;
  agent_name?: string;
  by_you?: boolean;
  previous_outcomes?: string[];
}

/**
 * A cleared surface and an unresolved one must never read alike — the ledger
 * exists so that the negative space of a scan is legible, so each outcome gets
 * its own icon and color rather than a shared neutral row.
 */
const OUTCOMES: Record<string, { label: string; color: string; Icon: typeof Circle }> = {
  reported: { label: "reported", color: "text-orange-400", Icon: AlertTriangle },
  no_issue_found: { label: "no issue found", color: "text-emerald-400", Icon: CheckCircle2 },
  ruled_out: { label: "ruled out", color: "text-emerald-400/70", Icon: CheckCircle2 },
  not_applicable: { label: "not applicable", color: "text-[#777]", Icon: CircleSlash },
  needs_follow_up: { label: "needs follow-up", color: "text-yellow-400", Icon: HelpCircle },
};

const OUTCOME_ORDER = [
  "reported", "needs_follow_up", "no_issue_found", "ruled_out", "not_applicable",
] as const;

function outcomeMeta(outcome: string | undefined) {
  const key = (outcome ?? "").trim().toLowerCase();
  return OUTCOMES[key] ?? {
    label: key ? key.replace(/_/g, " ") : "unrecorded",
    color: "text-[#777]",
    Icon: Circle,
  };
}

const ACTION_LABELS: Record<string, string> = {
  record_coverage: "Coverage recorded",
  update_coverage: "Coverage updated",
  list_coverage: "Coverage",
};

function Header({ toolName }: { toolName: string }) {
  return (
    <div className="flex items-center gap-2">
      <ClipboardList className="w-3.5 h-3.5 text-cyan-400/60" />
      <span className="text-cyan-400/80 font-semibold text-sm">
        {ACTION_LABELS[toolName] ?? "Coverage"}
      </span>
    </div>
  );
}

function Row({ entry }: { entry: CoverageEntry }) {
  const { label, color, Icon } = outcomeMeta(entry.outcome);
  const previous = (entry.previous_outcomes ?? [])
    .map((o) => outcomeMeta(o).label)
    .filter(Boolean);
  return (
    <div className="flex items-start gap-2.5 py-1.5">
      <Icon className={`w-3.5 h-3.5 shrink-0 mt-[2px] ${color}`} />
      <div className="min-w-0">
        <div className="text-[13px] leading-snug">
          <span className="text-[#bbb]">{entry.surface ?? "(unnamed surface)"}</span>
          {entry.risk_area && <span className="text-[#666]"> · {entry.risk_area}</span>}
        </div>
        <div className="text-xs mt-0.5">
          <span className={color}>{label}</span>
          {previous.length > 0 && (
            <span className="text-[#555]"> (was {previous.join(" → ")})</span>
          )}
          {(entry.by_you || entry.agent_name) && (
            <span className="text-[#555]"> · {entry.by_you ? "you" : entry.agent_name}</span>
          )}
        </div>
        {entry.evidence && (
          <div className="text-[#777] text-xs mt-1 leading-snug">{entry.evidence}</div>
        )}
      </div>
    </div>
  );
}

export default function CoverageRenderer({ toolName, args, result }: ToolRendererProps) {
  const res = result as Record<string, unknown> | string | null;

  if (typeof res === "string" && res.trim()) {
    return (
      <div>
        <Header toolName={toolName} />
        <div className="mt-1.5 text-[#888] text-[13px]">{res.trim()}</div>
      </div>
    );
  }

  const structured = res && typeof res === "object" ? res : null;
  const surface = (args.surface as string) ?? "";
  const riskArea = (args.risk_area as string) ?? "";
  const evidence = (args.evidence as string) ?? "";

  if (structured && !structured.success) {
    return (
      <div>
        <Header toolName={toolName} />
        {(surface || riskArea) && (
          <div className="mt-1.5 text-[13px] text-[#bbb]">
            {surface}
            {riskArea && <span className="text-[#666]"> · {riskArea}</span>}
          </div>
        )}
        <div className="mt-1 text-red-400/70 text-[13px]">
          {(structured.error as string) ?? "Coverage call failed"}
        </div>
      </div>
    );
  }

  if (toolName === "list_coverage") {
    const rawEntries = structured?.entries;
    const entries: CoverageEntry[] = Array.isArray(rawEntries) ? (rawEntries as CoverageEntry[]) : [];
    const counts = (structured?.outcome_counts as Record<string, number> | undefined) ?? {};
    const total = (structured?.total_count as number) ?? 0;
    return (
      <div>
        <Header toolName={toolName} />
        {Object.keys(counts).length > 0 && (
          <div className="mt-2 flex items-center gap-3 flex-wrap">
            {OUTCOME_ORDER.filter((o) => counts[o]).map((o) => {
              const { label, color } = outcomeMeta(o);
              return (
                <span key={o} className={`text-xs ${color}`}>
                  {label}: {counts[o]}
                </span>
              );
            })}
          </div>
        )}
        {entries.length > 0 ? (
          <div className="mt-2 rounded-lg border border-white/[0.06] bg-white/[0.015] px-3 py-1 divide-y divide-white/[0.04]">
            {entries.map((entry, i) => <Row key={entry.entry_id ?? i} entry={entry} />)}
          </div>
        ) : (
          <div className="mt-1.5 text-[#555] text-xs">
            {total === 0 ? "No surfaces recorded yet" : "No surfaces match this filter"}
          </div>
        )}
      </div>
    );
  }

  const outcome = (structured?.outcome as string) ?? "";
  const previousOutcome = (structured?.previous_outcome as string) ?? "";
  const { label, color, Icon } = outcomeMeta(outcome);

  return (
    <div>
      <Header toolName={toolName} />
      <div className="mt-2 flex items-start gap-2.5">
        <Icon className={`w-3.5 h-3.5 shrink-0 mt-[2px] ${color}`} />
        <div className="min-w-0">
          <div className="text-[13px] leading-snug text-[#bbb]">
            {surface || (structured?.entry_id ? `entry ${structured.entry_id as string}` : "(unnamed surface)")}
            {riskArea && <span className="text-[#666]"> · {riskArea}</span>}
          </div>
          <div className="text-xs mt-0.5">
            {previousOutcome && (
              <span className="text-[#666]">{outcomeMeta(previousOutcome).label} → </span>
            )}
            <span className={color}>{label}</span>
          </div>
          {evidence && (
            <div className="text-[#777] text-xs mt-1 leading-snug">{evidence}</div>
          )}
        </div>
      </div>
    </div>
  );
}
