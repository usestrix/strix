"use client";

import type { ToolRendererProps } from "@/types/events";
import { TruncatedText } from "./ToolCard";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-red-400", high: "text-orange-400", medium: "text-yellow-400",
  low: "text-blue-400", info: "text-cyan-400",
};

/** A withdrawn finding: which report went, and what disproved it. */
export default function VulnReportDeleteRenderer({ args, result, status }: ToolRendererProps) {
  const reportId = (args.report_id as string) ?? "";
  const reason = (args.delete_reason as string) ?? "";

  const res = result && typeof result === "object" ? (result as Record<string, unknown>) : null;
  const ok = res?.success === true;
  const error = typeof res?.error === "string" ? res.error : "";
  const title = typeof res?.title === "string" ? res.title : "";
  const severity = typeof res?.severity === "string" ? res.severity.toLowerCase() : "";
  const failed = res != null ? !ok : status === "failed" || status === "error";
  const pending = res == null && !failed;
  const label = pending ? "withdrawing report\u2026" : failed ? "report not withdrawn" : "report withdrawn";
  const labelColor = pending ? "text-[#888]" : failed ? "text-red-400/80" : "text-yellow-400/80";

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 flex-wrap">
        <span className={`font-semibold text-sm ${labelColor}`} aria-live="polite">
          {label}
        </span>
        {reportId && <span className="text-[#555] font-mono text-[13px]">{reportId}</span>}
        {severity && (
          <span className={`text-[13px] line-through ${SEVERITY_COLORS[severity] ?? "text-[#888]"}`}>
            {severity.toUpperCase()}
          </span>
        )}
      </div>
      {title && <div className="text-[15px] text-white/60 line-through">{title}</div>}
      {reason && (
        <div>
          <span className="text-emerald-400/60 text-sm font-semibold">Why</span>
          <div className="mt-1"><TruncatedText text={reason} maxLines={10} /></div>
        </div>
      )}
      {error && <div className="text-red-400/80 text-[13px]">{error}</div>}
    </div>
  );
}
