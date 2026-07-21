"use client";

import type { ToolRendererProps } from "@/types/events";
import { TruncatedText } from "./ToolCard";
import { MdCodeBlock } from "@/components/vulnerability/MdCodeBlock";
import Markdown from "./Markdown";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-red-400", high: "text-orange-400", medium: "text-yellow-400",
  low: "text-blue-400", info: "text-cyan-400",
};

export default function VulnReportRenderer({ args, result }: ToolRendererProps) {
  const title = (args.title as string) ?? "";
  const description = (args.description as string) ?? "";
  const impact = (args.impact as string) ?? "";
  const target = (args.target as string) ?? "";
  const endpoint = (args.endpoint as string) ?? "";
  const method = (args.method as string) ?? "";
  const technicalAnalysis = (args.technical_analysis as string) ?? "";
  const pocDescription = (args.poc_description as string) ?? "";
  const pocCode = (args.poc_script_code as string) ?? "";
  const remediation = (args.remediation_steps as string) ?? "";
  const cve = (args.cve as string) ?? "";
  const cwe = (args.cwe as string) ?? "";

  const res = result as Record<string, unknown> | null;
  const rawSev = (res && typeof res === "object" ? res.severity : null) ?? args.severity ?? "medium";
  const severity = String(rawSev).toLowerCase();
  const cvss = (res && typeof res === "object" ? (res.cvss_score as number) : null) ?? (args.cvss as number) ?? null;
  const sevColor = SEVERITY_COLORS[severity] ?? "text-yellow-400";

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 flex-wrap">
        <span className={`font-semibold text-sm ${sevColor}`}>{severity.toUpperCase()}</span>
        {cvss != null && <span className="text-[#888] text-[13px]">CVSS {cvss}</span>}
        {cve && <span className="text-[#888] font-mono text-[13px]">{cve}</span>}
        {cwe && <span className="text-[#888] font-mono text-[13px]">{cwe}</span>}
      </div>
      {title && <div className="text-[15px] text-white/80 font-semibold">{title}</div>}
      {(target || endpoint) && (
        <div className="text-[13px] text-[#888] font-mono">{target}{endpoint ? ` ${method} ${endpoint}` : ""}</div>
      )}
      {description && <TruncatedText text={description} maxLines={20} />}
      {impact && (
        <div>
          <span className="text-emerald-400/60 text-sm font-semibold">Impact</span>
          <div className="mt-1"><TruncatedText text={impact} maxLines={15} /></div>
        </div>
      )}
      {technicalAnalysis && (
        <div>
          <span className="text-emerald-400/60 text-sm font-semibold">Technical Analysis</span>
          <div className="mt-1"><TruncatedText text={technicalAnalysis} maxLines={20} /></div>
        </div>
      )}
      {(pocDescription || pocCode) && (
        <div>
          <span className="text-emerald-400/60 text-sm font-semibold">Proof of Concept</span>
          {pocDescription && <div className="mt-1"><Markdown text={pocDescription} /></div>}
          {pocCode && <MdCodeBlock>{pocCode}</MdCodeBlock>}
        </div>
      )}
      {remediation && (
        <div>
          <span className="text-emerald-400/60 text-sm font-semibold">Remediation</span>
          <div className="mt-1"><TruncatedText text={remediation} maxLines={15} /></div>
        </div>
      )}
    </div>
  );
}
