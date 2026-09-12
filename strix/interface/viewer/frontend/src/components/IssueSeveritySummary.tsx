import React from "react";

import { cn } from "@/lib/utils";

export interface IssueSeveritySummaryFindings {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

interface IssueSeveritySummaryProps {
  findings: IssueSeveritySummaryFindings;
  className?: string;
  /** Noun for the total count (e.g. "issues", "CVEs"). Defaults to "issues". */
  unit?: string;
  /** Optional content rendered at the end of the count row (e.g. a KEV badge). */
  trailing?: React.ReactNode;
}

const SEVERITIES = [
  { key: "critical", label: "critical", dotClass: "bg-red-500", textClass: "text-red-500" },
  { key: "high", label: "high", dotClass: "bg-orange-500", textClass: "text-orange-500" },
  { key: "medium", label: "medium", dotClass: "bg-yellow-500", textClass: "text-yellow-500" },
  { key: "low", label: "low", dotClass: "bg-blue-500", textClass: "text-blue-500" },
] as const;

export function IssueSeveritySummary({
  findings,
  className,
  unit = "issues",
  trailing,
}: IssueSeveritySummaryProps) {
  if (findings.total <= 0) return null;

  return (
    <div className={cn("space-y-3", className)}>
      <div className="flex flex-wrap items-center gap-x-8 gap-y-3">
        <div className="flex items-center gap-2">
          <span className="text-2xl font-semibold text-white tabular-nums">{findings.total}</span>
          <span className="text-sm text-[#666]">{unit}</span>
        </div>
        <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
          {SEVERITIES.map(({ key, label, dotClass, textClass }) => {
            const count = findings[key];
            if (count <= 0) return null;

            return (
              <div key={key} className="flex items-center gap-1.5">
                <div className={cn("w-2 h-2 rounded-full", dotClass)} aria-hidden="true" />
                <span className={cn("text-sm tabular-nums", textClass)}>{count}</span>
                <span className="text-xs text-[#555]">{label}</span>
              </div>
            );
          })}
        </div>
        {trailing ? <div className="flex items-center gap-2">{trailing}</div> : null}
      </div>

      <div className="h-1.5 rounded-full bg-[#222] overflow-hidden flex">
        {SEVERITIES.map(({ key, dotClass }) => {
          const count = findings[key];
          if (count <= 0) return null;

          return (
            <div
              key={key}
              className={cn("h-full", dotClass)}
              style={{ width: `${(count / findings.total) * 100}%` }}
            />
          );
        })}
      </div>
    </div>
  );
}
