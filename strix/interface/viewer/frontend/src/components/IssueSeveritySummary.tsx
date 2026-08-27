"use client";

import type { VulnerabilitySeverity } from "@/types/issues";

interface IssueSeveritySummaryProps {
  findings: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

const SEVERITY_CONFIG: Record<
  VulnerabilitySeverity,
  { label: string; bg: string; text: string; bar: string }
> = {
  critical: {
    label: "严重 (Critical)",
    bg: "bg-red-500/10 border-red-500/30",
    text: "text-red-400",
    bar: "bg-red-500",
  },
  high: {
    label: "高危 (High)",
    bg: "bg-orange-500/10 border-orange-500/30",
    text: "text-orange-400",
    bar: "bg-orange-500",
  },
  medium: {
    label: "中危 (Medium)",
    bg: "bg-yellow-500/10 border-yellow-500/30",
    text: "text-yellow-400",
    bar: "bg-yellow-500",
  },
  low: {
    label: "低危 (Low)",
    bg: "bg-blue-500/10 border-blue-500/30",
    text: "text-blue-400",
    bar: "bg-blue-500",
  },
};

export function IssueSeveritySummary({ findings }: IssueSeveritySummaryProps) {
  const { total, critical, high, medium, low } = findings;

  const items: { key: VulnerabilitySeverity; count: number }[] = [
    { key: "critical", count: critical },
    { key: "high", count: high },
    { key: "medium", count: medium },
    { key: "low", count: low },
  ];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-white">漏洞风险等级分布</h3>
        <span className="text-xs text-[#888]">
          共计 <strong className="text-white font-semibold">{total}</strong> 项安全漏洞
        </span>
      </div>

      {/* Distribution bar */}
      {total > 0 && (
        <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-[#222]">
          {items.map(
            (item) =>
              item.count > 0 && (
                <div
                  key={item.key}
                  style={{ width: `${(item.count / total) * 100}%` }}
                  className={`h-full ${SEVERITY_CONFIG[item.key].bar} transition-all duration-500`}
                  title={`${SEVERITY_CONFIG[item.key].label}: ${item.count}`}
                />
              )
          )}
        </div>
      )}

      {/* Badges Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {items.map((item) => {
          const config = SEVERITY_CONFIG[item.key];
          return (
            <div
              key={item.key}
              className={`rounded-lg border p-3 flex flex-col justify-between ${
                item.count > 0 ? config.bg : "border-[#222] bg-black/20 opacity-60"
              }`}
            >
              <span className="text-xs text-[#888]">{config.label}</span>
              <span className={`text-xl font-bold font-mono mt-1 ${config.text}`}>
                {item.count}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default IssueSeveritySummary;
