"use client";

import { History, ShieldCheck, ArrowRight, Clock, Target, AlertTriangle } from "lucide-react";
import type { RunsPayload, RunListEntry } from "@/data/serverSource";
import { formatTimeAgo } from "@/lib/utils";

interface PastRunsViewProps {
  runs: RunsPayload;
  activeRun: string | null;
  onSelectRun: (name: string) => void;
  onVerified?: () => void;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-red-400 bg-red-500/10 border-red-500/30",
  high: "text-orange-400 bg-orange-500/10 border-orange-500/30",
  medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
  low: "text-blue-400 bg-blue-500/10 border-blue-500/30",
};

function formatDuration(startTime: string | null, endTime: string | null): string | null {
  if (!startTime) return null;
  const start = new Date(startTime).getTime();
  const end = endTime ? new Date(endTime).getTime() : Date.now();
  if (Number.isNaN(start) || Number.isNaN(end) || end < start) return null;
  const seconds = Math.round((end - start) / 1000);
  if (seconds < 60) return `${seconds} 秒`;
  const m = Math.floor(seconds / 60);
  if (m < 60) return `${m} 分钟`;
  const h = Math.floor(m / 60);
  return `${h} 小时 ${m % 60} 分钟`;
}

export default function PastRunsView({
  runs,
  activeRun,
  onSelectRun,
}: PastRunsViewProps) {
  const entries: RunListEntry[] = runs.runs || [];

  if (entries.length === 0) {
    return (
      <div className="rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-12 text-center">
        <History className="w-10 h-10 mx-auto mb-3 text-[#555]" />
        <p className="text-base font-medium text-white">暂无历史扫描记录</p>
        <p className="mt-1 text-sm text-[#888]">
          本机发起渗透测试后，所有的扫描过程、漏洞数据与报告均会自动记录在此处。
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-[#888]">
          共记录 <span className="font-semibold text-white">{entries.length}</span> 次渗透测试任务，点击任意任务可切换并查看其完整的漏洞详情、智能体拓扑与审计报告。
        </p>
      </div>

      <div className="grid gap-3">
        {entries.map((entry) => {
          const isActive = activeRun === entry.name;
          const totalVulns =
            (entry.severity_counts?.critical || 0) +
            (entry.severity_counts?.high || 0) +
            (entry.severity_counts?.medium || 0) +
            (entry.severity_counts?.low || 0);

          const modeLabel =
            entry.scan_mode === "deep"
              ? "深度渗透 (Deep)"
              : entry.scan_mode === "standard"
              ? "标准渗透 (Standard)"
              : "快速探测 (Quick)";

          const statusLabel =
            entry.status === "completed"
              ? "已完成"
              : entry.status === "running"
              ? "执行中"
              : entry.status === "failed"
              ? "异常终止"
              : entry.status || "未知状态";

          const statusBadgeColor =
            entry.status === "completed"
              ? "text-emerald-400 border-emerald-500/30 bg-emerald-500/10"
              : entry.status === "running"
              ? "text-blue-400 border-blue-500/30 bg-blue-500/10 animate-pulse"
              : "text-[#888] border-[#333] bg-[#1a1a1a]";

          const durationStr = formatDuration(entry.start_time, entry.end_time);

          return (
            <div
              key={entry.name}
              onClick={() => onSelectRun(entry.name)}
              className={`cursor-pointer rounded-xl border p-5 transition-all ${
                isActive
                  ? "border-emerald-500/50 bg-emerald-500/[0.04] ring-1 ring-emerald-500/30"
                  : "border-[#222] bg-[rgba(255,255,255,0.02)] hover:border-[#444] hover:bg-[rgba(255,255,255,0.04)]"
              }`}
            >
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div className="min-w-0 flex-1 space-y-1.5">
                  <div className="flex items-center gap-2.5 flex-wrap">
                    <Target className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                    <span className="font-mono text-base font-semibold text-white truncate">
                      {entry.target || entry.name}
                    </span>
                    <span
                      className={`text-xs font-medium px-2 py-0.5 rounded-full border ${statusBadgeColor}`}
                    >
                      {statusLabel}
                    </span>
                    {isActive && (
                      <span className="text-xs font-medium px-2 py-0.5 rounded-full border border-emerald-500/40 bg-emerald-500/20 text-emerald-300">
                        当前查看中
                      </span>
                    )}
                  </div>

                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-[#888]">
                    <span>任务标识: <code className="text-[#aaa]">{entry.name}</code></span>
                    <span>模式: <span className="text-[#aaa]">{modeLabel}</span></span>
                    {durationStr && (
                      <span className="inline-flex items-center gap-1">
                        <Clock className="w-3 h-3 text-[#666]" /> 耗时 {durationStr}
                      </span>
                    )}
                    {entry.start_time && (
                      <span>发起于 {formatTimeAgo(entry.start_time)}</span>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-3 flex-shrink-0">
                  {totalVulns > 0 ? (
                    <div className="flex items-center gap-1.5">
                      {entry.severity_counts?.critical > 0 && (
                        <span className={`text-xs font-bold px-2 py-0.5 rounded border ${SEVERITY_COLORS.critical}`}>
                          严重 {entry.severity_counts.critical}
                        </span>
                      )}
                      {entry.severity_counts?.high > 0 && (
                        <span className={`text-xs font-bold px-2 py-0.5 rounded border ${SEVERITY_COLORS.high}`}>
                          高危 {entry.severity_counts.high}
                        </span>
                      )}
                      {entry.severity_counts?.medium > 0 && (
                        <span className={`text-xs font-bold px-2 py-0.5 rounded border ${SEVERITY_COLORS.medium}`}>
                          中危 {entry.severity_counts.medium}
                        </span>
                      )}
                      {entry.severity_counts?.low > 0 && (
                        <span className={`text-xs font-bold px-2 py-0.5 rounded border ${SEVERITY_COLORS.low}`}>
                          低危 {entry.severity_counts.low}
                        </span>
                      )}
                    </div>
                  ) : (
                    <span className="inline-flex items-center gap-1 text-xs text-[#666]">
                      <ShieldCheck className="w-3.5 h-3.5 text-[#555]" /> 无安全漏洞
                    </span>
                  )}
                  <ArrowRight className="w-4 h-4 text-[#555] group-hover:text-white transition-colors" />
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
