"use client";

import { useState } from "react";
import { ChevronDown, ChevronUp, Cpu, Sliders, Target, Clock, Terminal, Bot } from "lucide-react";

interface RunDetailsProps {
  raw: Record<string, unknown>;
  durationSeconds?: number | null;
}

function formatNumber(num: number | null | undefined): string {
  if (num == null) return "0";
  return num.toLocaleString();
}

function formatDuration(seconds: number | null | undefined): string {
  if (seconds == null || seconds === 0) return "--";
  if (seconds < 60) return `${seconds} 秒`;
  const m = Math.floor(seconds / 60);
  if (m < 60) return `${m} 分钟 ${seconds % 60} 秒`;
  const h = Math.floor(m / 60);
  return `${h} 小时 ${m % 60} 分钟`;
}

export function RunDetails({ raw, durationSeconds }: RunDetailsProps) {
  const [open, setOpen] = useState(false);

  const targetsInfo = (Array.isArray(raw.targets_info) ? raw.targets_info : []) as Array<Record<string, unknown>>;
  const targets = targetsInfo.map((t) => (typeof t === "object" && t ? String(t.original || "") : "")).filter(Boolean);
  const instruction = (raw.instruction as string) || (raw.guidance as string) || null;
  const scanMode = (raw.scan_mode as string) || "standard";
  const status = (raw.status as string) || "running";

  const llmUsage = (raw.llm_usage && typeof raw.llm_usage === "object" ? raw.llm_usage : {}) as Record<string, unknown>;
  const modelName = (llmUsage.model as string) || (raw.model as string) || (raw.llm_model as string) || "openai/Qwen3.8-27B-abliterated";
  const calls = (llmUsage.requests as number) || (llmUsage.calls as number) || (llmUsage.total_requests as number) || 0;
  const inputTokens = (llmUsage.input_tokens as number) || 0;
  const outputTokens = (llmUsage.output_tokens as number) || 0;
  const totalTokens = (llmUsage.total_tokens as number) || inputTokens + outputTokens;
  const cost = llmUsage.cost as number | null;

  const modeLabel =
    scanMode === "deep" ? "深度渗透 (Deep)" : scanMode === "standard" ? "标准渗透 (Standard)" : "快速探测 (Quick)";

  return (
    <div className="rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] overflow-hidden transition-all">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-5 py-3.5 text-left text-sm text-[#888] hover:text-white transition-colors cursor-pointer"
      >
        <div className="flex items-center gap-2">
          <Sliders className="w-4 h-4 text-emerald-400" />
          <span className="font-medium text-white">任务运行参数与模型开销统计</span>
          <span className="text-xs text-[#666]">
            (模型: <span className="text-[#aaa] font-mono">{modelName}</span> · 总计 {formatNumber(totalTokens)} Tokens)
          </span>
        </div>
        <div className="flex items-center gap-1 text-xs text-[#888]">
          <span>{open ? "收起详情" : "展开详情"}</span>
          {open ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </div>
      </button>

      {open && (
        <div className="px-5 pb-5 pt-1 border-t border-[#1a1a1a] space-y-4 text-xs">
          {/* Target & Guidance */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <div className="flex items-center gap-1.5 text-[#888]">
                <Target className="w-3.5 h-3.5 text-emerald-400" />
                <span className="font-medium text-white">测试目标与范围</span>
              </div>
              <p className="font-mono text-[#aaa] bg-black/40 border border-[#222] rounded-lg p-2.5 break-all">
                {targets.length > 0 ? targets.join(", ") : (raw.target as string) || "未指定目标"}
              </p>
            </div>

            <div className="space-y-1.5">
              <div className="flex items-center gap-1.5 text-[#888]">
                <Clock className="w-3.5 h-3.5 text-blue-400" />
                <span className="font-medium text-white">扫描模式与耗时</span>
              </div>
              <div className="bg-black/40 border border-[#222] rounded-lg p-2.5 flex items-center justify-between">
                <span className="text-[#aaa]">模式: <strong className="text-white font-normal">{modeLabel}</strong></span>
                <span className="text-[#aaa]">执行耗时: <strong className="text-emerald-400 font-normal">{formatDuration(durationSeconds)}</strong></span>
              </div>
            </div>
          </div>

          {instruction && (
            <div className="space-y-1.5">
              <div className="flex items-center gap-1.5 text-[#888]">
                <Terminal className="w-3.5 h-3.5 text-purple-400" />
                <span className="font-medium text-white">引导提示词与审计要求 (Instruction)</span>
              </div>
              <div className="bg-black/40 border border-[#222] rounded-lg p-3 text-[#aaa] font-mono whitespace-pre-wrap leading-relaxed">
                {instruction}
              </div>
            </div>
          )}

          {/* Model Tokens & Cost */}
          <div className="space-y-2 pt-2 border-t border-[#1a1a1a]">
            <div className="flex items-center gap-1.5 text-[#888]">
              <Cpu className="w-3.5 h-3.5 text-amber-400" />
              <span className="font-medium text-white">大模型推理资源开销 (LLM Metrics)</span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="bg-black/40 border border-[#222] rounded-lg p-3 text-center">
                <span className="block text-[#666] mb-1">推理调用轮次</span>
                <span className="text-sm font-semibold text-white font-mono">{calls} 次</span>
              </div>
              <div className="bg-black/40 border border-[#222] rounded-lg p-3 text-center">
                <span className="block text-[#666] mb-1">输入 Tokens</span>
                <span className="text-sm font-semibold text-blue-400 font-mono">{formatNumber(inputTokens)}</span>
              </div>
              <div className="bg-black/40 border border-[#222] rounded-lg p-3 text-center">
                <span className="block text-[#666] mb-1">输出 Tokens</span>
                <span className="text-sm font-semibold text-purple-400 font-mono">{formatNumber(outputTokens)}</span>
              </div>
              <div className="bg-black/40 border border-[#222] rounded-lg p-3 text-center">
                <span className="block text-[#666] mb-1">总计 Tokens</span>
                <span className="text-sm font-semibold text-emerald-400 font-mono">{formatNumber(totalTokens)}</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default RunDetails;
