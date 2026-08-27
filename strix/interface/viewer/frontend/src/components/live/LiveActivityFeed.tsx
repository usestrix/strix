import { useState, useMemo, useEffect, useRef } from "react";
import {
  Terminal,
  Activity,
  Search,
  ShieldAlert,
  CheckCircle2,
  Clock,
  Play,
  Pause,
  ChevronDown,
  ChevronUp,
  Copy,
  Check,
  Filter,
  Bot,
  MessageSquare,
  Sparkles,
  Zap,
  Globe,
  Radio,
  FileCode,
  ArrowUpRight,
  ShieldCheck,
  Layers,
} from "lucide-react";
import type { Transcript, TranscriptAgent, TranscriptEvent } from "@/data/serverSource";
import { getToolIcon } from "./tool-renderers";

interface LiveActivityFeedProps {
  transcript: Transcript | null;
  finished: boolean;
  onSelectAgent?: (agentId: string) => void;
  maxInitialEvents?: number;
}

type EventFilterCategory = "all" | "commands" | "network" | "findings" | "agents" | "thinking";

function parseEventOutput(data: Record<string, unknown>): {
  cmd: string | null;
  output: string | null;
  toolName: string;
  thought: string | null;
  isError: boolean;
} {
  const toolName = String(data.tool_name || data.tool || "unknown_action");
  let cmd: string | null = null;
  let output: string | null = null;
  let thought: string | null = null;
  let isError = false;

  const rawArgs = data.args;
  if (typeof rawArgs === "string") {
    cmd = rawArgs;
  } else if (rawArgs && typeof rawArgs === "object") {
    const argsObj = rawArgs as Record<string, unknown>;
    cmd = (argsObj.cmd || argsObj.command || argsObj.query || argsObj.instruction || argsObj.task || null) as string | null;
    if (!cmd && argsObj.thought) {
      thought = String(argsObj.thought);
    }
  }

  const rawResult = data.result;
  if (typeof rawResult === "string") {
    output = rawResult;
  } else if (rawResult && typeof rawResult === "object") {
    const resObj = rawResult as Record<string, unknown>;
    if (resObj.output) output = String(resObj.output);
    else if (resObj.stdout || resObj.stderr) {
      output = `${resObj.stdout ? String(resObj.stdout) : ""}${resObj.stderr ? `\n[STDERR]\n${String(resObj.stderr)}` : ""}`;
    } else if (resObj.__raw) {
      output = String(resObj.__raw);
    } else {
      output = JSON.stringify(resObj, null, 2);
    }
    if (resObj.error || resObj.is_error || (typeof resObj.exit_code === "number" && resObj.exit_code !== 0)) {
      isError = true;
    }
  }

  // Clean up Strix/Chunk ID prefixes from outputs
  if (output) {
    const cleanOutput = output
      .replace(/^Chunk ID:\s*[a-f0-9]+\s*\n/i, "")
      .replace(/^Wall time:\s*[\d.]+\s*seconds\s*\n/i, "")
      .replace(/^Process exited with code \d+\s*\n/i, "")
      .replace(/^Output:\s*\n/i, "")
      .trim();
    if (cleanOutput) {
      output = cleanOutput;
    }
  }

  return { cmd, output, toolName, thought, isError };
}

function cleanCommandPreview(cmd: string): string {
  // If multi-line python script or bash EOF, extract key summary
  if (cmd.includes("<< 'PYEOF'") || cmd.includes("<< 'EOF'")) {
    const lines = cmd.split("\n").filter((l) => !l.includes("<<") && !l.includes("EOF") && l.trim().length > 0);
    const comment = lines.find((l) => l.trim().startsWith("#"));
    if (comment) return comment.replace(/^#\s*/, "").trim();
    return lines[0]?.trim() || "Python Script Execution";
  }
  return cmd.trim();
}

export function LiveActivityFeed({
  transcript,
  finished,
  onSelectAgent,
  maxInitialEvents = 30,
}: LiveActivityFeedProps) {
  const [filterCategory, setFilterCategory] = useState<EventFilterCategory>("all");
  const [selectedAgentId, setSelectedAgentId] = useState<string>("all");
  const [searchTerm, setSearchTerm] = useState<string>("");
  const [expandedIds, setExpandedIds] = useState<Record<string, boolean>>({});
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [autoScroll, setAutoScroll] = useState<boolean>(!finished);
  const feedEndRef = useRef<HTMLDivElement | null>(null);

  const agents = useMemo(() => transcript?.agents ?? [], [transcript]);
  const agentMap = useMemo(() => {
    const m = new Map<string, TranscriptAgent>();
    for (const a of agents) m.set(a.id, a);
    return m;
  }, [agents]);

  // Extract all tool & chat events
  const rawEvents = useMemo(() => transcript?.events ?? [], [transcript]);

  // Filter events
  const filteredEvents = useMemo(() => {
    return rawEvents
      .filter((e) => {
        // Exclude internal telemetry or raw ping events
        if (e.type !== "tool" && e.type !== "chat") return false;

        const data = (e.data || {}) as Record<string, unknown>;
        const toolName = String(data.tool_name || data.tool || "");

        // Agent filter
        if (selectedAgentId !== "all" && e.agent_id !== selectedAgentId) {
          return false;
        }

        // Category filter
        if (filterCategory === "commands") {
          if (!["exec_command", "write_stdin", "terminal_execute", "python_action"].includes(toolName)) {
            return false;
          }
        } else if (filterCategory === "network") {
          if (!toolName.includes("request") && !toolName.includes("proxy") && !toolName.includes("browser") && !toolName.includes("scan")) {
            const { cmd } = parseEventOutput(data);
            if (!cmd || (!cmd.includes("curl") && !cmd.includes("http") && !cmd.includes("urllib") && !cmd.includes("nmap"))) {
              return false;
            }
          }
        } else if (filterCategory === "findings") {
          if (!["create_vulnerability_report", "create_note", "update_todo"].includes(toolName)) {
            return false;
          }
        } else if (filterCategory === "agents") {
          if (!["create_agent", "agent_finish", "send_message_to_agent", "wait_for_agents"].includes(toolName)) {
            return false;
          }
        } else if (filterCategory === "thinking") {
          if (toolName !== "think" && e.type !== "chat") {
            return false;
          }
        }

        // Search filter
        if (searchTerm.trim()) {
          const s = searchTerm.toLowerCase();
          const { cmd, output, thought } = parseEventOutput(data);
          const agentName = agentMap.get(e.agent_id)?.name || "";
          const text = `${toolName} ${cmd || ""} ${output || ""} ${thought || ""} ${agentName}`.toLowerCase();
          if (!text.includes(s)) return false;
        }

        return true;
      })
      .reverse(); // Newest first
  }, [rawEvents, selectedAgentId, filterCategory, searchTerm, agentMap]);

  const toggleExpand = (id: string) => {
    setExpandedIds((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const copyToClipboard = (id: string, text: string) => {
    void navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Extract quick metrics
  const stats = useMemo(() => {
    let commandCount = 0;
    let noteCount = 0;
    let activeAgents = 0;
    for (const a of agents) {
      if (a.status === "running") activeAgents++;
    }
    for (const e of rawEvents) {
      if (e.type === "tool") {
        const name = String(e.data?.tool_name || "");
        if (name.includes("command") || name.includes("execute")) commandCount++;
        if (name.includes("note") || name.includes("vuln")) noteCount++;
      }
    }
    return {
      totalEvents: rawEvents.length,
      commandCount,
      noteCount,
      activeAgents: activeAgents || (finished ? 0 : 1),
    };
  }, [rawEvents, agents, finished]);

  return (
    <div className="rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-5 sm:p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[#222] pb-5">
        <div className="space-y-1">
          <div className="flex items-center gap-2.5">
            <span className="relative flex h-2.5 w-2.5">
              {!finished ? (
                <>
                  <span className="absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75 animate-ping" />
                  <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-emerald-400" />
                </>
              ) : (
                <span className="inline-flex h-2.5 w-2.5 rounded-full bg-[#555]" />
              )}
            </span>
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <Activity className="w-5 h-5 text-emerald-400" />
              实时渗透动态与扫描回包 (Live Activity & Probe Stream)
            </h2>
            <span className="text-xs px-2 py-0.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 text-emerald-400 font-mono">
              {!finished ? "实时监听中 (Live)" : "扫描已归档"}
            </span>
          </div>
          <p className="text-xs text-[#888]">
            实时捕获各专职智能体执行的终端命令、端口探测、网络回包与审计阶段性成果。
          </p>
        </div>

        {/* Live Metrics */}
        <div className="flex items-center gap-2 flex-wrap">
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[#262626] bg-black/40 text-xs">
            <Bot className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-[#888]">协同智能体:</span>
            <span className="font-semibold text-white font-mono">{agents.length || 1} 个</span>
          </div>
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[#262626] bg-black/40 text-xs">
            <Terminal className="w-3.5 h-3.5 text-emerald-400" />
            <span className="text-[#888]">探测指令:</span>
            <span className="font-semibold text-white font-mono">{stats.commandCount} 次</span>
          </div>
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[#262626] bg-black/40 text-xs">
            <Sparkles className="w-3.5 h-3.5 text-purple-400" />
            <span className="text-[#888]">审计事件:</span>
            <span className="font-semibold text-white font-mono">{stats.totalEvents} 轮</span>
          </div>
        </div>
      </div>

      {/* Agents Quick Strip */}
      {agents.length > 0 && (
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs text-[#888]">
            <span className="font-medium text-white flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5 text-cyan-400" />
              协同智能体阵列 (点击可过滤查看单个智能体的探测轨迹):
            </span>
            <button
              onClick={() => setSelectedAgentId("all")}
              className={`text-xs hover:underline ${selectedAgentId === "all" ? "text-emerald-400 font-semibold" : "text-[#888]"}`}
            >
              显示全部智能体
            </button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
            {agents.map((agent) => {
              const isSelected = selectedAgentId === agent.id;
              const isRunning = agent.status === "running" && !finished;
              return (
                <button
                  key={agent.id}
                  onClick={() => {
                    setSelectedAgentId((prev) => (prev === agent.id ? "all" : agent.id));
                    if (onSelectAgent) onSelectAgent(agent.id);
                  }}
                  className={`group text-left rounded-lg p-2.5 transition-all border ${
                    isSelected
                      ? "border-cyan-500/60 bg-cyan-500/10 shadow-[0_0_12px_rgba(6,182,212,0.15)]"
                      : "border-[#222] bg-black/30 hover:border-[#333] hover:bg-white/[0.02]"
                  }`}
                >
                  <div className="flex items-center justify-between gap-1.5">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="w-2 h-2 rounded-full flex-shrink-0 bg-cyan-400" />
                      <span className="text-xs font-semibold text-white truncate group-hover:text-cyan-300">
                        {agent.name}
                      </span>
                    </div>
                    <span
                      className={`text-[10px] px-1.5 py-0.5 rounded font-mono ${
                        isRunning
                          ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                          : agent.status === "failed"
                          ? "bg-red-500/10 text-red-400 border border-red-500/20"
                          : "bg-[#222] text-[#888]"
                      }`}
                    >
                      {isRunning ? "探测中" : agent.status === "failed" ? "已终止" : "已收工"}
                    </span>
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 max-w-full">
          {[
            { id: "all", label: "全部动态", count: rawEvents.length },
            { id: "commands", label: "命令与探测", count: stats.commandCount },
            { id: "network", label: "网络回包", icon: Globe },
            { id: "findings", label: "阶段性成果", count: stats.noteCount },
            { id: "agents", label: "智能体协同", icon: Bot },
            { id: "thinking", label: "推理决策", icon: Sparkles },
          ].map((cat) => (
            <button
              key={cat.id}
              onClick={() => setFilterCategory(cat.id as EventFilterCategory)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors flex items-center gap-1.5 whitespace-nowrap ${
                filterCategory === cat.id
                  ? "bg-white text-black font-semibold"
                  : "bg-[#161616] text-[#888] hover:text-white hover:bg-[#222] border border-[#262626]"
              }`}
            >
              {cat.label}
              {cat.count != null && cat.count > 0 && (
                <span
                  className={`text-[10px] px-1.5 py-0.2 rounded-full ${
                    filterCategory === cat.id ? "bg-black/20 text-black" : "bg-[#262626] text-[#aaa]"
                  }`}
                >
                  {cat.count}
                </span>
              )}
            </button>
          ))}
        </div>

        {/* Search */}
        <div className="relative min-w-[220px] flex-1 sm:flex-initial">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-[#666]" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="搜索回包、命令、端口..."
            className="w-full pl-8 pr-3 py-1.5 text-xs bg-[#111] border border-[#2a2a2a] rounded-lg text-white placeholder-[#555] focus:outline-none focus:border-emerald-500"
          />
        </div>
      </div>

      {/* Events List */}
      <div className="space-y-3 max-h-[700px] overflow-y-auto pr-1 scrollbar-thin">
        {filteredEvents.length === 0 ? (
          <div className="rounded-xl border border-[#222] bg-black/20 p-8 text-center space-y-2">
            <Radio className="w-6 h-6 mx-auto text-[#666] animate-pulse" />
            <p className="text-sm font-medium text-white">暂无匹配的探测动态</p>
            <p className="text-xs text-[#888]">
              {searchTerm ? "未找到包含搜索关键词的扫描回包。" : "智能体正在准备下一次探测指令…"}
            </p>
          </div>
        ) : (
          filteredEvents.map((event) => {
            const data = (event.data || {}) as Record<string, unknown>;
            const { cmd, output, toolName, thought, isError } = parseEventOutput(data);
            const agent = agentMap.get(event.agent_id);
            const isExpanded = expandedIds[event.id] ?? false;
            const toolIconMeta = getToolIcon(toolName);
            const ToolIcon = toolIconMeta.icon;

            // Timestamp formatting
            const timeStr = event.timestamp
              ? new Date(event.timestamp).toLocaleTimeString()
              : "";

            return (
              <div
                key={event.id}
                className="animate-card-in rounded-xl border border-[#222] hover:border-[#333] bg-[#0c0c0c] p-4 transition-all space-y-2.5"
              >
                {/* Event Header */}
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className={`p-1.5 rounded-md bg-white/[0.04] ${toolIconMeta.color}`}>
                      <ToolIcon className="w-3.5 h-3.5" />
                    </span>
                    <span className="text-xs font-semibold text-white font-mono">
                      {toolName.replace(/_/g, " ")}
                    </span>
                    {agent && (
                      <span className="text-[11px] px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 truncate max-w-[200px]">
                        {agent.name}
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-2 text-xs text-[#666] font-mono">
                    {timeStr && <span>{timeStr}</span>}
                    <button
                      onClick={() =>
                        copyToClipboard(event.id, `${cmd || ""}\n\n${output || thought || ""}`)
                      }
                      title="复制本条探测与回包内容"
                      className="p-1 hover:text-white transition-colors"
                    >
                      {copiedId === event.id ? (
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                </div>

                {/* Command / Input Execution Preview */}
                {cmd && (
                  <div className="space-y-1">
                    <div className="text-[11px] font-medium text-[#777] flex items-center gap-1">
                      <Terminal className="w-3 h-3 text-emerald-400" />
                      执行指令 / 探测动作:
                    </div>
                    <div className="rounded-lg bg-black border border-[#222] p-2.5 text-xs font-mono text-emerald-300 overflow-x-auto whitespace-pre-wrap break-all leading-relaxed">
                      {cleanCommandPreview(cmd)}
                    </div>
                  </div>
                )}

                {/* Reasoning Thought Preview */}
                {thought && !cmd && (
                  <div className="space-y-1">
                    <div className="text-[11px] font-medium text-[#777] flex items-center gap-1">
                      <Sparkles className="w-3 h-3 text-purple-400" />
                      智能体决策分析:
                    </div>
                    <div className="rounded-lg bg-purple-950/20 border border-purple-500/20 p-2.5 text-xs text-purple-200 leading-relaxed">
                      {thought}
                    </div>
                  </div>
                )}

                {/* Returned Scan Output (Real Results from server/target) */}
                {output && (
                  <div className="space-y-1 pt-1">
                    <div className="flex items-center justify-between text-[11px] font-medium text-[#777]">
                      <span className="flex items-center gap-1">
                        <Zap className="w-3 h-3 text-amber-400" />
                        目标响应与扫描回包 (Scan Result):
                      </span>
                      {output.split("\n").length > 6 && (
                        <button
                          onClick={() => toggleExpand(event.id)}
                          className="text-xs text-emerald-400 hover:text-emerald-300 flex items-center gap-1 transition-colors"
                        >
                          {isExpanded ? "收起" : "展开全部回包"}
                          {isExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                        </button>
                      )}
                    </div>

                    <div
                      className={`rounded-lg bg-[#050505] border ${
                        isError ? "border-red-500/30 text-red-300" : "border-[#1e1e1e] text-[#ccc]"
                      } p-3 text-xs font-mono overflow-x-auto whitespace-pre-wrap break-all leading-relaxed ${
                        !isExpanded && output.split("\n").length > 6 ? "max-h-36 overflow-hidden" : ""
                      }`}
                    >
                      {output}
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
