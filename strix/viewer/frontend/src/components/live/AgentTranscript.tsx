import { Component, useMemo, type ReactNode } from "react";
import { Brain, Bot } from "lucide-react";
import { getToolRenderer, getToolIcon } from "./tool-renderers";
import ChatBubble from "./tool-renderers/ChatBubble";
import type { ToolRendererProps, AgentNode as GraphAgentNode } from "@/types/events";
import type { TranscriptAgent, TranscriptEvent } from "@/data/serverSource";

/* ---------- Error boundary so one bad event never blanks the transcript ---------- */
class RendererErrorBoundary extends Component<
  { toolName: string; children: ReactNode },
  { hasError: boolean }
> {
  constructor(props: { toolName: string; children: ReactNode }) {
    super(props);
    this.state = { hasError: false };
  }
  static getDerivedStateFromError() {
    return { hasError: true };
  }
  render() {
    if (this.state.hasError) {
      return (
        <span className="text-[#555] font-semibold text-sm">
          {this.props.toolName.replace(/_/g, " ")}
        </span>
      );
    }
    return this.props.children;
  }
}

function SafeToolRenderer(props: ToolRendererProps) {
  const Renderer = getToolRenderer(props.toolName);
  return (
    <RendererErrorBoundary toolName={props.toolName}>
      <Renderer {...props} />
    </RendererErrorBoundary>
  );
}

/* ---------- Value coercion ----------
 * args/result arrive as either a JSON object or a Python-repr string
 * ("{'thought': '...'}"). Try JSON, then a naive python->json pass, then wrap
 * the raw string so the fallback renderer can display it. Never throws. */
function coerce(value: unknown): unknown {
  if (value == null || typeof value !== "string") return value;
  const t = value.trim();
  if (!t) return value;
  try {
    return JSON.parse(t);
  } catch {
    /* not JSON */
  }
  try {
    const jsonish = t
      .replace(/\bNone\b/g, "null")
      .replace(/\bTrue\b/g, "true")
      .replace(/\bFalse\b/g, "false")
      .replace(/'/g, '"');
    return JSON.parse(jsonish);
  } catch {
    return { __raw: value };
  }
}

function asRecord(value: unknown): Record<string, unknown> {
  const c = coerce(value);
  if (c && typeof c === "object" && !Array.isArray(c)) return c as Record<string, unknown>;
  if (c == null) return {};
  return { __raw: typeof c === "string" ? c : JSON.stringify(c) };
}

/** Numeric suffix of an event id ("tool_37" -> 37) for stable ordering. */
function eventSeq(id: string): number {
  const m = /(\d+)$/.exec(id);
  return m ? parseInt(m[1], 10) : 0;
}

/** A chat event whose author is the human/user (vs an assistant "thinking"). */
function isUserChat(event: TranscriptEvent): boolean {
  const role = event.data?.role;
  return event.type === "chat" && (role === "user" || role === "human");
}

/**
 * Inter-agent message deliveries land in the recipient's session as user-role
 * items prefixed with a header (see the engine's message formatter). They are
 * already represented via the sending agent's tool renderer, so we never render
 * them as chat bubbles here.
 */
function isInterAgentDelivery(event: TranscriptEvent): boolean {
  return isUserChat(event) && String(event.data?.content ?? "").startsWith("[Message from ");
}

/**
 * The reconstructed SDK session records every incoming user-role item for an
 * agent: its initial input (the root's assembled brief, or a subagent's spawn /
 * inherited-context prompt), inter-agent deliveries, AND genuine human steering
 * messages sent live from the viewer or TUI. We only want the last group. Given
 * an agent's events in order, hide the first user message (its initial input)
 * and every inter-agent delivery; keep the rest, which are the human's live
 * instructions, rendered as "User" bubbles.
 */
function hiddenUserEventIds(agentEventsInOrder: TranscriptEvent[]): Set<string> {
  const hidden = new Set<string>();
  let sawInitialInput = false;
  for (const e of agentEventsInOrder) {
    if (!isUserChat(e)) continue;
    if (isInterAgentDelivery(e)) {
      hidden.add(e.id);
      continue;
    }
    if (!sawInitialInput) {
      sawInitialInput = true;
      hidden.add(e.id);
    }
  }
  return hidden;
}

const STATUS_STYLE: Record<string, string> = {
  completed: "text-emerald-400 border-emerald-500/30 bg-emerald-500/10",
  running: "text-blue-400 border-blue-500/30 bg-blue-500/10",
  waiting: "text-yellow-400 border-yellow-500/30 bg-yellow-500/10",
  stopped: "text-[#aaa] border-[#333] bg-[#1a1a1a]",
  crashed: "text-red-400 border-red-500/30 bg-red-500/10",
  failed: "text-red-400 border-red-500/30 bg-red-500/10",
};

/** Map our engine agent statuses onto the graph node's status union. */
function graphStatus(status: string): GraphAgentNode["status"] {
  if (status === "completed") return "completed";
  if (status === "running") return "running";
  if (status === "failed" || status === "crashed") return "failed";
  // waiting / stopped / unknown → keep the raw string; AgentNode/MiniMap fall
  // back to a neutral gray for anything they don't explicitly style.
  return status as GraphAgentNode["status"];
}

/**
 * Adapt transcript agents + events into the Map<id, AgentNode> that the live
 * AgentGraph renders: children from parent_id, tool/message counts by scanning
 * events, and a task pulled from the spawning create_agent call where present.
 */
export function buildGraphAgents(
  agents: TranscriptAgent[],
  events: TranscriptEvent[]
): Map<string, GraphAgentNode> {
  const childrenOf = new Map<string, string[]>();
  for (const a of agents) {
    if (a.parent_id) {
      const arr = childrenOf.get(a.parent_id) ?? [];
      arr.push(a.id);
      childrenOf.set(a.parent_id, arr);
    }
  }

  const toolCount = new Map<string, number>();
  const messageCount = new Map<string, number>();
  // A create_agent call names the child but not its id, so map spawned tasks by
  // agent NAME (best-effort — used only for the graph node subtitle).
  const taskByName = new Map<string, string>();
  for (const e of events) {
    if (e.type === "tool") {
      toolCount.set(e.agent_id, (toolCount.get(e.agent_id) ?? 0) + 1);
      if (e.data?.tool_name === "create_agent") {
        const args = asRecord(e.data.args);
        const name = (args.name as string) ?? (args.agent_name as string) ?? "";
        const task = (args.task as string) ?? "";
        if (name && task) taskByName.set(name, task);
      }
    } else if (!isUserChat(e)) {
      // Count only assistant messages for the graph node subtitle.
      messageCount.set(e.agent_id, (messageCount.get(e.agent_id) ?? 0) + 1);
    }
  }

  const map = new Map<string, GraphAgentNode>();
  for (const a of agents) {
    map.set(a.id, {
      id: a.id,
      name: a.name,
      task: taskByName.get(a.name) ?? "",
      status: graphStatus(a.status),
      parentId: a.parent_id,
      children: childrenOf.get(a.id) ?? [],
      createdAt: a.created_at,
      toolCount: toolCount.get(a.id) ?? 0,
      messageCount: messageCount.get(a.id) ?? 0,
    });
  }
  return map;
}

/* ---------- Per-agent transcript ---------- */
export function AgentTranscript({
  agent,
  events,
  showHeader = true,
}: {
  agent: TranscriptAgent;
  events: TranscriptEvent[];
  showHeader?: boolean;
}) {
  const mine = useMemo(() => {
    const ordered = events
      .filter((e) => e.agent_id === agent.id)
      .sort((a, b) => eventSeq(a.id) - eventSeq(b.id));
    const hidden = hiddenUserEventIds(ordered);
    return ordered.filter((e) => !hidden.has(e.id));
  }, [events, agent.id]);

  const toolCount = mine.filter((e) => e.type === "tool").length;
  const msgCount = mine.length - toolCount;

  return (
    <div>
      {showHeader && (
        <>
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <span className="text-base font-semibold text-white truncate">{agent.name}</span>
            <span
              className={`flex-shrink-0 text-xs font-medium capitalize px-2 py-0.5 rounded-full border ${
                STATUS_STYLE[agent.status] ?? "text-[#aaa] border-[#333] bg-[#1a1a1a]"
              }`}
            >
              {agent.status}
            </span>
            <span className="font-mono text-xs text-[#555]">{agent.id}</span>
          </div>
          <p className="text-xs text-[#666] mb-4">
            {msgCount} message{msgCount === 1 ? "" : "s"} · {toolCount} tool call
            {toolCount === 1 ? "" : "s"}
          </p>
        </>
      )}

      {mine.length === 0 ? (
        <p className="text-sm text-[#666]">No recorded activity for this agent.</p>
      ) : (
        <div className="py-1">
          {mine.map((event, i) => {
            const isLast = i === mine.length - 1;
            const isTool = event.type === "tool";
            const toolName = isTool ? String(event.data?.tool_name ?? "tool") : "";
            const role = !isTool ? String(event.data?.role ?? "assistant") : "";

            let Icon;
            let iconColor: string;
            if (isTool) {
              const meta = getToolIcon(toolName);
              Icon = meta.icon;
              iconColor = meta.color;
            } else {
              const isUser = role === "user" || role === "human";
              Icon = isUser ? Bot : Brain;
              iconColor = isUser ? "text-blue-400" : "text-purple-400";
            }

            const status = isTool ? String(event.data?.status ?? "completed") : "completed";

            return (
              <div key={event.id} className="flex gap-3">
                <div className="flex flex-col items-center shrink-0">
                  <div
                    className={`w-[30px] h-[30px] rounded-full bg-black border flex items-center justify-center shrink-0 ${
                      isTool && status === "running"
                        ? "border-blue-500/40 animate-pulse"
                        : isTool && status === "failed"
                          ? "border-red-500/30"
                          : "border-[#222]"
                    }`}
                  >
                    <Icon className={`w-3.5 h-3.5 ${iconColor}`} />
                  </div>
                  {!isLast && <div className="w-px flex-1 bg-[#1a1a1a] mt-1" />}
                </div>
                <div className="flex-1 min-w-0 pt-[5px] pb-6">
                  {isTool ? (
                    <SafeToolRenderer
                      toolName={toolName}
                      args={asRecord(event.data?.args)}
                      result={coerce(event.data?.result) ?? null}
                      status={
                        status as ToolRendererProps["status"]
                      }
                    />
                  ) : (
                    <ChatBubble
                      role={role}
                      content={String(event.data?.content ?? "")}
                    />
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
