import type { ComponentType } from "react";
import type { ToolRendererProps } from "@/types/events";
import {
  Terminal, Globe, FileText, ShieldAlert, ArrowUpRight, Brain,
  Bot, MessageCircle, Flag, Eye, Search, Code, StickyNote,
  ListTodo, Crosshair, Wrench, Ban, Image, ClipboardList, Plug,
} from "lucide-react";

import TerminalRenderer from "./TerminalRenderer";
import BrowserRenderer from "./BrowserRenderer";
import FileEditRenderer from "./FileEditRenderer";
import ApplyPatchRenderer from "./ApplyPatchRenderer";
import ViewImageRenderer from "./ViewImageRenderer";
import VulnReportRenderer from "./VulnReportRenderer";
import ReportListRenderer from "./ReportListRenderer";
import ProxyRenderer from "./ProxyRenderer";
import ThinkRenderer from "./ThinkRenderer";
import AgentCommsRenderer from "./AgentCommsRenderer";
import WebSearchRenderer from "./WebSearchRenderer";
import PythonRenderer from "./PythonRenderer";
import ScanInfoRenderer from "./ScanInfoRenderer";
import FinishRenderer from "./FinishRenderer";
import NotesRenderer from "./NotesRenderer";
import TodoRenderer from "./TodoRenderer";
import FallbackRenderer from "./FallbackRenderer";
import LoadSkillRenderer from "./LoadSkillRenderer";
import RespondRenderer from "./RespondRenderer";
import CoverageRenderer from "./CoverageRenderer";
import ThreatModelRenderer from "./ThreatModelRenderer";
import McpRenderer from "./McpRenderer";

/**
 * Tool-renderer mapping — data-driven, keyed by the engine's tool *family*.
 *
 * The OSS strix engine (usestrix/strix) is the source of truth for tool names:
 * see `strix/tools/**` for definitions and `strix/interface/tui/renderers/` for
 * the TUI equivalents of these components. Tools come in families that share a
 * React renderer + icon (terminal, proxy, notes, todos, …), so we describe each
 * family ONCE instead of repeating a row per tool name. A new tool that joins an
 * existing family (e.g. another `*_request` proxy tool) is picked up by the
 * family prefix matcher with no code change; only genuinely-new families need an
 * entry here.
 */

export type ToolCategory =
  | "terminal"
  | "python"
  | "browser"
  | "filesystem"
  | "proxy"
  | "reporting"
  | "thinking"
  | "agents"
  | "search"
  | "lifecycle"
  | "notes"
  | "skills"
  | "todos"
  | "coverage"
  | "threatModel"
  | "telemetry"
  | "mcp";

export interface ToolIconMeta {
  icon: ComponentType<{ className?: string }>;
  color: string;
}

interface CategoryMeta {
  renderer: ComponentType<ToolRendererProps>;
  icon: ComponentType<{ className?: string }>;
  color: string;
  /** Family matcher for graceful fallback of unknown tools in this family. */
  match?: RegExp;
}

/** Per-family defaults: renderer + base icon/color + a family-name matcher. */
const CATEGORY_META: Record<ToolCategory, CategoryMeta> = {
  terminal: { renderer: TerminalRenderer, icon: Terminal, color: "text-emerald-400" },
  python: { renderer: PythonRenderer, icon: Code, color: "text-yellow-400" },
  browser: { renderer: BrowserRenderer, icon: Globe, color: "text-blue-400" },
  filesystem: { renderer: FileEditRenderer, icon: FileText, color: "text-sky-400" },
  proxy: { renderer: ProxyRenderer, icon: ArrowUpRight, color: "text-purple-400", match: /request|sitemap|scope/ },
  reporting: { renderer: VulnReportRenderer, icon: ShieldAlert, color: "text-red-400" },
  thinking: { renderer: ThinkRenderer, icon: Brain, color: "text-purple-400" },
  agents: { renderer: AgentCommsRenderer, icon: Bot, color: "text-cyan-400", match: /agent/ },
  search: { renderer: WebSearchRenderer, icon: Search, color: "text-amber-400" },
  lifecycle: { renderer: ScanInfoRenderer, icon: Flag, color: "text-emerald-400" },
  notes: { renderer: NotesRenderer, icon: StickyNote, color: "text-amber-400", match: /note/ },
  skills: { renderer: LoadSkillRenderer, icon: Wrench, color: "text-emerald-400" },
  todos: { renderer: TodoRenderer, icon: ListTodo, color: "text-purple-400", match: /todo/ },
  coverage: { renderer: CoverageRenderer, icon: ClipboardList, color: "text-cyan-400", match: /coverage/ },
  threatModel: { renderer: ThreatModelRenderer, icon: Crosshair, color: "text-blue-400", match: /threat_model/ },
  telemetry: { renderer: FallbackRenderer, icon: Wrench, color: "text-[#555]" },
  // Tools from the user's own MCP servers. Resolved from the connection on the
  // event rather than from a tool name — except list_mcps, the engine's
  // inventory of every connection, which touches none and so carries no
  // connection to resolve from; it is the family's one name below.
  mcp: { renderer: McpRenderer, icon: Plug, color: "text-teal-400" },
};

/**
 * Tool name → family. Grouped by family; legacy names the engine used before the
 * OSS SDK migration (terminal_execute, python_action, browser_action,
 * str_replace_editor, send_request, …) are kept as aliases so historical scan
 * data keeps rendering.
 */
const CATEGORY_TOOLS: Record<ToolCategory, readonly string[]> = {
  // Shell — SDK `exec_command` / `write_stdin` (legacy: terminal_execute)
  terminal: ["exec_command", "write_stdin", "terminal_execute"],
  // Legacy Python session tool (now runs through the shell)
  python: ["python_action"],
  // Legacy browser tool (now driven via agent-browser CLI over the shell)
  browser: ["browser_action"],
  // SDK filesystem — `apply_patch` / `view_image` (legacy: str_replace_editor, list/search)
  filesystem: ["apply_patch", "view_image", "str_replace_editor", "list_files", "search_files"],
  // Caido proxy tools (legacy: send_request)
  proxy: ["list_requests", "view_request", "repeat_request", "list_sitemap", "view_sitemap_entry", "scope_rules", "send_request"],
  reporting: ["create_vulnerability_report", "update_vulnerability_report", "list_reports", "get_report"],
  thinking: ["think"],
  agents: ["create_agent", "agent_finish", "send_message_to_agent", "wait_for_agents", "view_agent_graph", "stop_agent"],
  search: ["web_search"],
  // scan_start_info / subagent_start_info are strix-app synthetic events; finish_scan is the engine's
  lifecycle: ["scan_start_info", "subagent_start_info", "finish_scan", "respond_to_user"],
  notes: ["create_note", "delete_note", "update_note", "list_notes", "get_note"],
  skills: ["load_skill"],
  todos: ["create_todo", "list_todos", "update_todo", "mark_todo_done", "mark_todo_pending", "delete_todo"],
  // Shared coverage ledger — one row per surface × risk area for the whole run
  coverage: ["record_coverage", "update_coverage", "list_coverage"],
  // Per-target threat model, shared across the agent tree
  threatModel: ["get_threat_model", "save_threat_model", "amend_threat_model"],
  telemetry: ["sandbox_error_details", "llm_error_details"],
  mcp: ["list_mcps"],
};

/** Reverse index (tool name → family), built once from CATEGORY_TOOLS. */
const TOOL_CATEGORY: Record<string, ToolCategory> = Object.fromEntries(
  (Object.entries(CATEGORY_TOOLS) as [ToolCategory, readonly string[]][]).flatMap(
    ([category, names]) => names.map((name) => [name, category] as const),
  ),
);

/**
 * Per-tool renderer overrides — for the rare tool whose renderer differs from its
 * family default (finish_scan renders the final report, not the scan-start card).
 */
const RENDERER_OVERRIDES: Partial<Record<string, ComponentType<ToolRendererProps>>> = {
  finish_scan: FinishRenderer,
  respond_to_user: RespondRenderer,
  apply_patch: ApplyPatchRenderer,
  view_image: ViewImageRenderer,
  list_reports: ReportListRenderer,
  get_report: ReportListRenderer,
};

/**
 * Per-tool icon overrides — for tools whose icon/color differs from their family
 * default (the agents family and lifecycle family each vary per tool).
 */
const ICON_OVERRIDES: Partial<Record<string, ToolIconMeta>> = {
  agent_finish: { icon: Flag, color: "text-cyan-400" },
  send_message_to_agent: { icon: MessageCircle, color: "text-cyan-400" },
  wait_for_agents: { icon: MessageCircle, color: "text-cyan-400" },
  respond_to_user: { icon: MessageCircle, color: "text-emerald-400" },
  view_agent_graph: { icon: Eye, color: "text-cyan-400" },
  stop_agent: { icon: Ban, color: "text-red-400" },
  scan_start_info: { icon: Crosshair, color: "text-emerald-400" },
  subagent_start_info: { icon: Bot, color: "text-purple-400" },
  view_image: { icon: Image, color: "text-sky-400" },
};

const FALLBACK_META: CategoryMeta = CATEGORY_META.telemetry;

/** Resolve a tool name to its family, falling back to family-name matchers. */
function resolveCategory(toolName: string): ToolCategory | null {
  const direct = TOOL_CATEGORY[toolName];
  if (direct) return direct;
  for (const [category, meta] of Object.entries(CATEGORY_META) as [ToolCategory, CategoryMeta][]) {
    if (meta.match?.test(toolName)) return category;
  }
  return null;
}

/**
 * A call to a tool from one of the user's MCP servers is placed by the
 * connection it was tagged with, ahead of every name-keyed lookup below. Every
 * MCP call goes through the `call_mcp` / `describe_mcp` dispatch tools, so the
 * connection tag, not the tool name, is what routes it to the MCP renderer.
 */
export function getToolRenderer(
  toolName: string,
  mcpConnection?: string | null
): ComponentType<ToolRendererProps> {
  if (mcpConnection) return CATEGORY_META.mcp.renderer;
  const override = RENDERER_OVERRIDES[toolName];
  if (override) return override;
  const category = resolveCategory(toolName);
  return category ? CATEGORY_META[category].renderer : FallbackRenderer;
}

export function getToolIcon(toolName: string, mcpConnection?: string | null): ToolIconMeta {
  if (mcpConnection) {
    return { icon: CATEGORY_META.mcp.icon, color: CATEGORY_META.mcp.color };
  }
  const override = ICON_OVERRIDES[toolName];
  if (override) return override;
  const category = resolveCategory(toolName);
  const meta = category ? CATEGORY_META[category] : FALLBACK_META;
  return { icon: meta.icon, color: meta.color };
}
