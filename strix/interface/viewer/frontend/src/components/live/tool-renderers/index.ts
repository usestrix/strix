import type { ComponentType } from "react";
import type { ToolRendererProps } from "@/types/events";
import {
  Terminal, Globe, FileText, ShieldAlert, ArrowUpRight, Brain,
  Bot, MessageCircle, Flag, Eye, Search, Code, StickyNote,
  ListTodo, Crosshair, Wrench, Ban, Image,
} from "lucide-react";

import TerminalRenderer from "./TerminalRenderer";
import BrowserRenderer from "./BrowserRenderer";
import FileEditRenderer from "./FileEditRenderer";
import ApplyPatchRenderer from "./ApplyPatchRenderer";
import ViewImageRenderer from "./ViewImageRenderer";
import VulnReportRenderer from "./VulnReportRenderer";
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
  | "telemetry";

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
  telemetry: { renderer: FallbackRenderer, icon: Wrench, color: "text-[#555]" },
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
  reporting: ["create_vulnerability_report"],
  thinking: ["think"],
  agents: ["create_agent", "agent_finish", "send_message_to_agent", "wait_for_message", "view_agent_graph", "stop_agent"],
  search: ["web_search"],
  // scan_start_info / subagent_start_info are strix-app synthetic events; finish_scan is the engine's
  lifecycle: ["scan_start_info", "subagent_start_info", "finish_scan"],
  notes: ["create_note", "delete_note", "update_note", "list_notes", "get_note"],
  skills: ["load_skill"],
  todos: ["create_todo", "list_todos", "update_todo", "mark_todo_done", "mark_todo_pending", "delete_todo"],
  telemetry: ["sandbox_error_details", "llm_error_details"],
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
  apply_patch: ApplyPatchRenderer,
  view_image: ViewImageRenderer,
};

/**
 * Per-tool icon overrides — for tools whose icon/color differs from their family
 * default (the agents family and lifecycle family each vary per tool).
 */
const ICON_OVERRIDES: Partial<Record<string, ToolIconMeta>> = {
  agent_finish: { icon: Flag, color: "text-cyan-400" },
  send_message_to_agent: { icon: MessageCircle, color: "text-cyan-400" },
  wait_for_message: { icon: MessageCircle, color: "text-cyan-400" },
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

export function getToolRenderer(toolName: string): ComponentType<ToolRendererProps> {
  const override = RENDERER_OVERRIDES[toolName];
  if (override) return override;
  const category = resolveCategory(toolName);
  return category ? CATEGORY_META[category].renderer : FallbackRenderer;
}

export function getToolIcon(toolName: string): ToolIconMeta {
  const override = ICON_OVERRIDES[toolName];
  if (override) return override;
  const category = resolveCategory(toolName);
  const meta = category ? CATEGORY_META[category] : FALLBACK_META;
  return { icon: meta.icon, color: meta.color };
}
