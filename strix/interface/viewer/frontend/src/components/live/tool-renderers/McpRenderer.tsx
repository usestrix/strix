"use client";

import type { ToolRendererProps } from "@/types/events";

/**
 * A call to a tool from one of the MCP servers the user connected.
 *
 * Deliberately the same shape as the terminal: the tool's own name, the server
 * it went to, the arguments one per line, and a status. The result is not shown.
 * These payloads are routinely thousands of characters of JSON that say nothing a
 * reader wants at this point in the transcript, and the agent narrates what it
 * learned in its next message. A failure is the exception, because that is what
 * someone is looking for when a step did not work; it renders as inert text,
 * never as markdown, since it came from a server outside Strix.
 *
 * The full result is still in the run's event data on disk either way.
 *
 * list_mcps is the other exception: its result is the engine's own inventory of
 * the run's connections (names and tool counts), short and assembled by Strix
 * rather than returned by an outside server, so it is shown inline.
 */

/** Arguments one line each, as the terminal prints them. */
function argLines(args: unknown): string[] {
  if (!args || typeof args !== "object" || Array.isArray(args)) return [];
  return Object.entries(args as Record<string, unknown>).map(([key, value]) => {
    const rendered = typeof value === "string" ? value : JSON.stringify(value);
    return `${key}: ${rendered ?? String(value)}`;
  });
}

/** One connection out of a list_mcps inventory. */
interface McpListingEntry {
  name: string;
  toolCount: number | null;
  dead: boolean;
}

/**
 * The connections out of a list_mcps result, which is
 * `{"connections": [{id, name, description, tool_count}, ...]}`, sometimes
 * arriving JSON-encoded as a string. Anything else yields an empty list and the
 * row shows just the header and status. Unlike other MCP results this one is
 * safe to show: the engine assembled it from the run's own registered
 * connections, so it is short and never an outside server's payload. It still
 * renders as inert text.
 */
function listingEntries(result: unknown): McpListingEntry[] {
  let value = result;
  if (typeof value === "string") {
    try {
      value = JSON.parse(value);
    } catch {
      return [];
    }
  }
  const connections =
    value && typeof value === "object" && !Array.isArray(value)
      ? (value as Record<string, unknown>).connections
      : null;
  if (!Array.isArray(connections)) return [];
  return connections.flatMap((entry) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) return [];
    const record = entry as Record<string, unknown>;
    const name =
      typeof record.name === "string" && record.name.trim()
        ? record.name.trim()
        : typeof record.id === "string"
          ? record.id.trim()
          : "";
    if (!name) return [];
    const toolCount = typeof record.tool_count === "number" ? record.tool_count : null;
    const dead = record.dead === true;
    return [{ name, toolCount, dead }];
  });
}

const MAX_ERROR_CHARS = 600;

function errorText(result: unknown): string | null {
  if (typeof result === "string") {
    const trimmed = result.trim();
    if (!trimmed) return null;
    return trimmed.length > MAX_ERROR_CHARS ? `${trimmed.slice(0, MAX_ERROR_CHARS)}…` : trimmed;
  }
  return null;
}

export default function McpRenderer({
  toolName,
  mcpTool,
  mcpConnection,
  args,
  result,
  status,
}: ToolRendererProps) {
  const lines = argLines(args);
  const failed = status === "failed" || status === "error";
  const error = failed ? errorText(result) : null;
  // describe_mcp inspects a connection's catalog rather than calling a tool on
  // it, so the connection is the subject and there is no underlying tool.
  const inspecting = toolName === "describe_mcp";
  // list_mcps inventories every connection rather than touching one, so it
  // carries no connection at all and is routed here by name instead.
  const listing = toolName === "list_mcps";
  const entries = listing ? listingEntries(result) : [];

  return (
    <div>
      <div className="flex items-center gap-2 flex-wrap">
        {listing ? (
          <span className="text-[13px] text-[#555]">Listing connected MCP servers</span>
        ) : inspecting ? (
          <>
            <span className="text-[13px] text-[#555]">Inspecting MCP server</span>
            {mcpConnection && (
              <span className="font-mono text-teal-300 font-semibold text-sm">{mcpConnection}</span>
            )}
          </>
        ) : (
          <>
            <span className="font-mono text-teal-300 font-semibold text-sm">
              {mcpTool || toolName}
            </span>
            <span className="text-[13px] text-[#555]">via MCP server</span>
            {mcpConnection && <span className="text-[13px] text-teal-400/80">{mcpConnection}</span>}
          </>
        )}
      </div>

      {lines.length > 0 && (
        <div className="mt-1 font-mono text-[13px] leading-relaxed">
          {lines.map((line) => (
            <div key={line} className="text-[#777] break-all">
              {line}
            </div>
          ))}
        </div>
      )}

      {entries.length > 0 && (
        <div className="mt-1 font-mono text-[13px] leading-relaxed">
          {entries.map((entry) => (
            <div key={entry.name} className={`break-all${entry.dead ? " opacity-50" : ""}`}>
              <span className="text-teal-300">{entry.name}</span>
              {entry.dead ? (
                <span className="text-red-400/80"> · offline</span>
              ) : (
                entry.toolCount !== null && (
                  <span className="text-[#555]">
                    {" "}
                    · {entry.toolCount} {entry.toolCount === 1 ? "tool" : "tools"}
                  </span>
                )
              )}
            </div>
          ))}
        </div>
      )}

      <div className="mt-1 text-[13px]">
        {status === "running" && <span className="text-[#666]">Running</span>}
        {status === "completed" && <span className="text-emerald-400/80">✓ Done</span>}
        {failed && <span className="text-red-400/80">✗ Failed</span>}
      </div>

      {error && (
        <pre className="mt-1 font-mono text-[13px] leading-relaxed whitespace-pre-wrap break-words text-red-400/70">
          {error}
        </pre>
      )}
    </div>
  );
}
