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
 */

/** Arguments one line each, as the terminal prints them. */
function argLines(args: unknown): string[] {
  if (!args || typeof args !== "object" || Array.isArray(args)) return [];
  return Object.entries(args as Record<string, unknown>).map(([key, value]) => {
    const rendered = typeof value === "string" ? value : JSON.stringify(value);
    return `${key}: ${rendered ?? String(value)}`;
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

  return (
    <div>
      <div className="flex items-center gap-2 flex-wrap">
        <span className="font-mono text-teal-300 font-semibold text-sm">{mcpTool || toolName}</span>
        <span className="text-[13px] text-[#555]">via MCP server</span>
        {mcpConnection && <span className="text-[13px] text-teal-400/80">{mcpConnection}</span>}
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
