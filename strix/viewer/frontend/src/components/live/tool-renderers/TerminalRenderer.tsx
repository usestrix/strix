"use client";

import type { ToolRendererProps } from "@/types/events";
import { CodeBlock, SyntaxBlock } from "./ToolCard";

const MAX_OUTPUT_LINES = 50;
const MAX_LINE_LENGTH = 200;
const HEAD = 25;
const TAIL = 24;

const STRIP_PATTERNS: RegExp[] = [
  /\n?\[Command still running after [\d.]+s - showing output so far\.?\s*(?:Use C-c to interrupt if needed\.)?\]/g,
  /^\[Below is the output of the previous command\.\]\n?/gm,
  /^No command is currently running\. Cannot send input\.$/gm,
  /^A command is already running\. Use is_input=true to send input to it, or interrupt it first \(e\.g\., with C-c\)\.$/gm,
];

// Terminal-tool chunk metadata (the OSS engine's shell tool prepends these; the
// TUI strips them in strix/interface/tui/renderers/shell_renderer.py). Only a
// contiguous block anchored on a "Chunk ID:" line is stripped, so identical
// text inside real command output is left untouched.
const CHUNK_PREAMBLE_START = /^Chunk ID: [0-9a-f]+\s*$/;
const CHUNK_PREAMBLE_METADATA: RegExp[] = [
  /^Wall time: [\d.]+ seconds\s*$/,
  /^Process exited with code -?\d+\s*$/,
  /^Process running with session ID \d+\s*$/,
  /^Original token count: \d+\s*$/,
];

function stripChunkPreambles(lines: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (CHUNK_PREAMBLE_START.test(lines[i])) {
      let j = i + 1;
      while (j < lines.length && CHUNK_PREAMBLE_METADATA.some((p) => p.test(lines[j]))) j++;
      if (j < lines.length && lines[j].trim() === "Output:") j++;
      i = j - 1;
      continue;
    }
    out.push(lines[i]);
  }
  return out;
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function truncateLine(line: string): string {
  if (line.length > MAX_LINE_LENGTH) return line.slice(0, MAX_LINE_LENGTH - 3) + "...";
  return line;
}

function cleanOutput(raw: string, command: string = ""): string {
  // Strip ANSI escape sequences and carriage returns
  let cleaned = raw.replace(/\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~]|\][^\x07]*\x07)/g, "").replace(/\r/g, "");

  for (const pattern of STRIP_PATTERNS) {
    cleaned = cleaned.replace(pattern, "");
  }

  if (cleaned.trim()) {
    const lines = stripChunkPreambles(cleaned.split("\n"));
    const filtered: string[] = [];
    for (const line of lines) {
      // Skip leading blank lines
      if (filtered.length === 0 && !line.trim()) continue;
      // Skip [STRIX_N]$ prompt lines
      if (/^\[STRIX_\d+\]\$\s*/.test(line)) continue;
      // Skip echoed command (plain)
      if (command && line.trim() === command.trim()) continue;
      // Skip echoed command with $/#/> prefix
      if (command && new RegExp(`^[\\$#>]\\s*${escapeRegex(command.trim())}\\s*$`).test(line)) continue;
      filtered.push(line);
    }
    // Strip trailing [STRIX_N]$ lines
    while (filtered.length > 0 && /^\[STRIX_\d+\]\$\s*/.test(filtered[filtered.length - 1])) {
      filtered.pop();
    }
    cleaned = filtered.join("\n");
  }

  return cleaned.trim();
}

function formatOutput(output: string): string {
  const lines = output.split("\n");
  if (lines.length <= MAX_OUTPUT_LINES) return lines.map(truncateLine).join("\n");
  const hiddenCount = lines.length - HEAD - TAIL;
  return [
    ...lines.slice(0, HEAD).map(truncateLine),
    `... ${hiddenCount} lines truncated ...`,
    ...lines.slice(-TAIL).map(truncateLine),
  ].join("\n");
}

export default function TerminalRenderer({ toolName, args, result }: ToolRendererProps) {
  const isStdin = toolName === "write_stdin";
  const command = isStdin
    ? ((args.chars as string) ?? (args.input as string) ?? "")
    : ((args.command as string) ?? (args.cmd as string) ?? "");

  const res = result as Record<string, unknown> | string | null;
  let content: string | null = null;
  let error: string | null = null;
  let exitCode: number | null = null;

  if (res && typeof res === "object") {
    content = typeof res.content === "string" ? res.content : null;
    error = typeof res.error === "string" ? res.error : null;
    exitCode = typeof res.exit_code === "number" ? res.exit_code : null;
    const s = typeof res.status === "string" ? res.status : "";
    if (s === "running" || s === "command still running") content = null;
  } else if (typeof res === "string") {
    content = res;
  }

  const output = content ? formatOutput(cleanOutput(content, command)) : null;

  return (
    <div>
      <span className="text-emerald-400/80 font-semibold text-sm">{isStdin ? "Terminal input" : "Terminal"}</span>
      {command && <SyntaxBlock code={command} language="bash" collapsible />}
      {error && <CodeBlock className="text-red-400/70">{error}</CodeBlock>}
      {output && <CodeBlock className="text-[#666]">{output}</CodeBlock>}
      {exitCode != null && exitCode !== 0 && (
        <div className="font-mono text-[13px] text-red-400/70 mt-0.5">exit code {exitCode}</div>
      )}
    </div>
  );
}
