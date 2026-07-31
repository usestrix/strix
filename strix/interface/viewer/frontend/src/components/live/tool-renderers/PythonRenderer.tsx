"use client";

import type { ToolRendererProps } from "@/types/events";
import { CodeBlock, SyntaxBlock } from "./ToolCard";

const MAX_OUTPUT_LINES = 50;
const MAX_LINE_LENGTH = 200;
const HEAD = 25;
const TAIL = 24;

// Full ANSI escape sequence pattern (matches Python's ANSI_PATTERN)
const ANSI_PATTERN = /\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~]|\][^\x07]*\x07)/g;

// Strips truncation notices added by Python executor
const STRIP_PATTERN = /\.\.\. \[(stdout|stderr|result|output|error) truncated at \d+k? chars\]/g;

function stripAnsi(text: string): string {
  return text.replace(ANSI_PATTERN, "");
}

function truncateLine(line: string): string {
  const clean = stripAnsi(line);
  if (clean.length > MAX_LINE_LENGTH) return clean.slice(0, MAX_LINE_LENGTH - 3) + "...";
  return clean;
}

function cleanOutput(output: string): string {
  return output.replace(STRIP_PATTERN, "").trim();
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

export default function PythonRenderer({ args, result }: ToolRendererProps) {
  const action = (args.action as string) ?? "";
  const code = (args.code as string) ?? (args.script as string) ?? "";

  const res = result as Record<string, unknown> | string | null;
  let stdout: string | null = null;
  if (res && typeof res === "object") stdout = typeof res.stdout === "string" ? res.stdout : null;
  else if (typeof res === "string") stdout = res;

  const subtitle =
    action === "new_session" ? "new session" :
    action === "close" ? "close session" :
    action === "list_sessions" ? "list sessions" : null;

  const output = stdout ? formatOutput(cleanOutput(stdout)) : null;

  return (
    <div>
      <div className="flex items-center gap-2">
        <span className="text-yellow-400/80 font-semibold text-sm">Python</span>
        {subtitle && <span className="text-[#888] text-[13px]">{subtitle}</span>}
      </div>
      {code && <SyntaxBlock code={code} language="python" collapsible />}
      {output && <CodeBlock className="text-[#666]">{output}</CodeBlock>}
    </div>
  );
}
