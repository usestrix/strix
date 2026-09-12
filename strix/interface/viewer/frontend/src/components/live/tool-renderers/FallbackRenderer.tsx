import type { ToolRendererProps } from "@/types/events";
import { CodeBlock } from "./ToolCard";

/**
 * Generic renderer for tool names without a dedicated family renderer. Shows the
 * humanized tool name plus a pretty-printed dump of args/result. Tolerates the
 * server sending args/result as either a parsed object or an unparseable
 * Python-repr string (which arrives here wrapped as { __raw }); never crashes.
 */
function pretty(value: unknown): string | null {
  if (value == null) return null;
  if (typeof value === "string") return value.trim() ? value : null;
  if (typeof value === "object") {
    const rec = value as Record<string, unknown>;
    if (typeof rec.__raw === "string") return rec.__raw;
    if (Object.keys(rec).length === 0) return null;
    try {
      return JSON.stringify(value, null, 2);
    } catch {
      return String(value);
    }
  }
  return String(value);
}

export default function FallbackRenderer({ toolName, args, result }: ToolRendererProps) {
  const argsText = pretty(args);
  const resultText = pretty(result);
  return (
    <div>
      <span className="text-[#888] font-semibold text-sm">{toolName.replace(/_/g, " ")}</span>
      {argsText && <CodeBlock className="text-[#777]">{argsText}</CodeBlock>}
      {resultText && <CodeBlock className="text-[#666]">{resultText}</CodeBlock>}
    </div>
  );
}
