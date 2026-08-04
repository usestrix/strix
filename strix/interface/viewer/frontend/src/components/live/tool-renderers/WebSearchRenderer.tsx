"use client";

import type { ToolRendererProps } from "@/types/events";
import { TruncatedText } from "./ToolCard";

export default function WebSearchRenderer({ args, result }: ToolRendererProps) {
  const query = (args.query as string) ?? (args.search_query as string) ?? "";
  const res = result as Record<string, unknown> | null;
  const content = res ? (res.content as string) ?? null : null;
  const error = res && !res.success ? (res.message as string) ?? null : null;

  return (
    <div>
      <span className="text-amber-400/80 font-semibold text-sm">Searching the web</span>
      {query && <div className="text-[#888] text-[13px] mt-0.5">{query}</div>}
      {error && <div className="text-red-400/70 text-[13px] mt-1.5">{error}</div>}
      {content && (
        <div className="mt-2">
          <TruncatedText text={content} maxLines={15} />
        </div>
      )}
    </div>
  );
}
