"use client";

import type { ToolRendererProps } from "@/types/events";
import { TruncatedText } from "./ToolCard";

export default function ThinkRenderer({ args }: ToolRendererProps) {
  const thought = (args.thought as string) ?? (args.content as string) ?? "";
  if (!thought) return null;

  return (
    <div>
      <span className="text-purple-400/80 font-semibold text-sm">Agent is thinking</span>
      <div className="mt-1.5 italic text-[#888]">
        <TruncatedText text={thought} maxLines={20} />
      </div>
    </div>
  );
}
