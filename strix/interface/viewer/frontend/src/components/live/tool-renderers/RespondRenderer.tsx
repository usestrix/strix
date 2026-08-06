"use client";

import type { ToolRendererProps } from "@/types/events";
import Markdown from "./Markdown";

/**
 * `respond_to_user` carries the message the user is meant to read, so it renders
 * as the agent's own prose rather than as a tool call.
 */
export default function RespondRenderer({ args }: ToolRendererProps) {
  const message = (args.message as string) ?? "";
  if (!message) return null;

  return (
    <div>
      <Markdown text={message} />
      <div className="mt-1.5 text-[#888] text-[13px]">waiting for your reply</div>
    </div>
  );
}
