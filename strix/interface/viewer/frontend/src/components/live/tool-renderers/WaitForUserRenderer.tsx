"use client";

import type { ToolRendererProps } from "@/types/events";
import Markdown from "./Markdown";

/**
 * `wait_for_user` hands the turn to the user and carries no text: whatever the
 * agent had to say was already shown as its own prose. Recorded runs still hold
 * `respond_to_user` calls, whose `message` argument was the reply itself.
 */
export default function WaitForUserRenderer({ args }: ToolRendererProps) {
  const message = typeof args.message === "string" ? args.message : "";

  return (
    <div>
      {message && <Markdown text={message} />}
      <div className={message ? "mt-1.5 text-[#888] text-[13px]" : "text-[#888] text-[13px]"}>
        waiting for your reply
      </div>
    </div>
  );
}
