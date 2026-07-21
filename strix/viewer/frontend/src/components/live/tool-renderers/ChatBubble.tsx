"use client";

import { TruncatedText } from "./ToolCard";

interface ChatBubbleProps {
  role: string;
  content: string;
}

const MAX_LINES = 30;

export default function ChatBubble({ role, content }: ChatBubbleProps) {
  const isUser = role === "user" || role === "human";

  return (
    <div>
      <span className={`font-semibold text-sm ${isUser ? "text-blue-400/80" : "text-purple-400/80"}`}>
        {isUser ? "User" : "Thinking"}
      </span>
      <div className="mt-1.5 italic text-[#888]">
        <TruncatedText text={content} maxLines={MAX_LINES} />
      </div>
    </div>
  );
}
