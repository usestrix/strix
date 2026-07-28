"use client";

import { useState } from "react";
import Markdown from "./Markdown";
import hljs from "@/lib/hljs";
import "highlight.js/styles/github-dark.css";

const OUTPUT_PREVIEW_LINES = 6;
const CODE_PREVIEW_LINES = 20;

/** Truncatable markdown text with "Show more" */
export function TruncatedText({ text, maxLines = 20 }: { text: string; maxLines?: number }) {
  const [expanded, setExpanded] = useState(false);
  const lines = text.trimEnd().split("\n");
  const needsTruncation = lines.length > maxLines;

  return (
    <div>
      <div
        className={expanded && needsTruncation ? "max-h-[1200px] overflow-auto" : ""}
        style={!expanded && needsTruncation ? { display: "-webkit-box", WebkitLineClamp: maxLines, WebkitBoxOrient: "vertical", overflow: "hidden" } : undefined}
      >
        <Markdown text={text} />
      </div>
      {needsTruncation && (
        <button onClick={() => setExpanded(!expanded)} className="text-xs text-[#555] hover:text-[#888] mt-1">
          {expanded ? "Show less" : "Show more"}
        </button>
      )}
    </div>
  );
}

/** Code/output block — truncates to 12 lines with "Show more", expanded view scrolls */
export function CodeBlock({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  const [expanded, setExpanded] = useState(false);

  const isString = typeof children === "string";
  const lines = isString ? (children as string).trimEnd().split("\n") : null;
  const needsTruncation = lines !== null && lines.length > OUTPUT_PREVIEW_LINES;
  const displayContent = needsTruncation && !expanded
    ? lines!.slice(0, OUTPUT_PREVIEW_LINES).join("\n")
    : children;

  return (
    <div>
      <pre className={`font-mono text-[13px] leading-relaxed whitespace-pre-wrap break-words mt-1 ${
        expanded ? "overflow-auto max-h-[1200px]" : "overflow-hidden"
      } ${className}`}>
        {displayContent}
      </pre>
      {needsTruncation && (
        <button
          onClick={() => setExpanded(!expanded)}
          className="text-xs text-[#555] hover:text-[#888] mt-0.5"
        >
          {expanded ? "Show less" : "Show more"}
        </button>
      )}
    </div>
  );
}

/** Syntax-highlighted code block — no border, no line numbers, just highlighting.
 *  Pass `collapsible` to get a "Show more" toggle instead of a scroll cap. */
export function SyntaxBlock({ code, language, className = "", collapsible = false }: { code: string; language?: string; className?: string; collapsible?: boolean }) {
  const [expanded, setExpanded] = useState(false);

  const lines = code.trimEnd().split("\n");
  const needsTruncation = collapsible && lines.length > CODE_PREVIEW_LINES;
  const displayCode = needsTruncation && !expanded
    ? lines.slice(0, CODE_PREVIEW_LINES).join("\n")
    : code;

  let highlighted: string;
  try {
    highlighted = language
      ? hljs.highlight(displayCode, { language, ignoreIllegals: true }).value
      : hljs.highlightAuto(displayCode).value;
  } catch {
    highlighted = hljs.highlightAuto(displayCode).value;
  }

  return (
    <div>
      <pre className={`font-mono text-[12px] leading-relaxed px-0 py-1 mt-1 whitespace-pre-wrap break-all ${
        collapsible
          ? expanded ? "overflow-auto max-h-[1200px]" : "overflow-hidden"
          : "overflow-auto max-h-[400px]"
      } ${className}`}>
        <code dangerouslySetInnerHTML={{ __html: highlighted }} />
      </pre>
      {needsTruncation && (
        <button onClick={() => setExpanded(!expanded)} className="text-xs text-[#555] hover:text-[#888] mt-0.5">
          {expanded ? "Show less" : "Show more"}
        </button>
      )}
    </div>
  );
}
