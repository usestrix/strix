"use client";

import type { ToolRendererProps } from "@/types/events";
import { SyntaxBlock } from "./ToolCard";

const SIMPLE_ACTIONS: Record<string, string> = {
  back: "going back in browser history",
  forward: "going forward in browser history",
  scroll_down: "scrolling down",
  scroll_up: "scrolling up",
  refresh: "refreshing",
  close_tab: "closing tab",
  switch_tab: "switching tab",
  list_tabs: "listing tabs",
  view_source: "viewing page source",
  get_console_logs: "getting console logs",
  screenshot: "taking screenshot",
  wait: "waiting...",
  close: "closing",
};

const CLICK_ACTIONS: Record<string, string> = {
  click: "clicking",
  double_click: "double clicking",
  hover: "hovering",
};

function UrlLabel({ prefix, url, suffix }: { prefix: string; url?: string; suffix?: string }) {
  return (
    <span className="text-[#888] text-[13px]">
      {prefix}
      {url && (
        <a
          href={url}
          target="_blank"
          rel="noopener noreferrer"
          className="text-cyan-400/80 hover:underline"
        >
          {url}
        </a>
      )}
      {suffix}
    </span>
  );
}

function describeAction(args: Record<string, unknown>): React.ReactNode {
  const action = (args.action as string) ?? "";
  const url = (args.url as string) ?? undefined;

  // Simple actions (no extra args)
  if (action in SIMPLE_ACTIONS) return SIMPLE_ACTIONS[action];

  // URL actions: launch, goto, new_tab
  if (action === "launch") {
    if (!url) return "launching";
    return <UrlLabel prefix="launching " url={url} />;
  }
  if (action === "goto" || action === "navigate") {
    return <UrlLabel prefix="navigating to " url={url} />;
  }
  if (action === "new_tab") {
    return <UrlLabel prefix="opening tab " url={url} />;
  }

  // Click actions
  if (action in CLICK_ACTIONS) return CLICK_ACTIONS[action];

  // Type
  if (action === "type") {
    const text = ((args.text as string) ?? "").slice(0, 40);
    return `typing "${text}"`;
  }

  // Key press
  if (action === "press_key" || action === "key_press") {
    return `pressing key ${(args.key as string) ?? ""}`;
  }

  // Save PDF
  if (action === "save_pdf" || action === "save_as_pdf") {
    const path = (args.file_path as string) ?? "";
    return `saving PDF${path ? ` to ${path}` : ""}`;
  }

  // Execute JS — description only, code shown separately
  if (action === "execute_js") return "executing javascript";

  return action || "browser action";
}

export default function BrowserRenderer({ args }: ToolRendererProps) {
  const action = (args.action as string) ?? "";
  const jsCode = action === "execute_js"
    ? ((args.js_code as string) ?? (args.code as string) ?? "")
    : "";
  const description = describeAction(args);

  return (
    <div>
      <div className="flex items-center gap-2 min-w-0">
        <span className="text-blue-400/80 font-semibold text-sm shrink-0">Browser</span>
        <span className="min-w-0 truncate text-[#888] text-[13px]">
          {typeof description === "string" ? description : description}
        </span>
      </div>
      {jsCode && <SyntaxBlock code={jsCode} language="javascript" collapsible />}
    </div>
  );
}
