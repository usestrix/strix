"use client";

import type { ToolRendererProps } from "@/types/events";
import Markdown from "./Markdown";

export default function NotesRenderer({ toolName, args, result }: ToolRendererProps) {
  if (toolName === "create_note") {
    const title = (args.title as string) ?? "";
    const content = (args.content as string) ?? "";
    const category = (args.category as string) ?? "general";
    return (
      <div>
        <div className="flex items-center gap-2">
          <span className="text-amber-400/80 font-semibold text-sm">note</span>
          <span className="text-[#555] text-[13px]">({category})</span>
        </div>
        {title && <div className="mt-1.5 text-[#999] text-[13px]">{title}</div>}
        {content && <div className="mt-1"><Markdown text={content} /></div>}
      </div>
    );
  }

  if (toolName === "delete_note") {
    return <span className="text-amber-400/80 font-semibold text-sm">note removed</span>;
  }

  if (toolName === "update_note") {
    const title = (args.title as string) ?? "";
    const content = (args.content as string) ?? "";
    return (
      <div>
        <span className="text-amber-400/80 font-semibold text-sm">note updated</span>
        {title && <div className="mt-1.5 text-[#999] text-[13px]">{title}</div>}
        {content && <div className="mt-1"><Markdown text={content} /></div>}
      </div>
    );
  }

  if (toolName === "get_note") {
    const res = result as Record<string, unknown> | null;
    const note = res && typeof res === "object" && res.success
      ? (res.note as Record<string, string> | undefined)
      : undefined;
    return (
      <div>
        <span className="text-amber-400/80 font-semibold text-sm">note read</span>
        {note && (
          <>
            <div className="mt-1.5 text-[#999] text-[13px]">
              {note.title ?? "(untitled)"}
              <span className="text-[#555] ml-1">({note.category ?? "general"})</span>
            </div>
            {note.content && <div className="mt-1"><Markdown text={note.content} /></div>}
          </>
        )}
      </div>
    );
  }

  if (toolName === "list_notes") {
    const res = result as Record<string, unknown> | null;
    let notes: Array<Record<string, string>> = [];
    if (res && typeof res === "object" && res.success) {
      const rawNotes = res.notes;
      notes = Array.isArray(rawNotes) ? rawNotes as Array<Record<string, string>> : [];
    }
    return (
      <div>
        <span className="text-amber-400/80 font-semibold text-sm">notes</span>
        {notes.length > 0 ? (
          <div className="mt-1.5 space-y-0.5">
            {notes.map((n, i) => (
              <div key={i} className="text-[13px]">
                <span className="text-[#555] mr-1">-</span>
                <span className="text-[#999]">{n.title ?? "(untitled)"}</span>
                <span className="text-[#555] ml-1">({n.category ?? "general"})</span>
                {n.content && <div className="ml-3"><Markdown text={n.content} /></div>}
              </div>
            ))}
          </div>
        ) : <div className="mt-1 text-[#555] text-xs">No notes</div>}
      </div>
    );
  }

  return <span className="text-amber-400/80 font-semibold text-sm">note</span>;
}
