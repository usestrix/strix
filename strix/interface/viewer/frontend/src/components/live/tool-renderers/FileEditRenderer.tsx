"use client";

import type { ToolRendererProps } from "@/types/events";
import { shortPath } from "./utils";

const DIFF_PREVIEW_LINES = 30;

export default function FileEditRenderer({ toolName, args }: ToolRendererProps) {
  const filePath = (args.path as string) ?? (args.file_path as string) ?? "";
  const command = (args.command as string) ?? "";
  const oldStr = (args.old_str as string) ?? "";
  const newStr = (args.new_str as string) ?? "";
  const regex = (args.regex as string) ?? "";

  let label: string;
  if (toolName === "list_files") label = "list";
  else if (toolName === "search_files") label = "search";
  else if (command === "view") label = "view";
  else if (command === "create") label = "create";
  else if (command === "str_replace") label = "edit";
  else if (command === "undo_edit") label = "undo";
  else if (command === "insert") label = "insert";
  else label = "file";

  const pathDisplay = filePath ? shortPath(filePath) : "";
  const regexDisplay = regex ? ` /${regex}/` : "";

  const oldLines = oldStr ? oldStr.split("\n") : [];
  const newLines = newStr ? newStr.split("\n") : [];
  const totalLines = oldLines.length + newLines.length;
  const truncated = totalLines > DIFF_PREVIEW_LINES;

  // If truncated, split the budget proportionally
  const oldBudget = truncated ? Math.round(DIFF_PREVIEW_LINES * (oldLines.length / totalLines)) : oldLines.length;
  const newBudget = truncated ? DIFF_PREVIEW_LINES - oldBudget : newLines.length;

  return (
    <div>
      <div className="flex items-baseline gap-2">
        <span className="text-sky-400/80 font-semibold text-sm shrink-0">{label}</span>
        {pathDisplay && <span className="text-[#888] font-mono text-[13px] break-all">{pathDisplay}</span>}
      </div>
      {regexDisplay && (
        <div className="text-purple-400/60 font-mono text-[13px] break-all mt-0.5">{regexDisplay}</div>
      )}
      {(oldStr || newStr) && (
        <div className="font-mono text-[13px] leading-relaxed mt-1.5">
          {oldLines.slice(0, oldBudget).map((line, i) => (
            <div key={`o${i}`} className="text-red-400/60">
              <span className="select-none text-red-400/30 mr-1">-</span>{line}
            </div>
          ))}
          {newLines.slice(0, newBudget).map((line, i) => (
            <div key={`n${i}`} className="text-emerald-400/60">
              <span className="select-none text-emerald-400/30 mr-1">+</span>{line}
            </div>
          ))}
          {truncated && (
            <div className="text-[#444] mt-0.5">... {totalLines - DIFF_PREVIEW_LINES} more lines</div>
          )}
        </div>
      )}
    </div>
  );
}
