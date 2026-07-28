"use client";

import type { ToolRendererProps } from "@/types/events";
import { shortPath } from "./utils";

const DIFF_PREVIEW_LINES = 30;

const BEGIN_PATCH = "*** Begin Patch";
const END_PATCH = "*** End Patch";
const ADD_FILE = "*** Add File: ";
const UPDATE_FILE = "*** Update File: ";
const DELETE_FILE = "*** Delete File: ";

const OP_LABEL: Record<string, string> = { add: "create", update: "edit", delete: "delete" };

interface PatchOp {
  kind: "add" | "update" | "delete";
  path: string;
  oldLines: string[];
  newLines: string[];
}

/** apply_patch args arrive as {patch: text} (chat-completions FunctionTool) or
 *  {input: text} (CustomTool). Mirrors the OSS `_extract_patch_text`. */
function extractPatchText(args: Record<string, unknown>): string {
  const raw = args.patch;
  if (typeof raw === "string") return raw;
  if (raw && typeof raw === "object" && typeof (raw as Record<string, unknown>).patch === "string") {
    return (raw as Record<string, string>).patch;
  }
  return typeof args.input === "string" ? args.input : "";
}

/** Parse V4A patch text into per-file operations (mirrors `_parse_patch_operations`). */
function parsePatchOperations(patchText: string): PatchOp[] {
  const ops: PatchOp[] = [];
  let current: PatchOp | null = null;

  const flush = () => {
    if (current) ops.push(current);
    current = null;
  };

  for (const line of patchText.split("\n")) {
    if (line === BEGIN_PATCH || line === END_PATCH) continue;
    if (line.startsWith(ADD_FILE)) {
      flush();
      current = { kind: "add", path: line.slice(ADD_FILE.length).trim(), oldLines: [], newLines: [] };
    } else if (line.startsWith(UPDATE_FILE)) {
      flush();
      current = { kind: "update", path: line.slice(UPDATE_FILE.length).trim(), oldLines: [], newLines: [] };
    } else if (line.startsWith(DELETE_FILE)) {
      flush();
      current = { kind: "delete", path: line.slice(DELETE_FILE.length).trim(), oldLines: [], newLines: [] };
    } else if (current?.kind === "update") {
      if (line.startsWith("@@")) continue;
      if (line.startsWith("-") && !line.startsWith("---")) current.oldLines.push(line.slice(1));
      else if (line.startsWith("+") && !line.startsWith("+++")) current.newLines.push(line.slice(1));
    } else if (current?.kind === "add") {
      if (line.startsWith("+")) current.newLines.push(line.slice(1));
      else if (line.trim()) current.newLines.push(line);
    }
  }
  flush();
  return ops;
}

function Operation({ op }: { op: PatchOp }) {
  const label = OP_LABEL[op.kind] ?? "file";
  const total = op.oldLines.length + op.newLines.length;
  const truncated = total > DIFF_PREVIEW_LINES;
  const oldBudget = truncated && total > 0 ? Math.round(DIFF_PREVIEW_LINES * (op.oldLines.length / total)) : op.oldLines.length;
  const newBudget = truncated ? DIFF_PREVIEW_LINES - oldBudget : op.newLines.length;

  return (
    <div>
      <div className="flex items-baseline gap-2">
        <span className="text-sky-400/80 font-semibold text-sm shrink-0">{label}</span>
        {op.path && <span className="text-[#888] font-mono text-[13px] break-all">{shortPath(op.path)}</span>}
      </div>
      {(op.oldLines.length > 0 || op.newLines.length > 0) && (
        <div className="font-mono text-[13px] leading-relaxed mt-1.5">
          {op.oldLines.slice(0, oldBudget).map((line, i) => (
            <div key={`o${i}`} className="text-red-400/60">
              <span className="select-none text-red-400/30 mr-1">-</span>{line}
            </div>
          ))}
          {op.newLines.slice(0, newBudget).map((line, i) => (
            <div key={`n${i}`} className="text-emerald-400/60">
              <span className="select-none text-emerald-400/30 mr-1">+</span>{line}
            </div>
          ))}
          {truncated && <div className="text-[#444] mt-0.5">... {total - DIFF_PREVIEW_LINES} more lines</div>}
        </div>
      )}
    </div>
  );
}

export default function ApplyPatchRenderer({ args, result, status }: ToolRendererProps) {
  const ops = parsePatchOperations(extractPatchText(args));

  if (ops.length === 0) {
    return (
      <div>
        <span className="text-sky-400/80 font-semibold text-sm">patch</span>
        {status === "failed" && typeof result === "string" && result.trim() && (
          <div className="text-red-400/70 text-[13px] mt-1">{result.trim()}</div>
        )}
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {ops.map((op, i) => (
        <Operation key={i} op={op} />
      ))}
      {status === "failed" && typeof result === "string" && result.trim() && (
        <div className="text-red-400/70 text-[13px]">{result.trim()}</div>
      )}
    </div>
  );
}
