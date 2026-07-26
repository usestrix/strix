"use client";

import type { ToolRendererProps } from "@/types/events";
import { shortPath } from "./utils";

/** Mirrors the OSS TUI `ViewImageRenderer`: surfaces load errors, otherwise a
 *  compact "view image <path>" line. */
export default function ViewImageRenderer({ args, result }: ToolRendererProps) {
  const path = ((args.path as string) ?? "").trim();

  const res = result as Record<string, unknown> | string | null;
  let error: string | null = null;
  if (typeof res === "string") {
    const trimmed = res.trim();
    // A string result that isn't an image payload or structured data is an error message
    if (trimmed && !trimmed.toLowerCase().startsWith("data:image/") && !trimmed.startsWith("{")) {
      error = trimmed;
    }
  }

  return (
    <div>
      <div className="flex items-baseline gap-2">
        <span className="text-sky-400/80 font-semibold text-sm shrink-0">view image</span>
        {path && <span className="text-[#888] font-mono text-[13px] break-all">{shortPath(path)}</span>}
      </div>
      {error && <div className="text-red-400/70 text-[13px] mt-1">{error}</div>}
    </div>
  );
}
