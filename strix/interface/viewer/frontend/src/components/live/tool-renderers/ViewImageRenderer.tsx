"use client";

import type { ToolRendererProps } from "@/types/events";
import { shortPath } from "./utils";

const IMAGE_DATA_URI_RE = /data:image\/(png|jpe?g|gif|webp);base64,([A-Za-z0-9+/]+={0,2})/;

function extractImageDataUri(res: unknown): string | null {
  let s: string | null = null;
  if (typeof res === "string") {
    s = res;
  } else if (res && typeof res === "object") {
    const o = res as Record<string, unknown>;
    if (typeof o.image_url === "string") s = o.image_url;
    else if (typeof o.url === "string") s = o.url;
  }
  if (!s) return null;
  const m = IMAGE_DATA_URI_RE.exec(s);
  if (!m || m[2].length < 100 || m[2].length % 4 !== 0) return null;
  return `data:image/${m[1]};base64,${m[2]}`;
}

/** Renders the view_image result as an inline image, like the strix-app
 *  renderer; falls back to the load-error text when there is no payload. */
export default function ViewImageRenderer({ args, result }: ToolRendererProps) {
  const path = ((args.path as string) ?? "").trim();

  const imgSrc = extractImageDataUri(result);
  let error: string | null = null;
  if (!imgSrc && typeof result === "string") {
    const trimmed = result.trim();
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
      {imgSrc && (
        <img
          src={imgSrc}
          alt={path || "Tool image output"}
          className="mt-1.5 max-w-full max-h-96 rounded-lg border border-white/[0.06] object-contain"
        />
      )}
      {error && <div className="text-red-400/70 text-[13px] mt-1">{error}</div>}
    </div>
  );
}
