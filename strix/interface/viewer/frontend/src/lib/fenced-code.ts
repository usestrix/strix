export interface ParsedFencedCode {
  language?: string;
  code: string;
}

const FENCE_RE = /^```([^\n`]*)\r?\n([\s\S]*?)\r?\n?```$/;

/**
 * Agent-generated `poc_script_code` is stored wrapped in a markdown code fence
 * that carries the language, e.g.
 *
 *     ```python
 *     import requests
 *     ```
 *
 * Renderers that show the value as bare code must not display the fence lines
 * literally. This extracts the inner code and the fence's language tag. Returns
 * the input unchanged (no language) when it isn't fenced.
 */
export function parseFencedCode(raw: string | null | undefined): ParsedFencedCode {
  if (!raw) return { code: "" };
  const match = FENCE_RE.exec(raw.trim());
  if (!match) return { code: raw };
  const info = match[1].trim();
  const language = info ? info.split(/\s+/)[0] : undefined;
  return { language: language || undefined, code: match[2] };
}
