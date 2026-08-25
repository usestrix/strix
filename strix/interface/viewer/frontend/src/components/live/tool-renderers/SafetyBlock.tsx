import type { ToolRendererProps } from "../../../types/events";

/**
 * The safety verdict for a tool call the safety runtime refused.
 *
 * Every renderer that shows a result must render this: without it a blocked call is
 * indistinguishable from one that ran. The envelope's `error` is a fixed string, so the
 * reason has to come from `safety.reason`.
 */
export default function SafetyBlock({ status, result }: Pick<ToolRendererProps, "status" | "result">) {
  if (status !== "blocked") return null;

  const envelope = result as Record<string, unknown> | null;
  const safety =
    envelope && typeof envelope === "object" ? (envelope.safety as Record<string, unknown> | undefined) : undefined;
  const reason =
    safety && typeof safety.reason === "string" && safety.reason.trim()
      ? safety.reason.trim()
      : "Action blocked by safety policy";

  return (
    <div className="flex items-start gap-1.5 text-amber-400/80 text-[13px] mt-1">
      <span className="shrink-0">■</span>
      <span>{reason}</span>
    </div>
  );
}
