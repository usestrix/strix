import { useCallback, useEffect, useRef } from "react";
import { X } from "lucide-react";
import { AgentTranscript } from "./AgentTranscript";
import { ScanPromptComposer } from "./ScanPromptComposer";
import type { TranscriptAgent, TranscriptEvent } from "@/data/serverSource";

/** Status -> the small leading dot color, matching the graph node styling. */
const STATUS_DOT: Record<string, string> = {
  completed: "bg-emerald-400",
  running: "bg-blue-400",
  waiting: "bg-yellow-400",
  stopped: "bg-[#888]",
  crashed: "bg-red-400",
  failed: "bg-red-400",
};

/** Consider the user "at the bottom" within this many px. */
const NEAR_BOTTOM_PX = 80;

/**
 * Overlay modal showing a single agent's full transcript. Matches the cloud
 * app: a fixed-size panel with a pinned header (status dot + agent name), the
 * transcript scrolling beneath it, and a footer. Auto-scrolls to follow new
 * activity while the user is near the bottom (so a live run trails). Closes on
 * backdrop click, the X button, or Escape.
 */
export function AgentDetailModal({
  agent,
  events,
  steerable,
  onClose,
}: {
  agent: TranscriptAgent;
  events: TranscriptEvent[];
  steerable: boolean;
  onClose: () => void;
}) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const nearBottom = useRef(false);

  const handleScroll = useCallback(() => {
    const el = scrollRef.current;
    if (!el) return;
    nearBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < NEAR_BOTTOM_PX;
  }, []);

  // Follow new activity when the user is near the bottom (live trailing).
  useEffect(() => {
    const el = scrollRef.current;
    if (!el || !nearBottom.current) return;
    requestAnimationFrame(() => {
      el.scrollTo({ top: el.scrollHeight, behavior: "smooth" });
    });
  }, [events]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = prevOverflow;
    };
  }, [onClose]);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 sm:p-8"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-label={`Agent ${agent.name}`}
    >
      <div
        className="relative flex h-[80vh] w-full max-w-5xl flex-col rounded-xl border border-[#222] bg-[#0a0a0a] shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between gap-3 border-b border-[#222] px-5 py-3.5">
          <div className="flex min-w-0 items-center gap-2">
            <span
              className={`h-2 w-2 flex-shrink-0 rounded-full ${STATUS_DOT[agent.status] ?? "bg-[#888]"}`}
            />
            <span className="truncate text-sm font-semibold text-white">{agent.name}</span>
            <span className="flex-shrink-0 font-mono text-xs text-[#555]">{agent.id}</span>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="flex-shrink-0 rounded-md p-1 text-[#888] transition-colors hover:bg-[#1a1a1a] hover:text-white"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div ref={scrollRef} onScroll={handleScroll} className="flex-1 overflow-y-auto p-5">
          <AgentTranscript agent={agent} events={events} showHeader={false} />
        </div>

        {steerable && (
          <div className="border-t border-[#222] px-5 py-3">
            <ScanPromptComposer
              agents={[agent]}
              fixedAgentId={agent.id}
              className="mt-0"
            />
          </div>
        )}
      </div>
    </div>
  );
}

export default AgentDetailModal;
