import { useEffect, useState } from "react";
import { ChevronLeft, ChevronRight, Loader2 } from "lucide-react";
import { decideApproval, fetchApprovals, type ApprovalState } from "@/data/serverSource";

const control = "inline-flex min-h-11 items-center justify-center gap-2 rounded-md border border-white/20 px-3 text-sm hover:bg-white/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/60 disabled:opacity-50 sm:min-h-8";

export function ActionApprovals({ runName, enabled }: { runName: string | null; enabled: boolean }) {
  const [state, setState] = useState<ApprovalState>({ pending: [], can_decide: false });
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      try {
        const next = await fetchApprovals(runName);
        if (!cancelled) { setState(next); setLoadError(null); }
      } catch {
        if (!cancelled) setLoadError("Could not load action approvals. Retrying.");
      } finally {
        if (!cancelled) timer = setTimeout(poll, 2000);
      }
    }
    void poll();
    return () => { cancelled = true; clearTimeout(timer); };
  }, [runName, enabled]);

  const index = Math.max(0, state.pending.findIndex(row => row.approval_id === selectedId));
  const selected = state.pending[index];
  async function decide(approved: boolean) {
    if (!selected || busy) return;
    setBusy(true);
    setError(null);
    try {
      const result = await decideApproval(selected.approval_id, approved, runName);
      if (!result.ok) setError(result.status === 409 ? "This action is no longer waiting for approval." : "Could not save your decision. Try again.");
      setState(await fetchApprovals(runName));
    } catch {
      setError("Could not save your decision. Try again.");
    } finally {
      setBusy(false);
    }
  }
  if (!enabled || !state.can_decide || !selected) {
    return enabled && (error || loadError) ? <p role="alert" className="text-sm text-white/70">{error || loadError}</p> : null;
  }
  const deadline = new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit", timeZoneName: "short" }).format(new Date(selected.expires_at));
  return <section aria-label="Action approvals" className="max-w-[440px] overflow-hidden rounded-xl border border-white/20 bg-white/[0.03]">
    <div className="flex items-center justify-between gap-3 border-b border-white/10 px-4 py-2">
      <span className="text-sm" aria-live="polite">Action approvals · {index + 1} of {state.pending.length}</span>
      <div className="flex gap-2">
        <button type="button" className={control} aria-label="Previous action" disabled={busy || index === 0} onClick={() => setSelectedId(state.pending[index - 1].approval_id)}><ChevronLeft className="size-4" aria-hidden="true" /></button>
        <button type="button" className={control} aria-label="Next action" disabled={busy || index === state.pending.length - 1} onClick={() => setSelectedId(state.pending[index + 1].approval_id)}><ChevronRight className="size-4" aria-hidden="true" /></button>
      </div>
    </div>
    <div className="space-y-3 p-4">
      <h2 className="break-words text-base font-semibold">{selected.agent_name || selected.agent_id}</h2>
      {selected.reason && <p className="break-words text-sm text-white/70">{selected.reason}</p>}
      <pre tabIndex={0} aria-label="Proposed command" className="max-h-[calc(6lh+1.5rem+2px)] overflow-y-auto whitespace-pre-wrap rounded-md border border-white/10 bg-black p-3 font-mono text-xs leading-5 [overflow-wrap:anywhere] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/60"><code translate="no">{selected.summary}</code></pre>
      {(error || loadError) && <p role="alert" className="text-sm text-white/70">{error || loadError}</p>}
    </div>
    <div className="flex items-center justify-between gap-3 border-t border-white/10 p-4">
      <p className="text-xs text-white/70">{state.on_timeout === "allow" ? "Runs" : "Blocks"} at <time dateTime={selected.expires_at}>{deadline}</time> if no one answers</p>
      <div className="flex shrink-0 gap-2">
        <button type="button" className={control} disabled={busy} onClick={() => void decide(false)}>Deny</button>
        <button type="button" className={`${control} bg-white text-black hover:bg-white/90`} disabled={busy} onClick={() => void decide(true)}>{busy && <Loader2 className="size-4 motion-safe:animate-spin" aria-hidden="true" />}Approve</button>
      </div>
    </div>
  </section>;
}
