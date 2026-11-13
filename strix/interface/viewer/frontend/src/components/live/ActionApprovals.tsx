import { createContext, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { ChevronLeft, ChevronRight, Loader2, Pause, X } from "lucide-react";
import { decideApproval, fetchApprovals, type ApprovalState, type PendingApproval, type Transcript } from "@/data/serverSource";
import { buildGraphAgents } from "./AgentTranscript";

const control = "inline-flex min-h-11 items-center justify-center gap-2 rounded-md border border-white/20 px-3 text-sm hover:bg-white/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/60 disabled:opacity-50 touch-manipulation sm:min-h-8";
const iconControl = "inline-flex size-11 items-center justify-center rounded-md hover:bg-white/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/60 disabled:opacity-50 touch-manipulation sm:size-8";
const PendingActions = createContext<PendingApproval[]>([]);
const BannerActions = createContext<{ open: (trigger: HTMLButtonElement) => void; retry: () => Promise<void>; error: string | null } | null>(null);

export function AgentApprovalStatus({ agentId }: { agentId: string }) {
  const pending = useContext(PendingActions);
  return pending.some(row => row.agent_id === agentId) ? <span className="mt-2 inline-flex items-center gap-2 text-xs text-white/70"><Pause className="size-3" aria-hidden="true" />Waiting for approval</span> : null;
}

export function ActionApprovalsProvider({ runName, enabled, transcript, children }: { runName: string | null; enabled: boolean; transcript?: Transcript; children: ReactNode }) {
  const [state, setState] = useState<ApprovalState>({ pending: [], can_decide: false });
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [opened, setOpened] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const dialog = useRef<HTMLDialogElement>(null);
  const agents = useMemo(() => buildGraphAgents(transcript?.agents ?? [], transcript?.events ?? []), [transcript]);
  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      try {
        const next = await fetchApprovals(runName);
        if (!cancelled) { setState(next); setLoadError(null); }
      } catch {
        if (!cancelled) setLoadError("Could not load action approvals. Try again.");
      } finally {
        if (!cancelled) timer = setTimeout(poll, 2000);
      }
    }
    void poll();
    return () => { cancelled = true; clearTimeout(timer); };
  }, [runName, enabled]);

  const pending = enabled && state.can_decide ? state.pending : [];
  const index = Math.max(0, pending.findIndex(row => row.approval_id === selectedId));
  const selected = pending[index];
  const agent = selected ? agents.get(selected.agent_id) : undefined;
  const task = agent?.parentId ? agent.task.replace(/\s+/g, " ").trim() : "";
  const visible = opened && !!selected;
  useEffect(() => { if (!pending.length) setOpened(false); }, [pending.length]);
  useEffect(() => {
    const element = dialog.current;
    if (!visible || !element) return;
    const previous = document.activeElement;
    const overflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    element.showModal();
    return () => {
      element.close();
      document.body.style.overflow = overflow;
      if (previous instanceof HTMLElement && previous.isConnected) previous.focus();
    };
  }, [visible]);

  async function decide(approved: boolean) {
    if (!selected || busy) return;
    setBusy(true);
    setError(null);
    try {
      const result = await decideApproval(selected.approval_id, approved, runName);
      if (!result.ok) setError(result.status === 409 ? "This action is no longer waiting for approval." : "Could not decide this action. Try again.");
      setState(await fetchApprovals(runName));
    } catch {
      setError("Could not send your decision. Try again.");
    } finally {
      setBusy(false);
    }
  }
  const deadline = selected ? new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit", timeZoneName: "short" }).format(new Date(selected.expires_at)) : "";
  async function retry() {
    setError(null);
    try { setState(await fetchApprovals(runName)); setLoadError(null); }
    catch { setLoadError("Could not load action approvals. Try again."); }
  }
  return <PendingActions.Provider value={pending}>
    <BannerActions.Provider value={{ open: trigger => { trigger.focus(); setError(null); setSelectedId(null); setOpened(true); }, retry, error: error || loadError }}>{children}</BannerActions.Provider>
    <dialog ref={dialog} aria-labelledby="approval-title" aria-describedby="approval-detail" onKeyDown={event => {
      if (event.key !== "Tab") return;
      const controls = Array.from(event.currentTarget.querySelectorAll<HTMLElement>('button:not(:disabled), [tabindex="0"]'));
      const first = controls[0], last = controls[controls.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault(); last?.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault(); first?.focus();
      }
    }} onCancel={() => setOpened(false)} onClose={() => setOpened(false)} onClick={event => {
      if (event.target !== event.currentTarget) return;
      const bounds = event.currentTarget.getBoundingClientRect();
      if (event.clientX < bounds.left || event.clientX > bounds.right || event.clientY < bounds.top || event.clientY > bounds.bottom) setOpened(false);
    }} className="fixed inset-0 m-auto max-h-[90dvh] w-[calc(100vw-2rem)] max-w-[440px] flex-col overflow-hidden rounded-xl border border-white/20 bg-neutral-950 p-0 text-white shadow-lg open:flex backdrop:bg-black/80">
      <h1 id="approval-title" className="sr-only">Action approvals</h1>
      <div className="relative flex shrink-0 items-center justify-between border-b border-white/10 py-2 pl-4 pr-12">
        <span className="text-sm tabular-nums text-white/70" aria-live="polite">{index + 1} of {pending.length}</span>
        <div className="flex gap-1">
          <button type="button" className={iconControl} aria-label="Previous action" disabled={busy || index === 0} onClick={() => setSelectedId(pending[index - 1].approval_id)}><ChevronLeft className="size-4" aria-hidden="true" /></button>
          <button type="button" className={iconControl} aria-label="Next action" disabled={busy || index >= pending.length - 1} onClick={() => setSelectedId(pending[index + 1].approval_id)}><ChevronRight className="size-4" aria-hidden="true" /></button>
        </div>
        <button type="button" className={`${iconControl} absolute right-1 top-2`} aria-label="Close" onClick={() => setOpened(false)}><X className="size-4" aria-hidden="true" /></button>
      </div>
      {selected && <div className="flex min-h-0 flex-col">
        <div className="min-h-0 space-y-3 overflow-y-auto overscroll-contain p-4">
          <div><h2 className="break-words text-base font-semibold">{selected.agent_name || agent?.name || "Agent"}</h2>
            <p id="approval-detail" className={task ? "mt-1 line-clamp-2 break-words text-sm text-white/70" : "sr-only"}>{task || "Waiting for your decision before this action runs."}</p></div>
          {selected.reason && <p className="break-words text-sm leading-normal">{selected.reason}</p>}
          <pre tabIndex={0} aria-label="Proposed command" className="max-h-[calc(6lh+1.5rem+2px)] overflow-y-auto whitespace-pre-wrap break-words rounded-md border border-white/10 bg-white/5 p-3 font-mono text-xs leading-5 [overflow-wrap:anywhere] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/60"><code translate="no">{selected.summary}</code></pre>
          {(error || loadError) && <p role="alert" className="text-sm text-white/70">{error || loadError}</p>}
        </div>
        <div className="flex shrink-0 items-center justify-between gap-3 border-t border-white/10 p-4">
          <p className="min-w-0 text-xs text-white/70">{state.on_timeout === "allow" ? "Runs" : "Blocks"} at <time dateTime={selected.expires_at}>{deadline}</time> if no one answers</p>
          <div className="ml-auto flex shrink-0 gap-2">
            <button type="button" className={control} disabled={busy} onClick={() => void decide(false)}>Deny</button>
            <button type="button" className={`${control} bg-white text-black hover:bg-white/90`} disabled={busy} onClick={() => void decide(true)}>{busy && <Loader2 className="size-4 motion-safe:animate-spin" aria-hidden="true" />}Approve</button>
          </div>
        </div>
      </div>}
    </dialog>
  </PendingActions.Provider>;
}

export function ActionApprovalBanner() {
  const pending = useContext(PendingActions);
  const actions = useContext(BannerActions);
  return <>
    {actions?.error && <div role="alert" className="flex items-center justify-between gap-4 rounded-lg border border-white/20 p-4 text-sm"><span>{actions.error}</span><button type="button" className={control} onClick={() => void actions.retry()}>Retry</button></div>}
    {pending.length > 0 && <div role="status" className="flex items-center justify-between gap-4 rounded-lg border border-white/20 bg-white/[0.03] p-4">
      <span className="text-sm font-medium">{pending.length} {pending.length === 1 ? "action needs" : "actions need"} approval</span><button type="button" className={control} onClick={event => actions?.open(event.currentTarget)}>Review</button>
    </div>}
  </>;
}
