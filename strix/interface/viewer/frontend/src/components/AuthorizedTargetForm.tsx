import { useState } from "react";
import { Link2, ShieldAlert } from "lucide-react";
import { postAuthorizedScan, type AuthorizedScanResponse } from "@/data/serverSource";

/**
 * Visible URL entry for Attack Path / thesis demo.
 * Hard gate: authorization checkbox must be checked before any queue/demo action.
 */
export default function AuthorizedTargetForm() {
  const [url, setUrl] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<AuthorizedScanResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function submit(action: "queue_scan" | "demo_fixture") {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const payload = await postAuthorizedScan({
        url,
        authorized,
        action,
        scan_mode: "quick",
      });
      setResult(payload);
      if (!payload.ok) {
        setError(payload.message || payload.error || "Request refused.");
      }
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Request failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="rounded-lg border border-[rgba(255,255,255,0.1)] bg-[#121212] p-4">
      <div className="mb-2 flex items-center gap-2 text-sm font-medium text-[#ededed]">
        <Link2 className="h-4 w-4 text-emerald-400" />
        Authorized target URL
      </div>
      <p className="mb-3 text-[11px] leading-relaxed text-[#999]">
        Paste a target URL here to queue a Strix scan or stage a SYNTHETIC Attack Path demo.
        Attack-path graphs stay <span className="text-[#ccc]">MODELED</span> (not confirmed
        multi-hop exploits). Simulated lateral remains off by default.
      </p>

      <div className="mb-3 flex gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-[11px] text-amber-100/95">
        <ShieldAlert className="mt-0.5 h-3.5 w-3.5 flex-none" />
        <span>
          Only scan systems you own or have explicit written permission to test. Unauthorized
          scanning may be illegal. The Start buttons stay disabled until you confirm below.
        </span>
      </div>

      <label className="mb-1 block text-[11px] text-[#888]" htmlFor="authorized-target-url">
        Target URL
      </label>
      <input
        id="authorized-target-url"
        type="url"
        inputMode="url"
        placeholder="https://your-authorized-lab.example"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        className="mb-3 w-full rounded border border-[rgba(255,255,255,0.12)] bg-[#0d0d0d] px-3 py-2 font-mono text-sm text-[#eee] outline-none focus:border-emerald-500/50"
        autoComplete="off"
        spellCheck={false}
      />

      <label className="mb-3 flex cursor-pointer items-start gap-2 text-[11px] text-[#ccc]">
        <input
          type="checkbox"
          className="mt-0.5 accent-emerald-500"
          checked={authorized}
          onChange={(e) => setAuthorized(e.target.checked)}
        />
        <span>
          I confirm I own this system or have written authorization to test it. Do not start a
          scan without this confirmation.
        </span>
      </label>

      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          disabled={busy || !authorized || !url.trim()}
          onClick={() => void submit("queue_scan")}
          className="rounded border border-emerald-500/40 bg-emerald-500/15 px-3 py-1.5 text-xs font-medium text-emerald-200 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {busy ? "Working…" : "Queue authorized Strix scan"}
        </button>
        <button
          type="button"
          disabled={busy || !authorized || !url.trim()}
          onClick={() => void submit("demo_fixture")}
          className="rounded border border-sky-500/40 bg-sky-500/10 px-3 py-1.5 text-xs font-medium text-sky-200 disabled:cursor-not-allowed disabled:opacity-40"
        >
          Stage MODELED Attack Path demo
        </button>
      </div>

      {error && (
        <p className="mt-3 rounded border border-red-500/30 bg-red-500/10 px-3 py-2 text-[11px] text-red-200">
          {error}
        </p>
      )}

      {result?.ok && (
        <div className="mt-3 space-y-1 rounded border border-emerald-500/20 bg-emerald-500/5 px-3 py-2 text-[11px] text-[#bbb]">
          <p className="text-emerald-200">{result.message}</p>
          {result.run_name && (
            <p>
              Run: <span className="font-mono text-[#ddd]">{result.run_name}</span>
              {" — "}
              open with{" "}
              <code className="text-[#ddd]">uv run strix view {result.run_name}</code> then the
              Attack path tab.
            </p>
          )}
          {result.command && (
            <p className="font-mono text-[10px] text-[#888]">
              {(result.command as string[]).join(" ")}
            </p>
          )}
          {result.skipped_reason && (
            <p className="text-amber-200/90">Note: {result.skipped_reason}</p>
          )}
          {Array.isArray(result.next_steps) && (
            <ul className="list-disc space-y-0.5 pl-4 text-[#999]">
              {result.next_steps.map((step) => (
                <li key={step}>{step}</li>
              ))}
            </ul>
          )}
        </div>
      )}
    </section>
  );
}
