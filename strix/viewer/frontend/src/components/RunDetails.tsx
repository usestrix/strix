import { useState } from "react";
import { ChevronDown, ChevronUp, Info } from "lucide-react";
import { formatNumber } from "@/lib/display-number";

/**
 * "Run details" card for the Overview tab: the launch configuration the run was
 * started with (targets, instruction, scope, mode) and its LLM usage + cost.
 * Everything is read defensively from the raw run.json record, which may be
 * partial while a scan is still live.
 */

type Rec = Record<string, unknown>;

function rec(v: unknown): Rec {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Rec) : {};
}
function arr(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}
function str(v: unknown): string | null {
  return typeof v === "string" && v.trim() ? v : null;
}
function num(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}
function humanize(s: string): string {
  return s.replace(/_/g, " ");
}
function cap(s: string | null): string | null {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
}
function fmtDuration(seconds: number | null): string {
  if (seconds == null || seconds < 0) return "n/a";
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h) return `${h}h ${m}m ${s}s`;
  if (m) return `${m}m ${s}s`;
  return `${s}s`;
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[7rem_1fr] gap-3 items-baseline">
      <dt className="text-[11px] uppercase tracking-wide text-[#666]">{label}</dt>
      <dd className="min-w-0 break-words text-sm text-[#ddd]">{children}</dd>
    </div>
  );
}

export function RunDetails({
  raw,
  durationSeconds,
}: {
  raw: Rec;
  durationSeconds: number | null;
}) {
  const [open, setOpen] = useState(true);

  // Configuration (launch inputs)
  const targets = arr(raw.targets_info).map((t) => {
    const o = rec(t);
    const display = str(o.original) ?? str(rec(o.details).target_url) ?? "unknown target";
    const type = str(o.type);
    return { display, type: type ? humanize(type) : null };
  });
  const instruction = str(raw.instruction);
  const scanMode = cap(str(raw.scan_mode));
  const scopeMode = str(raw.scope_mode);
  const diff = rec(raw.diff_scope);
  const diffActive = diff.active === true;
  const diffMode = str(diff.mode);
  const diffBase = str(raw.diff_base);
  const nonInteractive = raw.non_interactive === true;
  const localSources = arr(raw.local_sources)
    .map((x) => {
      if (typeof x === "string") return x;
      const o = rec(x);
      return str(o.source_path) ?? str(o.target_path) ?? "";
    })
    .filter(Boolean);
  const status = cap(str(raw.status));

  let scope = scopeMode ?? "auto";
  if (diffActive) {
    scope += ` (diff${diffMode ? `: ${diffMode}` : ""}${diffBase ? ` vs ${diffBase}` : ""})`;
  }

  // Usage & cost
  const usage = rec(raw.llm_usage);
  const hasUsage = Object.keys(usage).length > 0;
  const agents = arr(usage.agents).map(rec);
  const models = Array.from(
    new Set(agents.map((a) => str(a.model)).filter((m): m is string => !!m))
  );
  const requests = num(usage.requests);
  const inputTokens = num(usage.input_tokens);
  const cached = num(rec(arr(usage.input_tokens_details)[0]).cached_tokens);
  const outputTokens = num(usage.output_tokens);
  const reasoning = num(rec(arr(usage.output_tokens_details)[0]).reasoning_tokens);
  const totalTokens = num(usage.total_tokens);
  const cost = num(usage.cost);

  const sub = (n: number, word: string) => (
    <span className="text-[#666]"> ({formatNumber(n)} {word})</span>
  );

  return (
    <div className="rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-5">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="flex w-full cursor-pointer items-center gap-2 text-left"
      >
        <Info className="h-4 w-4 text-[#888]" aria-hidden="true" />
        <h2 className="text-sm font-semibold text-white">Run details</h2>
        {open ? (
          <ChevronUp className="ml-auto h-4 w-4 text-[#666]" aria-hidden="true" />
        ) : (
          <ChevronDown className="ml-auto h-4 w-4 text-[#666]" aria-hidden="true" />
        )}
      </button>

      {open && (
      <div className="mt-4 grid grid-cols-1 gap-x-8 gap-y-6 md:grid-cols-2">
        <section>
          <h3 className="mb-3 text-[11px] font-semibold uppercase tracking-wide text-[#555]">
            Configuration
          </h3>
          <dl className="space-y-2.5">
            {targets.length > 0 && (
              <Field label="Targets">
                <div className="space-y-1">
                  {targets.map((t, i) => (
                    <div key={i} className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-[#ddd]">{t.display}</span>
                      {t.type && (
                        <span className="rounded-full border border-[#2a2a2a] px-1.5 py-0.5 text-[10px] text-[#888]">
                          {t.type}
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              </Field>
            )}
            <Field label="Instruction">
              {instruction ? (
                <span className="whitespace-pre-wrap">{instruction}</span>
              ) : (
                <span className="text-[#666]">None</span>
              )}
            </Field>
            {scanMode && <Field label="Scan mode">{scanMode}</Field>}
            <Field label="Scope">{scope}</Field>
            <Field label="Mode">{nonInteractive ? "Non-interactive" : "Interactive"}</Field>
            {localSources.length > 0 && (
              <Field label="Local sources">
                <div className="space-y-0.5 font-mono text-[#ddd]">
                  {localSources.map((s, i) => (
                    <div key={i}>{s}</div>
                  ))}
                </div>
              </Field>
            )}
            {status && <Field label="Status">{status}</Field>}
          </dl>
        </section>

        <section>
          <h3 className="mb-3 text-[11px] font-semibold uppercase tracking-wide text-[#555]">
            Usage &amp; cost
          </h3>
          {hasUsage ? (
            <dl className="space-y-2.5 tabular-nums">
              <Field label="Model">{models.length ? models.join(", ") : "n/a"}</Field>
              <Field label="Run time">{fmtDuration(durationSeconds)}</Field>
              {requests != null && <Field label="Requests">{formatNumber(requests)}</Field>}
              {inputTokens != null && (
                <Field label="Input tokens">
                  {formatNumber(inputTokens)}
                  {cached != null && sub(cached, "cached")}
                </Field>
              )}
              {outputTokens != null && (
                <Field label="Output tokens">
                  {formatNumber(outputTokens)}
                  {reasoning != null && sub(reasoning, "reasoning")}
                </Field>
              )}
              {totalTokens != null && <Field label="Total tokens">{formatNumber(totalTokens)}</Field>}
              {cost != null && <Field label="Cost">${cost.toFixed(2)}</Field>}
              {agents.length > 0 && <Field label="Agents">{formatNumber(agents.length)}</Field>}
            </dl>
          ) : (
            <p className="text-sm text-[#666]">Not available yet.</p>
          )}
        </section>
      </div>
      )}
    </div>
  );
}

export default RunDetails;
