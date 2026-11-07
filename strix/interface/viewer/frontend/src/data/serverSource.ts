import type { Vulnerability } from "@/types/issues";
import type { AttackPathPayload } from "@/types/attack-path";
import {
  parseRunJson,
  parseVulnerabilitiesJson,
  type ParsedRunSummary,
} from "@/lib/local-run-parser";

/**
 * Data seam for the local viewer: fetches against the local Python server's
 * JSON endpoints (same origin, relative URLs), producing the in-memory
 * `LoadedRun` shape the UI renders plus a `finished` flag driving live polling.
 *
 * The server serves a live in-progress run and a finished one identically; the
 * only signal is `run.finished`.
 */

/** A transcript agent as emitted by GET /api/transcript (already parsed). */
export interface TranscriptAgent {
  id: string;
  name: string;
  parent_id: string | null;
  status: string;
  created_at: string;
  updated_at: string;
}

/** Chat/tool event data as emitted by GET /api/transcript. */
export interface TranscriptEvent {
  id: string;
  type: "chat" | "tool";
  agent_id: string;
  timestamp: string;
  version: number;
  data: Record<string, unknown>;
}

export interface Transcript {
  agents: TranscriptAgent[];
  events: TranscriptEvent[];
}

/**
 * One MCP connection's non-secret status, as persisted to run.json by the
 * engine under `mcp_connection_status` and surfaced verbatim by GET /api/run.
 * Only name / provider / tool_count / dead ride here; never config, url, or
 * token. `dead` means the connection's live session gave up reconnecting.
 */
export interface McpConnectionStatus {
  name: string;
  provider: string | null;
  toolCount: number;
  dead: boolean;
}

/**
 * Read the MCP connection roster out of a raw run record. Tolerates the field
 * being absent (older runs, or a run with no MCP) and any malformed entry,
 * yielding an empty list rather than throwing.
 */
export function parseMcpConnectionStatus(raw: Record<string, unknown>): McpConnectionStatus[] {
  const list = raw?.mcp_connection_status;
  if (!Array.isArray(list)) return [];
  return list.flatMap((entry) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) return [];
    const record = entry as Record<string, unknown>;
    const name = typeof record.name === "string" ? record.name.trim() : "";
    if (!name) return [];
    const provider = typeof record.provider === "string" && record.provider.trim() ? record.provider.trim() : null;
    const toolCount = typeof record.tool_count === "number" ? record.tool_count : 0;
    const dead = record.dead === true;
    return [{ name, provider, toolCount, dead }];
  });
}

export interface LoadedRun {
  summary: ParsedRunSummary;
  /** Whole raw run record (for llm_usage, targets_info details, etc.). */
  raw: Record<string, unknown>;
  finished: boolean;
  vulnerabilities: Vulnerability[];
  reportMarkdown: string | null;
  transcript: Transcript;
}

async function getJson(path: string): Promise<unknown> {
  const res = await fetch(path, { cache: "no-store" });
  if (!res.ok) throw new Error(`${path} responded ${res.status}`);
  return res.json();
}

/** Build a ``?run=<name>`` suffix for run-scoped data endpoints. */
function runQuery(runName?: string | null): string {
  return runName ? `?run=${encodeURIComponent(runName)}` : "";
}

export async function fetchRunSummary(runName?: string | null): Promise<{
  summary: ParsedRunSummary;
  raw: Record<string, unknown>;
  finished: boolean;
}> {
  const raw = (await getJson("/api/run" + runQuery(runName))) as Record<string, unknown>;
  // parseRunJson tolerates extra keys and takes raw TEXT.
  const summary = parseRunJson(JSON.stringify(raw));
  const finished = raw.finished === true;
  return { summary, raw, finished };
}

export async function fetchVulnerabilities(
  runId: string | null,
  runName?: string | null
): Promise<Vulnerability[]> {
  const arr = await getJson("/api/vulnerabilities" + runQuery(runName));
  return parseVulnerabilitiesJson(JSON.stringify(arr), runId);
}

export async function fetchReportMarkdown(runName?: string | null): Promise<string | null> {
  const obj = (await getJson("/api/report" + runQuery(runName))) as { markdown?: string };
  return obj?.markdown ?? null;
}

export async function fetchTranscript(runName?: string | null): Promise<Transcript> {
  const obj = (await getJson("/api/transcript" + runQuery(runName))) as Partial<Transcript>;
  return {
    agents: Array.isArray(obj?.agents) ? obj.agents : [],
    events: Array.isArray(obj?.events) ? obj.events : [],
  };
}

/** Modeled attack-path artifacts (Phase 4). Always returns a payload; available may be false. */
export async function fetchAttackPath(runName?: string | null): Promise<AttackPathPayload> {
  const obj = (await getJson("/api/attack-path" + runQuery(runName))) as Partial<AttackPathPayload>;
  return {
    available: obj?.available === true,
    reason: typeof obj?.reason === "string" ? obj.reason : null,
    graph: obj?.graph ?? null,
    meta: obj?.meta ?? null,
    analysis_text: typeof obj?.analysis_text === "string" ? obj.analysis_text : null,
    disclaimer: typeof obj?.disclaimer === "string" ? obj.disclaimer : undefined,
    simulated_lateral_default: obj?.simulated_lateral_default === true,
  };
}

export interface AuthorizedScanResponse {
  ok: boolean;
  error?: string | null;
  message?: string;
  warning?: string;
  modeled_note?: string;
  target_url?: string;
  run_name?: string;
  run_dir?: string;
  scan_started?: boolean;
  skipped_reason?: string | null;
  command?: string[] | string;
  next_steps?: string[];
  action?: string;
}

/** Queue an authorized Strix scan or stage a SYNTHETIC Attack Path demo (auth checkbox required). */
export async function postAuthorizedScan(body: {
  url: string;
  authorized: boolean;
  action?: "queue_scan" | "demo_fixture";
  scan_mode?: string;
}): Promise<AuthorizedScanResponse> {
  const { data, status } = await postJson("/api/attack-path/authorized-scan", {
    url: body.url,
    authorized: body.authorized,
    action: body.action ?? "queue_scan",
    scan_mode: body.scan_mode ?? "quick",
  });
  return {
    ok: data.ok === true && status < 400,
    error: typeof data.error === "string" ? data.error : null,
    message: typeof data.message === "string" ? data.message : undefined,
    warning: typeof data.warning === "string" ? data.warning : undefined,
    modeled_note: typeof data.modeled_note === "string" ? data.modeled_note : undefined,
    target_url: typeof data.target_url === "string" ? data.target_url : undefined,
    run_name: typeof data.run_name === "string" ? data.run_name : undefined,
    run_dir: typeof data.run_dir === "string" ? data.run_dir : undefined,
    scan_started: data.scan_started === true,
    skipped_reason: typeof data.skipped_reason === "string" ? data.skipped_reason : null,
    command: Array.isArray(data.command)
      ? (data.command as string[])
      : typeof data.command === "string"
        ? data.command
        : undefined,
    next_steps: Array.isArray(data.next_steps) ? (data.next_steps as string[]) : undefined,
    action: typeof data.action === "string" ? data.action : undefined,
  };
}

/** One-shot fetch of every endpoint (used on mount and on final settle). */
export async function fetchAll(runName?: string | null): Promise<LoadedRun> {
  const { summary, raw, finished } = await fetchRunSummary(runName);
  const [vulnerabilities, reportMarkdown, transcript] = await Promise.all([
    fetchVulnerabilities(summary.runId, runName).catch(() => [] as Vulnerability[]),
    fetchReportMarkdown(runName).catch(() => null),
    fetchTranscript(runName).catch(() => ({ agents: [], events: [] }) as Transcript),
  ]);
  return { summary, raw, finished, vulnerabilities, reportMarkdown, transcript };
}

// ---------------------------------------------------------------------------
// Run history + email auth + report send
//
// These endpoints back the "Your runs" sidebar section. Auth and report-send
// responses carry a meaningful JSON body on non-2xx statuses (an ``error``
// code), so they read the body regardless of status rather than throwing.
// ---------------------------------------------------------------------------

export interface RunSeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface RunListEntry {
  name: string;
  target: string | null;
  scan_mode: string | null;
  status: string | null;
  start_time: string | null;
  end_time: string | null;
  finished: boolean;
  severity_counts: RunSeverityCounts;
}

export interface RunsPayload {
  locked: boolean;
  count: number;
  runs: RunListEntry[];
}

export interface AuthStatus {
  verified: boolean;
  email: string | null;
}

export type OtpStartResult = { ok: true } | { ok: false; error: string };
export type OtpVerifyResult =
  | { verified: true; email: string }
  | { verified: false; error: string };
export type SendReportResult =
  | { ok: true; password: string; filename: string }
  | { ok: false; error: string };

async function postJson(
  path: string,
  body: Record<string, unknown>
): Promise<{ ok: boolean; status: number; data: Record<string, unknown> }> {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    cache: "no-store",
  });
  let data: Record<string, unknown> = {};
  try {
    const parsed = await res.json();
    if (parsed && typeof parsed === "object") data = parsed as Record<string, unknown>;
  } catch {
    /* empty or non-JSON body */
  }
  return { ok: res.ok, status: res.status, data };
}

export async function fetchRuns(): Promise<RunsPayload> {
  const obj = (await getJson("/api/runs")) as Partial<RunsPayload>;
  return {
    locked: obj?.locked ?? true,
    count: typeof obj?.count === "number" ? obj.count : 0,
    runs: Array.isArray(obj?.runs) ? (obj.runs as RunListEntry[]) : [],
  };
}

export interface Capabilities {
  can_steer: boolean;
}

export type SteerResult = { ok: true } | { ok: false; error: string };

/** GET /api/capabilities. can_steer is true only inside a live in-TUI scan. */
export async function fetchCapabilities(): Promise<Capabilities> {
  const obj = (await getJson("/api/capabilities")) as Partial<Capabilities>;
  return { can_steer: obj?.can_steer === true };
}

/** POST /api/agents/steer. Sends a steering instruction to a running agent. */
export async function steerAgent(agentId: string, message: string): Promise<SteerResult> {
  const { ok, data } = await postJson("/api/agents/steer", {
    agent_id: agentId,
    message,
  });
  if (ok && data.ok === true) return { ok: true };
  return { ok: false, error: String(data.error ?? "unavailable") };
}

export type SubmitFeedbackResult = { ok: true } | { ok: false; error: string };

/**
 * POST /api/feedback. Sends a feedback message plus a work email (no
 * verification) to the local server, which relays it to Strix.
 */
export async function submitFeedback(
  message: string,
  email: string
): Promise<SubmitFeedbackResult> {
  const { ok, data } = await postJson("/api/feedback", { message, email });
  if (ok && data.ok === true) return { ok: true };
  return { ok: false, error: String(data.error ?? "unavailable") };
}

export async function fetchAuthStatus(): Promise<AuthStatus> {
  const obj = (await getJson("/api/auth/status")) as Partial<AuthStatus>;
  return { verified: obj?.verified === true, email: obj?.email ?? null };
}

export async function otpStart(email: string): Promise<OtpStartResult> {
  const { ok, data } = await postJson("/api/auth/otp/start", { email });
  if (ok && data.ok === true) return { ok: true };
  return { ok: false, error: String(data.error ?? "unavailable") };
}

export async function otpVerify(email: string, code: string): Promise<OtpVerifyResult> {
  const { ok, data } = await postJson("/api/auth/otp/verify", { email, code });
  if (ok && data.verified === true) {
    return { verified: true, email: String(data.email ?? email) };
  }
  return { verified: false, error: String(data.error ?? "invalid_code") };
}

export async function forgetAuth(): Promise<void> {
  await postJson("/api/auth/forget", {});
}

export async function sendReport(runName?: string | null): Promise<SendReportResult> {
  const { ok, data } = await postJson("/api/report/send", runName ? { run: runName } : {});
  if (ok && data.ok === true) {
    return {
      ok: true,
      password: String(data.password ?? ""),
      filename: String(data.filename ?? "strix-report.pdf"),
    };
  }
  return { ok: false, error: String(data.error ?? "unavailable") };
}
