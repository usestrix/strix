import type {
  Vulnerability,
  VulnerabilitySeverity,
  VulnerabilityStatus,
} from "@/types/issues";

/**
 * Pure, dependency-free parsers that turn a Strix CLI local run
 * (`strix_runs/<run>/{run.json,vulnerabilities.json}`) into the app's own
 * types, so the /results view can reuse the dashboard's finding components.
 *
 * These run entirely client-side against files the user picked from disk —
 * nothing here uploads or persists anything.
 */

export class RunParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RunParseError";
  }
}

export interface ParsedRunSummary {
  runId: string | null;
  runName: string | null;
  targets: string[];
  scanMode: string | null;
  status: string | null;
  startTime: string | null;
  endTime: string | null;
  durationSeconds: number | null;
  executiveSummary: string | null;
  technicalAnalysis: string | null;
  methodology: string | null;
  recommendations: string | null;
}

const KNOWN_SEVERITIES: VulnerabilitySeverity[] = ["critical", "high", "medium", "low"];

function coerceSeverity(raw: unknown): VulnerabilitySeverity {
  const s = String(raw ?? "").toLowerCase().trim();
  if ((KNOWN_SEVERITIES as string[]).includes(s)) return s as VulnerabilitySeverity;
  // The app's severity type has no "info"/"informational" bucket; fold those
  // (and anything unrecognized) into "low" so the shared UI renders cleanly.
  return "low";
}

function toIsoTimestamp(raw: unknown): string {
  if (typeof raw === "string" && raw.trim()) {
    // CLI writes e.g. "2025-01-02 03:04:05 UTC".
    const normalized = raw.trim().replace(" UTC", "Z").replace(" ", "T");
    const d = new Date(normalized);
    if (!Number.isNaN(d.getTime())) return d.toISOString();
    const direct = new Date(raw);
    if (!Number.isNaN(direct.getTime())) return direct.toISOString();
  }
  return new Date().toISOString();
}

function asStringOrNull(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}

function asNumberOrNull(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

function parseJson(text: string, label: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    throw new RunParseError(
      `${label} isn't valid JSON. Make sure you selected a Strix run directory.`
    );
  }
}

export function parseRunJson(text: string): ParsedRunSummary {
  const data = parseJson(text, "run.json");
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new RunParseError("run.json is not an object.");
  }
  const record = data as Record<string, unknown>;

  const targets: string[] = [];
  const targetsInfo = record.targets_info;
  if (Array.isArray(targetsInfo)) {
    for (const t of targetsInfo) {
      if (t && typeof t === "object") {
        const original = (t as Record<string, unknown>).original;
        if (typeof original === "string" && original) targets.push(original);
      }
    }
  }

  const startTime = asStringOrNull(record.start_time);
  const endTime = asStringOrNull(record.end_time);
  let durationSeconds: number | null = null;
  if (startTime && endTime) {
    const s = new Date(startTime).getTime();
    const e = new Date(endTime).getTime();
    if (!Number.isNaN(s) && !Number.isNaN(e) && e >= s) {
      durationSeconds = Math.round((e - s) / 1000);
    }
  }

  let executiveSummary: string | null = null;
  let technicalAnalysis: string | null = null;
  let methodology: string | null = null;
  let recommendations: string | null = null;
  const scanResults = record.scan_results;
  if (scanResults && typeof scanResults === "object") {
    const sr = scanResults as Record<string, unknown>;
    executiveSummary = asStringOrNull(sr.executive_summary);
    technicalAnalysis = asStringOrNull(sr.technical_analysis);
    methodology = asStringOrNull(sr.methodology);
    recommendations = asStringOrNull(sr.recommendations);
  }

  return {
    runId: asStringOrNull(record.run_id),
    runName: asStringOrNull(record.run_name),
    targets,
    scanMode: asStringOrNull(record.scan_mode),
    status: asStringOrNull(record.status),
    startTime,
    endTime,
    durationSeconds,
    executiveSummary,
    technicalAnalysis,
    methodology,
    recommendations,
  };
}

/** Fields on the app's Vulnerability type that a local run never provides. */
function emptyVulnerabilityDefaults(): Omit<
  Vulnerability,
  | "id"
  | "title"
  | "description"
  | "severity"
  | "created_at"
  | "scan_id"
  | "status"
> {
  return {
    pr_review_id: null,
    cve: null,
    cvss: null,
    potential_risk_saving: null,
    risk_saving_description: null,
    impact: null,
    endpoint: null,
    method: null,
    target: null,
    technical_analysis: null,
    poc_description: null,
    poc_script_code: null,
    code_diff: null,
    code_file: null,
    code_before: null,
    code_after: null,
    cwe: null,
    code_locations: null,
    remediation_steps: null,
    fix_pr_body: null,
    evidence: null,
    assumptions: null,
    fix_effort: null,
    cvss_breakdown: null,
    status_changed_at: null,
    status_changed_by: null,
    status_note: null,
    snoozed_until: null,
    reopened_at: null,
    reopened_by: null,
    original_severity: null,
    severity_changed_at: null,
    severity_changed_by: null,
    severity_override_reason: null,
    retest_of_vulnerability_id: null,
  };
}

function parseOneVulnerability(
  raw: Record<string, unknown>,
  index: number,
  runId: string | null
): Vulnerability {
  const cweRaw = raw.cwe;
  const cwe =
    typeof cweRaw === "string" && cweRaw.trim()
      ? [cweRaw.trim()]
      : Array.isArray(cweRaw)
        ? (cweRaw.filter((c) => typeof c === "string" && c) as string[])
        : null;

  const status: VulnerabilityStatus = "open";

  return {
    ...emptyVulnerabilityDefaults(),
    id: asStringOrNull(raw.id) ?? `vuln-${index + 1}`,
    scan_id: runId,
    title: asStringOrNull(raw.title) ?? "Untitled finding",
    description: asStringOrNull(raw.description) ?? "",
    severity: coerceSeverity(raw.severity),
    status,
    created_at: toIsoTimestamp(raw.timestamp),
    cve: asStringOrNull(raw.cve),
    cvss: asNumberOrNull(raw.cvss),
    impact: asStringOrNull(raw.impact),
    endpoint: asStringOrNull(raw.endpoint),
    method: asStringOrNull(raw.method),
    target: asStringOrNull(raw.target),
    technical_analysis: asStringOrNull(raw.technical_analysis),
    poc_description: asStringOrNull(raw.poc_description),
    poc_script_code: asStringOrNull(raw.poc_script_code),
    cwe,
    code_locations: Array.isArray(raw.code_locations)
      ? (raw.code_locations as Vulnerability["code_locations"])
      : null,
    remediation_steps: asStringOrNull(raw.remediation_steps),
    fix_pr_body: asStringOrNull(raw.fix_pr_body),
    evidence: asStringOrNull(raw.evidence),
    assumptions: asStringOrNull(raw.assumptions),
    fix_effort: (asStringOrNull(raw.fix_effort) as Vulnerability["fix_effort"]) ?? null,
    cvss_breakdown: (raw.cvss_breakdown as Vulnerability["cvss_breakdown"]) ?? null,
  };
}

export function parseVulnerabilitiesJson(
  text: string,
  runId: string | null = null
): Vulnerability[] {
  const data = parseJson(text, "vulnerabilities.json");
  if (!Array.isArray(data)) {
    throw new RunParseError("vulnerabilities.json is not a JSON array.");
  }
  return data.map((item, i) => {
    if (!item || typeof item !== "object") {
      throw new RunParseError(`vulnerabilities.json entry #${i + 1} is not an object.`);
    }
    return parseOneVulnerability(item as Record<string, unknown>, i, runId);
  });
}

export interface ParsedAgent {
  id: string;
  name: string;
  status: string;
  parentId: string | null;
  task: string | null;
  skills: string[];
  depth: number;
}

/**
 * Parse the agent execution trace from `.state/agents.json` into a pre-ordered
 * tree (children follow their parent; `depth` drives indentation). Rendered
 * 100% client-side and never uploaded — traces contain target details, so they
 * must stay on the user's machine. The heavier `.state/agents.db` (SQLite) is
 * intentionally ignored; `agents.json` has everything the panel needs.
 */
export function parseAgentsJson(text: string): ParsedAgent[] {
  const data = parseJson(text, "agents.json");
  if (!data || typeof data !== "object" || Array.isArray(data)) return [];
  const record = data as Record<string, unknown>;
  const statuses = (record.statuses ?? {}) as Record<string, unknown>;
  const parentOf = (record.parent_of ?? {}) as Record<string, unknown>;
  const names = (record.names ?? {}) as Record<string, unknown>;
  const metadata = (record.metadata ?? {}) as Record<string, unknown>;

  const agents = new Map<string, ParsedAgent>();
  for (const id of Object.keys(statuses)) {
    const meta = (metadata[id] ?? {}) as Record<string, unknown>;
    const skillsRaw = meta.skills;
    agents.set(id, {
      id,
      name: asStringOrNull(names[id]) ?? id,
      status: asStringOrNull(statuses[id]) ?? "unknown",
      parentId: asStringOrNull(parentOf[id]),
      task: asStringOrNull(meta.task),
      skills: Array.isArray(skillsRaw)
        ? skillsRaw.filter((s): s is string => typeof s === "string")
        : [],
      depth: 0,
    });
  }
  if (agents.size === 0) return [];

  const childrenOf = new Map<string | null, string[]>();
  for (const a of agents.values()) {
    const key = a.parentId && agents.has(a.parentId) ? a.parentId : null;
    (childrenOf.get(key) ?? childrenOf.set(key, []).get(key)!).push(a.id);
  }

  const ordered: ParsedAgent[] = [];
  const seen = new Set<string>();
  const visit = (id: string, depth: number): void => {
    const a = agents.get(id);
    if (!a || seen.has(id)) return;
    seen.add(id);
    a.depth = depth;
    ordered.push(a);
    for (const childId of childrenOf.get(id) ?? []) visit(childId, depth + 1);
  };
  for (const rootId of childrenOf.get(null) ?? []) visit(rootId, 0);
  // Defensive: include any agents not reachable from a root.
  for (const a of agents.values()) if (!seen.has(a.id)) ordered.push(a);
  return ordered;
}

export function severityCounts(
  vulns: Vulnerability[]
): Record<VulnerabilitySeverity, number> {
  const counts: Record<VulnerabilitySeverity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  for (const v of vulns) counts[v.severity] += 1;
  return counts;
}
