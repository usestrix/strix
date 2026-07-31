export type VulnerabilitySeverity = "critical" | "high" | "medium" | "low";
export type VulnerabilityStatus = "open" | "in_progress" | "snoozed" | "fixed" | "ignored";
export type FixEffort = "trivial" | "low" | "medium" | "high";

export const ACTIVE_STATUSES: VulnerabilityStatus[] = ["open", "in_progress", "snoozed"];
export const RESOLVED_STATUSES: VulnerabilityStatus[] = ["fixed", "ignored"];

// Statuses worth retesting in a "retest all" — everything except ignored
// (fixed issues are still re-verified; ignored issues are intentionally skipped).
export const RETESTABLE_STATUSES: VulnerabilityStatus[] = ["open", "in_progress", "snoozed", "fixed"];

export const ALL_STATUSES: VulnerabilityStatus[] = ["open", "in_progress", "snoozed", "fixed", "ignored"];

export interface StatusCounts {
  all: number;
  open: number;
  in_progress: number;
  snoozed: number;
  fixed: number;
  ignored: number;
}

export interface StatusMeta {
  label: string;
  color: string;
  dotColor: string;
  description: string;
}

export const STATUS_META: Record<VulnerabilityStatus, StatusMeta> = {
  open: {
    label: "Open",
    color: "bg-red-500/10 text-red-400 border-red-500/20",
    dotColor: "bg-red-500",
    description: "Newly discovered, awaiting triage",
  },
  in_progress: {
    label: "In Progress",
    color: "bg-blue-500/10 text-blue-400 border-blue-500/20",
    dotColor: "bg-blue-500",
    description: "Someone is working on this",
  },
  snoozed: {
    label: "Snoozed",
    color: "bg-purple-500/10 text-purple-400 border-purple-500/20",
    dotColor: "bg-purple-500",
    description: "Temporarily hidden until a follow-up date",
  },
  fixed: {
    label: "Fixed",
    color: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
    dotColor: "bg-emerald-500",
    description: "This vulnerability has been fixed",
  },
  ignored: {
    label: "Ignored",
    color: "bg-gray-500/10 text-gray-400 border-gray-500/20",
    dotColor: "bg-gray-500",
    description: "Acknowledged but accepted",
  },
};

export const FIX_EFFORT_META: Record<FixEffort, { label: string; color: string }> = {
  trivial: { label: "Trivial", color: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" },
  low: { label: "Low", color: "bg-blue-500/10 text-blue-400 border-blue-500/20" },
  medium: { label: "Medium", color: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20" },
  high: { label: "High", color: "bg-orange-500/10 text-orange-400 border-orange-500/20" },
};

export interface CodeLocation {
  file: string;
  start_line: number;
  end_line?: number;
  snippet?: string;
  label?: string;
  fix_before?: string;
  fix_after?: string;
}

export interface CVSSBreakdown {
  attack_vector: string | null;
  attack_complexity: string | null;
  privileges_required: string | null;
  user_interaction: string | null;
  scope: string | null;
  confidentiality: string | null;
  integrity: string | null;
  availability: string | null;
}

export interface Vulnerability {
  id: string;
  scan_id: string | null;
  pr_review_id: string | null;
  title: string;
  description: string;
  cve: string | null;
  cvss: number | null;
  created_at: string;
  potential_risk_saving: number | null;
  risk_saving_description: string | null;
  status: VulnerabilityStatus;
  severity: VulnerabilitySeverity;
  impact: string | null;
  endpoint: string | null;
  method: string | null;
  target: string | null;
  technical_analysis: string | null;
  poc_description: string | null;
  poc_script_code: string | null;
  code_diff: string | null;
  code_file: string | null;
  code_before: string | null;
  code_after: string | null;
  cwe: string[] | null;
  code_locations: CodeLocation[] | null;
  remediation_steps: string | null;
  fix_pr_body: string | null;
  evidence: string | null;
  assumptions: string | null;
  fix_effort: FixEffort | null;
  cvss_breakdown: CVSSBreakdown | null;
  status_changed_at: string | null;
  status_changed_by: string | null;
  status_note: string | null;
  snoozed_until: string | null;
  reopened_at: string | null;
  reopened_by: string | null;
  original_severity: VulnerabilitySeverity | null;
  severity_changed_at: string | null;
  severity_changed_by: string | null;
  severity_override_reason: string | null;
  retest_of_vulnerability_id: string | null;
  slack_thread_url?: string;
  display_number?: number | null;
  location_meta?: {
    branch: string;
    provider: string;
    repo_url: string;
  } | null;
  fix_pr_eligible?: boolean;
  fix_pr_reason?: string | null;
  fix_pr_url?: string | null;
}

export interface VulnerabilityFilters {
  scan_id?: string;
  severity?: VulnerabilitySeverity;
  status?: VulnerabilityStatus;
  search?: string;
  sortBy?: "cvss" | "created_at";
  sortOrder?: "asc" | "desc";
  domain_id?: string;
  repository_id?: string;
}

export interface VulnerabilityAction {
  type: "status_change" | "generate_report" | "create_ticket";
  notes?: string;
  verification?: string;
  reason?: string;
  explanation?: string;
  report_type?: string;
  system?: string;
  priority?: string;
  assignee?: string;
  timestamp: string;
}

export const SEVERITY_COLORS: Record<VulnerabilitySeverity, string> = {
  critical: "bg-red-500/20 text-red-500 border-red-500/30",
  high: "bg-orange-500/20 text-orange-500 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-500 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-500 border-blue-500/30",
};

export const STATUS_COLORS: Record<VulnerabilityStatus, string> = {
  open: STATUS_META.open.color,
  in_progress: STATUS_META.in_progress.color,
  snoozed: STATUS_META.snoozed.color,
  fixed: STATUS_META.fixed.color,
  ignored: STATUS_META.ignored.color,
};

export function isSeverityOverridden(
  v: Pick<Vulnerability, "original_severity" | "severity">
): boolean {
  return v.original_severity != null && v.original_severity !== v.severity;
}

export function formatCvssLabel(cvss: number | null): string {
  if (cvss === null) return "N/A";
  if (cvss >= 9.0) return "Critical";
  if (cvss >= 7.0) return "High";
  if (cvss >= 4.0) return "Medium";
  return "Low";
}
