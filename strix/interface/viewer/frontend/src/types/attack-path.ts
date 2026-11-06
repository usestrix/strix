/** Types matching Phase-2/3 attack_graph.json + /api/attack-path wrapper. */

export type AttackProvenance = "from_finding" | "simulated" | string;

export interface AttackPathNode {
  id: number;
  name: string;
  type: string;
  zone: string;
  impact: number;
  is_entry_point?: boolean;
  is_crown_jewel?: boolean;
  provenance: AttackProvenance;
  finding_ids?: string[];
  labels?: string[];
}

export interface AttackPathEdge {
  from: number;
  to: number;
  protocol?: string;
  relation?: string;
  probability?: number;
  status?: string;
  provenance: AttackProvenance;
  finding_ids?: string[];
  labels?: string[];
  title?: string | null;
}

export interface AttackGraph {
  schema_version?: string;
  disclaimer?: string;
  sources?: {
    finding_ids?: string[];
    run_name?: string | null;
    simulated_entry?: boolean;
    simulated_lateral?: boolean;
  };
  warnings?: string[];
  analysis_defaults?: { start?: number | null; target?: number | null };
  nodes: AttackPathNode[];
  edges: AttackPathEdge[];
  counts?: Record<string, number>;
}

export interface AttackPathMeta {
  schema_version?: string;
  generated_at?: string;
  disclaimer?: string;
  product_defaults?: {
    allow_simulated_lateral?: boolean;
    allow_simulated_entry?: boolean;
    note?: string;
  };
  counts?: Record<string, number>;
  warnings?: string[];
  analysis_defaults?: { start?: number | null; target?: number | null };
  engine?: {
    invoked?: boolean;
    skipped_reason?: string | null;
    returncode?: number | null;
    executable?: string | null;
  };
}

export interface AttackPathPayload {
  available: boolean;
  reason: string | null;
  graph: AttackGraph | null;
  meta: AttackPathMeta | null;
  analysis_text: string | null;
  disclaimer?: string;
  simulated_lateral_default?: boolean;
}
