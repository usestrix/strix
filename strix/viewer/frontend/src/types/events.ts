// Types matching the Python tracer's event shapes stored in Convex

export type EventType =
  | "run.started"
  | "run.configured"
  | "run.completed"
  | "agent.created"
  | "agent.status.updated"
  | "tool.execution.started"
  | "tool.execution.updated"
  | "chat.message"
  | "finding.created"
  | "finding.reviewed"
  | "traffic.batch";

export interface EventActor {
  agent_id?: string;
  agent_name?: string;
  tool_name?: string;
  execution_id?: number;
  role?: string;
}

export interface ConvexEvent {
  _id: string;
  _creationTime: number;
  timestamp: string;
  event_type: EventType;
  run_id: string;
  trace_id?: string | null;
  span_id?: string | null;
  parent_span_id?: string | null;
  actor: EventActor | null;
  payload: Record<string, unknown> | null;
  status: string | null;
  error: unknown | null;
  source?: string;
  run_metadata?: RunMetadata;
}

export interface RunMetadata {
  run_id: string;
  run_name: string | null;
  start_time: string;
  end_time: string | null;
  targets: string[];
  status: string;
  user_instructions?: string;
  max_iterations?: number;
}

export interface AgentNode {
  id: string;
  name: string;
  task: string;
  status: "running" | "completed" | "failed" | "error";
  parentId: string | null;
  children: string[];
  createdAt: string;
  toolCount: number;
  messageCount: number;
}

export interface ToolExecution {
  executionId: number;
  agentId: string;
  toolName: string;
  args: Record<string, unknown>;
  result: unknown;
  status: "running" | "completed" | "failed" | "error";
  startedAt: string;
  completedAt: string | null;
}

export interface ChatMessage {
  messageId: number;
  agentId: string | null;
  role: string;
  content: string;
  timestamp: string;
  metadata: Record<string, unknown>;
}

export interface Finding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  description?: string;
  target?: string;
  endpoint?: string;
  method?: string;
  cvss?: number;
  cve?: string;
  timestamp: string;
}

export interface ToolRendererProps {
  toolName: string;
  args: Record<string, unknown>;
  result: unknown;
  status: "running" | "completed" | "failed" | "error";
}
