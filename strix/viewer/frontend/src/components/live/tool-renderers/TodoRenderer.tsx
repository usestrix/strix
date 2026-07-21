"use client";

import type { ToolRendererProps } from "@/types/events";
import { Circle, CircleDot, CircleCheckBig, Trash2, Plus, RefreshCw, CheckCheck, RotateCcw, Pencil } from "lucide-react";

interface TodoItem {
  id?: string;
  title?: string;
  status?: string;
}

const ACTION_LABELS: Record<string, { label: string; Icon: typeof Circle }> = {
  create_todo: { label: "Task added", Icon: Plus },
  list_todos: { label: "Plan", Icon: CheckCheck },
  update_todo: { label: "Task updated", Icon: Pencil },
  mark_todo_done: { label: "Task completed", Icon: CircleCheckBig },
  mark_todo_pending: { label: "Task reopened", Icon: RotateCcw },
  delete_todo: { label: "Task removed", Icon: Trash2 },
};

function StatusIcon({ status }: { status: string }) {
  if (status === "done") return <CircleCheckBig className="w-3.5 h-3.5 text-emerald-400/70 shrink-0" />;
  if (status === "in_progress") return <CircleDot className="w-3.5 h-3.5 text-purple-400/70 shrink-0 animate-pulse" />;
  return <Circle className="w-3.5 h-3.5 text-[#444] shrink-0" />;
}

function TodoList({ todos, highlightId }: { todos: TodoItem[]; highlightId?: string }) {
  return (
    <div className="space-y-0">
      {todos.map((todo, i) => {
        const s = todo.status ?? "pending";
        const isHighlighted = highlightId && todo.id === highlightId;
        return (
          <div
            key={todo.id ?? i}
            className={`flex items-start gap-2.5 py-1.5 px-2 -mx-2 rounded-md transition-colors ${
              isHighlighted ? "bg-purple-500/[0.08]" : ""
            }`}
          >
            <div className="mt-[1px]">
              <StatusIcon status={s} />
            </div>
            <span
              className={`text-[13px] leading-snug ${
                s === "done"
                  ? "text-[#555] line-through"
                  : s === "in_progress"
                    ? "text-[#bbb]"
                    : "text-[#999]"
              }`}
            >
              {todo.title ?? "(untitled)"}
            </span>
          </div>
        );
      })}
    </div>
  );
}

export default function TodoRenderer({ toolName, args, result }: ToolRendererProps) {
  const action = ACTION_LABELS[toolName] ?? { label: "Plan", Icon: RefreshCw };
  const ActionIcon = action.Icon;
  const res = result as Record<string, unknown> | string | null;

  // Simple string result
  if (typeof res === "string" && res.trim()) {
    return (
      <div>
        <div className="flex items-center gap-2">
          <ActionIcon className="w-3.5 h-3.5 text-purple-400/60" />
          <span className="text-purple-400/80 font-semibold text-sm">{action.label}</span>
        </div>
        <div className="mt-1.5 text-[#888] text-[13px]">{res.trim()}</div>
      </div>
    );
  }

  // Parse structured result
  let todos: TodoItem[] = [];
  let error: string | null = null;
  let todoId: string | undefined;

  if (res && typeof res === "object") {
    error = (res.error as string) ?? null;
    if (res.success) {
      const rawTodos = res.todos;
      todos = Array.isArray(rawTodos) ? (rawTodos as TodoItem[]) : [];
    }
    todoId = (res.id as string) ?? (args.todo_id as string) ?? undefined;
  }

  // For mutations, highlight the affected item
  const highlightId = toolName !== "list_todos" ? todoId : undefined;

  // No todos and no error — brief label only
  if (todos.length === 0 && !error) {
    return (
      <div className="flex items-center gap-2">
        <ActionIcon className="w-3.5 h-3.5 text-purple-400/60" />
        <span className="text-purple-400/80 font-semibold text-sm">{action.label}</span>
      </div>
    );
  }

  return (
    <div>
      <div className="flex items-center gap-2 mb-2">
        <ActionIcon className="w-3.5 h-3.5 text-purple-400/60" />
        <span className="text-purple-400/80 font-semibold text-sm">{action.label}</span>
      </div>
      {error && <div className="text-red-400/70 text-[13px] mb-2">{error}</div>}
      {todos.length > 0 && (
        <div className="rounded-lg border border-white/[0.06] bg-white/[0.015] px-3 py-2">
          <TodoList todos={todos} highlightId={highlightId} />
        </div>
      )}
    </div>
  );
}
