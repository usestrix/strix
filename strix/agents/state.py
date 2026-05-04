import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


def _generate_agent_id() -> str:
    return f"agent_{uuid.uuid4().hex[:8]}"


class AgentState(BaseModel):
    agent_id: str = Field(default_factory=_generate_agent_id)
    agent_name: str = "Strix Agent"
    parent_id: str | None = None
    sandbox_id: str | None = None
    sandbox_token: str | None = None
    sandbox_info: dict[str, Any] | None = None

    task: str = ""
    iteration: int = 0
    max_iterations: int = 300
    completed: bool = False
    stop_requested: bool = False
    waiting_for_input: bool = False
    llm_failed: bool = False
    waiting_start_time: datetime | None = None
    final_result: dict[str, Any] | None = None
    max_iterations_warning_sent: bool = False

    messages: list[dict[str, Any]] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)

    start_time: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    last_updated: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())

    actions_taken: list[dict[str, Any]] = Field(default_factory=list)
    observations: list[dict[str, Any]] = Field(default_factory=list)

    errors: list[str] = Field(default_factory=list)

    def increment_iteration(self) -> None:
        self.iteration += 1
        self.last_updated = datetime.now(UTC).isoformat()

    def add_message(self, role: str, content: Any, thinking_blocks: list[dict[str, Any]] | None = None) -> None:
        message = {"role": role, "content": content}
        if thinking_blocks:
            message["thinking_blocks"] = thinking_blocks
        self.messages.append(message)
        self.last_updated = datetime.now(UTC).isoformat()

    def add_action(self, action: dict[str, Any]) -> None:
        self.actions_taken.append(
            {
                "iteration": self.iteration,
                "timestamp": datetime.now(UTC).isoformat(),
                "action": action,
            }
        )

    def add_observation(self, observation: dict[str, Any]) -> None:
        self.observations.append(
            {
                "iteration": self.iteration,
                "timestamp": datetime.now(UTC).isoformat(),
                "observation": observation,
            }
        )

    def add_error(self, error: str) -> None:
        self.errors.append(f"Iteration {self.iteration}: {error}")
        self.last_updated = datetime.now(UTC).isoformat()

    def update_context(self, key: str, value: Any) -> None:
        self.context[key] = value
        self.last_updated = datetime.now(UTC).isoformat()

    def set_completed(self, final_result: dict[str, Any] | None = None) -> None:
        self.completed = True
        self.final_result = final_result
        self.last_updated = datetime.now(UTC).isoformat()

    def request_stop(self) -> None:
        self.stop_requested = True
        self.last_updated = datetime.now(UTC).isoformat()

    def should_stop(self) -> bool:
        return self.stop_requested or self.completed or self.has_reached_max_iterations()

    def is_waiting_for_input(self) -> bool:
        return self.waiting_for_input

    def enter_waiting_state(self, llm_failed: bool = False) -> None:
        self.waiting_for_input = True
        self.waiting_start_time = datetime.now(UTC)
        self.llm_failed = llm_failed
        self.last_updated = datetime.now(UTC).isoformat()

    def resume_from_waiting(self, new_task: str | None = None) -> None:
        self.waiting_for_input = False
        self.waiting_start_time = None
        self.stop_requested = False
        self.completed = False
        self.llm_failed = False
        if new_task:
            self.task = new_task
        self.last_updated = datetime.now(UTC).isoformat()

    def has_reached_max_iterations(self) -> bool:
        return self.iteration >= self.max_iterations

    def is_approaching_max_iterations(self, threshold: float = 0.85) -> bool:
        return self.iteration >= int(self.max_iterations * threshold)

    def has_waiting_timeout(self) -> bool:
        if not self.waiting_for_input or not self.waiting_start_time:
            return False

        if (
            self.stop_requested
            or self.llm_failed
            or self.completed
            or self.has_reached_max_iterations()
        ):
            return False

        elapsed = (datetime.now(UTC) - self.waiting_start_time).total_seconds()
        return elapsed > 600

    def has_empty_last_messages(self, count: int = 3) -> bool:
        if len(self.messages) < count:
            return False

        last_messages = self.messages[-count:]

        for message in last_messages:
            content = message.get("content", "")
            if isinstance(content, str) and content.strip():
                return False

        return True

    def get_conversation_history(self) -> list[dict[str, Any]]:
        return self.messages

    def get_execution_summary(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "parent_id": self.parent_id,
            "sandbox_id": self.sandbox_id,
            "sandbox_info": self.sandbox_info,
            "task": self.task,
            "iteration": self.iteration,
            "max_iterations": self.max_iterations,
            "completed": self.completed,
            "final_result": self.final_result,
            "start_time": self.start_time,
            "last_updated": self.last_updated,
            "total_actions": len(self.actions_taken),
            "total_observations": len(self.observations),
            "total_errors": len(self.errors),
            "has_errors": len(self.errors) > 0,
            "max_iterations_reached": self.has_reached_max_iterations() and not self.completed,
        }
