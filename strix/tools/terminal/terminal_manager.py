import atexit
import contextlib
import threading
from typing import Any

from strix.tools.context import get_current_agent_id

from .terminal_session import TerminalSession


class TerminalManager:
    def __init__(self) -> None:
        self._sessions_by_agent: dict[str, dict[str, TerminalSession]] = {}
        self._lock = threading.Lock()
        self.default_terminal_id = "default"
        self.default_timeout = 30.0

        self._register_cleanup_handlers()

    def _get_agent_sessions(self) -> dict[str, TerminalSession]:
        agent_id = get_current_agent_id()
        with self._lock:
            if agent_id not in self._sessions_by_agent:
                self._sessions_by_agent[agent_id] = {}
            return self._sessions_by_agent[agent_id]

    def execute_command(
        self,
        command: str,
        is_input: bool = False,
        timeout: float | None = None,
        terminal_id: str | None = None,
        no_enter: bool = False,
    ) -> dict[str, Any]:
        if terminal_id is None:
            terminal_id = self.default_terminal_id

        session = self._get_or_create_session(terminal_id)

        try:
            result = session.execute(command, is_input, timeout or self.default_timeout, no_enter)

            return {
                "content": result["content"],
                "command": command,
                "terminal_id": terminal_id,
                "status": result["status"],
                "exit_code": result.get("exit_code"),
                "working_dir": result.get("working_dir"),
            }

        except RuntimeError as e:
            return {
                "error": str(e),
                "command": command,
                "terminal_id": terminal_id,
                "content": "",
                "status": "error",
                "exit_code": None,
                "working_dir": None,
            }
        except OSError as e:
            return {
                "error": f"System error: {e}",
                "command": command,
                "terminal_id": terminal_id,
                "content": "",
                "status": "error",
                "exit_code": None,
                "working_dir": None,
            }

    def _get_or_create_session(self, terminal_id: str) -> TerminalSession:
        sessions = self._get_agent_sessions()
        with self._lock:
            if terminal_id not in sessions:
                sessions[terminal_id] = TerminalSession(terminal_id)
            return sessions[terminal_id]

    def close_session(self, terminal_id: str | None = None) -> dict[str, Any]:
        if terminal_id is None:
            terminal_id = self.default_terminal_id

        sessions = self._get_agent_sessions()
        with self._lock:
            if terminal_id not in sessions:
                return {
                    "terminal_id": terminal_id,
                    "message": f"Terminal '{terminal_id}' not found",
                    "status": "not_found",
                }

            session = sessions.pop(terminal_id)

        try:
            session.close()
        except (RuntimeError, OSError) as e:
            return {
                "terminal_id": terminal_id,
                "error": f"Failed to close terminal '{terminal_id}': {e}",
                "status": "error",
            }
        else:
            return {
                "terminal_id": terminal_id,
                "message": f"Terminal '{terminal_id}' closed successfully",
                "status": "closed",
            }

    def list_sessions(self) -> dict[str, Any]:
        sessions = self._get_agent_sessions()
        with self._lock:
            session_info: dict[str, dict[str, Any]] = {}
            for tid, session in sessions.items():
                session_info[tid] = {
                    "is_running": session.is_running(),
                    "working_dir": session.get_working_dir(),
                }

        return {"sessions": session_info, "total_count": len(session_info)}

    def cleanup_agent(self, agent_id: str) -> None:
        with self._lock:
            sessions = self._sessions_by_agent.pop(agent_id, {})

        for session in sessions.values():
            with contextlib.suppress(Exception):
                session.close()

    def cleanup_dead_sessions(self) -> None:
        with self._lock:
            for sessions in self._sessions_by_agent.values():
                dead_sessions: list[str] = []
                for tid, session in sessions.items():
                    if not session.is_running():
                        dead_sessions.append(tid)

                for tid in dead_sessions:
                    session = sessions.pop(tid)
                    with contextlib.suppress(Exception):
                        session.close()

    def close_all_sessions(self) -> None:
        with self._lock:
            all_sessions: list[TerminalSession] = []
            for sessions in self._sessions_by_agent.values():
                all_sessions.extend(sessions.values())
            self._sessions_by_agent.clear()

        for session in all_sessions:
            with contextlib.suppress(Exception):
                session.close()

    def _register_cleanup_handlers(self) -> None:
        atexit.register(self.close_all_sessions)


_terminal_manager = TerminalManager()


def get_terminal_manager() -> TerminalManager:
    return _terminal_manager
