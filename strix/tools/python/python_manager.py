import atexit
import contextlib
import threading
from typing import Any

from strix.tools.context import get_current_agent_id

from .python_instance import PythonInstance


class PythonSessionManager:
    def __init__(self) -> None:
        self._sessions_by_agent: dict[str, dict[str, PythonInstance]] = {}
        self._lock = threading.Lock()
        self.default_session_id = "default"

        self._register_cleanup_handlers()

    def _get_agent_sessions(self) -> dict[str, PythonInstance]:
        agent_id = get_current_agent_id()
        with self._lock:
            if agent_id not in self._sessions_by_agent:
                self._sessions_by_agent[agent_id] = {}
            return self._sessions_by_agent[agent_id]

    def create_session(
        self, session_id: str | None = None, initial_code: str | None = None, timeout: int = 30
    ) -> dict[str, Any]:
        if session_id is None:
            session_id = self.default_session_id

        sessions = self._get_agent_sessions()
        with self._lock:
            if session_id in sessions:
                raise ValueError(f"Python session '{session_id}' already exists")

            session = PythonInstance(session_id)
            sessions[session_id] = session

            if initial_code:
                result = session.execute_code(initial_code, timeout)
                result["message"] = (
                    f"Python session '{session_id}' created successfully with initial code"
                )
            else:
                result = {
                    "session_id": session_id,
                    "message": f"Python session '{session_id}' created successfully",
                }

            return result

    def execute_code(
        self, session_id: str | None = None, code: str | None = None, timeout: int = 30
    ) -> dict[str, Any]:
        if session_id is None:
            session_id = self.default_session_id

        if not code:
            raise ValueError("No code provided for execution")

        sessions = self._get_agent_sessions()
        with self._lock:
            if session_id not in sessions:
                raise ValueError(f"Python session '{session_id}' not found")

            session = sessions[session_id]

        result = session.execute_code(code, timeout)
        result["message"] = f"Code executed in session '{session_id}'"
        return result

    def close_session(self, session_id: str | None = None) -> dict[str, Any]:
        if session_id is None:
            session_id = self.default_session_id

        sessions = self._get_agent_sessions()
        with self._lock:
            if session_id not in sessions:
                raise ValueError(f"Python session '{session_id}' not found")

            session = sessions.pop(session_id)

        session.close()
        return {
            "session_id": session_id,
            "message": f"Python session '{session_id}' closed successfully",
            "is_running": False,
        }

    def list_sessions(self) -> dict[str, Any]:
        sessions = self._get_agent_sessions()
        with self._lock:
            session_info = {}
            for sid, session in sessions.items():
                session_info[sid] = {
                    "is_running": session.is_running,
                    "is_alive": session.is_alive(),
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
                dead_sessions = []
                for sid, session in sessions.items():
                    if not session.is_alive():
                        dead_sessions.append(sid)

                for sid in dead_sessions:
                    session = sessions.pop(sid)
                    with contextlib.suppress(Exception):
                        session.close()

    def close_all_sessions(self) -> None:
        with self._lock:
            all_sessions: list[PythonInstance] = []
            for sessions in self._sessions_by_agent.values():
                all_sessions.extend(sessions.values())
            self._sessions_by_agent.clear()

        for session in all_sessions:
            with contextlib.suppress(Exception):
                session.close()

    def _register_cleanup_handlers(self) -> None:
        atexit.register(self.close_all_sessions)


_python_session_manager = PythonSessionManager()


def get_python_session_manager() -> PythonSessionManager:
    return _python_session_manager
