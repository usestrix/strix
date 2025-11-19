import atexit
import contextlib
import signal
import sys
import threading
from typing import Any

from .python_instance import PythonInstance


class PythonSessionManager:
    def __init__(self) -> None:
        self.sessions: dict[str, PythonInstance] = {}
        self._lock = threading.Lock()
        self.default_session_id = "default"

        self._register_cleanup_handlers()

    def create_session(
        self, session_id: str | None = None, initial_code: str | None = None, timeout: int = 30
    ) -> dict[str, Any]:
        if session_id is None:
            session_id = self.default_session_id

        with self._lock:
            if session_id in self.sessions:
                raise ValueError(f"Python session '{session_id}' already exists")

            session = PythonInstance(session_id)
            self.sessions[session_id] = session

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

        with self._lock:
            if session_id not in self.sessions:
                raise ValueError(f"Python session '{session_id}' not found")

            session = self.sessions[session_id]

        result = session.execute_code(code, timeout)
        result["message"] = f"Code executed in session '{session_id}'"
        return result

    def close_session(self, session_id: str | None = None) -> dict[str, Any]:
        if session_id is None:
            session_id = self.default_session_id

        with self._lock:
            if session_id not in self.sessions:
                raise ValueError(f"Python session '{session_id}' not found")

            session = self.sessions.pop(session_id)

        session.close()
        return {
            "session_id": session_id,
            "message": f"Python session '{session_id}' closed successfully",
            "is_running": False,
        }

    def list_sessions(self) -> dict[str, Any]:
        with self._lock:
            session_info = {}
            for sid, session in self.sessions.items():
                session_info[sid] = {
                    "is_running": session.is_running,
                    "is_alive": session.is_alive(),
                }

        return {"sessions": session_info, "total_count": len(session_info)}

    def cleanup_dead_sessions(self) -> None:
        with self._lock:
            dead_sessions = []
            for sid, session in self.sessions.items():
                if not session.is_alive():
                    dead_sessions.append(sid)

            for sid in dead_sessions:
                session = self.sessions.pop(sid)
                with contextlib.suppress(Exception):
                    session.close()

    def close_all_sessions(self) -> None:
        with self._lock:
            sessions_to_close = list(self.sessions.values())
            self.sessions.clear()

        for session in sessions_to_close:
            with contextlib.suppress(Exception):
                session.close()

    def _register_cleanup_handlers(self) -> None:
        atexit.register(self.close_all_sessions)

        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

        if hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, self._signal_handler)

    def _signal_handler(self, _signum: int, _frame: Any) -> None:
        self.close_all_sessions()
        sys.exit(0)


_python_session_manager = PythonSessionManager()


def get_python_session_manager() -> PythonSessionManager:
    return _python_session_manager
