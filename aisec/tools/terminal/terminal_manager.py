import atexit
import contextlib
import signal
import sys
import threading
from typing import Any

from .terminal_session import TerminalSession


class TerminalManager:
    def __init__(self) -> None:
        self.sessions: dict[str, TerminalSession] = {}
        self._lock = threading.Lock()
        self.default_terminal_id = "default"
        self.default_timeout = 30.0

        self._register_cleanup_handlers()

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
        with self._lock:
            if terminal_id not in self.sessions:
                self.sessions[terminal_id] = TerminalSession(terminal_id)
            return self.sessions[terminal_id]

    def close_session(self, terminal_id: str | None = None) -> dict[str, Any]:
        if terminal_id is None:
            terminal_id = self.default_terminal_id

        with self._lock:
            if terminal_id not in self.sessions:
                return {
                    "terminal_id": terminal_id,
                    "message": f"Terminal '{terminal_id}' not found",
                    "status": "not_found",
                }

            session = self.sessions.pop(terminal_id)

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
        with self._lock:
            session_info: dict[str, dict[str, Any]] = {}
            for tid, session in self.sessions.items():
                session_info[tid] = {
                    "is_running": session.is_running(),
                    "working_dir": session.get_working_dir(),
                }

        return {"sessions": session_info, "total_count": len(session_info)}

    def cleanup_dead_sessions(self) -> None:
        with self._lock:
            dead_sessions: list[str] = []
            for tid, session in self.sessions.items():
                if not session.is_running():
                    dead_sessions.append(tid)

            for tid in dead_sessions:
                session = self.sessions.pop(tid)
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


_terminal_manager = TerminalManager()


def get_terminal_manager() -> TerminalManager:
    return _terminal_manager
