import io
import signal
import sys
import threading
from typing import Any

from IPython.core.interactiveshell import InteractiveShell


MAX_STDOUT_LENGTH = 10_000
MAX_STDERR_LENGTH = 5_000


class PythonInstance:
    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self.is_running = True
        self._execution_lock = threading.Lock()

        import os

        os.chdir("/workspace")

        self.shell = InteractiveShell()
        self.shell.init_completer()
        self.shell.init_history()
        self.shell.init_logger()

        self._setup_proxy_functions()

    def _setup_proxy_functions(self) -> None:
        try:
            from aisec.tools.proxy import proxy_actions

            proxy_functions = [
                "list_requests",
                "list_sitemap",
                "repeat_request",
                "scope_rules",
                "send_request",
                "view_request",
                "view_sitemap_entry",
            ]

            proxy_dict = {name: getattr(proxy_actions, name) for name in proxy_functions}
            self.shell.user_ns.update(proxy_dict)
        except ImportError:
            pass

    def _validate_session(self) -> dict[str, Any] | None:
        if not self.is_running:
            return {
                "session_id": self.session_id,
                "stdout": "",
                "stderr": "Session is not running",
                "result": None,
            }
        return None

    def _setup_execution_environment(self, timeout: int) -> tuple[Any, io.StringIO, io.StringIO]:
        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()

        def timeout_handler(signum: int, frame: Any) -> None:
            raise TimeoutError(f"Code execution timed out after {timeout} seconds")

        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(timeout)

        sys.stdout = stdout_capture
        sys.stderr = stderr_capture

        return old_handler, stdout_capture, stderr_capture

    def _cleanup_execution_environment(
        self, old_handler: Any, old_stdout: Any, old_stderr: Any
    ) -> None:
        signal.signal(signal.SIGALRM, old_handler)
        sys.stdout = old_stdout
        sys.stderr = old_stderr

    def _truncate_output(self, content: str, max_length: int, suffix: str) -> str:
        if len(content) > max_length:
            return content[:max_length] + suffix
        return content

    def _format_execution_result(
        self, execution_result: Any, stdout_content: str, stderr_content: str
    ) -> dict[str, Any]:
        stdout = self._truncate_output(
            stdout_content, MAX_STDOUT_LENGTH, "... [stdout truncated at 10k chars]"
        )

        if execution_result.result is not None:
            if stdout and not stdout.endswith("\n"):
                stdout += "\n"
            result_repr = repr(execution_result.result)
            result_repr = self._truncate_output(
                result_repr, MAX_STDOUT_LENGTH, "... [result truncated at 10k chars]"
            )
            stdout += result_repr

        stdout = self._truncate_output(
            stdout, MAX_STDOUT_LENGTH, "... [output truncated at 10k chars]"
        )

        stderr_content = stderr_content if stderr_content else ""
        stderr_content = self._truncate_output(
            stderr_content, MAX_STDERR_LENGTH, "... [stderr truncated at 5k chars]"
        )

        if (
            execution_result.error_before_exec or execution_result.error_in_exec
        ) and not stderr_content:
            stderr_content = "Execution error occurred"

        return {
            "session_id": self.session_id,
            "stdout": stdout,
            "stderr": stderr_content,
            "result": repr(execution_result.result)
            if execution_result.result is not None
            else None,
        }

    def _handle_execution_error(self, error: BaseException) -> dict[str, Any]:
        error_msg = str(error)
        error_msg = self._truncate_output(
            error_msg, MAX_STDERR_LENGTH, "... [error truncated at 5k chars]"
        )

        return {
            "session_id": self.session_id,
            "stdout": "",
            "stderr": error_msg,
            "result": None,
        }

    def execute_code(self, code: str, timeout: int = 30) -> dict[str, Any]:
        session_error = self._validate_session()
        if session_error:
            return session_error

        with self._execution_lock:
            old_stdout, old_stderr = sys.stdout, sys.stderr

            try:
                old_handler, stdout_capture, stderr_capture = self._setup_execution_environment(
                    timeout
                )

                try:
                    execution_result = self.shell.run_cell(code, silent=False, store_history=True)
                    signal.alarm(0)

                    return self._format_execution_result(
                        execution_result, stdout_capture.getvalue(), stderr_capture.getvalue()
                    )

                except (TimeoutError, KeyboardInterrupt, SystemExit) as e:
                    signal.alarm(0)
                    return self._handle_execution_error(e)

            finally:
                self._cleanup_execution_environment(old_handler, old_stdout, old_stderr)

    def close(self) -> None:
        self.is_running = False
        self.shell.reset(new_session=False)

    def is_alive(self) -> bool:
        return self.is_running
