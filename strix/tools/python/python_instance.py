import io
import sys
import threading
from typing import Any

from IPython.core.interactiveshell import InteractiveShell


MAX_STDOUT_LENGTH = 10_000
MAX_STDERR_LENGTH = 5_000

# Module-level thread-local storage for per-execution output buffers.
# Each background execution thread sets these attributes before running user
# code and clears them in its finally block.  _PerThreadStream.write() reads
# them to route output to the correct per-session StringIO without any shared
# mutable state or global locking.
_thread_local = threading.local()


class _PerThreadStream:
    """
    Transparent proxy for sys.stdout / sys.stderr.

    Installed once at module import time.  Each execution thread stores its own
    StringIO capture buffer in the module-level _thread_local object before
    calling run_cell.  Writes that occur on a thread with a registered buffer
    are routed to that buffer; writes on all other threads (the main thread,
    IPython internals, etc.) fall through to the original real stream.

    Because routing uses thread-local storage there is no global lock and no
    serialisation across sessions: a hung or slow thread has zero impact on
    any other session's ability to capture output.
    """

    def __init__(self, original: Any, attr: str) -> None:
        self._original = original
        self._attr = attr  # "stdout_capture" or "stderr_capture"

    def _capture(self) -> io.StringIO | None:
        return getattr(_thread_local, self._attr, None)

    def write(self, data: str) -> int:
        buf = self._capture()
        return buf.write(data) if buf is not None else self._original.write(data)

    def flush(self) -> None:
        buf = self._capture()
        if buf is not None:
            buf.flush()
        else:
            self._original.flush()

    def fileno(self) -> int:
        return self._original.fileno()

    def isatty(self) -> bool:
        return False

    @property
    def encoding(self) -> str:
        return getattr(self._original, "encoding", "utf-8")

    @property
    def errors(self) -> str | None:
        return getattr(self._original, "errors", None)


# Install the per-thread proxies once at module import time.
# Every subsequent write on any thread is routed through these objects.
# Guard against double-installation if the module is somehow reloaded.
if not isinstance(sys.stdout, _PerThreadStream):
    sys.stdout = _PerThreadStream(sys.stdout, "stdout_capture")  # type: ignore[assignment]
if not isinstance(sys.stderr, _PerThreadStream):
    sys.stderr = _PerThreadStream(sys.stderr, "stderr_capture")  # type: ignore[assignment]


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
            from strix.tools.proxy import proxy_actions

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
            result_container: dict[str, Any] = {}
            stdout_capture = io.StringIO()
            stderr_capture = io.StringIO()

            def _run_code() -> None:
                # Register per-thread capture buffers.  The _PerThreadStream
                # proxy installed at module level routes all writes on this
                # thread to these buffers without any global lock, so a hung
                # thread cannot block output capture for any other session.
                _thread_local.stdout_capture = stdout_capture
                _thread_local.stderr_capture = stderr_capture
                try:
                    execution_result = self.shell.run_cell(
                        code, silent=False, store_history=True
                    )
                    result_container["execution_result"] = execution_result
                    result_container["stdout"] = stdout_capture.getvalue()
                    result_container["stderr"] = stderr_capture.getvalue()
                except (KeyboardInterrupt, SystemExit) as e:
                    result_container["error"] = e
                except Exception as e:  # noqa: BLE001
                    result_container["error"] = e
                finally:
                    # Clear references so that any daemon threads spawned inside
                    # run_cell that outlive this scope fall back to the real streams
                    # rather than writing to a StringIO that may no longer be read.
                    _thread_local.stdout_capture = None
                    _thread_local.stderr_capture = None

            exec_thread = threading.Thread(target=_run_code, daemon=True)
            exec_thread.start()
            exec_thread.join(timeout=timeout)

            if exec_thread.is_alive():
                # The thread is still running (hung or timed out).  Its
                # thread-local state is entirely private to it — reading or
                # modifying those buffers from this thread is a data race.
                # The background thread will clear its own _thread_local
                # attributes in its finally block whenever it terminates.
                # No global resource is leaked; all other sessions are
                # completely unaffected.
                return self._handle_execution_error(
                    TimeoutError(f"Code execution timed out after {timeout} seconds")
                )

            if "error" in result_container:
                return self._handle_execution_error(result_container["error"])

            if "execution_result" in result_container:
                return self._format_execution_result(
                    result_container["execution_result"],
                    result_container.get("stdout", ""),
                    result_container.get("stderr", ""),
                )

            return self._handle_execution_error(RuntimeError("Unknown execution error"))

    def close(self) -> None:
        self.is_running = False
        self.shell.reset(new_session=False)

    def is_alive(self) -> bool:
        return self.is_running
