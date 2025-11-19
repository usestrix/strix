import logging
import re
import time
import uuid
from enum import Enum
from pathlib import Path
from typing import Any

import libtmux


logger = logging.getLogger(__name__)


class BashCommandStatus(Enum):
    CONTINUE = "continue"
    COMPLETED = "completed"
    NO_CHANGE_TIMEOUT = "no_change_timeout"
    HARD_TIMEOUT = "hard_timeout"


def _remove_command_prefix(command_output: str, command: str) -> str:
    return command_output.lstrip().removeprefix(command.lstrip()).lstrip()


class TerminalSession:
    POLL_INTERVAL = 0.5
    HISTORY_LIMIT = 10_000
    PS1_END = "]$ "

    def __init__(self, session_id: str, work_dir: str = "/workspace") -> None:
        self.session_id = session_id
        self.work_dir = str(Path(work_dir).resolve())
        self._closed = False
        self._cwd = self.work_dir

        self.server: libtmux.Server | None = None
        self.session: libtmux.Session | None = None
        self.window: libtmux.Window | None = None
        self.pane: libtmux.Pane | None = None

        self.prev_status: BashCommandStatus | None = None
        self.prev_output: str = ""
        self._initialized = False

        self.initialize()

    @property
    def PS1(self) -> str:  # noqa: N802
        return r"[STRIX_$?]$ "

    @property
    def PS1_PATTERN(self) -> str:  # noqa: N802
        return r"\[STRIX_(\d+)\]"

    def initialize(self) -> None:
        self.server = libtmux.Server()

        session_name = f"strix-{self.session_id}-{uuid.uuid4()}"
        self.session = self.server.new_session(
            session_name=session_name,
            start_directory=self.work_dir,
            kill_session=True,
            x=120,
            y=30,
        )

        self.session.set_option("history-limit", str(self.HISTORY_LIMIT))
        self.session.history_limit = self.HISTORY_LIMIT

        _initial_window = self.session.active_window
        self.window = self.session.new_window(
            window_name="bash",
            window_shell="/bin/bash",
            start_directory=self.work_dir,
        )
        self.pane = self.window.active_pane
        _initial_window.kill()

        self.pane.send_keys(f'export PROMPT_COMMAND=\'export PS1="{self.PS1}"\'; export PS2=""')
        time.sleep(0.1)
        self._clear_screen()

        self.prev_status = None
        self.prev_output = ""
        self._closed = False

        self._cwd = str(Path(self.work_dir).resolve())
        self._initialized = True

        assert self.server is not None
        assert self.session is not None
        assert self.window is not None
        assert self.pane is not None

    def _get_pane_content(self) -> str:
        if not self.pane:
            raise RuntimeError("Terminal session not properly initialized")
        return "\n".join(
            line.rstrip() for line in self.pane.cmd("capture-pane", "-J", "-pS", "-").stdout
        )

    def _clear_screen(self) -> None:
        if not self.pane:
            raise RuntimeError("Terminal session not properly initialized")
        self.pane.send_keys("C-l", enter=False)
        time.sleep(0.1)
        self.pane.cmd("clear-history")

    def _is_control_key(self, command: str) -> bool:
        return (
            (command.startswith("C-") and len(command) >= 3)
            or (command.startswith("^") and len(command) >= 2)
            or (command.startswith("S-") and len(command) >= 3)
            or (command.startswith("M-") and len(command) >= 3)
        )

    def _is_function_key(self, command: str) -> bool:
        if not command.startswith("F") or len(command) > 3:
            return False
        try:
            num_part = command[1:]
            return num_part.isdigit() and 1 <= int(num_part) <= 12
        except (ValueError, IndexError):
            return False

    def _is_navigation_or_special_key(self, command: str) -> bool:
        navigation_keys = {"Up", "Down", "Left", "Right", "Home", "End"}
        special_keys = {"BSpace", "BTab", "DC", "Enter", "Escape", "IC", "Space", "Tab"}
        page_keys = {"NPage", "PageDown", "PgDn", "PPage", "PageUp", "PgUp"}

        return command in navigation_keys or command in special_keys or command in page_keys

    def _is_complex_modifier_key(self, command: str) -> bool:
        return "-" in command and any(
            command.startswith(prefix)
            for prefix in ["C-S-", "C-M-", "S-M-", "M-S-", "M-C-", "S-C-"]
        )

    def _is_special_key(self, command: str) -> bool:
        _command = command.strip()

        if not _command:
            return False

        return (
            self._is_control_key(_command)
            or self._is_function_key(_command)
            or self._is_navigation_or_special_key(_command)
            or self._is_complex_modifier_key(_command)
        )

    def _matches_ps1_metadata(self, content: str) -> list[re.Match[str]]:
        return list(re.finditer(self.PS1_PATTERN + r"\]\$ ", content))

    def _get_command_output(
        self,
        command: str,
        raw_command_output: str,
        continue_prefix: str = "",
    ) -> str:
        if self.prev_output:
            command_output = raw_command_output.removeprefix(self.prev_output)
            if continue_prefix:
                command_output = continue_prefix + command_output
        else:
            command_output = raw_command_output
        self.prev_output = raw_command_output
        command_output = _remove_command_prefix(command_output, command)
        return command_output.rstrip()

    def _combine_outputs_between_matches(
        self,
        pane_content: str,
        ps1_matches: list[re.Match[str]],
        get_content_before_last_match: bool = False,
    ) -> str:
        if len(ps1_matches) == 1:
            if get_content_before_last_match:
                return pane_content[: ps1_matches[0].start()]
            return pane_content[ps1_matches[0].end() + 1 :]
        if len(ps1_matches) == 0:
            return pane_content

        combined_output = ""
        for i in range(len(ps1_matches) - 1):
            output_segment = pane_content[ps1_matches[i].end() + 1 : ps1_matches[i + 1].start()]
            combined_output += output_segment + "\n"
        combined_output += pane_content[ps1_matches[-1].end() + 1 :]
        return combined_output

    def _extract_exit_code_from_matches(self, ps1_matches: list[re.Match[str]]) -> int | None:
        if not ps1_matches:
            return None

        last_match = ps1_matches[-1]
        try:
            return int(last_match.group(1))
        except (ValueError, IndexError):
            return None

    def _handle_empty_command(
        self,
        cur_pane_output: str,
        ps1_matches: list[re.Match[str]],
        is_command_running: bool,
        timeout: float,
    ) -> dict[str, Any]:
        if not is_command_running:
            raw_command_output = self._combine_outputs_between_matches(cur_pane_output, ps1_matches)
            command_output = self._get_command_output("", raw_command_output)
            return {
                "content": command_output,
                "status": "completed",
                "exit_code": 0,
                "working_dir": self._cwd,
            }

        start_time = time.time()
        last_pane_output = cur_pane_output

        while True:
            cur_pane_output = self._get_pane_content()
            ps1_matches = self._matches_ps1_metadata(cur_pane_output)

            if cur_pane_output.rstrip().endswith(self.PS1_END.rstrip()) or len(ps1_matches) > 0:
                exit_code = self._extract_exit_code_from_matches(ps1_matches)
                raw_command_output = self._combine_outputs_between_matches(
                    cur_pane_output, ps1_matches
                )
                command_output = self._get_command_output("", raw_command_output)
                self.prev_status = BashCommandStatus.COMPLETED
                self.prev_output = ""
                self._ready_for_next_command()
                return {
                    "content": command_output,
                    "status": "completed",
                    "exit_code": exit_code or 0,
                    "working_dir": self._cwd,
                }

            elapsed_time = time.time() - start_time
            if elapsed_time >= timeout:
                raw_command_output = self._combine_outputs_between_matches(
                    cur_pane_output, ps1_matches
                )
                command_output = self._get_command_output("", raw_command_output)
                return {
                    "content": command_output
                    + f"\n[Command still running after {timeout}s - showing output so far]",
                    "status": "running",
                    "exit_code": None,
                    "working_dir": self._cwd,
                }

            if cur_pane_output != last_pane_output:
                last_pane_output = cur_pane_output

            time.sleep(self.POLL_INTERVAL)

    def _handle_input_command(
        self, command: str, no_enter: bool, is_command_running: bool
    ) -> dict[str, Any]:
        if not is_command_running:
            return {
                "content": "No command is currently running. Cannot send input.",
                "status": "error",
                "exit_code": None,
                "working_dir": self._cwd,
            }

        if not self.pane:
            raise RuntimeError("Terminal session not properly initialized")

        is_special_key = self._is_special_key(command)
        should_add_enter = not is_special_key and not no_enter
        self.pane.send_keys(command, enter=should_add_enter)

        time.sleep(2)
        cur_pane_output = self._get_pane_content()
        ps1_matches = self._matches_ps1_metadata(cur_pane_output)
        raw_command_output = self._combine_outputs_between_matches(cur_pane_output, ps1_matches)
        command_output = self._get_command_output(command, raw_command_output)

        is_still_running = not (
            cur_pane_output.rstrip().endswith(self.PS1_END.rstrip()) or len(ps1_matches) > 0
        )

        if is_still_running:
            return {
                "content": command_output,
                "status": "running",
                "exit_code": None,
                "working_dir": self._cwd,
            }

        exit_code = self._extract_exit_code_from_matches(ps1_matches)
        self.prev_status = BashCommandStatus.COMPLETED
        self.prev_output = ""
        self._ready_for_next_command()
        return {
            "content": command_output,
            "status": "completed",
            "exit_code": exit_code or 0,
            "working_dir": self._cwd,
        }

    def _execute_new_command(self, command: str, no_enter: bool, timeout: float) -> dict[str, Any]:
        if not self.pane:
            raise RuntimeError("Terminal session not properly initialized")

        initial_pane_output = self._get_pane_content()
        initial_ps1_matches = self._matches_ps1_metadata(initial_pane_output)
        initial_ps1_count = len(initial_ps1_matches)

        start_time = time.time()
        last_pane_output = initial_pane_output

        is_special_key = self._is_special_key(command)
        should_add_enter = not is_special_key and not no_enter
        self.pane.send_keys(command, enter=should_add_enter)

        while True:
            cur_pane_output = self._get_pane_content()
            ps1_matches = self._matches_ps1_metadata(cur_pane_output)
            current_ps1_count = len(ps1_matches)

            if cur_pane_output != last_pane_output:
                last_pane_output = cur_pane_output

            if current_ps1_count > initial_ps1_count or cur_pane_output.rstrip().endswith(
                self.PS1_END.rstrip()
            ):
                exit_code = self._extract_exit_code_from_matches(ps1_matches)

                get_content_before_last_match = bool(len(ps1_matches) == 1)
                raw_command_output = self._combine_outputs_between_matches(
                    cur_pane_output,
                    ps1_matches,
                    get_content_before_last_match=get_content_before_last_match,
                )

                command_output = self._get_command_output(command, raw_command_output)
                self.prev_status = BashCommandStatus.COMPLETED
                self.prev_output = ""
                self._ready_for_next_command()

                return {
                    "content": command_output,
                    "status": "completed",
                    "exit_code": exit_code or 0,
                    "working_dir": self._cwd,
                }

            elapsed_time = time.time() - start_time
            if elapsed_time >= timeout:
                raw_command_output = self._combine_outputs_between_matches(
                    cur_pane_output, ps1_matches
                )
                command_output = self._get_command_output(
                    command,
                    raw_command_output,
                    continue_prefix="[Below is the output of the previous command.]\n",
                )
                self.prev_status = BashCommandStatus.CONTINUE

                timeout_msg = (
                    f"\n[Command still running after {timeout}s - showing output so far. "
                    "Use C-c to interrupt if needed.]"
                )
                return {
                    "content": command_output + timeout_msg,
                    "status": "running",
                    "exit_code": None,
                    "working_dir": self._cwd,
                }

            time.sleep(self.POLL_INTERVAL)

    def execute(
        self, command: str, is_input: bool = False, timeout: float = 10.0, no_enter: bool = False
    ) -> dict[str, Any]:
        if not self._initialized:
            raise RuntimeError("Bash session is not initialized")

        cur_pane_output = self._get_pane_content()
        ps1_matches = self._matches_ps1_metadata(cur_pane_output)
        is_command_running = not (
            cur_pane_output.rstrip().endswith(self.PS1_END.rstrip()) or len(ps1_matches) > 0
        )

        if command.strip() == "":
            return self._handle_empty_command(
                cur_pane_output, ps1_matches, is_command_running, timeout
            )

        is_special_key = self._is_special_key(command)

        if is_input:
            return self._handle_input_command(command, no_enter, is_command_running)

        if is_special_key and is_command_running:
            return self._handle_input_command(command, no_enter, is_command_running)

        if is_command_running:
            return {
                "content": (
                    "A command is already running. Use is_input=true to send input to it, "
                    "or interrupt it first (e.g., with C-c)."
                ),
                "status": "error",
                "exit_code": None,
                "working_dir": self._cwd,
            }

        return self._execute_new_command(command, no_enter, timeout)

    def _ready_for_next_command(self) -> None:
        self._clear_screen()

    def is_running(self) -> bool:
        if self._closed or not self.session:
            return False
        try:
            return self.session.id in [s.id for s in self.server.sessions] if self.server else False
        except (AttributeError, OSError) as e:
            logger.debug("Error checking if session is running: %s", e)
            return False

    def get_working_dir(self) -> str:
        return self._cwd

    def close(self) -> None:
        if self._closed:
            return

        if self.session:
            try:
                self.session.kill()
            except (AttributeError, OSError) as e:
                logger.debug("Error closing terminal session: %s", e)

        self._closed = True
        self.server = None
        self.session = None
        self.window = None
        self.pane = None
