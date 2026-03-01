"""Tests for the Human-in-the-Loop (HIL) file-based input manager."""

import threading
import time
from pathlib import Path

import pytest

from strix.hil.input_manager import (
    HILTimeoutError,
    InputManager,
    clear_inbox,
    get_inbox_path,
    list_pending_requests,
    request_input,
    wait_for_response,
)
from strix.utils.resource_paths import get_strix_resource_path


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_inbox(tmp_path: Path) -> Path:
    """Create and return a temporary inbox directory for test isolation."""
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    return inbox


# ---------------------------------------------------------------------------
# get_inbox_path
# ---------------------------------------------------------------------------


class TestGetInboxPath:
    """Tests for the get_inbox_path function."""

    def test_returns_path_object(self) -> None:
        result = get_inbox_path()
        assert isinstance(result, Path)

    def test_directory_exists(self) -> None:
        result = get_inbox_path()
        assert result.is_dir()

    def test_default_is_under_strix_hil(self) -> None:
        result = get_inbox_path()
        assert result.name == "inbox"
        assert result.parent.name == "hil"

    def test_env_override(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        custom = tmp_path / "custom_inbox"
        monkeypatch.setenv("HIL_INBOX_PATH", str(custom))
        result = get_inbox_path()
        assert result == custom
        assert result.is_dir()

    def test_env_override_creates_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        nested = tmp_path / "a" / "b" / "c"
        monkeypatch.setenv("HIL_INBOX_PATH", str(nested))
        result = get_inbox_path()
        assert result.is_dir()


# ---------------------------------------------------------------------------
# request_input
# ---------------------------------------------------------------------------


class TestRequestInput:
    """Tests for the request_input function."""

    def test_creates_request_file(self, tmp_inbox: Path) -> None:
        path = request_input("abc123", "Run nmap -A target", inbox=tmp_inbox)
        assert path.exists()
        assert path.name == "req_abc123.txt"

    def test_request_file_contains_prompt(self, tmp_inbox: Path) -> None:
        prompt = "Run nmap -sV -sC -O target and paste full output"
        request_input("task1", prompt, inbox=tmp_inbox)
        content = (tmp_inbox / "req_task1.txt").read_text(encoding="utf-8")
        assert content == prompt

    def test_returns_path_of_request_file(self, tmp_inbox: Path) -> None:
        result = request_input("t1", "prompt", inbox=tmp_inbox)
        assert result == tmp_inbox / "req_t1.txt"

    def test_overwrites_existing_request(self, tmp_inbox: Path) -> None:
        request_input("dup", "first prompt", inbox=tmp_inbox)
        request_input("dup", "second prompt", inbox=tmp_inbox)
        content = (tmp_inbox / "req_dup.txt").read_text(encoding="utf-8")
        assert content == "second prompt"

    def test_handles_unicode_prompt(self, tmp_inbox: Path) -> None:
        prompt = "Test with unicode: cafe\u0301, \u00fc\u00f6\u00e4, \u4f60\u597d"
        request_input("unicode", prompt, inbox=tmp_inbox)
        content = (tmp_inbox / "req_unicode.txt").read_text(encoding="utf-8")
        assert content == prompt

    def test_handles_large_prompt(self, tmp_inbox: Path) -> None:
        prompt = "x" * 100_000
        request_input("large", prompt, inbox=tmp_inbox)
        content = (tmp_inbox / "req_large.txt").read_text(encoding="utf-8")
        assert len(content) == 100_000


# ---------------------------------------------------------------------------
# wait_for_response
# ---------------------------------------------------------------------------


class TestWaitForResponse:
    """Tests for the wait_for_response function."""

    def test_returns_response_content(self, tmp_inbox: Path) -> None:
        request_input("r1", "prompt", inbox=tmp_inbox)
        (tmp_inbox / "resp_r1.txt").write_text("nmap output here", encoding="utf-8")
        result = wait_for_response("r1", inbox=tmp_inbox, timeout=5)
        assert result == "nmap output here"

    def test_cleanup_removes_both_files(self, tmp_inbox: Path) -> None:
        request_input("r2", "prompt", inbox=tmp_inbox)
        (tmp_inbox / "resp_r2.txt").write_text("data", encoding="utf-8")
        wait_for_response("r2", inbox=tmp_inbox, timeout=5, cleanup=True)
        assert not (tmp_inbox / "req_r2.txt").exists()
        assert not (tmp_inbox / "resp_r2.txt").exists()

    def test_no_cleanup_preserves_files(self, tmp_inbox: Path) -> None:
        request_input("r3", "prompt", inbox=tmp_inbox)
        (tmp_inbox / "resp_r3.txt").write_text("data", encoding="utf-8")
        wait_for_response("r3", inbox=tmp_inbox, timeout=5, cleanup=False)
        assert (tmp_inbox / "req_r3.txt").exists()
        assert (tmp_inbox / "resp_r3.txt").exists()

    def test_timeout_raises_hil_timeout_error(self, tmp_inbox: Path) -> None:
        request_input("timeout_test", "prompt", inbox=tmp_inbox)
        with pytest.raises(HILTimeoutError, match="No response for task timeout_test"):
            wait_for_response(
                "timeout_test", inbox=tmp_inbox, timeout=1, poll_interval=1
            )

    def test_hil_timeout_error_is_timeout_error(self) -> None:
        assert issubclass(HILTimeoutError, TimeoutError)

    def test_polls_until_response_appears(self, tmp_inbox: Path) -> None:
        """Simulate the operator dropping a response file after a short delay."""
        request_input("delayed", "prompt", inbox=tmp_inbox)

        def _drop_response() -> None:
            time.sleep(1)
            (tmp_inbox / "resp_delayed.txt").write_text("delayed data", encoding="utf-8")

        thread = threading.Thread(target=_drop_response, daemon=True)
        thread.start()
        result = wait_for_response(
            "delayed", inbox=tmp_inbox, timeout=10, poll_interval=1
        )
        assert result == "delayed data"
        thread.join(timeout=5)

    def test_handles_large_response(self, tmp_inbox: Path) -> None:
        request_input("big", "prompt", inbox=tmp_inbox)
        large_data = "PORT   STATE SERVICE VERSION\n" * 10_000
        (tmp_inbox / "resp_big.txt").write_text(large_data, encoding="utf-8")
        result = wait_for_response("big", inbox=tmp_inbox, timeout=5)
        assert len(result) == len(large_data)

    def test_handles_binary_like_content(self, tmp_inbox: Path) -> None:
        request_input("bin", "prompt", inbox=tmp_inbox)
        content = "\\x00\\x01\\x02 mixed content \n\ttabs and nulls"
        (tmp_inbox / "resp_bin.txt").write_text(content, encoding="utf-8")
        result = wait_for_response("bin", inbox=tmp_inbox, timeout=5)
        assert result == content


# ---------------------------------------------------------------------------
# list_pending_requests
# ---------------------------------------------------------------------------


class TestListPendingRequests:
    """Tests for the list_pending_requests function."""

    def test_empty_inbox(self, tmp_inbox: Path) -> None:
        result = list_pending_requests(inbox=tmp_inbox)
        assert result == []

    def test_single_pending_request(self, tmp_inbox: Path) -> None:
        request_input("p1", "Run nmap", inbox=tmp_inbox)
        result = list_pending_requests(inbox=tmp_inbox)
        assert len(result) == 1
        assert result[0]["task_id"] == "p1"
        assert result[0]["prompt"] == "Run nmap"

    def test_multiple_pending_requests(self, tmp_inbox: Path) -> None:
        request_input("a", "first", inbox=tmp_inbox)
        request_input("b", "second", inbox=tmp_inbox)
        request_input("c", "third", inbox=tmp_inbox)
        result = list_pending_requests(inbox=tmp_inbox)
        assert len(result) == 3
        task_ids = {r["task_id"] for r in result}
        assert task_ids == {"a", "b", "c"}

    def test_excludes_answered_requests(self, tmp_inbox: Path) -> None:
        request_input("answered", "prompt", inbox=tmp_inbox)
        (tmp_inbox / "resp_answered.txt").write_text("done", encoding="utf-8")
        request_input("pending", "still waiting", inbox=tmp_inbox)
        result = list_pending_requests(inbox=tmp_inbox)
        assert len(result) == 1
        assert result[0]["task_id"] == "pending"

    def test_results_are_sorted_by_task_id(self, tmp_inbox: Path) -> None:
        for tid in ["z", "a", "m"]:
            request_input(tid, f"task {tid}", inbox=tmp_inbox)
        result = list_pending_requests(inbox=tmp_inbox)
        ids = [r["task_id"] for r in result]
        assert ids == sorted(ids)


# ---------------------------------------------------------------------------
# clear_inbox
# ---------------------------------------------------------------------------


class TestClearInbox:
    """Tests for the clear_inbox function."""

    def test_empty_inbox_returns_zero(self, tmp_inbox: Path) -> None:
        assert clear_inbox(inbox=tmp_inbox) == 0

    def test_clears_request_files(self, tmp_inbox: Path) -> None:
        request_input("c1", "prompt", inbox=tmp_inbox)
        request_input("c2", "prompt", inbox=tmp_inbox)
        count = clear_inbox(inbox=tmp_inbox)
        assert count == 2
        assert list(tmp_inbox.glob("req_*")) == []

    def test_clears_response_files(self, tmp_inbox: Path) -> None:
        (tmp_inbox / "resp_x.txt").write_text("data", encoding="utf-8")
        count = clear_inbox(inbox=tmp_inbox)
        assert count == 1
        assert list(tmp_inbox.glob("resp_*")) == []

    def test_clears_both_request_and_response(self, tmp_inbox: Path) -> None:
        request_input("both", "prompt", inbox=tmp_inbox)
        (tmp_inbox / "resp_both.txt").write_text("data", encoding="utf-8")
        count = clear_inbox(inbox=tmp_inbox)
        assert count == 2

    def test_preserves_non_hil_files(self, tmp_inbox: Path) -> None:
        (tmp_inbox / "other.txt").write_text("keep me", encoding="utf-8")
        (tmp_inbox / ".gitkeep").write_text("", encoding="utf-8")
        request_input("del", "prompt", inbox=tmp_inbox)
        clear_inbox(inbox=tmp_inbox)
        assert (tmp_inbox / "other.txt").exists()
        assert (tmp_inbox / ".gitkeep").exists()


# ---------------------------------------------------------------------------
# InputManager class
# ---------------------------------------------------------------------------


class TestInputManager:
    """Tests for the InputManager stateful wrapper."""

    def test_init_default_inbox(self, tmp_inbox: Path) -> None:
        mgr = InputManager(inbox=tmp_inbox)
        assert mgr.inbox == tmp_inbox

    def test_ask_creates_request_and_reads_response(self, tmp_inbox: Path) -> None:
        mgr = InputManager(inbox=tmp_inbox, default_timeout=5)
        # Pre-create response so ask() finds it immediately.
        (tmp_inbox / "resp_t1.txt").write_text("result data", encoding="utf-8")
        result = mgr.ask("t1", "Run sqlmap")
        assert result == "result data"

    def test_ask_records_history(self, tmp_inbox: Path) -> None:
        mgr = InputManager(inbox=tmp_inbox, default_timeout=5)
        (tmp_inbox / "resp_h1.txt").write_text("out1", encoding="utf-8")
        mgr.ask("h1", "p1")
        (tmp_inbox / "resp_h2.txt").write_text("out2", encoding="utf-8")
        mgr.ask("h2", "p2")
        assert len(mgr.history) == 2
        assert mgr.history[0]["task_id"] == "h1"
        assert mgr.history[1]["response"] == "out2"

    def test_ask_timeout(self, tmp_inbox: Path) -> None:
        mgr = InputManager(inbox=tmp_inbox, default_timeout=1)
        with pytest.raises(HILTimeoutError):
            mgr.ask("nope", "prompt")

    def test_pending_delegates_to_list_pending(self, tmp_inbox: Path) -> None:
        mgr = InputManager(inbox=tmp_inbox)
        request_input("m1", "hello", inbox=tmp_inbox)
        pending = mgr.pending()
        assert len(pending) == 1
        assert pending[0]["task_id"] == "m1"

    def test_clear_delegates_to_clear_inbox(self, tmp_inbox: Path) -> None:
        mgr = InputManager(inbox=tmp_inbox)
        request_input("d1", "p", inbox=tmp_inbox)
        count = mgr.clear()
        assert count == 1
        assert list(tmp_inbox.glob("req_*")) == []

    def test_history_is_copy(self, tmp_inbox: Path) -> None:
        mgr = InputManager(inbox=tmp_inbox, default_timeout=5)
        (tmp_inbox / "resp_cp.txt").write_text("data", encoding="utf-8")
        mgr.ask("cp", "prompt")
        h1 = mgr.history
        h2 = mgr.history
        assert h1 == h2
        assert h1 is not h2


# ---------------------------------------------------------------------------
# Tool skill .md Operator Help section
# ---------------------------------------------------------------------------


TOOLS_DIR = get_strix_resource_path("skills") / "tools"


class TestToolSkillOperatorHelp:
    """Verify all 25 tool skill files have the Operator Help section."""

    @pytest.fixture
    def all_tool_files(self) -> list[tuple[str, str]]:
        return [
            (md.stem, md.read_text(encoding="utf-8"))
            for md in sorted(TOOLS_DIR.glob("*.md"))
        ]

    def test_all_have_operator_help_section(
        self, all_tool_files: list[tuple[str, str]]
    ) -> None:
        for stem, content in all_tool_files:
            assert "## Operator Help" in content, (
                f"{stem}.md missing Operator Help section"
            )

    def test_all_mention_hil_inbox(
        self, all_tool_files: list[tuple[str, str]]
    ) -> None:
        for stem, content in all_tool_files:
            assert "strix/hil/inbox/resp_" in content, (
                f"{stem}.md missing inbox path reference"
            )

    def test_all_mention_hil_inbox_path_env(
        self, all_tool_files: list[tuple[str, str]]
    ) -> None:
        for stem, content in all_tool_files:
            assert "HIL_INBOX_PATH" in content, (
                f"{stem}.md missing HIL_INBOX_PATH env var reference"
            )

    def test_pipe_command_matches_tool_name(
        self, all_tool_files: list[tuple[str, str]]
    ) -> None:
        """The pipe example should reference the tool's own name."""
        for stem, content in all_tool_files:
            # Tool name in the md uses hyphens (e.g. aircrack-ng, john-the-ripper)
            expected_tool = stem.replace("_", "-")
            assert expected_tool in content, (
                f"{stem}.md pipe example does not reference {expected_tool}"
            )


# ---------------------------------------------------------------------------
# Config integration
# ---------------------------------------------------------------------------


class TestHILConfig:
    """Verify the Config class tracks the HIL_INBOX_PATH variable."""

    def test_hil_inbox_path_in_tracked_vars(self) -> None:
        from strix.config.config import Config

        tracked = Config.tracked_vars()
        assert "HIL_INBOX_PATH" in tracked

    def test_config_get_hil_inbox_path_default(self) -> None:
        from strix.config.config import Config

        # Without env var set, should return None (the class default).
        result = Config.get("hil_inbox_path")
        assert result is None or isinstance(result, str)

    def test_config_get_hil_inbox_path_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from strix.config.config import Config

        monkeypatch.setenv("HIL_INBOX_PATH", "/custom/path")
        result = Config.get("hil_inbox_path")
        assert result == "/custom/path"


# ---------------------------------------------------------------------------
# Module-level imports via __init__.py
# ---------------------------------------------------------------------------


class TestHILModuleExports:
    """Verify the strix.hil package exports all public symbols."""

    def test_import_from_package(self) -> None:
        from strix.hil import (
            HILTimeoutError,
            InputManager,
            clear_inbox,
            get_inbox_path,
            list_pending_requests,
            request_input,
            wait_for_response,
        )

        assert callable(request_input)
        assert callable(wait_for_response)
        assert callable(list_pending_requests)
        assert callable(clear_inbox)
        assert callable(get_inbox_path)
        assert issubclass(HILTimeoutError, TimeoutError)
        assert callable(InputManager)
