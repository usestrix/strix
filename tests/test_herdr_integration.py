from unittest.mock import MagicMock, patch

import pytest

from strix.interface import herdr


def test_is_active_false_when_env_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HERDR_ENV", raising=False)
    monkeypatch.delenv("HERDR_BIN_PATH", raising=False)
    monkeypatch.delenv("HERDR_PANE_ID", raising=False)
    assert not herdr.is_active()


def test_is_active_true_when_env_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HERDR_ENV", "1")
    monkeypatch.setenv("HERDR_BIN_PATH", "/usr/local/bin/herdr")
    monkeypatch.setenv("HERDR_PANE_ID", "w1:p1")
    assert herdr.is_active()


def test_report_state_calls_herdr_bin_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HERDR_ENV", "1")
    monkeypatch.setenv("HERDR_BIN_PATH", "/usr/local/bin/herdr")
    monkeypatch.setenv("HERDR_PANE_ID", "w1:p1")

    mock_res = MagicMock(returncode=0)
    with patch("subprocess.run", return_value=mock_res) as mock_run:
        result = herdr.report_state(
            "working",
            session_id="run-123",
            resume_argv=["strix", "--resume", "run-123"],
        )
        assert result is True
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "/usr/local/bin/herdr"
        assert cmd[1:3] == ["pane", "report-agent"]
        assert cmd[3] == "w1:p1"
        assert "--agent" in cmd and "strix" in cmd
        assert "--state" in cmd and "working" in cmd
        assert "--agent-session-id" in cmd and "run-123" in cmd
        assert "--" in cmd
        assert cmd[cmd.index("--") + 1 :] == ["strix", "--resume", "run-123"]


def test_report_state_returns_false_on_nonzero_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HERDR_ENV", "1")
    monkeypatch.setenv("HERDR_BIN_PATH", "/usr/local/bin/herdr")
    monkeypatch.setenv("HERDR_PANE_ID", "w1:p1")

    mock_res = MagicMock(returncode=1)
    with patch("subprocess.run", return_value=mock_res):
        assert not herdr.report_state("working")


def test_release_agent_calls_herdr_bin_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HERDR_ENV", "1")
    monkeypatch.setenv("HERDR_BIN_PATH", "/usr/local/bin/herdr")
    monkeypatch.setenv("HERDR_PANE_ID", "w1:p1")

    mock_res = MagicMock(returncode=0)
    with patch("subprocess.run", return_value=mock_res) as mock_run:
        result = herdr.release_agent()
        assert result is True
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "/usr/local/bin/herdr"
        assert cmd[1:3] == ["pane", "release-agent"]
        assert cmd[3] == "w1:p1"


def test_release_agent_returns_false_on_nonzero_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HERDR_ENV", "1")
    monkeypatch.setenv("HERDR_BIN_PATH", "/usr/local/bin/herdr")
    monkeypatch.setenv("HERDR_PANE_ID", "w1:p1")

    mock_res = MagicMock(returncode=1)
    with patch("subprocess.run", return_value=mock_res):
        assert not herdr.release_agent()
