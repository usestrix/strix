"""Tests for the Linux parent-death signal helper in interface/main.py."""

from __future__ import annotations

import os
import signal
from unittest import mock

from strix.interface.main import (
    _enable_parent_death_signal,
    _install_cleanup_sigterm_handler,
)


def _ctypes_fixture() -> tuple[mock.Mock, mock.Mock, mock._patch]:
    """Return (ctypes_mock, libc_mock, sysmods_patch) for intercepting ctypes.

    ``_enable_parent_death_signal`` binds ``ctypes`` as a function-local name via
    ``import ctypes``, so patching the module attribute does not intercept it.
    Replacing the module in ``sys.modules`` does.
    """

    ctypes_mock = mock.Mock()
    libc_mock = ctypes_mock.CDLL.return_value
    return ctypes_mock, libc_mock, mock.patch.dict("sys.modules", {"ctypes": ctypes_mock})


@mock.patch("strix.interface.main.is_binary_install", return_value=False)
def test_noop_for_source_install(_mock_binary: mock.Mock) -> None:
    ctypes_mock, _, sysmods = _ctypes_fixture()
    with mock.patch("strix.interface.main.sys.platform", "linux"), sysmods:
        _enable_parent_death_signal()
        ctypes_mock.CDLL.assert_not_called()


@mock.patch("strix.interface.main.is_binary_install", return_value=True)
def test_noop_for_non_linux(_mock_binary: mock.Mock) -> None:
    ctypes_mock, _, sysmods = _ctypes_fixture()
    with mock.patch("strix.interface.main.sys.platform", "darwin"), sysmods:
        _enable_parent_death_signal()
        ctypes_mock.CDLL.assert_not_called()


@mock.patch("strix.interface.main.is_binary_install", return_value=True)
def test_registers_pdeathsig_when_frozen(_mock_binary: mock.Mock) -> None:
    _, libc_mock, sysmods = _ctypes_fixture()
    libc_mock.prctl.return_value = 0
    with (
        mock.patch("strix.interface.main.sys.platform", "linux"),
        mock.patch("strix.interface.main.os.getppid", return_value=1234),
        mock.patch("strix.interface.main.os.kill") as mock_kill,
        sysmods,
    ):
        _enable_parent_death_signal()
        libc_mock.prctl.assert_called_once_with(1, signal.SIGTERM)
        mock_kill.assert_not_called()


@mock.patch("strix.interface.main.is_binary_install", return_value=True)
def test_self_terminates_when_parent_died_before_registration(
    _mock_binary: mock.Mock,
) -> None:
    _, libc_mock, sysmods = _ctypes_fixture()
    libc_mock.prctl.return_value = 0
    with (
        mock.patch("strix.interface.main.sys.platform", "linux"),
        mock.patch("strix.interface.main.os.getppid", side_effect=[1234, 1]),
        mock.patch("strix.interface.main.os.kill") as mock_kill,
        sysmods,
    ):
        _enable_parent_death_signal()
        mock_kill.assert_called_once_with(os.getpid(), signal.SIGTERM)


@mock.patch("strix.interface.main.is_binary_install", return_value=True)
def test_warns_and_returns_when_prctl_fails(_mock_binary: mock.Mock) -> None:
    _, libc_mock, sysmods = _ctypes_fixture()
    libc_mock.prctl.return_value = -1
    with (
        mock.patch("strix.interface.main.sys.platform", "linux"),
        mock.patch("strix.interface.main.os.getppid", return_value=1234),
        mock.patch("strix.interface.main.os.kill") as mock_kill,
        sysmods,
    ):
        _enable_parent_death_signal()
        libc_mock.prctl.assert_called_once_with(1, signal.SIGTERM)
        mock_kill.assert_not_called()


def test_cleanup_sigterm_handler_cleans_state_and_exits() -> None:
    with mock.patch("strix.interface.main.signal.signal") as mock_signal:
        _install_cleanup_sigterm_handler()
    handler = mock_signal.call_args.args[1]

    state = mock.Mock()
    with (
        mock.patch("strix.report.state.get_global_report_state", return_value=state),
        mock.patch("sys.exit") as mock_exit,
    ):
        handler(signal.SIGTERM, None)
        state.cleanup.assert_called_once_with(status="interrupted")
        mock_exit.assert_called_once_with(1)


def test_cleanup_sigterm_handler_exits_without_state() -> None:
    with mock.patch("strix.interface.main.signal.signal") as mock_signal:
        _install_cleanup_sigterm_handler()
    handler = mock_signal.call_args.args[1]

    with (
        mock.patch("strix.report.state.get_global_report_state", return_value=None),
        mock.patch("sys.exit") as mock_exit,
    ):
        handler(signal.SIGTERM, None)
        mock_exit.assert_called_once_with(1)
