"""Regression tests for run-directory path handling and clone safety."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from strix.core.paths import RUNS_DIR_NAME, run_dir_for, validate_run_name


_UTILS_PATH = Path(__file__).resolve().parents[1] / "strix" / "interface" / "utils.py"
_UTILS_SPEC = importlib.util.spec_from_file_location("strix_interface_utils_test", _UTILS_PATH)
if _UTILS_SPEC is None or _UTILS_SPEC.loader is None:
    raise RuntimeError(f"Unable to load utils module from {_UTILS_PATH}")
_UTILS_MODULE = importlib.util.module_from_spec(_UTILS_SPEC)
sys.modules[_UTILS_SPEC.name] = _UTILS_MODULE
_UTILS_SPEC.loader.exec_module(_UTILS_MODULE)

clone_repository = _UTILS_MODULE.clone_repository
validate_repo_url = _UTILS_MODULE.validate_repo_url


class TestRunDirectoryPaths(unittest.TestCase):
    """Verify run names cannot escape the intended storage directory."""

    def test_validate_run_name_accepts_simple_name(self) -> None:
        self.assertEqual(validate_run_name("scan-123"), "scan-123")

    def test_validate_run_name_strips_outer_whitespace(self) -> None:
        self.assertEqual(validate_run_name("  scan-123  "), "scan-123")

    def test_validate_run_name_rejects_empty_name(self) -> None:
        with self.assertRaises(ValueError):
            validate_run_name("   ")

    def test_validate_run_name_rejects_relative_traversal(self) -> None:
        for candidate in ("../escape", "..", "./run", "nested/run", r"..\escape", r"nested\run"):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                validate_run_name(candidate)

    def test_validate_run_name_rejects_absolute_paths(self) -> None:
        for candidate in ("/tmp/escape", str(Path("/var/tmp/escape"))):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                validate_run_name(candidate)

    def test_run_dir_for_keeps_valid_runs_under_runs_directory(self) -> None:
        cwd = Path("/tmp/project")
        expected = cwd / RUNS_DIR_NAME / "scan-123"
        self.assertEqual(run_dir_for("scan-123", cwd=cwd), expected)


class TestCloneRepositoryHardening(unittest.TestCase):
    """Verify clone_repository preserves argument and path boundaries."""

    def test_clone_repository_uses_end_of_options_separator(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            with (
                patch.object(_UTILS_MODULE.shutil, "which", return_value="/usr/bin/git"),
                patch.object(_UTILS_MODULE.tempfile, "gettempdir", return_value=tmp_dir),
                patch.object(_UTILS_MODULE.subprocess, "run") as mock_run,
            ):
                result = clone_repository("-c core.sshCommand=evil", "scan-123")

            expected = f"{tmp_dir}/strix_repos/scan-123/-c core.sshCommand=evil"
            self.assertEqual(result, expected)
            args = mock_run.call_args.args[0]
            self.assertEqual(args[:3], ["/usr/bin/git", "clone", "--"])
            self.assertEqual(args[3], "-c core.sshCommand=evil")

    def test_clone_repository_rejects_invalid_run_name(self) -> None:
        with self.assertRaises(ValueError):
            clone_repository("https://example.com/repo.git", "../escape")

    def test_clone_repository_rejects_unsafe_transport(self) -> None:
        # The remote-helper transport ``ext::`` can execute arbitrary commands;
        # it must be rejected before any filesystem or subprocess work happens.
        with (
            patch.object(_UTILS_MODULE.shutil, "which", return_value="/usr/bin/git"),
            patch.object(_UTILS_MODULE.subprocess, "run") as mock_run,
            self.assertRaises(ValueError),
        ):
            clone_repository("ext::sh -c 'id'", "scan-123")

        mock_run.assert_not_called()


class TestRepoUrlValidation(unittest.TestCase):
    """Verify repository URLs are restricted to safe git transports."""

    def test_accepts_supported_url_forms(self) -> None:
        for candidate in (
            "https://github.com/org/repo.git",
            "http://example.com/org/repo",
            "ssh://git@github.com/org/repo.git",
            "git://github.com/org/repo.git",
            "git@github.com:org/repo.git",
            "/srv/mirrors/repo.git",
        ):
            with self.subTest(candidate=candidate):
                self.assertEqual(validate_repo_url(candidate), candidate)

    def test_strips_outer_whitespace(self) -> None:
        self.assertEqual(
            validate_repo_url("  https://github.com/org/repo.git  "),
            "https://github.com/org/repo.git",
        )

    def test_rejects_empty_url(self) -> None:
        with self.assertRaises(ValueError):
            validate_repo_url("   ")

    def test_rejects_remote_helper_transports(self) -> None:
        for candidate in ("ext::sh -c 'id'", "fd::17/foo", "transport::address"):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                validate_repo_url(candidate)

    def test_rejects_disallowed_schemes(self) -> None:
        for candidate in ("file:///etc/passwd", "ftp://example.com/repo.git"):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                validate_repo_url(candidate)


if __name__ == "__main__":
    unittest.main()
