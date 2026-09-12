import hashlib
import io
import json
import platform
import time
from pathlib import Path

import pytest
from rich.console import Console

from strix.interface import update_check


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_check, "_CACHE_PATH", tmp_path / "update-check.json")
    monkeypatch.setattr(update_check, "_background_thread", None)
    monkeypatch.delenv("STRIX_NO_UPDATE_CHECK", raising=False)
    for key in ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "BUILDKITE", "CIRCLECI"):
        monkeypatch.delenv(key, raising=False)


@pytest.mark.parametrize(
    ("latest", "current", "expected"),
    [
        ("1.2.0", "1.1.0", True),
        ("1.1.0", "1.1.0", False),
        ("1.0.9", "1.1.0", False),
        ("2.0.0", "1.99.99", True),
        ("1.10.0", "1.9.0", True),
        ("v1.2.0", "1.1.0", True),
        ("not-a-version", "1.1.0", False),
        ("1.2.0", "unknown", False),
    ],
)
def test_is_newer(latest: str, current: str, expected: bool) -> None:
    assert update_check._is_newer(latest, current) is expected


def test_get_available_update_from_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    update_check._CACHE_PATH.write_text(
        json.dumps({"latest_version": "9.9.9", "checked_at": time.time()})
    )
    monkeypatch.setattr(update_check, "get_version", lambda: "1.0.0")
    assert update_check.get_available_update() == "9.9.9"


def test_get_available_update_up_to_date(monkeypatch: pytest.MonkeyPatch) -> None:
    update_check._CACHE_PATH.write_text(
        json.dumps({"latest_version": "1.0.0", "checked_at": time.time()})
    )
    monkeypatch.setattr(update_check, "get_version", lambda: "1.0.0")
    assert update_check.get_available_update() is None


def test_get_available_update_disabled_by_env(monkeypatch: pytest.MonkeyPatch) -> None:
    update_check._CACHE_PATH.write_text(
        json.dumps({"latest_version": "9.9.9", "checked_at": time.time()})
    )
    monkeypatch.setattr(update_check, "get_version", lambda: "1.0.0")
    monkeypatch.setenv("STRIX_NO_UPDATE_CHECK", "1")
    assert update_check.get_available_update() is None


def test_get_available_update_disabled_in_ci(monkeypatch: pytest.MonkeyPatch) -> None:
    update_check._CACHE_PATH.write_text(
        json.dumps({"latest_version": "9.9.9", "checked_at": time.time()})
    )
    monkeypatch.setattr(update_check, "get_version", lambda: "1.0.0")
    monkeypatch.setenv("CI", "true")
    assert update_check.get_available_update() is None


def test_get_available_update_corrupt_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    update_check._CACHE_PATH.write_text("{not json")
    monkeypatch.setattr(update_check, "get_version", lambda: "1.0.0")
    assert update_check.get_available_update() is None


def test_background_check_skipped_when_fresh(monkeypatch: pytest.MonkeyPatch) -> None:
    update_check._CACHE_PATH.write_text(
        json.dumps({"latest_version": "1.0.0", "checked_at": time.time()})
    )
    called = False

    def fake_refresh() -> None:
        nonlocal called
        called = True

    monkeypatch.setattr(update_check, "_refresh_cache", fake_refresh)
    update_check.start_background_check()
    assert update_check._background_thread is None
    assert called is False


def test_background_check_runs_when_stale(monkeypatch: pytest.MonkeyPatch) -> None:
    update_check._CACHE_PATH.write_text(
        json.dumps({"latest_version": "1.0.0", "checked_at": time.time() - 2 * 24 * 60 * 60})
    )
    monkeypatch.setattr(update_check, "_fetch_latest_version", lambda: "1.2.3")
    update_check.start_background_check()
    assert update_check._background_thread is not None
    update_check._background_thread.join(timeout=5)
    cache = json.loads(update_check._CACHE_PATH.read_text())
    assert cache["latest_version"] == "1.2.3"


def test_skipped_version_suppresses_update(monkeypatch: pytest.MonkeyPatch) -> None:
    update_check._CACHE_PATH.write_text(
        json.dumps({"latest_version": "9.9.9", "checked_at": time.time()})
    )
    monkeypatch.setattr(update_check, "get_version", lambda: "1.0.0")
    update_check.skip_version("9.9.9")
    assert update_check.get_available_update() is None
    assert update_check.get_available_update(respect_skip=False) == "9.9.9"


def test_newer_release_overrides_skipped_version(monkeypatch: pytest.MonkeyPatch) -> None:
    update_check._CACHE_PATH.write_text(
        json.dumps(
            {"latest_version": "9.9.10", "checked_at": time.time(), "skipped_version": "9.9.9"}
        )
    )
    monkeypatch.setattr(update_check, "get_version", lambda: "1.0.0")
    assert update_check.get_available_update() == "9.9.10"


def test_write_cache_preserves_existing_fields() -> None:
    update_check.skip_version("9.9.9")
    update_check._write_cache(latest_version="1.2.3", checked_at=123.0)
    cache = json.loads(update_check._CACHE_PATH.read_text())
    assert cache == {"latest_version": "1.2.3", "checked_at": 123.0, "skipped_version": "9.9.9"}


def test_get_upgrade_command_all_methods() -> None:
    assert update_check.get_upgrade_command("binary") == "strix --update"
    assert update_check.get_upgrade_command("pipx") == "pipx upgrade strix-agent"
    assert update_check.get_upgrade_command("uv") == "uv tool upgrade strix-agent"
    assert update_check.get_upgrade_command("pip") == "pip install --upgrade strix-agent"


def test_self_update_non_binary_prints_command(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_check, "is_binary_install", lambda: False)
    buffer = io.StringIO()
    assert update_check.self_update(Console(file=buffer)) is False
    assert "upgrade" in buffer.getvalue()


def test_self_update_already_latest(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_check, "is_binary_install", lambda: True)
    monkeypatch.setattr(update_check, "_fetch_latest_version", lambda: "1.0.0")
    monkeypatch.setattr(update_check, "get_version", lambda: "1.0.0")
    assert update_check.self_update() is True


def test_restart_env_strips_pyinstaller_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("_MEIPASS2", "/stale/_MEIold")
    monkeypatch.setenv("_PYI_APPLICATION_HOME_DIR", "/stale/_MEIold")
    monkeypatch.setenv("_PYI_ARCHIVE_FILE", "/old/strix")
    monkeypatch.setenv("_PYI_PARENT_PROCESS_LEVEL", "1")
    monkeypatch.setenv("SOME_OTHER_VAR", "kept")

    env = update_check.restart_env()

    assert "SOME_OTHER_VAR" in env
    assert "_MEIPASS2" not in env
    assert not any(key.startswith("_PYI_") for key in env)


def test_restart_env_restores_library_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LD_LIBRARY_PATH", "/stale/_MEIold/lib")
    monkeypatch.setenv("LD_LIBRARY_PATH_ORIG", "/usr/lib/custom")
    monkeypatch.setenv("DYLD_LIBRARY_PATH", "/stale/_MEIold/lib")
    monkeypatch.delenv("DYLD_LIBRARY_PATH_ORIG", raising=False)

    env = update_check.restart_env()

    assert env["LD_LIBRARY_PATH"] == "/usr/lib/custom"
    assert "LD_LIBRARY_PATH_ORIG" not in env
    assert "DYLD_LIBRARY_PATH" not in env


def test_sha256_file(tmp_path: Path) -> None:
    path = tmp_path / "blob"
    path.write_bytes(b"strix")
    assert update_check._sha256_file(path) == hashlib.sha256(b"strix").hexdigest()


@pytest.mark.parametrize(
    ("system", "machine", "expected"),
    [
        ("Linux", "x86_64", "linux-x86_64"),
        ("Linux", "aarch64", "linux-arm64"),
        ("Linux", "arm64", "linux-arm64"),
        ("Darwin", "arm64", "macos-arm64"),
        ("Darwin", "riscv64", None),
    ],
)
def test_release_target(
    monkeypatch: pytest.MonkeyPatch,
    system: str,
    machine: str,
    expected: str | None,
) -> None:
    monkeypatch.setattr(platform, "system", lambda: system)
    monkeypatch.setattr(platform, "machine", lambda: machine)

    assert update_check._release_target() == expected


def test_self_update_uses_linux_arm64_release(monkeypatch: pytest.MonkeyPatch) -> None:
    requested_update: list[tuple[str, str]] = []

    def record_download(version: str, target: str, _console: Console) -> bool:
        requested_update.append((version, target))
        return True

    monkeypatch.setattr(update_check, "is_binary_install", lambda: True)
    monkeypatch.setattr(update_check, "get_version", lambda: "1.0.0")
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(platform, "machine", lambda: "aarch64")
    monkeypatch.setattr(update_check, "_download_and_replace", record_download)

    assert update_check.self_update(Console(file=io.StringIO()), version="1.1.0") is True
    assert requested_update == [("1.1.0", "linux-arm64")]
