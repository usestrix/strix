"""Tests for release workflow compatibility-sensitive settings."""

from __future__ import annotations

from pathlib import Path


WORKFLOW = Path(".github/workflows/build-release.yml")


def _matrix_entries() -> list[dict[str, str]]:
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
    entries: list[dict[str, str]] = []
    current: dict[str, str] | None = None

    for raw_line in lines:
        line = raw_line.strip()
        if line.startswith("- os: "):
            current = {"os": line.removeprefix("- os: ")}
            entries.append(current)
        elif current is not None and line.startswith("target: "):
            current["target"] = line.removeprefix("target: ")

    return entries


def _runner_for_target(target: str) -> str:
    for entry in _matrix_entries():
        if entry.get("target") == target:
            return entry["os"]
    msg = f"release matrix target not found: {target}"
    raise AssertionError(msg)


def test_linux_release_binary_build_uses_older_glibc_baseline() -> None:
    assert _runner_for_target("linux-x86_64") == "ubuntu-22.04"
