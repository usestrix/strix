"""Structural checks for release signing + checksum publishing (#1267)."""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path

import pytest
import yaml


WORKFLOW = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "build-release.yml"
ATTEST_PIN = "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6"


def _workflow() -> dict[str, object]:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _job(name: str) -> dict[str, object]:
    jobs = _workflow()["jobs"]
    assert isinstance(jobs, dict)
    job = jobs[name]
    assert isinstance(job, dict)
    return job


def _steps(job_name: str) -> list[dict[str, object]]:
    steps = _job(job_name)["steps"]
    assert isinstance(steps, list)
    return [step for step in steps if isinstance(step, dict)]


def _step_named(job_name: str, name: str) -> dict[str, object]:
    for step in _steps(job_name):
        if step.get("name") == name:
            return step
    raise AssertionError(f"missing step {name!r} in job {job_name!r}")


def test_build_job_requests_attestation_permissions() -> None:
    permissions = _job("build")["permissions"]
    assert permissions == {
        "contents": "read",
        "id-token": "write",
        "attestations": "write",
    }


def test_release_job_requests_attestation_permissions() -> None:
    permissions = _job("release")["permissions"]
    assert permissions == {
        "contents": "write",
        "id-token": "write",
        "attestations": "write",
    }


def test_build_attests_unix_and_windows_archives_with_pinned_action() -> None:
    unix = _step_named("build", "Attest Unix archive and wheel")
    windows = _step_named("build", "Attest Windows archive and wheel")

    assert unix["uses"] == ATTEST_PIN
    assert unix["id"] == "attest-unix"
    assert unix["if"] == "runner.os != 'Windows'"
    assert "dist/release/*.tar.gz" in str(unix["with"]["subject-path"])
    assert "dist/*.whl" in str(unix["with"]["subject-path"])

    assert windows["uses"] == ATTEST_PIN
    assert windows["id"] == "attest-windows"
    assert windows["if"] == "runner.os == 'Windows'"
    assert "dist/release/*.zip" in str(windows["with"]["subject-path"])
    assert "dist/*.whl" in str(windows["with"]["subject-path"])


def test_build_publishes_and_uploads_per_target_attestation_bundle() -> None:
    publish = _step_named("build", "Publish attestation bundle")
    assert "strix-${{ matrix.target }}.intoto.jsonl" in str(publish["run"])
    assert "attest-unix.outputs.bundle-path" in str(publish["env"]["BUNDLE_PATH"])
    assert "attest-windows.outputs.bundle-path" in str(publish["env"]["BUNDLE_PATH"])

    upload = next(
        step for step in _steps("build") if "upload-artifact@" in str(step.get("uses", ""))
    )
    paths = str(upload["with"]["path"])
    assert "dist/release/*.intoto.jsonl" in paths
    assert "dist/release/*.tar.gz" in paths
    assert "dist/*.whl" in paths


def test_release_generates_sha256sums_excluding_provenance_bundles() -> None:
    generate = _step_named("release", "Generate SHA256SUMS")
    assert generate["working-directory"] == "release"
    script = str(generate["run"])
    assert "SHA256SUMS" in script
    assert "! -name '*.intoto.jsonl'" in script
    assert "sha256sum" in script


def test_release_attests_and_publishes_sha256sums_bundle() -> None:
    attest = _step_named("release", "Attest SHA256SUMS")
    assert attest["uses"] == ATTEST_PIN
    assert attest["id"] == "attest-sums"
    assert attest["with"]["subject-path"] == "release/SHA256SUMS"

    publish = _step_named("release", "Publish SHA256SUMS attestation bundle")
    assert "SHA256SUMS.intoto.jsonl" in str(publish["run"])
    assert "attest-sums.outputs.bundle-path" in str(publish["env"]["BUNDLE_PATH"])

    create = _step_named("release", "Create Release")
    assert create["with"]["files"] == "release/**"


def test_every_action_use_is_sha_pinned() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    uses = re.findall(r"^\s+uses:\s+(\S+)", text, flags=re.MULTILINE)
    assert uses
    for ref in uses:
        assert "@" in ref, ref
        digest = ref.rsplit("@", 1)[1]
        assert re.fullmatch(r"[0-9a-f]{40}", digest), ref


def test_sha256sums_script_hashes_product_files_only(tmp_path: Path) -> None:
    """Run the release job's checksum recipe against a fixture tree."""
    release_dir = tmp_path / "release"
    release_dir.mkdir()
    (release_dir / "strix-1.0.0-linux-x86_64.tar.gz").write_bytes(b"archive-bytes")
    (release_dir / "strix_agent-1.0.0-py3-none-any.whl").write_bytes(b"wheel-bytes")
    (release_dir / "strix-linux-x86_64.intoto.jsonl").write_text(
        '{"attestation":true}\n',
        encoding="utf-8",
    )

    script = str(_step_named("release", "Generate SHA256SUMS")["run"])
    result = subprocess.run(  # noqa: S603
        ["/bin/bash", "-c", script],
        cwd=release_dir,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr

    sums_path = release_dir / "SHA256SUMS"
    assert sums_path.is_file()
    lines = [line for line in sums_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    names = {line.split()[-1] for line in lines}
    assert names == {
        "strix-1.0.0-linux-x86_64.tar.gz",
        "strix_agent-1.0.0-py3-none-any.whl",
    }
    assert "strix-linux-x86_64.intoto.jsonl" not in names
    assert "SHA256SUMS" not in names

    for line in lines:
        digest, name = line.split()
        expected = hashlib.sha256((release_dir / name).read_bytes()).hexdigest()
        assert digest == expected


def test_release_notes_include_manual_verification() -> None:
    create = _step_named("release", "Create Release")
    body = str(create["with"]["body"])
    assert "## Verify this release" in body
    assert "sha256sum -c --ignore-missing SHA256SUMS" in body
    assert "gh attestation verify" in body
    assert "usestrix/strix/.github/workflows/build-release.yml" in body
    assert "docs.strix.ai/quickstart#verify-a-downloaded-release" in body
    assert create["with"]["generate_release_notes"] is True


@pytest.mark.parametrize(
    ("job_name", "step_name"),
    [
        ("build", "Attest Unix archive and wheel"),
        ("build", "Attest Windows archive and wheel"),
        ("release", "Attest SHA256SUMS"),
    ],
)
def test_attest_steps_comment_mentions_pinned_version(
    job_name: str,
    step_name: str,
) -> None:
    # Keep the SHA pin and the human version comment in sync with checkout/etc.
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6  # v4.2.2" in text
    step = _step_named(job_name, step_name)
    assert step["uses"] == ATTEST_PIN
