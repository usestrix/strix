"""Local-source packaging and scan upload tests."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import zipfile
from typing import TYPE_CHECKING, Any

import pytest

from strix.interface import cloud
from strix.interface.cloud import http, source_upload


if TYPE_CHECKING:
    from pathlib import Path


class FakeResponse:
    def __init__(self, payload: Any, status_code: int = 200) -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = json.dumps(payload)
        self.content = b""
        self.ok = 200 <= status_code < 400
        self.headers = {"content-type": "application/json"}

    def json(self) -> Any:
        return self._payload


class MalformedJsonResponse(FakeResponse):
    def json(self) -> Any:
        raise ValueError("malformed JSON")


@pytest.fixture(autouse=True)
def _token_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_API_TOKEN", "test-token")


def _git_source(tmp_path: Path) -> Path:
    git = shutil.which("git")
    assert git is not None
    subprocess.run([git, "init", "-q", str(tmp_path)], check=True)  # noqa: S603
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("hello\n", encoding="utf-8")
    (tmp_path / ".gitignore").write_text("ignored.log\n", encoding="utf-8")
    (tmp_path / "ignored.log").write_text("ignored\n", encoding="utf-8")
    subprocess.run(  # noqa: S603
        [git, "-C", str(tmp_path), "add", "app.py", ".gitignore"], check=True
    )
    return tmp_path


def test_source_defaults_are_private_and_git_aware(tmp_path: Path) -> None:
    source = _git_source(tmp_path)
    (source / ".hidden.py").write_text("hidden\n", encoding="utf-8")
    (source / ".env").write_text("TOKEN=secret\n", encoding="utf-8")
    (source / "private.pem").write_text("secret\n", encoding="utf-8")
    (source / "fixture.zip").write_bytes(b"not really a zip")
    (source / "node_modules").mkdir()
    (source / "node_modules" / "dep.js").write_text("dep\n", encoding="utf-8")
    (source / "linked.py").symlink_to(source / "app.py")

    bundle = source_upload.prepare_source(
        str(source),
        include_hidden=False,
        include_sensitive=False,
        include_archives=False,
        exclude=[],
    )
    try:
        names = [item.archive_name for item in bundle.manifest.files]
        assert names == ["README.md", "app.py"]
        assert bundle.manifest.total_bytes > 0
        assert bundle.archive_bytes <= source_upload.MAX_ARCHIVE_BYTES
        assert bundle.manifest.excluded["hidden"] == 3
        assert bundle.manifest.excluded["sensitive_filename"] == 1
        assert bundle.manifest.excluded["nested_archive"] == 1
        assert bundle.manifest.excluded["dependency_or_build_output"] == 1
        assert bundle.manifest.excluded["symlink_or_non_file"] == 1
        with zipfile.ZipFile(bundle.archive_path) as archive:
            assert archive.namelist() == names
    finally:
        source_upload.remove_bundle(bundle)


def test_hidden_and_sensitive_files_need_separate_opt_ins(tmp_path: Path) -> None:
    source = _git_source(tmp_path)
    (source / ".env").write_text("TOKEN=secret\n", encoding="utf-8")
    (source / ".github").mkdir()
    (source / ".github" / "workflow.yml").write_text("name: test\n", encoding="utf-8")

    hidden = source_upload.select_source(source, include_hidden=True)
    hidden_names = {item.archive_name for item in hidden.files}
    assert ".github/workflow.yml" in hidden_names
    assert ".env" not in hidden_names

    sensitive = source_upload.select_source(source, include_hidden=True, include_sensitive=True)
    assert ".env" in {item.archive_name for item in sensitive.files}
    assert all(
        not name.startswith(".git/") for name in (item.archive_name for item in sensitive.files)
    )


def test_hidden_opt_in_still_excludes_common_credential_paths(tmp_path: Path) -> None:
    paths = [
        ".aws/credentials",
        ".git-credentials",
        ".docker/config.json",
        ".config/gcloud/application_default_credentials.json",
        ".config/gcloud/credentials.db",
        ".azure/accessTokens.json",
        ".kube/config",
    ]
    for relative in paths:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("credential material\n", encoding="utf-8")

    hidden_only = source_upload.select_source(tmp_path, include_hidden=True)
    assert not ({item.archive_name for item in hidden_only.files} & set(paths))
    assert hidden_only.excluded["sensitive_filename"] == len(paths)

    explicitly_sensitive = source_upload.select_source(
        tmp_path, include_hidden=True, include_sensitive=True
    )
    assert set(paths) <= {item.archive_name for item in explicitly_sensitive.files}


def test_hidden_opt_in_cannot_reenable_dependency_cache_or_build_dirs(tmp_path: Path) -> None:
    excluded_dirs = [
        ".venv",
        "env",
        ".tox",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".next",
        ".nuxt",
        ".gradle",
    ]
    for directory in excluded_dirs:
        path = tmp_path / directory / "artifact.txt"
        path.parent.mkdir(parents=True)
        path.write_text("generated\n", encoding="utf-8")
    (tmp_path / ".github" / "workflow.yml").parent.mkdir()
    (tmp_path / ".github" / "workflow.yml").write_text("name: test\n", encoding="utf-8")

    manifest = source_upload.select_source(tmp_path, include_hidden=True)

    names = {item.archive_name for item in manifest.files}
    assert ".github/workflow.yml" in names
    assert not any(name.split("/", 1)[0] in excluded_dirs for name in names)
    assert manifest.excluded["dependency_or_build_output"] == len(excluded_dirs)


def test_strixignore_and_cli_excludes_are_applied(tmp_path: Path) -> None:
    (tmp_path / "keep.py").write_text("keep\n", encoding="utf-8")
    (tmp_path / "generated.py").write_text("generated\n", encoding="utf-8")
    (tmp_path / "test_app.py").write_text("test\n", encoding="utf-8")
    (tmp_path / ".strixignore").write_text("generated.py\n", encoding="utf-8")

    manifest = source_upload.select_source(tmp_path, exclude=["test_*.py"])
    assert [item.archive_name for item in manifest.files] == ["keep.py"]
    assert manifest.excluded["user_pattern"] == 2


def test_strixignore_trailing_slash_excludes_the_whole_directory(tmp_path: Path) -> None:
    (tmp_path / "keep.py").write_text("keep\n", encoding="utf-8")
    private = tmp_path / "private" / "nested"
    private.mkdir(parents=True)
    (private / "secret.txt").write_text("do not upload\n", encoding="utf-8")
    cache = tmp_path / "packages" / "cache"
    cache.mkdir(parents=True)
    (cache / "artifact.txt").write_text("do not upload\n", encoding="utf-8")
    (tmp_path / ".strixignore").write_text("private/\n", encoding="utf-8")

    manifest = source_upload.select_source(tmp_path, exclude=["cache/"])

    assert [item.archive_name for item in manifest.files] == ["keep.py"]
    assert manifest.excluded["user_pattern"] >= 2


def test_source_limits_expanded_bytes_before_compression(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(source_upload, "MAX_TOTAL_BYTES", 5)
    (tmp_path / "large.py").write_bytes(b"a" * 6)
    with pytest.raises(http.CloudError, match="expanded-size limit"):
        source_upload.select_source(tmp_path)


def test_source_rejects_archives_by_suffix_and_actual_bytes(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('safe')\n", encoding="utf-8")
    (tmp_path / "dependency.jar").write_bytes(b"not-even-a-valid-archive")
    (tmp_path / "renamed-source.txt").write_bytes(b"PK\x03\x04" + b"x" * 32)
    tar_header = bytearray(512)
    tar_header[257:262] = b"ustar"
    (tmp_path / "renamed-tar.bin").write_bytes(tar_header)

    manifest = source_upload.select_source(tmp_path)

    assert [item.archive_name for item in manifest.files] == ["app.py"]
    assert manifest.excluded["nested_archive"] == 3


def test_source_enumeration_is_bounded_before_filtering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(source_upload, "MAX_CANDIDATE_PATHS", 2)
    for index in range(3):
        (tmp_path / f"file-{index}.py").write_text("safe\n", encoding="utf-8")

    with pytest.raises(http.CloudError, match="enumeration exceeded 2 paths"):
        source_upload.select_source(tmp_path)


def test_strixignore_size_and_pattern_counts_are_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ignore = tmp_path / ".strixignore"
    monkeypatch.setattr(source_upload, "MAX_IGNORE_BYTES", 4)
    ignore.write_text("12345", encoding="utf-8")
    with pytest.raises(http.CloudError, match="larger than the 4-byte limit"):
        source_upload.select_source(tmp_path)

    monkeypatch.setattr(source_upload, "MAX_IGNORE_BYTES", 1_000)
    monkeypatch.setattr(source_upload, "MAX_IGNORE_PATTERNS", 1)
    ignore.write_text("one\ntwo\n", encoding="utf-8")
    with pytest.raises(http.CloudError, match="more than 1 exclusion patterns"):
        source_upload.select_source(tmp_path)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="named pipes are not supported")
def test_strixignore_must_be_a_nonblocking_regular_file(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    os.mkfifo(tmp_path / ".strixignore")

    with pytest.raises(http.CloudError, match="must be a regular file"):
        source_upload.select_source(tmp_path)


def test_source_archive_rejects_a_path_swapped_after_manifest_review(tmp_path: Path) -> None:
    source_path = tmp_path / "app.py"
    source_path.write_bytes(b"safe")
    manifest = source_upload.select_source(tmp_path)

    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"oops")
    replacement.replace(source_path)

    with pytest.raises(http.CloudError, match="changed while the source archive was being built"):
        source_upload._write_archive(tmp_path / "source.zip", manifest.files)


def test_source_archive_rejects_same_inode_same_size_change_after_review(tmp_path: Path) -> None:
    source_path = tmp_path / "app.py"
    source_path.write_bytes(b"safe")
    manifest = source_upload.select_source(tmp_path)

    source_path.write_bytes(b"evil")
    selected = manifest.files[0]
    os.utime(
        source_path,
        ns=(selected.mtime_ns + 1_000_000, selected.mtime_ns + 1_000_000),
    )

    with pytest.raises(http.CloudError, match="changed while the source archive was being built"):
        source_upload._write_archive(tmp_path / "source.zip", manifest.files)


def test_source_dry_run_never_calls_the_api(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    (tmp_path / "app.py").write_text("print('safe')\n", encoding="utf-8")

    def fail_request(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("dry-run must not make an API request")

    monkeypatch.setattr(http, "request", fail_request)
    assert (
        cloud.run_cloud(
            ["scans", "start", "--source", str(tmp_path), "--dry-run", "--show-files", "--json"]
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["source"]["files"] == ["app.py"]
    assert payload["source"]["archive_sha256"]


def test_noninteractive_source_upload_requires_yes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    (tmp_path / "app.py").write_text("print('safe')\n", encoding="utf-8")
    monkeypatch.setattr(
        http,
        "request",
        lambda *_args, **_kwargs: pytest.fail("approval must happen before any API request"),
    )
    assert cloud.run_cloud(["scans", "start", "--source", str(tmp_path), "--json"]) == 1
    output = capsys.readouterr().out
    assert "requires explicit approval" in output
    assert "--approve-sha256 <reviewed hash>" in output
    assert "--yes" in output
    assert "one-shot approval" in output


def test_source_digest_approval_rejects_a_changed_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    source = tmp_path / "app.py"
    source.write_text("print('reviewed')\n", encoding="utf-8")
    assert (
        cloud.run_cloud(["scans", "start", "--source", str(tmp_path), "--dry-run", "--json"]) == 0
    )
    approved = json.loads(capsys.readouterr().out)["source"]["archive_sha256"]
    source.write_text("print('changed')\n", encoding="utf-8")
    monkeypatch.setattr(
        http,
        "request",
        lambda *_args, **_kwargs: pytest.fail("a changed snapshot must not reach the API"),
    )

    assert (
        cloud.run_cloud(
            [
                "scans",
                "start",
                "--source",
                str(tmp_path),
                "--approve-sha256",
                approved,
                "--json",
            ]
        )
        == http.EXIT_ERROR
    )
    assert "does not match" in json.loads(capsys.readouterr().out)["error"]


def test_source_upload_is_completed_and_attached_to_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    (tmp_path / "app.py").write_text("print('safe')\n", encoding="utf-8")
    calls: list[tuple[str, str, dict[str, Any]]] = []
    uploaded_path: Path | None = None

    def fake_request(method: str, path: str, **kwargs: Any) -> FakeResponse:
        calls.append((method, path, kwargs))
        if path == "/uploads/request":
            return FakeResponse(
                {
                    "upload_id": "upload-1",
                    "signed_url": "https://storage.test/object",
                    "token": "signed",
                }
            )
        if path == "/uploads/complete":
            return FakeResponse({"id": "upload-1"})
        if path == "/scans":
            return FakeResponse({"scan_id": "scan-1", "status": "pending"})
        raise AssertionError(path)

    def fake_upload(_url: str, _token: str, path: Path) -> None:
        nonlocal uploaded_path
        uploaded_path = path
        assert path.exists()

    monkeypatch.setattr(http, "request", fake_request)
    monkeypatch.setattr(http, "upload_file", fake_upload)

    assert (
        cloud.run_cloud(
            ["scans", "start", "--source", str(tmp_path), "--yes", "--show-files", "--json"]
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["upload_id"] == "upload-1"
    assert payload["scan"]["scan_id"] == "scan-1"
    assert payload["source"]["files"] == ["app.py"]
    scan_call = next(call for call in calls if call[1] == "/scans")
    assert scan_call[2]["body"] == {
        "engagement_type": "code_review",
        "upload_ids": ["upload-1"],
    }
    assert uploaded_path is not None and not uploaded_path.exists()


def test_source_upload_with_domain_is_a_live_test(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    (tmp_path / "app.py").write_text("print('safe')\n", encoding="utf-8")
    calls: list[tuple[str, str, dict[str, Any]]] = []

    def fake_request(method: str, path: str, **kwargs: Any) -> FakeResponse:
        calls.append((method, path, kwargs))
        if path == "/uploads/request":
            return FakeResponse(
                {
                    "upload_id": "upload-1",
                    "signed_url": "https://storage.test/object",
                    "token": "signed",
                }
            )
        if path == "/uploads/complete":
            return FakeResponse({"id": "upload-1"})
        if path == "/scans":
            return FakeResponse({"scan_id": "scan-1", "status": "pending"})
        raise AssertionError(path)

    monkeypatch.setattr(http, "request", fake_request)
    monkeypatch.setattr(http, "upload_file", lambda *_args, **_kwargs: None)

    assert (
        cloud.run_cloud(
            [
                "scans",
                "start",
                "--source",
                str(tmp_path),
                "--domain-ids",
                "domain-1",
                "--yes",
                "--json",
            ]
        )
        == 0
    )
    scan_call = next(call for call in calls if call[1] == "/scans")
    assert scan_call[2]["body"] == {
        "engagement_type": "live_test",
        "domain_ids": ["domain-1"],
        "upload_ids": ["upload-1"],
    }
    assert json.loads(capsys.readouterr().out)["scan"]["scan_id"] == "scan-1"


def test_failed_scan_deletes_completed_source_upload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "app.py").write_text("print('safe')\n", encoding="utf-8")
    paths: list[tuple[str, str]] = []

    def fake_request(method: str, path: str, **_kwargs: Any) -> FakeResponse:
        paths.append((method, path))
        if path == "/uploads/request":
            return FakeResponse(
                {
                    "upload_id": "upload-1",
                    "signed_url": "https://storage.test/object",
                    "token": "signed",
                }
            )
        if path == "/uploads/complete":
            return FakeResponse({"id": "upload-1"})
        if path == "/scans":
            return FakeResponse({"detail": "not enough credits"}, status_code=402)
        if path == "/uploads/upload-1":
            return FakeResponse({"ok": True})
        raise AssertionError(path)

    monkeypatch.setattr(http, "request", fake_request)
    monkeypatch.setattr(http, "upload_file", lambda *_args, **_kwargs: None)
    assert cloud.run_cloud(["scans", "start", "--source", str(tmp_path), "--yes", "--json"]) == 5
    assert ("DELETE", "/uploads/upload-1") in paths


@pytest.mark.parametrize(
    "failure",
    ["network", "server", "malformed_success", "malformed_json_success", "wrong_shape_success"],
)
def test_ambiguous_scan_launch_retains_completed_source_upload(
    failure: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: Any,
) -> None:
    (tmp_path / "app.py").write_text("print('safe')\n", encoding="utf-8")
    paths: list[tuple[str, str]] = []

    def fake_request(method: str, path: str, **_kwargs: Any) -> FakeResponse:
        paths.append((method, path))
        if path == "/uploads/request":
            return FakeResponse(
                {
                    "upload_id": "upload-ambiguous",
                    "signed_url": "https://storage.test/object",
                    "token": "signed",
                }
            )
        if path == "/uploads/complete":
            return FakeResponse({"id": "upload-ambiguous"})
        if path == "/scans":
            if failure == "network":
                raise http.CloudError("connection closed before a response")
            if failure == "server":
                return FakeResponse({"detail": "temporary failure"}, status_code=500)
            if failure == "malformed_json_success":
                return MalformedJsonResponse("accepted")
            if failure == "wrong_shape_success":
                return FakeResponse({})
            response = FakeResponse("accepted")
            response.headers = {"content-type": "text/html"}
            return response
        if path == "/uploads/upload-ambiguous":
            pytest.fail("an upload with an ambiguous launch must not be deleted")
        raise AssertionError(path)

    monkeypatch.setattr(http, "request", fake_request)
    monkeypatch.setattr(http, "upload_file", lambda *_args, **_kwargs: None)

    assert (
        cloud.run_cloud(["scans", "start", "--source", str(tmp_path), "--yes", "--json"])
        == http.EXIT_ERROR
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["upload_id"] == "upload-ambiguous"
    assert payload["upload_retained"] is True
    assert payload["launch_outcome_unknown"] is True
    assert "outcome is unknown" in payload["error"]
    assert ("DELETE", "/uploads/upload-ambiguous") not in paths


def test_mismatched_upload_completion_response_is_cleaned_before_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "app.py").write_text("print('safe')\n", encoding="utf-8")
    paths: list[tuple[str, str]] = []

    def fake_request(method: str, path: str, **_kwargs: Any) -> FakeResponse:
        paths.append((method, path))
        if path == "/uploads/request":
            return FakeResponse(
                {
                    "upload_id": "upload-expected",
                    "signed_url": "https://storage.test/object",
                    "token": "signed",
                }
            )
        if path == "/uploads/complete":
            return FakeResponse({"id": "upload-different"})
        if path == "/uploads/upload-expected":
            return FakeResponse({"ok": True})
        if path == "/scans":
            pytest.fail("a scan must not launch before upload completion is confirmed")
        raise AssertionError(path)

    monkeypatch.setattr(http, "request", fake_request)
    monkeypatch.setattr(http, "upload_file", lambda *_args, **_kwargs: None)

    assert cloud.run_cloud(["scans", "start", "--source", str(tmp_path), "--yes"]) == 1
    assert ("DELETE", "/uploads/upload-expected") in paths


def test_interrupted_scan_launch_retains_completed_source_upload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    (tmp_path / "app.py").write_text("print('safe')\n", encoding="utf-8")
    paths: list[tuple[str, str]] = []

    def fake_request(method: str, path: str, **_kwargs: Any) -> FakeResponse:
        paths.append((method, path))
        if path == "/uploads/request":
            return FakeResponse(
                {
                    "upload_id": "upload-interrupted",
                    "signed_url": "https://storage.test/object",
                    "token": "signed",
                }
            )
        if path == "/uploads/complete":
            return FakeResponse({"id": "upload-interrupted"})
        if path == "/scans":
            raise KeyboardInterrupt
        if path == "/uploads/upload-interrupted":
            pytest.fail("an upload with an interrupted launch must not be deleted")
        raise AssertionError(path)

    monkeypatch.setattr(http, "request", fake_request)
    monkeypatch.setattr(http, "upload_file", lambda *_args, **_kwargs: None)

    assert cloud.run_cloud(["scans", "start", "--source", str(tmp_path), "--yes", "--json"]) == 130
    payload = json.loads(capsys.readouterr().out)
    assert payload["interrupted"] is True
    assert payload["upload_id"] == "upload-interrupted"
    assert payload["upload_retained"] is True
    assert payload["launch_outcome_unknown"] is True
    assert "scans list" in payload["error"]
    assert ("DELETE", "/uploads/upload-interrupted") not in paths


@pytest.mark.parametrize("cleanup_failure", ["timeout", "server"])
def test_failed_automatic_upload_cleanup_reports_retained_id(
    cleanup_failure: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: Any,
) -> None:
    (tmp_path / "app.py").write_text("print('safe')\n", encoding="utf-8")

    def fake_request(method: str, path: str, **_kwargs: Any) -> FakeResponse:
        if path == "/uploads/request":
            return FakeResponse(
                {
                    "upload_id": "upload-orphaned",
                    "signed_url": "https://storage.test/object",
                    "token": "signed",
                }
            )
        if path == "/uploads/upload-orphaned" and method == "DELETE":
            if cleanup_failure == "timeout":
                raise http.CloudError("cleanup timed out")
            return FakeResponse({"detail": "cleanup unavailable"}, status_code=500)
        raise AssertionError((method, path))

    monkeypatch.setattr(http, "request", fake_request)
    monkeypatch.setattr(
        http,
        "upload_file",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(http.CloudError("upload failed")),
    )

    assert (
        cloud.run_cloud(["scans", "start", "--source", str(tmp_path), "--yes", "--json"])
        == http.EXIT_ERROR
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["upload_id"] == "upload-orphaned"
    assert payload["upload_retained"] is True
    assert payload["cleanup_unknown"] is True
    assert "uploads delete upload-orphaned" in payload["error"]


def test_incomplete_upload_credentials_delete_the_reserved_upload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "app.py").write_text("print('safe')\n", encoding="utf-8")
    paths: list[tuple[str, str]] = []

    def fake_request(method: str, path: str, **_kwargs: Any) -> FakeResponse:
        paths.append((method, path))
        if path == "/uploads/request":
            return FakeResponse({"upload_id": "upload-incomplete"})
        if path == "/uploads/upload-incomplete":
            return FakeResponse({"ok": True})
        raise AssertionError(path)

    monkeypatch.setattr(http, "request", fake_request)
    assert cloud.run_cloud(["scans", "start", "--source", str(tmp_path), "--yes", "--json"]) == 1
    assert ("DELETE", "/uploads/upload-incomplete") in paths
