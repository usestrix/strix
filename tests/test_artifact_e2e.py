"""End-to-end of the artifact flow, all in-process: backend building the
payload for a repo target, orchestrator rendering the artifact from GridFS
and handing Strix a local path. Uses mongomock GridFS; the happy-path test
already covers real Mongo when STRIX_TEST_MONGO_URI is set.
"""

from __future__ import annotations

import io
import sys
import tarfile
from pathlib import Path
from unittest import mock

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "k8s"))

import artifact_fetch
from artifact_fetch import render_artifact


def _tar_bytes() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        data = b"print('audited source')\n"
        info = tarfile.TarInfo("the-repo/main.py")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_pipeline_backend_payload_to_local_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """audit.request {artifact_id} → render → the engine receives a local path."""
    # 2. The orchestrator side: the tar is in GridFS, the request carries its id.
    buf = io.BytesIO(_tar_bytes())
    bucket_impl = _Bucket(buf.getvalue())
    gridfs_mod = mock.MagicMock()
    gridfs_mod.GridFSBucket = lambda *a, **k: bucket_impl
    bson_mod = mock.MagicMock()
    bson_mod.ObjectId = str
    pymongo_mod = mock.MagicMock()
    pymongo_mod.MongoClient = lambda *a, **k: _Client()
    monkeypatch.setitem(__import__("sys").modules, "gridfs", gridfs_mod)
    monkeypatch.setitem(__import__("sys").modules, "bson", bson_mod)
    monkeypatch.setitem(__import__("sys").modules, "pymongo", pymongo_mod)
    monkeypatch.setattr(artifact_fetch.tempfile, "gettempdir", lambda: str(tmp_path))

    artifact_id = "e2e-artifact-1"
    local = render_artifact(artifact_id, mongo_uri="mongo://x", mongo_db="d", bucket="b")
    assert (local / "main.py").read_bytes() == b"print('audited source')\n"

    # 3. The engine side: that path classifies as a local_code target (no GitHub at all).
    class FakeResponse:
        status_code = 200
        headers = {"Content-Type": "application/json"}

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    from strix.interface import utils as strix_utils

    monkeypatch.setattr(strix_utils.requests, "get", lambda *a, **k: FakeResponse())
    target_type, details = strix_utils.infer_target_type(str(local))
    assert target_type == "local_code"
    assert details["target_path"] == str(local)


class _Bucket:
    def __init__(self, data: bytes) -> None:
        self.data = data

    def download_to_stream(self, file_id: object, out: io.BytesIO) -> None:
        out.write(self.data)


class _Client:
    def __getitem__(self, name: str):
        return mock.MagicMock()

    def close(self) -> None:
        pass
