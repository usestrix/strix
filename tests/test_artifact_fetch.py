"""``artifact_fetch``: the orchestrator renders a GridFS artifact without GitHub.

The happy path runs against a real MongoDB when ``STRIX_TEST_MONGO_URI`` is set
(like the backend's GridFS tests); the rest use fakes.
"""

from __future__ import annotations

import io
import os
import sys
import tarfile
from pathlib import Path
from typing import Any
from unittest import mock

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "k8s"))

import artifact_fetch
from artifact_fetch import artifact_from_payload, render_artifact


def test_artifact_from_payload() -> None:
    assert artifact_from_payload({"artifact_id": "abc"}) == "abc"
    assert artifact_from_payload({"artifact_id": ""}) is None
    assert artifact_from_payload({}) is None
    assert artifact_from_payload({"target": "http://x"}) is None


class FakeBucket:
    """GridFSBucket stand-in backed by in-memory id → bytes."""

    def __init__(self, store: dict[str, bytes]) -> None:
        self._store = store

    def download_to_stream(self, file_id: Any, out: io.BytesIO) -> None:
        data = self._store.get(str(file_id))
        if data is None:
            raise Exception(f"file {file_id} not found")
        out.write(data)


class FakeClient:
    def __init__(self, store: dict[str, bytes]) -> None:
        self._store = store
        self.closed = False

    def __getitem__(self, name: str) -> Any:
        return mock.MagicMock()

    def close(self) -> None:
        self.closed = True


def _fake_gridfs(store: dict[str, bytes], monkeypatch: pytest.MonkeyPatch) -> None:
    gridfs_mod = mock.MagicMock()
    gridfs_mod.GridFSBucket = lambda *a, **k: FakeBucket(store)
    bson_mod = mock.MagicMock()
    bson_mod.ObjectId = str
    pymongo_mod = mock.MagicMock()
    pymongo_mod.MongoClient = lambda *a, **k: FakeClient(store)
    monkeypatch.setitem(__import__("sys").modules, "gridfs", gridfs_mod)
    monkeypatch.setitem(__import__("sys").modules, "bson", bson_mod)
    monkeypatch.setitem(__import__("sys").modules, "pymongo", pymongo_mod)


def test_render_artifact_unpacks_tar_with_single_top_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        data = b"hello repo"
        info = tarfile.TarInfo("demo/README.md")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    store = {"abc123": buf.getvalue()}
    _fake_gridfs(store, monkeypatch)
    monkeypatch.setattr(artifact_fetch.tempfile, "gettempdir", lambda: str(tmp_path))

    path = render_artifact("abc123", mongo_uri="mongodb://x", mongo_db="d", bucket="b")
    assert (path / "README.md").read_bytes() == b"hello repo"


def test_render_artifact_missing_id_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_gridfs({}, monkeypatch)
    monkeypatch.setattr(artifact_fetch.tempfile, "gettempdir", lambda: str(tmp_path))
    with pytest.raises(Exception):
        render_artifact("nosuch", mongo_uri="mongodb://x", mongo_db="d", bucket="b")


@pytest.mark.skipif(not os.environ.get("STRIX_TEST_MONGO_URI"), reason="needs STRIX_TEST_MONGO_URI")
def test_render_roundtrip_against_real_mongo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Upload a tar with the same call the backend uses, then render it back."""
    import uuid  # noqa: PLC0415

    from gridfs import GridFSBucket  # noqa: PLC0415
    from pymongo import MongoClient  # noqa: PLC0415

    uri = os.environ["STRIX_TEST_MONGO_URI"]
    dbname = f"strix_test_{uuid.uuid4().hex[:8]}"
    client = MongoClient(uri, serverSelectionTimeoutMS=10_000)
    db = client[dbname]
    fs = GridFSBucket(db, bucket_name="test_bucket")

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo("repo/file.txt")
        info.size = 5
        tar.addfile(info, io.BytesIO(b"data"))
    fid = fs.upload_from_stream("runs/1/repo.tar.gz", buf.getvalue())
    try:
        monkeypatch.setattr(artifact_fetch.tempfile, "gettempdir", lambda: str(tmp_path))
        rendered = render_artifact(str(fid), mongo_uri=uri, mongo_db=dbname, bucket="test_bucket")
        assert (rendered / "file.txt").read_bytes() == b"data"
    finally:
        client.drop_database(dbname)
        client.close()
