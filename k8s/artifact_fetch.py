"""Download a repository artifact from GridFS into the scan workspace.

The backend clones the repository and uploads it as ``<prefix>/repo.tar.gz`` in
GridFS; ``audit.request`` carries that file's id in ``artifact_id``. The engine
must not touch GitHub at all, so before starting Strix the orchestrator renders
the artifact locally and hands Strix a local path (``local_code`` target).

The artifact lands under the scan workspace and, because the backend deletes it
when the result is folded, the GridFS copy is the only one that ever crosses pods.
"""

from __future__ import annotations

import tarfile
import tempfile
from pathlib import Path
from typing import Any


def artifact_from_payload(payload: dict[str, Any]) -> str | None:
    """The artifact id of the request, or None for non-artifact (web/API) targets."""
    artifact_id = payload.get("artifact_id")
    return str(artifact_id) if artifact_id else None


def render_artifact(artifact_id: str, *, mongo_uri: str, mongo_db: str, bucket: str) -> Path:
    """Download one GridFS file by id and unpack it as a directory; returns its path.

    Raises :class:`ArtifactError` on a missing artifact, a corrupt tar, or Mongo being
    unreachable, so the caller can fail the scan with a clear message instead of the
    engine later guessing why a repo URL is unreachable.
    """
    import shutil  # noqa: PLC0415

    from bson import ObjectId  # noqa: PLC0415 - deferred like the upload path
    from gridfs import GridFSBucket  # noqa: PLC0415
    from pymongo import MongoClient  # noqa: PLC0415

    client: Any = MongoClient(mongo_uri, serverSelectionTimeoutMS=15_000)
    try:
        db = client[mongo_db]
        fs = GridFSBucket(db, bucket_name=bucket)
        workdir = Path(tempfile.gettempdir()) / "strix-artifacts" / artifact_id
        if workdir.exists():
            shutil.rmtree(workdir, ignore_errors=True)
        workdir.mkdir(parents=True, exist_ok=True)
        tar_path = workdir / "repo.tar.gz"
        with tar_path.open("wb") as out:
            fs.download_to_stream(ObjectId(artifact_id), out)
        code_dir = workdir / "code"
        with tarfile.open(tar_path, "r:gz") as tar:
            tar.extractall(code_dir, filter="data")  # noqa: S202 - platform-controlled artifact
        # The tar wraps the clone inside one top-level directory: descend when so.
        entries = list(code_dir.iterdir()) if code_dir.exists() else []
        if len(entries) == 1 and entries[0].is_dir():
            return entries[0]
        return code_dir
    finally:
        client.close()


class ArtifactError(RuntimeError):
    """Raised when a repository artifact cannot be rendered locally."""
