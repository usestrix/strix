"""Where a finished run directory lives between the worker and the frontal.

Three backends, chosen by ``FRONTAL_ARTIFACT_STORE``:

  - ``file``: a shared filesystem (a RWX PVC in k8s). The worker moves the run
    directory onto it; the frontal reads it in place. This is today's model.
  - ``s3``:   object storage. The worker uploads the run tree; the frontal
    downloads it under ``artifacts_dir`` so the embedded viewer keeps reading
    from local disk unchanged.
  - ``mongo``: MongoDB GridFS. Same model as ``s3``: each file of the run is a
    GridFS file named ``<prefix>/<relative path>`` and tagged
    ``metadata.run = <prefix>``, so one GridFS bucket holds many runs.

All expose the same two operations, so nothing else in the code needs to know
which store is configured.
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from frontal.app.config import Settings


logger = logging.getLogger(__name__)


def _prefix(scan_id: int) -> str:
    return f"runs/{scan_id}"


class ArtifactStore:
    """A run directory's home, addressed by an opaque URI."""

    # Matches ``storage.backend`` in the orchestrator's audit.result event.
    backend = ""

    def publish_run(self, scan_id: int, run_dir: Path) -> str:
        """Store ``run_dir`` for ``scan_id``; return a URI the frontal can localize."""
        raise NotImplementedError

    def localize(self, scan_id: int, uri: str) -> Path:
        """Return a local path to the run directory, fetching it if needed."""
        raise NotImplementedError


class FileArtifactStore(ArtifactStore):
    backend = "file"

    def __init__(self, settings: Settings) -> None:
        self._root = settings.artifacts_dir

    def _dest(self, scan_id: int) -> Path:
        return self._root / "runs" / str(scan_id)

    def publish_run(self, scan_id: int, run_dir: Path) -> str:
        dest = self._dest(scan_id)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.rmtree(dest, ignore_errors=True)
        shutil.move(str(run_dir), str(dest))
        return f"file://{_prefix(scan_id)}"

    def localize(self, scan_id: int, _uri: str) -> Path:
        # Already on the shared volume; the run lives at runs/<scan_id>.
        return self._dest(scan_id)


class S3ArtifactStore(ArtifactStore):
    backend = "s3"

    def __init__(self, settings: Settings) -> None:
        import boto3  # noqa: PLC0415 - lazy so the file backend needs no boto3

        self._bucket = settings.s3_bucket
        self._root = settings.artifacts_dir
        from botocore.config import Config  # noqa: PLC0415

        # Explicit keys when configured (MinIO), else boto3's default chain.
        # Path-style addressing: MinIO does not serve <bucket>.<host> by default.
        self._client = boto3.client(
            "s3",
            endpoint_url=settings.s3_endpoint_url,
            region_name=settings.s3_region,
            aws_access_key_id=settings.s3_access_key,
            aws_secret_access_key=settings.s3_secret_key,
            verify=settings.s3_verify_tls,
            config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
        )

    def publish_run(self, scan_id: int, run_dir: Path) -> str:
        prefix = _prefix(scan_id)
        for path in run_dir.rglob("*"):
            if path.is_file():
                key = f"{prefix}/{path.relative_to(run_dir).as_posix()}"
                self._client.upload_file(str(path), self._bucket, key)
        return f"s3://{self._bucket}/{prefix}"

    def localize(self, scan_id: int, _uri: str) -> Path:
        return self.download_prefix(scan_id, self._bucket, _prefix(scan_id))

    def download_prefix(self, scan_id: int, bucket: str, prefix: str) -> Path:
        """Mirror ``s3://bucket/prefix/`` into the local cache for ``scan_id``.

        This is how the frontal receives an orchestrator run: the orchestrator
        uploads the run tree under ``<MINIO_PREFIX>/<run_name>/`` and names the
        bucket and prefix in its ``audit.result`` event.
        """
        prefix = prefix.strip("/")
        dest = self._root / "runs" / str(scan_id)
        root = dest.resolve()
        dest.mkdir(parents=True, exist_ok=True)
        paginator = self._client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket, Prefix=f"{prefix}/"):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                target = (dest / key[len(prefix) + 1 :]).resolve()
                # Object keys are data from the bucket: never write outside dest.
                if root not in target.parents:
                    logger.warning("skipping object outside run prefix: %s", key)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                self._client.download_file(bucket, key, str(target))
        return dest


def _safe_target(dest: Path, relative: str) -> Path | None:
    """``dest/relative``, or None when the name would escape ``dest``."""
    target = (dest / relative).resolve()
    return target if dest.resolve() in target.parents else None


class MongoArtifactStore(ArtifactStore):
    """GridFS-backed store; mirrors ``S3ArtifactStore`` (bucket = GridFS bucket)."""

    backend = "mongo"

    def __init__(self, settings: Settings) -> None:
        import gridfs  # noqa: PLC0415 - lazy so the other backends need no pymongo
        from pymongo import MongoClient  # noqa: PLC0415

        if not settings.mongo_uri:
            raise RuntimeError("FRONTAL_ARTIFACT_STORE=mongo needs MONGO_URI")
        self._gridfs = gridfs
        self._root = settings.artifacts_dir
        self._bucket = settings.mongo_bucket
        self._client: Any = MongoClient(settings.mongo_uri, serverSelectionTimeoutMS=10_000)
        self._db = self._client[settings.mongo_db]

    def _fs(self, bucket: str | None) -> Any:
        name = bucket or self._bucket
        self._db[f"{name}.files"].create_index("metadata.run")
        return self._gridfs.GridFSBucket(self._db, bucket_name=name)

    def publish_run(self, scan_id: int, run_dir: Path) -> str:
        prefix = _prefix(scan_id)
        fs = self._fs(None)
        for old in fs.find({"metadata.run": prefix}):
            fs.delete(old._id)
        for path in sorted(run_dir.rglob("*")):
            if path.is_file():
                name = f"{prefix}/{path.relative_to(run_dir).as_posix()}"
                with path.open("rb") as fh:
                    fs.upload_from_stream(name, fh, metadata={"run": prefix})
        return f"mongodb://{self._db.name}/{self._bucket}/{prefix}"

    def localize(self, scan_id: int, _uri: str) -> Path:
        return self.download_prefix(scan_id, self._bucket, _prefix(scan_id))

    def download_prefix(self, scan_id: int, bucket: str | None, prefix: str) -> Path:
        """Mirror every GridFS file of run ``prefix`` into the local cache.

        Oldest first, so when a run was uploaded twice the newest copy of a file
        is the one left on disk.
        """
        prefix = prefix.strip("/")
        dest = self._root / "runs" / str(scan_id)
        dest.mkdir(parents=True, exist_ok=True)
        fs = self._fs(bucket)
        for grid_out in fs.find({"metadata.run": prefix}).sort("uploadDate", 1):
            name: str = grid_out.filename
            # File names are data from the database: never write outside dest.
            target = _safe_target(dest, name[len(prefix) + 1 :])
            if not name.startswith(f"{prefix}/") or target is None:
                logger.warning("skipping GridFS file outside run prefix: %s", name)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(grid_out.read())
        return dest


def get_artifact_store(settings: Settings) -> ArtifactStore:
    if settings.artifact_store == "mongo":
        return MongoArtifactStore(settings)
    if settings.artifact_store == "s3":
        return S3ArtifactStore(settings)
    return FileArtifactStore(settings)
