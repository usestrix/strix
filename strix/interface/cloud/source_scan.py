"""Local-source approval, upload, and scan-launch lifecycle."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import quote

from rich.markup import escape

import strix.interface.cloud.http as http  # noqa: PLR0402
from strix.interface.cloud.render import emit
from strix.interface.cloud.source_upload import prepare_source, remove_bundle
from strix.interface.terminal_text import sanitize_terminal_text


if TYPE_CHECKING:
    import argparse
    from typing import NoReturn

    from rich.console import Console

    from strix.interface.cloud.source_upload import SourceBundle


_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass
class LocalSourceScan:
    """Own one local bundle and its staged upload through a scan launch."""

    bundle: SourceBundle | None = None
    upload_id: str | None = None
    idempotency_key: str | None = None
    _launch_started: bool = False

    def prepare_and_attach(
        self,
        console: Console,
        args: argparse.Namespace,
        body: dict[str, Any],
        *,
        as_json: bool,
        token: str | None,
    ) -> bool:
        """Prepare source, emit a dry run, or upload and attach it to ``body``.

        Returns ``True`` when a dry run was emitted and request execution should stop.
        """
        self.bundle = prepare_scan_source(console, args, as_json=as_json)
        if self.bundle is None:
            return False
        if getattr(args, "dry_run", False):
            emit(
                console,
                {"source": self.bundle.summary(show_files=getattr(args, "show_files", False))},
                as_json=as_json,
                view="source_manifest",
            )
            return True
        self.upload_id = _upload_scan_source(self.bundle, token=token)
        existing = body.get("upload_ids")
        body["upload_ids"] = [
            *(existing if isinstance(existing, list) else []),
            self.upload_id,
        ]
        return False

    def mark_launch_started(self) -> None:
        """Record that the scan-creation request may have reached the platform."""
        self._launch_started = self.upload_id is not None

    def handle_request_failure(self, error: BaseException, *, token: str | None) -> None:
        """Clean or retain a staged upload according to request ambiguity."""
        if self.upload_id is None:
            return
        if self._launch_started:
            if isinstance(error, KeyboardInterrupt):
                raise _interrupted_source_upload_error(
                    self.upload_id, self.idempotency_key
                ) from None
            if isinstance(error, Exception):
                raise _retained_source_upload_error(
                    self.upload_id, error, self.idempotency_key
                ) from error
            return
        try:
            _delete_upload(self.upload_id, token=token)
        except (http.CloudError, KeyboardInterrupt) as cleanup_error:
            if isinstance(error, Exception):
                raise _source_cleanup_error(self.upload_id, error, cleanup_error) from error
            interrupted = http.CloudError("source upload interrupted.", exit_code=130)
            raise _source_cleanup_error(self.upload_id, interrupted, cleanup_error) from None

    def handle_response_failure(
        self,
        error: BaseException,
        *,
        definitive: bool,
        token: str | None,
    ) -> None:
        """Clean a rejected upload or retain one whose scan result is ambiguous."""
        if self.upload_id is None:
            return
        if definitive:
            try:
                _delete_upload(self.upload_id, token=token)
            except (http.CloudError, KeyboardInterrupt) as cleanup_error:
                if isinstance(error, Exception):
                    raise _source_cleanup_error(self.upload_id, error, cleanup_error) from error
                interrupted = http.CloudError("source upload interrupted.", exit_code=130)
                raise _source_cleanup_error(self.upload_id, interrupted, cleanup_error) from None
            return
        if isinstance(error, Exception):
            raise _retained_source_upload_error(
                self.upload_id, error, self.idempotency_key
            ) from error

    def wrap_result(self, result: Any, args: argparse.Namespace) -> Any:
        """Attach the approved source manifest to a successful scan response."""
        if self.bundle is None:
            return result
        return {
            "source": self.bundle.summary(show_files=getattr(args, "show_files", False)),
            "upload_id": self.upload_id,
            "scan": result,
        }

    def close(self) -> None:
        """Remove the private temporary bundle, if one was built."""
        if self.bundle is not None:
            remove_bundle(self.bundle)


def prepare_scan_source(
    console: Console, args: argparse.Namespace, *, as_json: bool
) -> SourceBundle | None:
    """Build and approve the exact local-source snapshot for one invocation."""
    source = getattr(args, "source", None)
    source_flags = (
        "dry_run",
        "show_files",
        "include_hidden",
        "include_sensitive",
        "include_archives",
        "approve_sha256",
    )
    if source is None:
        if any(getattr(args, name, False) for name in source_flags) or getattr(args, "exclude", []):
            raise http.CloudError("source upload options require --source DIRECTORY.")
        return None
    bundle = prepare_source(
        source,
        include_hidden=bool(getattr(args, "include_hidden", False)),
        include_sensitive=bool(getattr(args, "include_sensitive", False)),
        include_archives=bool(getattr(args, "include_archives", False)),
        exclude=cast("list[str]", getattr(args, "exclude", [])),
    )
    keep_bundle = False
    try:
        approved_digest = _validate_source_digest_approval(args, bundle)
        if getattr(args, "dry_run", False):
            keep_bundle = True
            return bundle
        if getattr(args, "yes", False) or approved_digest is not None:
            keep_bundle = True
            return bundle
        if as_json or not (sys.stdin.isatty() and sys.stdout.isatty()):
            _source_approval_error(
                "source upload requires explicit approval in non-interactive mode. "
                "Review with --dry-run --show-files, then rerun with "
                "--approve-sha256 <reviewed hash>; use --yes only for a deliberate "
                "one-shot approval of the snapshot built by that invocation."
            )
        console.print(
            "[bold]Local source upload[/]\n"
            f"  {len(bundle.manifest.files):,} file(s), "
            f"{_format_bytes(bundle.manifest.total_bytes)} "
            f"({_format_bytes(bundle.archive_bytes)} compressed)\n"
            f"  {sum(bundle.manifest.excluded.values()):,} path(s) excluded\n"
            "  Only the selected files will be sent to Strix Cloud."
        )
        if getattr(args, "show_files", False):
            console.print(f"\n[bold]Selected files ({len(bundle.manifest.files):,})[/]")
            for selected in bundle.manifest.files:
                console.print(
                    f"  {escape(sanitize_terminal_text(selected.archive_name))}", soft_wrap=True
                )
        answer = (
            console.input("Upload this source and start the scan? [y/N]: ", markup=False)
            .strip()
            .lower()
        )
        if answer not in ("y", "yes"):
            _source_approval_error("source upload cancelled.")
        keep_bundle = True
        return bundle
    finally:
        if not keep_bundle:
            remove_bundle(bundle)


def _validate_source_digest_approval(args: argparse.Namespace, bundle: SourceBundle) -> str | None:
    approved_digest = getattr(args, "approve_sha256", None)
    if approved_digest is None:
        return None
    if not isinstance(approved_digest, str) or not _SHA256.fullmatch(approved_digest):
        _source_approval_error("--approve-sha256 must be exactly 64 hexadecimal characters.")
    if bundle.archive_sha256 != approved_digest.lower():
        _source_approval_error(
            "source archive SHA-256 does not match --approve-sha256; review a fresh "
            "--dry-run before uploading."
        )
    return approved_digest


def _source_approval_error(message: str) -> NoReturn:
    raise http.CloudError(message)


def _upload_scan_source(bundle: SourceBundle, *, token: str | None) -> str:
    file_name = f"strix-source-{bundle.archive_sha256[:12]}.zip"
    requested = http.check(
        http.request(
            "POST",
            "/uploads/request",
            token=token,
            body={
                "file_name": file_name,
                "file_size": bundle.archive_bytes,
                "category": "repository",
            },
        )
    )
    if not isinstance(requested, dict):
        raise http.CloudError("the platform returned an invalid source upload response.")
    fields = cast("dict[str, Any]", requested)
    upload_id = fields.get("upload_id")
    signed_url = fields.get("signed_url")
    upload_token = fields.get("token")
    if not all(isinstance(value, str) and value for value in (upload_id, signed_url, upload_token)):
        error = http.CloudError("the platform did not return complete source upload credentials.")
        if isinstance(upload_id, str) and upload_id:
            try:
                _delete_upload(upload_id, token=token)
            except (http.CloudError, KeyboardInterrupt) as cleanup_error:
                raise _source_cleanup_error(upload_id, error, cleanup_error) from error
        raise error
    try:
        http.upload_file(cast("str", signed_url), cast("str", upload_token), bundle.archive_path)
        completed = http.check(
            http.request(
                "POST",
                "/uploads/complete",
                token=token,
                body={"upload_id": upload_id},
            )
        )
        _validate_completed_upload(completed, expected_id=cast("str", upload_id))
    except BaseException as error:
        try:
            _delete_upload(cast("str", upload_id), token=token)
        except (http.CloudError, KeyboardInterrupt) as cleanup_error:
            if isinstance(error, Exception):
                raise _source_cleanup_error(cast("str", upload_id), error, cleanup_error) from error
            interrupted = http.CloudError("source upload interrupted.", exit_code=130)
            raise _source_cleanup_error(
                cast("str", upload_id), interrupted, cleanup_error
            ) from None
        raise
    return cast("str", upload_id)


def _validate_completed_upload(completed: Any, *, expected_id: str) -> None:
    fields = cast("dict[str, Any]", completed) if isinstance(completed, dict) else {}
    if fields.get("id") != expected_id:
        raise http.CloudError("the platform returned an invalid source upload completion response.")


def _delete_upload(upload_id: str, *, token: str | None) -> None:
    response = http.request("DELETE", f"/uploads/{quote(upload_id, safe='')}", token=token)
    if response.status_code == 404 or 200 <= response.status_code < 300:
        return
    http.check(response)


def _source_cleanup_note(upload_id: str, cleanup_error: BaseException) -> str:
    return (
        f"Cleanup of source upload {upload_id} could not be confirmed: {cleanup_error}. "
        f"Retry with `strix cloud uploads delete {upload_id}`."
    )


def _source_cleanup_error(
    upload_id: str, error: Exception, cleanup_error: BaseException
) -> http.CloudError:
    """Report a staged source object whenever automatic deletion is uncertain."""
    message = f"{error} {_source_cleanup_note(upload_id, cleanup_error)}"
    payload: dict[str, Any] = {}
    exit_code = http.EXIT_ERROR
    if isinstance(error, http.CloudError):
        exit_code = error.exit_code
        raw_payload: Any = error.payload
        if isinstance(raw_payload, dict):
            payload.update(cast("dict[str, Any]", raw_payload))
        elif raw_payload is not None:
            payload["detail"] = raw_payload
    payload.update(
        {
            "error": message,
            "upload_id": upload_id,
            "upload_retained": True,
            "cleanup_unknown": True,
        }
    )
    return http.CloudError(message, exit_code=exit_code, payload=payload)


def _interrupted_source_upload_error(
    upload_id: str, idempotency_key: str | None = None
) -> http.CloudError:
    retry_note = _idempotency_retry_note(idempotency_key)
    message = (
        "Interrupted while starting the scan. The launch outcome is unknown, so source upload "
        f"{upload_id} was retained. Check `strix cloud scans list` before retrying; if no scan "
        f"was created, run `strix cloud uploads delete {upload_id}`.{retry_note}"
    )
    payload: dict[str, Any] = {
        "error": message,
        "interrupted": True,
        "upload_id": upload_id,
        "upload_retained": True,
        "launch_outcome_unknown": True,
    }
    _attach_idempotency_recovery(payload, idempotency_key)
    return http.CloudError(message, exit_code=130, payload=payload)


def _retained_source_upload_error(
    upload_id: str,
    error: Exception,
    idempotency_key: str | None = None,
) -> http.CloudError:
    """Preserve source when the platform may already have accepted its scan."""
    retry_note = _idempotency_retry_note(idempotency_key)
    message = (
        f"{error} The scan launch outcome is unknown, so source upload {upload_id} was retained. "
        "Check `strix cloud scans list` before retrying; if no scan was created, clean it up "
        f"with `strix cloud uploads delete {upload_id}`. Linked uploads cannot be deleted."
        f"{retry_note}"
    )
    payload: dict[str, Any] = {}
    exit_code = http.EXIT_ERROR
    if isinstance(error, http.CloudError):
        exit_code = error.exit_code
        raw_payload: Any = error.payload
        error_payload = cast("dict[str, Any]", raw_payload)
        if isinstance(raw_payload, dict):
            payload.update(error_payload)
        elif raw_payload is not None:
            payload["detail"] = raw_payload
    payload.update(
        {
            "error": message,
            "upload_id": upload_id,
            "upload_retained": True,
            "launch_outcome_unknown": True,
        }
    )
    _attach_idempotency_recovery(payload, idempotency_key)
    return http.CloudError(message, exit_code=exit_code, payload=payload)


def _idempotency_retry_note(idempotency_key: str | None) -> str:
    if not idempotency_key:
        return ""
    return (
        " An exact retry is safe only with the same request body and "
        f"`--idempotency-key {idempotency_key}`."
    )


def _attach_idempotency_recovery(payload: dict[str, Any], idempotency_key: str | None) -> None:
    if not idempotency_key:
        return
    payload.update(
        {
            "idempotency_key": idempotency_key,
            "retry_safe": True,
            "retry_same_request": True,
        }
    )


def _format_bytes(value: int) -> str:
    if value < 1024:
        return f"{value} B"
    if value < 1024 * 1024:
        return f"{value / 1024:.1f} KB"
    return f"{value / (1024 * 1024):.1f} MB"
