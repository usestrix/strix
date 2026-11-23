"""Mask user-declared secrets in a run directory once the run is over.

Credentials for the target usually reach Strix through ``--instruction``. The
agents need the real values while they work, so nothing is masked in flight,
but every artifact Strix leaves behind keeps a copy: ``run.json`` stores the
instruction, ``.state/agents.db`` stores every message and tool call, and the
notes, to-dos, threat models, coverage ledger and reports repeat whatever the
agents wrote down. ``STRIX_REDACT_ENV`` names the environment variables whose
values are secret; :func:`redact_run_dir` replaces each of those values with
``[REDACTED:<NAME>]`` in every file under the run directory.

SQLite databases are rewritten through SQL rather than byte patching, with
``secure_delete`` on and a ``VACUUM`` afterwards, so the old values do not
survive in freed pages or in the write-ahead log.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import quote

from strix.config.loader import load_settings


if TYPE_CHECKING:
    from collections.abc import Mapping


logger = logging.getLogger(__name__)

# Values shorter than this are skipped: masking "abc" everywhere would mangle
# the artifacts far more than it protects.
MIN_SECRET_LENGTH = 4

_SQLITE_HEADER = b"SQLite format 3\x00"
_SQLITE_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")


@dataclass
class RedactionSummary:
    """What :func:`redact_run_dir` changed, for logging and tests."""

    files_changed: list[Path] = field(default_factory=list[Path])
    errors: list[tuple[Path, str]] = field(default_factory=list[tuple[Path, str]])


def parse_env_names(raw: str | None) -> list[str]:
    """Split a ``STRIX_REDACT_ENV`` value on commas and whitespace, keeping order."""
    if not raw:
        return []
    names: list[str] = []
    for part in raw.replace(",", " ").split():
        if part not in names:
            names.append(part)
    return names


def secrets_from_env(names: list[str], environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """Map each named variable to its value, skipping unset, empty and short ones."""
    env = os.environ if environ is None else environ
    secrets: dict[str, str] = {}
    for name in names:
        value = env.get(name)
        if not value:
            logger.warning("STRIX_REDACT_ENV names %s, but it is unset or empty", name)
            continue
        if len(value) < MIN_SECRET_LENGTH:
            logger.warning(
                "Not redacting %s: its value is shorter than %d characters",
                name,
                MIN_SECRET_LENGTH,
            )
            continue
        secrets[name] = value
    return secrets


def configured_secrets() -> dict[str, str]:
    """The secrets named by the ``STRIX_REDACT_ENV`` setting, read from the environment."""
    return secrets_from_env(parse_env_names(load_settings().redaction.env_names))


def _json_escaped(value: str, *, ensure_ascii: bool) -> str:
    return json.dumps(value, ensure_ascii=ensure_ascii)[1:-1]


def _encodings(value: str) -> set[str]:
    """The forms a secret takes on disk.

    The raw text; JSON-escaped once (a JSON file) and twice (tool-call
    arguments, which are a JSON string inside a stored JSON message), each with
    and without ASCII escaping; and percent-encoded, as in a form body or URL.
    """
    forms = {value, quote(value, safe="")}
    for ensure_ascii in (True, False):
        once = _json_escaped(value, ensure_ascii=ensure_ascii)
        forms.add(once)
        forms.add(_json_escaped(once, ensure_ascii=ensure_ascii))
    return forms


def build_replacements(secrets: dict[str, str]) -> list[tuple[str, str]]:
    """Pairs of (text on disk, marker), longest first so no form hides a longer one."""
    pairs: dict[str, str] = {}
    for name, value in secrets.items():
        for form in _encodings(value):
            pairs.setdefault(form, f"[REDACTED:{name}]")
    return sorted(pairs.items(), key=lambda pair: len(pair[0]), reverse=True)


def redact_text(text: str, replacements: list[tuple[str, str]]) -> str:
    """Apply :func:`build_replacements` pairs to ``text``, in order."""
    for needle, marker in replacements:
        if needle in text:
            text = text.replace(needle, marker)
    return text


def _is_sqlite(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(len(_SQLITE_HEADER)) == _SQLITE_HEADER
    except OSError:
        return False


def _redact_sqlite(path: Path, replacements: list[tuple[str, str]]) -> bool:
    connection = sqlite3.connect(str(path), timeout=5)
    try:
        connection.execute("PRAGMA secure_delete=ON")
        tables = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        ]
        changed = 0
        for table in tables:
            quoted_table = '"' + table.replace('"', '""') + '"'
            columns = [row[1] for row in connection.execute(f"PRAGMA table_info({quoted_table})")]
            for column in columns:
                quoted_column = '"' + column.replace('"', '""') + '"'
                for needle, marker in replacements:
                    # Table and column names come from this database's own
                    # schema and are quoted; the values are bound parameters.
                    cursor = connection.execute(
                        f"UPDATE {quoted_table} SET {quoted_column} = "  # noqa: S608  # nosec B608
                        f"replace({quoted_column}, ?, ?) "
                        f"WHERE typeof({quoted_column}) = 'text' AND instr({quoted_column}, ?) > 0",
                        (needle, marker, needle),
                    )
                    changed += cursor.rowcount
        connection.commit()
        if changed:
            connection.execute("VACUUM")
        # Fold the WAL back into the database and empty it, so no copy of the
        # pre-redaction pages stays on disk next to it. A database not in WAL
        # mode reports no frames; a busy one is an error the caller reports.
        busy, _, _ = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        if busy:
            raise sqlite3.OperationalError("database busy; its WAL may still hold secrets")
        return changed > 0
    finally:
        connection.close()


def _redact_file(path: Path, replacements: list[tuple[str, str]]) -> bool:
    original = path.read_bytes()
    data = original
    for needle, marker in replacements:
        encoded = needle.encode("utf-8")
        if encoded in data:
            data = data.replace(encoded, marker.encode("utf-8"))
    if data == original:
        return False
    mode = path.stat().st_mode & 0o777
    with tempfile.NamedTemporaryFile(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp", delete=False
    ) as tmp:
        tmp.write(data)
        tmp_path = Path(tmp.name)
    tmp_path.chmod(mode)
    tmp_path.replace(path)
    return True


def redact_run_dir(run_dir: Path, secrets: dict[str, str]) -> RedactionSummary:
    """Replace every secret value in every file under ``run_dir``.

    Call it only after the run's writers have stopped: a database or file
    still being written can receive the secret again afterwards. A file that
    cannot be redacted is logged and listed in the summary; the rest are still
    processed.
    """
    summary = RedactionSummary()
    if not secrets or not run_dir.is_dir():
        return summary
    replacements = build_replacements(secrets)

    files = sorted(p for p in run_dir.rglob("*") if p.is_file() and not p.is_symlink())
    databases = [p for p in files if _is_sqlite(p)]
    # Databases first: the checkpoint inside empties their -wal files, which
    # are then skipped below along with the other SQLite sidecars.
    for path in databases:
        try:
            if _redact_sqlite(path, replacements):
                summary.files_changed.append(path)
        except (OSError, sqlite3.Error) as exc:
            logger.exception("Could not redact secrets in %s", path)
            summary.errors.append((path, str(exc)))

    database_set = set(databases)
    for path in files:
        if path in database_set or path.name.endswith(_SQLITE_SIDECAR_SUFFIXES):
            continue
        try:
            if _redact_file(path, replacements):
                summary.files_changed.append(path)
        except OSError as exc:
            logger.exception("Could not redact secrets in %s", path)
            summary.errors.append((path, str(exc)))

    if summary.files_changed:
        logger.info(
            "Redacted %d secret(s) from %d file(s) under %s",
            len(secrets),
            len(summary.files_changed),
            run_dir,
        )
    return summary
