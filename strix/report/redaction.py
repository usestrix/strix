"""Mask user-declared secrets in a run directory once the run is over.

Credentials for the target usually reach Strix through ``--instruction``. The
agents need the real values while they work, so nothing is masked in flight,
but every artifact Strix leaves behind keeps a copy: ``run.json`` stores the
instruction, ``.state/agents.db`` stores every message and tool call, and the
notes, to-dos, threat models, coverage ledger and reports repeat whatever the
agents wrote down. ``STRIX_REDACT_ENV`` names the environment variables whose
values are secret; :func:`redact_run_dir` replaces each of those values with
``[REDACTED:<NAME>]`` in every file under the run directory.

JSON, whether a whole file, one line of a JSON Lines file or a value stored in
a database, is redacted inside its strings only, so a secret that is also a
run of digits does not turn a token count into invalid JSON. SQLite databases
are rewritten through SQL rather than byte patching, with ``secure_delete`` on
and a ``VACUUM`` afterwards, so the old values do not survive in freed pages
or in the write-ahead log.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, quote_plus

from strix.config.loader import load_settings


if TYPE_CHECKING:
    from collections.abc import Mapping


logger = logging.getLogger(__name__)

# Values shorter than this are skipped: masking "abc" everywhere would mangle
# the artifacts far more than it protects.
MIN_SECRET_LENGTH = 4

_SQLITE_HEADER = b"SQLite format 3\x00"
_SQLITE_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")
_JSON_INDENT = re.compile(r"\n( +)\S")


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
    and without ASCII escaping; percent-encoded with ``%20`` or ``+`` for a
    space, as in a URL or a form body; and with each quote doubled, as the
    :mod:`csv` module writes a field such as a title in ``vulnerabilities.csv``.
    """
    forms = {value, value.replace('"', '""'), quote(value, safe=""), quote_plus(value, safe="")}
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


def _redact_json_value(value: Any, replacements: list[tuple[str, str]]) -> Any:
    if isinstance(value, str):
        return _redact_json_string(value, replacements)
    if isinstance(value, dict):
        return {
            _redact_json_string(key, replacements): _redact_json_value(item, replacements)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_json_value(item, replacements) for item in value]
    if isinstance(value, int | float) and not isinstance(value, bool):
        # A secret stored as a JSON number, such as a numeric PIN. Only an
        # exact match is replaced, so a count or cost that merely contains the
        # digits stays a number.
        number = json.dumps(value)
        for needle, marker in replacements:
            if needle == number:
                return marker
    return value


def _redact_json_string(text: str, replacements: list[tuple[str, str]]) -> str:
    # A string can carry JSON of its own, such as a tool call's arguments.
    document = _redact_json_document(text, replacements)
    return redact_text(text, replacements) if document is None else document


def _redact_json_document(text: str, replacements: list[tuple[str, str]]) -> str | None:
    """Redact ``text`` inside its strings if it is a JSON object or array, else return None.

    A changed document is written back with the indentation and ASCII escaping
    it was read with.
    """
    if not text.lstrip().startswith(("{", "[")):
        return None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    redacted = _redact_json_value(parsed, replacements)
    if redacted == parsed:
        return text
    indent = _JSON_INDENT.search(text)
    dumped = json.dumps(
        redacted,
        indent=len(indent.group(1)) if indent else None,
        ensure_ascii=text.isascii(),
    )
    return dumped + text[len(text.rstrip()) :]


def _redact_document(text: str, replacements: list[tuple[str, str]]) -> str:
    """Redact a file's or a database value's text, JSON inside its strings only."""
    document = _redact_json_document(text, replacements)
    if document is not None:
        return document
    # JSON Lines, a log, or prose: each line on its own.
    return "".join(
        _redact_json_string(line, replacements) for line in text.splitlines(keepends=True)
    )


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
        needles = [needle for needle, _ in replacements]
        changed = 0
        for table in tables:
            quoted_table = '"' + table.replace('"', '""') + '"'
            columns = [row[1] for row in connection.execute(f"PRAGMA table_info({quoted_table})")]
            for column in columns:
                quoted_column = '"' + column.replace('"', '""') + '"'
                contains_needle = " OR ".join([f"instr({quoted_column}, ?) > 0"] * len(needles))
                # Table and column names come from this database's own schema
                # and are quoted; the values are bound parameters. Values are
                # redacted in Python so JSON stored in a column stays valid.
                values = connection.execute(
                    f"SELECT DISTINCT {quoted_column} FROM {quoted_table} "  # noqa: S608  # nosec B608
                    f"WHERE typeof({quoted_column}) = 'text' AND ({contains_needle})",
                    needles,
                ).fetchall()
                for (value,) in values:
                    redacted = _redact_document(value, replacements)
                    if redacted == value:
                        continue
                    cursor = connection.execute(
                        f"UPDATE {quoted_table} SET {quoted_column} = ? "  # noqa: S608  # nosec B608
                        f"WHERE {quoted_column} = ?",
                        (redacted, value),
                    )
                    changed += cursor.rowcount
        connection.commit()
        # Rebuild the file even when no current row held a secret: rows
        # deleted earlier, such as history that compaction replaced, can leave
        # their old values in freed pages, and secure_delete only covers
        # deletes made from now on.
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
    if not any(needle.encode("utf-8") in original for needle, _ in replacements):
        return False
    try:
        data = _redact_document(original.decode("utf-8"), replacements).encode("utf-8")
    except UnicodeDecodeError:
        # Not text: patch the bytes.
        data = original
        for needle, marker in replacements:
            data = data.replace(needle.encode("utf-8"), marker.encode("utf-8"))
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
