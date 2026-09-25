"""Deterministic source anchoring for finding locations and draft edits."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from strix.fix.contracts import CandidateLocation, FixCandidateV1, FixEdit


if TYPE_CHECKING:
    from pathlib import Path


class AnchorStatus(StrEnum):
    UNIQUE = "unique"
    MISSING = "missing"
    AMBIGUOUS = "ambiguous"
    STALE = "stale"


@dataclass(frozen=True, slots=True)
class AnchorResult:
    status: AnchorStatus
    location: CandidateLocation | FixEdit
    matches: tuple[int, ...] = ()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _find_blocks(content: str, block: str) -> tuple[int, ...]:
    source_lines = content.splitlines()
    block_lines = block.splitlines()
    if not block_lines:
        return ()
    width = len(block_lines)
    return tuple(
        index + 1
        for index in range(len(source_lines) - width + 1)
        if source_lines[index : index + width] == block_lines
    )


def _read_anchor_source(root: Path, file: str) -> str | None:
    """Read a location's source, refusing symlinks that escape ``root`` and
    files that cannot be decoded as UTF-8."""
    resolved_root = root.resolve()
    file_path = (root / file).resolve()
    if not file_path.is_relative_to(resolved_root) or not file_path.is_file():
        return None
    try:
        return file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None


def anchor_location(
    root: Path,
    location: CandidateLocation | FixEdit,
) -> AnchorResult:
    content = _read_anchor_source(root, location.file)
    if content is None:
        return AnchorResult(AnchorStatus.MISSING, location)
    block = location.before if isinstance(location, FixEdit) else location.snippet
    if not block:
        return AnchorResult(AnchorStatus.UNIQUE, location, (location.start_line,))

    matches = _find_blocks(content, block)
    if not matches:
        if (
            isinstance(location, FixEdit)
            and location.original_sha256
            and sha256_text(content) != location.original_sha256
        ):
            return AnchorResult(AnchorStatus.STALE, location)
        return AnchorResult(AnchorStatus.MISSING, location)
    if len(matches) > 1:
        return AnchorResult(AnchorStatus.AMBIGUOUS, location, matches)

    start_line = next(iter(matches))
    end_line = start_line + len(block.splitlines()) - 1
    anchored = location.model_copy(update={"start_line": start_line, "end_line": end_line})
    return AnchorResult(AnchorStatus.UNIQUE, anchored, matches)


def anchor_candidate(
    root: Path,
    candidate: FixCandidateV1,
) -> tuple[FixCandidateV1, list[AnchorResult]]:
    results = [
        *(anchor_location(root, location) for location in candidate.finding_locations),
        *(anchor_location(root, edit) for edit in candidate.draft_edits),
    ]
    finding_count = len(candidate.finding_locations)
    anchored_locations = [result.location for result in results[:finding_count]]
    anchored_edits = [result.location for result in results[finding_count:]]
    return (
        candidate.model_copy(
            update={
                "finding_locations": anchored_locations,
                "draft_edits": anchored_edits,
            }
        ),
        results,
    )
