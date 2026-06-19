"""Structure-aware truncation for oversized tool outputs.

Prevents context-window overflow by replacing large outputs with a compact
summary before they are stored in the agent session.
"""

from __future__ import annotations

import json
import logging


logger = logging.getLogger(__name__)

# Maximum records to keep when truncating a JSON array.
_JSON_KEEP = 50
# Maximum lines to keep when truncating plain text.
_TEXT_KEEP = 300
# Separator the agents SDK inserts between its header and the actual stdout.
_SDK_OUTPUT_SEPARATOR = "\nOutput:\n"


def truncate_exec_result(result: str, *, threshold: int) -> str:
    """Truncate an exec_command result, preserving the SDK's header section.

    The agents SDK wraps stdout in metadata lines (Chunk ID, Wall time, exit
    code) followed by a ``\\nOutput:\\n`` separator.  Truncation must apply only
    to the content after that separator so JSON detection works on the actual
    command output, not on the header text.
    """
    idx = result.find(_SDK_OUTPUT_SEPARATOR)
    if idx < 0:
        return truncate_tool_output(result, threshold=threshold)
    sep_end = idx + len(_SDK_OUTPUT_SEPARATOR)
    return result[:sep_end] + truncate_tool_output(result[sep_end:], threshold=threshold)


def truncate_tool_output(output: str, *, threshold: int) -> str:
    """Return *output* unchanged if it fits within *threshold* chars.

    When *output* exceeds the threshold the most useful portion is preserved:

    - JSON arrays: first :data:`_JSON_KEEP` records (syntactically valid,
      halved progressively if those records still exceed the threshold).
    - Plain text: first :data:`_TEXT_KEEP` lines, capped at *threshold* chars.

    A header line is prepended in both cases so the agent knows the full size
    and how many records or lines were omitted.  Pass ``threshold=0`` to
    disable truncation entirely.
    """
    if threshold <= 0 or len(output) <= threshold:
        return output

    total_chars = len(output)
    logger.warning(
        "Tool output is %d chars (threshold %d) — truncating",
        total_chars,
        threshold,
    )

    stripped = output.lstrip()
    if stripped.startswith("["):
        result = _truncate_json_array(stripped, total_chars, threshold=threshold)
        if result is not None:
            return result

    return _truncate_text(output, total_chars, threshold=threshold)


def _truncate_json_array(output: str, total_chars: int, *, threshold: int) -> str | None:
    """Attempt JSON-array truncation; return None if *output* is not valid JSON."""
    try:
        records = json.loads(output)
    except json.JSONDecodeError:
        return None
    if not isinstance(records, list):
        return None

    # Start with _JSON_KEEP records; halve until the re-serialised form fits.
    kept = records[:_JSON_KEEP]
    serialized = json.dumps(kept, indent=2)
    while len(serialized) > threshold and len(kept) > 1:
        kept = kept[: len(kept) // 2]
        serialized = json.dumps(kept, indent=2)

    header = (
        f"[truncated: {total_chars:,} chars, {len(records):,} records"
        f" — showing first {len(kept)}]\n"
    )
    return header + serialized


def _truncate_text(output: str, total_chars: int, *, threshold: int) -> str:
    """Truncate plain-text output to the first :data:`_TEXT_KEEP` lines.

    A secondary character cap is applied after line selection so that a single
    extremely long line cannot bypass the threshold.
    """
    lines = output.splitlines()
    kept = lines[:_TEXT_KEEP]
    header = (
        f"[truncated: {total_chars:,} chars, {len(lines):,} lines — showing first {len(kept)}]\n"
    )
    body = "\n".join(kept)
    if len(body) > threshold:
        body = body[:threshold] + " …"
    return header + body
