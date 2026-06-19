"""MapReduce LLM compression for oversized exec_command outputs.

Splits large output into chunks, summarises each with a lightweight
litellm call in parallel, and consolidates the summaries. Individual
chunk failures produce inline placeholders rather than aborting.
"""

from __future__ import annotations

import asyncio
import json
import logging

import litellm

from strix.config import load_settings


logger = logging.getLogger(__name__)

CHUNK_SIZE_RECORDS = 100  # JSON records per chunk (~100 KB for typical semgrep findings)
CHUNK_SIZE_LINES = 500  # plain-text lines per chunk
_SUMMARISE_TIMEOUT = 60.0  # per-chunk wall-clock cap (seconds)
_SDK_OUTPUT_SEPARATOR = "\nOutput:\n"


async def compress_exec_result(result: str, *, model: str, task_hint: str) -> str:
    """Compress an exec_command result produced by the agents SDK.

    Strips the SDK metadata header (Chunk ID / Wall time / exit code),
    compresses the content section, then re-attaches the header.
    """
    idx = result.find(_SDK_OUTPUT_SEPARATOR)
    if idx < 0:
        return await compress_large_output(result, model=model, task_hint=task_hint)
    sep_end = idx + len(_SDK_OUTPUT_SEPARATOR)
    compressed = await compress_large_output(result[sep_end:], model=model, task_hint=task_hint)
    return result[:sep_end] + compressed


async def compress_large_output(output: str, *, model: str, task_hint: str) -> str:
    """Fan *output* into N chunks, summarise each, return consolidated summaries.

    Returns *output* unchanged when it fits in a single chunk (nothing to
    fan out).  If the consolidated result still exceeds the threshold it is
    hard-truncated with an inline warning.
    """
    chunks = _split(output)
    if len(chunks) <= 1:
        return output
    summaries = list(await asyncio.gather(*[_summarise(c, model, task_hint) for c in chunks]))
    consolidated = _consolidate(summaries, total_chars=len(output), total_chunks=len(chunks))
    threshold = load_settings().runtime.max_tool_output_chars
    if threshold > 0 and len(consolidated) > threshold:
        return consolidated[:threshold] + "\n[consolidated summary still too large — truncated]"
    return consolidated


def _split(output: str) -> list[str]:
    """Split at JSON record boundaries; fall back to line-count split."""
    stripped = output.lstrip()
    if stripped.startswith("["):
        try:
            records = json.loads(stripped)
            if isinstance(records, list):
                chunks = [
                    json.dumps(records[i : i + CHUNK_SIZE_RECORDS])
                    for i in range(0, len(records), CHUNK_SIZE_RECORDS)
                ]
                return chunks or [output]
        except json.JSONDecodeError:
            pass
    lines = output.splitlines()
    if not lines:
        return [output]
    return [
        "\n".join(lines[i : i + CHUNK_SIZE_LINES]) for i in range(0, len(lines), CHUNK_SIZE_LINES)
    ]


async def _summarise(chunk: str, model: str, task_hint: str) -> str:
    """Summarise one chunk; return a fallback excerpt on any failure."""
    try:
        resp = await asyncio.wait_for(
            litellm.acompletion(
                model=model,
                messages=[
                    {
                        "role": "user",
                        "content": (
                            f"Context: {task_hint}\n\n"
                            "Summarise the key security findings concisely "
                            "(tool names, severities, affected locations):\n\n"
                            f"{chunk}"
                        ),
                    }
                ],
                max_tokens=500,
            ),
            timeout=_SUMMARISE_TIMEOUT,
        )
        return str(resp.choices[0].message.content or "[empty]")
    except Exception:
        logger.exception("Chunk summarisation failed")
        return f"[summarisation failed — excerpt:]\n{chunk[:500]}"


def _consolidate(summaries: list[str], *, total_chars: int, total_chunks: int) -> str:
    """Join summaries under a descriptive header."""
    header = (
        f"[MapReduce compression: {total_chars:,} chars,"
        f" {total_chunks} chunks → {len(summaries)} summaries]\n\n"
    )
    body = "\n\n".join(f"[Chunk {i + 1}/{total_chunks}]\n{s}" for i, s in enumerate(summaries))
    return header + body
