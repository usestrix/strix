"""Fleet-scale target scoring and near-duplicate collapse (opt-in, ``--triage-targets``).

Mirrors the pattern XBOW's engineering blog describes for large target sets:
score each live target by response signal (status, WAF presence, tech
fingerprint), then collapse near-identical assets via a body-content
similarity hash so agent effort concentrates on unique, high-value targets
instead of restating the same finding across a dozen near-clones.

Strix's default single/handful-of-targets flow doesn't need this — it only
matters once ``--target-list`` supplies enough targets that duplicate effort
is a real cost. It is never on by default: it makes one best-effort HTTP GET
per network target before the scan starts, and that network activity should
be something the operator explicitly asked for, not a silent side effect of
supplying a target list.

Scoring never drops a target by default — it *annotates* ``details["triage"]``
on each ``web_application`` entry in ``targets_info`` and reorders the list
best-signal-first, so an operator or the root agent can see what was found
and choose to deprioritize a near-duplicate. Actually removing detected
near-duplicates requires the separate ``--drop-similar-targets`` flag, since
silently skipping a target the operator explicitly listed is a bigger
behavior change than reordering.
"""

from __future__ import annotations

import hashlib
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Protocol

import requests


logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT_S = 5.0
_MAX_BODY_BYTES = 65536
_MAX_CONCURRENT_FETCHES = 10
_SIMHASH_BITS = 64
_SIMHASH_NEAR_DUPLICATE_MAX_DISTANCE = 3
_SHINGLE_SIZE = 4

_WAF_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("server", "cloudflare"),
    ("cf-ray", ""),
    ("x-sucuri-id", ""),
    ("x-sucuri-cache", ""),
    ("server", "awselb"),
    ("x-akamai-transformed", ""),
    ("server", "cloudfront"),
    ("x-iinfo", ""),
    ("x-denied-reason", ""),
    ("server", "bigip"),
    ("x-cdn", "imperva"),
    ("x-cdn", "incapsula"),
)


class TargetFetcher(Protocol):
    """Fetches one target and returns (status_code, headers, body_text) or None on failure."""

    def __call__(self, url: str, *, timeout: float) -> tuple[int, dict[str, str], str] | None: ...


def default_fetcher(url: str, *, timeout: float) -> tuple[int, dict[str, str], str] | None:
    """Best-effort single GET — never raises, returns ``None`` on any failure."""
    try:
        with requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            stream=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; strix-triage/1.0)"},
        ) as resp:
            body = resp.raw.read(_MAX_BODY_BYTES, decode_content=True)
            text = body.decode(resp.encoding or "utf-8", errors="replace")
            headers = {k.lower(): v for k, v in resp.headers.items()}
            status = resp.status_code
    except Exception:  # noqa: BLE001 - triage is best-effort, never fatal to the scan
        logger.debug("target triage: fetch failed for %s", url, exc_info=True)
        return None
    else:
        return status, headers, text


def _detect_waf(headers: dict[str, str]) -> str | None:
    """Match a WAF/CDN signature. An empty ``needle`` means presence alone is the signal."""
    for header_name, needle in _WAF_SIGNATURES:
        if header_name not in headers:
            continue
        if not needle:
            return header_name
        if needle in headers[header_name].lower():
            return f"{header_name}:{needle}"
    return None


_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")


def _simhash(text: str) -> int | None:
    """64-bit SimHash over 4-token shingles of the body — near-identical pages hash close.

    Returns ``None`` for a tokenless body (empty/binary/no-content response) rather
    than a fixed value: every tokenless body would otherwise hash identically and
    get flagged as a near-duplicate of every other tokenless body, which is a false
    signal, not a real content match.
    """
    tokens = _TOKEN_RE.findall(text.lower())
    if not tokens:
        return None
    shingle_count = max(1, len(tokens) - _SHINGLE_SIZE + 1)
    shingles = [" ".join(tokens[i : i + _SHINGLE_SIZE]) for i in range(shingle_count)]
    bit_weights = [0] * _SIMHASH_BITS
    for shingle in shingles:
        digest = hashlib.blake2b(shingle.encode("utf-8"), digest_size=8).digest()
        shingle_hash = int.from_bytes(digest, "big")
        for bit in range(_SIMHASH_BITS):
            bit_weights[bit] += 1 if (shingle_hash >> bit) & 1 else -1
    fingerprint = 0
    for bit in range(_SIMHASH_BITS):
        if bit_weights[bit] > 0:
            fingerprint |= 1 << bit
    return fingerprint


def _hamming_distance(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


@dataclass(frozen=True)
class _Signal:
    index: int
    original: str
    status: int | None
    waf: str | None
    simhash: int | None
    score: float


def _score_signal(status: int | None, waf: str | None, body_len: int) -> float:
    """Higher = more worth agent effort. Reachable, no-WAF, substantive-body targets rank first."""
    if status is None:
        return -1.0
    score = 0.0
    if 200 <= status < 300:
        score += 3.0
    elif 300 <= status < 400:
        score += 1.5
    elif status in (401, 403):
        score += 1.0
    elif status >= 500:
        score += 0.5
    if waf is None:
        score += 1.0
    score += min(body_len / 10000.0, 1.0)
    return score


def _group_near_duplicates(signals: list[_Signal]) -> dict[int, int]:
    """Return {index: index_of_kept_representative} for every index in a near-dup cluster."""
    duplicate_of: dict[int, int] = {}
    hashed = [s for s in signals if s.simhash is not None]
    hashed.sort(key=lambda s: s.score, reverse=True)
    kept: list[_Signal] = []
    for signal in hashed:
        match = next(
            (
                k
                for k in kept
                if _hamming_distance(k.simhash or 0, signal.simhash or 0)
                <= _SIMHASH_NEAR_DUPLICATE_MAX_DISTANCE
            ),
            None,
        )
        if match is not None:
            duplicate_of[signal.index] = match.index
        else:
            kept.append(signal)
    return duplicate_of


def triage_network_targets(
    targets_info: list[dict[str, Any]],
    *,
    fetcher: TargetFetcher = default_fetcher,
    timeout: float = _DEFAULT_TIMEOUT_S,
    drop_near_duplicates: bool = False,
) -> list[dict[str, Any]]:
    """Score and reorder ``web_application`` entries; flag near-duplicates.

    No-ops (returns the input unchanged) when there are fewer than 2 network
    targets, since triage has nothing to prioritize with a single target.
    Never raises: a fetch failure scores that target ``-1`` (sorted last,
    still scanned) rather than blocking the run.
    """
    network_indices = [
        i
        for i, t in enumerate(targets_info)
        if t.get("type") == "web_application" and t.get("details", {}).get("target_url")
    ]
    if len(network_indices) < 2:
        return targets_info

    def _fetch_one(index: int) -> _Signal:
        target = targets_info[index]
        url = target["details"]["target_url"]
        fetched = fetcher(url, timeout=timeout)
        if fetched is None:
            return _Signal(index, target["original"], None, None, None, -1.0)
        status, headers, body = fetched
        waf = _detect_waf(headers)
        simhash = _simhash(body)
        score = _score_signal(status, waf, len(body))
        return _Signal(index, target["original"], status, waf, simhash, score)

    # Concurrent, not serial: a fleet of hundreds of targets at ~5s/request each
    # would otherwise delay scan startup by many minutes.
    with ThreadPoolExecutor(max_workers=min(_MAX_CONCURRENT_FETCHES, len(network_indices))) as pool:
        signals = list(pool.map(_fetch_one, network_indices))

    duplicate_of = _group_near_duplicates(signals)
    by_index = {s.index: s for s in signals}
    for signal in signals:
        target = targets_info[signal.index]
        dup_index = duplicate_of.get(signal.index)
        target["details"]["triage"] = {
            "status": signal.status,
            "waf_detected": signal.waf,
            "score": round(signal.score, 3),
            "near_duplicate_of": by_index[dup_index].original if dup_index is not None else None,
        }

    logger.info(
        "target triage: scored %d network target(s), %d flagged as near-duplicates",
        len(signals),
        len(duplicate_of),
    )

    if drop_near_duplicates and duplicate_of:
        dropped = set(duplicate_of.keys())
        targets_info = [t for i, t in enumerate(targets_info) if i not in dropped]

    def sort_key(t: dict[str, Any]) -> float:
        triage = t.get("details", {}).get("triage")
        return -float(triage["score"]) if triage else float("inf")

    return sorted(targets_info, key=sort_key)
