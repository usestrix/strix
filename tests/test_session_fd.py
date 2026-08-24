from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, cast

import pytest

from strix.core.sessions import open_agent_session


def _count_open_fds() -> int | None:
    for path in (Path("/proc/self/fd"), Path("/dev/fd")):
        if path.is_dir():
            return len(list(path.iterdir()))
    return None


@pytest.mark.asyncio
async def test_sessions_hold_no_descriptors_while_parked(tmp_path: Path) -> None:
    """Descriptor use must track live operations, not the number of sessions.

    The SDK keeps a connection per (session, pool thread) open for the session's
    whole life. An agent parks rather than exits, so its session lives for the
    scan, and fan-out multiplies those handles until the process runs out of file
    descriptors (#1018). A session that is not mid-operation should hold none.
    """
    baseline = _count_open_fds()
    if baseline is None:
        pytest.skip("no /proc/self/fd or /dev/fd on this platform")

    sessions = [open_agent_session(f"a{i}", tmp_path / f"s{i}.db") for i in range(60)]
    try:
        for _ in range(4):
            await asyncio.gather(
                *(s.add_items([{"role": "user", "content": "x"}]) for s in sessions)
            )
            await asyncio.gather(*(s.get_items() for s in sessions))
        parked = _count_open_fds()
        assert parked is not None
        # 60 parked sessions, yet descriptors are back at the baseline.
        assert parked - baseline <= 5, f"parked fds grew by {parked - baseline}"
    finally:
        for s in sessions:
            s.close()


@pytest.mark.asyncio
async def test_in_flight_descriptors_track_concurrency_not_session_count(
    tmp_path: Path,
) -> None:
    baseline = _count_open_fds()
    if baseline is None:
        pytest.skip("no /proc/self/fd or /dev/fd on this platform")

    sessions = [open_agent_session(f"a{i}", tmp_path / f"s{i}.db") for i in range(200)]
    peak = baseline
    try:

        async def sample() -> None:
            nonlocal peak
            for _ in range(500):
                current = _count_open_fds()
                if current is not None:
                    peak = max(peak, current)
                await asyncio.sleep(0)

        async def load() -> None:
            for _ in range(4):
                await asyncio.gather(
                    *(s.add_items([{"role": "user", "content": "x"}]) for s in sessions)
                )

        await asyncio.gather(load(), sample())
        # 200 sessions, but peak is bounded by the thread pool, well under 200.
        assert peak - baseline < 100, f"in-flight fds peaked at +{peak - baseline}"
    finally:
        for s in sessions:
            s.close()


@pytest.mark.asyncio
async def test_history_survives_the_per_operation_connection(tmp_path: Path) -> None:
    session = open_agent_session("agent-1", tmp_path / "agents.db")
    try:
        for i in range(30):
            await session.add_items([{"role": "user", "content": f"m{i}"}])
        items = [cast("dict[str, Any]", i) for i in await session.get_items()]
        assert [i["content"] for i in items] == [f"m{i}" for i in range(30)]
    finally:
        session.close()


@pytest.mark.asyncio
async def test_concurrent_sessions_sharing_one_file_stay_consistent(tmp_path: Path) -> None:
    db = tmp_path / "shared.db"
    sessions = [open_agent_session(f"a{i}", db) for i in range(10)]
    try:
        await asyncio.gather(
            *(s.add_items([{"role": "user", "content": s.session_id}]) for s in sessions)
        )
        # Each session sees only its own row despite sharing the file.
        for s in sessions:
            items = [cast("dict[str, Any]", i) for i in await s.get_items()]
            assert [i["content"] for i in items] == [s.session_id]
    finally:
        for s in sessions:
            s.close()


@pytest.mark.asyncio
async def test_a_closed_session_refuses_operations(tmp_path: Path) -> None:
    session = open_agent_session("agent-1", tmp_path / "agents.db")
    await session.add_items([{"role": "user", "content": "x"}])
    session.close()
    with pytest.raises(RuntimeError, match="closed"):
        await session.add_items([{"role": "user", "content": "y"}])
