"""Tests for the session-setup hook registry (register_session_setup)."""

from __future__ import annotations

from typing import Any

import pytest

from strix.runtime import session_manager


@pytest.fixture(autouse=True)
def _clear_registry() -> Any:
    """Each test starts with an empty registry and restores it after."""
    saved = list(session_manager._SESSION_SETUP_CALLBACKS)
    session_manager._SESSION_SETUP_CALLBACKS.clear()
    yield
    session_manager._SESSION_SETUP_CALLBACKS[:] = saved


def _bundle(session: Any = None) -> dict[str, Any]:
    """A minimal session bundle, as create_or_reuse returns + caches."""
    return {"session": session if session is not None else object()}


async def test_callbacks_run_in_registration_order() -> None:
    calls: list[str] = []

    async def a(_session: Any, _cfg: dict[str, Any]) -> None:
        calls.append("a")

    async def b(_session: Any, _cfg: dict[str, Any]) -> None:
        calls.append("b")

    session_manager.register_session_setup(a)
    session_manager.register_session_setup(b)
    await session_manager.run_session_setups(_bundle(), scan_config={})

    assert calls == ["a", "b"]


async def test_callback_receives_session_and_config() -> None:
    seen: dict[str, Any] = {}
    sentinel_session = object()

    async def grab(session: Any, cfg: dict[str, Any]) -> None:
        seen["session"] = session
        seen["cfg"] = cfg

    session_manager.register_session_setup(grab)
    cfg = {"targets": [{"type": "local_code"}]}
    await session_manager.run_session_setups(_bundle(sentinel_session), scan_config=cfg)

    assert seen["session"] is sentinel_session
    assert seen["cfg"] is cfg


async def test_setups_run_once_per_session_on_reuse() -> None:
    """The bundle is cached + reused when a scan resumes in-process; setups must
    run ONCE per materialized session, not again on reuse (non-idempotent hooks
    would double-apply). A fresh bundle runs them again."""
    calls: list[str] = []

    async def setup(_session: Any, _cfg: dict[str, Any]) -> None:
        calls.append("run")

    session_manager.register_session_setup(setup)

    bundle = _bundle()
    await session_manager.run_session_setups(bundle, scan_config={})
    await session_manager.run_session_setups(bundle, scan_config={})  # resume: same bundle
    assert calls == ["run"], "setup must not re-run on a reused session"

    # A different materialized session (new bundle) runs setups afresh.
    await session_manager.run_session_setups(_bundle(), scan_config={})
    assert calls == ["run", "run"]


async def test_setup_marked_done_even_when_callback_fails() -> None:
    """A partial/failed setup still marks the session done, so a resume doesn't
    retry-loop a broken non-idempotent hook."""
    calls: list[str] = []

    async def boom(_session: Any, _cfg: dict[str, Any]) -> None:
        calls.append("boom")
        raise RuntimeError("half-applied")

    session_manager.register_session_setup(boom)
    bundle = _bundle()
    await session_manager.run_session_setups(bundle, scan_config={})
    await session_manager.run_session_setups(bundle, scan_config={})
    assert calls == ["boom"]


async def test_duplicate_registration_ignored() -> None:
    async def once(_session: Any, _cfg: dict[str, Any]) -> None:
        pass

    session_manager.register_session_setup(once)
    session_manager.register_session_setup(once)

    assert session_manager.registered_session_setups() == (once,)


async def test_failing_callback_is_swallowed_and_others_still_run() -> None:
    calls: list[str] = []

    async def boom(_session: Any, _cfg: dict[str, Any]) -> None:
        calls.append("boom")
        raise RuntimeError("setup blew up")

    async def after(_session: Any, _cfg: dict[str, Any]) -> None:
        calls.append("after")

    session_manager.register_session_setup(boom)
    session_manager.register_session_setup(after)
    # Must not raise — a best-effort setup step can't fail the scan.
    await session_manager.run_session_setups(_bundle(), scan_config={})

    assert calls == ["boom", "after"]


async def test_no_callbacks_is_a_noop() -> None:
    await session_manager.run_session_setups(_bundle(), scan_config={})  # no raise
