from __future__ import annotations

import threading
from typing import TYPE_CHECKING

from strix.llm import warmup


if TYPE_CHECKING:
    import pytest


def test_wait_for_import_warmup_joins_active_thread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered = threading.Event()
    release = threading.Event()
    returned = threading.Event()

    def blocked_warm(_modules: tuple[str, ...]) -> None:
        entered.set()
        assert release.wait(timeout=2)

    monkeypatch.setattr(warmup, "_thread", None)
    monkeypatch.setattr(warmup, "_warm", blocked_warm)
    thread = warmup.start_import_warmup(())
    assert entered.wait(timeout=1)

    waiter = threading.Thread(
        target=lambda: (warmup.wait_for_import_warmup(), returned.set()),
    )
    waiter.start()
    assert not returned.wait(timeout=0.05)

    release.set()
    waiter.join(timeout=1)
    thread.join(timeout=1)
    assert returned.is_set()
