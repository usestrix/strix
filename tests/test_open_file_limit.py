"""The scan runner raises the open-file soft limit so many-agent scans don't
exhaust file descriptors (surfacing as SQLite 'unable to open database file')."""

from __future__ import annotations

import pytest

from strix.core.runner import raise_open_file_limit


resource = pytest.importorskip("resource")


@pytest.fixture
def _restore_nofile() -> None:
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    try:
        yield
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))


@pytest.mark.usefixtures("_restore_nofile")
def test_raises_soft_limit_toward_hard() -> None:
    _, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if hard != resource.RLIM_INFINITY and hard <= 1024:
        pytest.skip("hard limit too low to raise in this environment")
    resource.setrlimit(resource.RLIMIT_NOFILE, (1024, hard))

    raise_open_file_limit(4096)

    soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    assert soft >= min(4096, hard)


@pytest.mark.usefixtures("_restore_nofile")
def test_never_lowers_an_already_high_limit() -> None:
    _, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if hard == resource.RLIM_INFINITY or hard < 8192:
        pytest.skip("need headroom above the requested minimum")
    resource.setrlimit(resource.RLIMIT_NOFILE, (8192, hard))

    raise_open_file_limit(4096)

    soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    assert soft == 8192


@pytest.mark.usefixtures("_restore_nofile")
def test_does_not_exceed_the_hard_cap() -> None:
    _, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if hard == resource.RLIM_INFINITY:
        pytest.skip("no finite hard cap to test against")
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(1024, hard), hard))

    raise_open_file_limit(hard + 1_000_000)  # ask for more than allowed

    soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    assert soft <= hard
