"""assert_compatible_sdk_version() guards the openai-agents SDK version.

Strix's sandbox runtime (strix/runtime/docker_client.py) and agent tool
wiring (strix/agents/factory.py) depend on internal shapes of the
``openai-agents`` SDK that are not guaranteed stable across versions (see
strix/runtime/sdk_compat.py for the full list). This module must raise a
clear RuntimeError for an out-of-range installed version and pass silently
for a version inside SUPPORTED_AGENTS_SDK_RANGE.
"""

from __future__ import annotations

import pytest

from strix.runtime import sdk_compat


def test_currently_pinned_version_is_compatible() -> None:
    """The version actually installed in this environment must pass.

    This keeps SUPPORTED_AGENTS_SDK_RANGE honest against what pyproject.toml
    and uv.lock actually resolve to.
    """
    installed = sdk_compat.installed_agents_sdk_version()
    assert sdk_compat._satisfies(installed, sdk_compat.SUPPORTED_AGENTS_SDK_RANGE)
    # Must not raise.
    sdk_compat.assert_compatible_sdk_version()


@pytest.mark.parametrize("bad_version", ["0.14.6", "0.18.9", "0.20.0", "1.0.0"])
def test_out_of_range_version_raises_clear_error(
    monkeypatch: pytest.MonkeyPatch, bad_version: str
) -> None:
    monkeypatch.setattr(sdk_compat, "installed_agents_sdk_version", lambda: bad_version)

    with pytest.raises(RuntimeError) as exc_info:
        sdk_compat.assert_compatible_sdk_version()

    message = str(exc_info.value)
    assert bad_version in message
    assert "openai-agents" in message
    for spec in sdk_compat.SUPPORTED_AGENTS_SDK_RANGE:
        assert spec in message
    assert "sdk_compat.py" in message


@pytest.mark.parametrize("good_version", ["0.19.0", "0.19.1", "0.19.99"])
def test_in_range_versions_pass(monkeypatch: pytest.MonkeyPatch, good_version: str) -> None:
    monkeypatch.setattr(sdk_compat, "installed_agents_sdk_version", lambda: good_version)
    sdk_compat.assert_compatible_sdk_version()  # must not raise


def test_unparseable_version_raises_clear_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sdk_compat, "installed_agents_sdk_version", lambda: "not-a-version")

    with pytest.raises(RuntimeError) as exc_info:
        sdk_compat.assert_compatible_sdk_version()

    assert "not-a-version" in str(exc_info.value)
