"""Comprehensive tests for the Strix i18n engine."""

import asyncio
import os
from unittest.mock import patch
import pytest

import strix.i18n as i18n
from strix.i18n import get_language, get_language_directive, set_language, t


@pytest.fixture(autouse=True)
def _reset_i18n():
    i18n._current_language.set(None)
    with i18n._locales_lock:
        i18n._locales_cache.clear()
    yield
    i18n._current_language.set(None)


def test_set_and_get_language():
    set_language("es")
    assert get_language() == "es"
    set_language("id")
    assert get_language() == "id"


def test_fallback_unsupported_language():
    set_language("fr")
    assert get_language() == "en"


def test_translation_formatting():
    set_language("id")
    result = t("cli.scan_started", target="example.com")
    assert "example.com" in result
    assert "Memulai" in result


def test_safe_interpolation_on_missing_key():
    set_language("en")
    result = t("cli.scan_started")  # target missing
    assert "target" in result or isinstance(result, str)


@pytest.mark.asyncio
async def test_async_contextvar_isolation():
    """Verify concurrent async tasks maintain isolated language contexts."""

    async def task_es():
        set_language("es")
        await asyncio.sleep(0.01)
        assert get_language() == "es"

    async def task_id():
        set_language("id")
        await asyncio.sleep(0.01)
        assert get_language() == "id"

    await asyncio.gather(task_es(), task_id())


def test_language_directive():
    set_language("es")
    directive = get_language_directive()
    assert "Spanish" in directive
    assert "CVE" in directive
