"""Tests for the target-scoped threat model cache."""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from strix.agents.factory import _BASE_TOOLS
from strix.tools.threat_model import tools as threat_model_tools
from strix.tools.threat_model.tools import (
    _amend_impl,
    _get_impl,
    _save_impl,
    amend_threat_model,
    get_threat_model,
    save_threat_model,
)


if TYPE_CHECKING:
    from pathlib import Path


_MODEL = """# Threat Model

## Overview
A multi-tenant billing API. Product code lives in `api/`; `scripts/` is
developer-only tooling and is not deployed.

## Trust Boundaries and Assumptions
Requests arrive from untrusted tenants through `api/router.py`. The tenant id
is taken from the signed session, never from the request body. Operators
configure webhooks; developers control migrations.

## Attack Surface and Attacker Stories
The public REST surface and the webhook receiver are attacker-reachable. A
realistic story is a tenant reading another tenant's invoices. Local CLI
tooling is not a realistic surface.

## Severity Calibration
Critical: cross-tenant write. High: cross-tenant read. Medium: authenticated
self-scoped information leak. Low: verbose errors.
"""


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["/usr/bin/env", "git", *args], cwd=repo, check=True)  # noqa: S603


def _make_repo(tmp_path: Path, name: str = "repo") -> Path:
    repo = tmp_path / name
    repo.mkdir(parents=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "t")
    (repo / "README.md").write_text("hi\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-qm", "init")
    return repo


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(threat_model_tools, "_CACHE_DIR", tmp_path / "cache")


def test_missing_model_reports_not_found(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)

    result = _get_impl(str(repo))

    assert result["success"] is True
    assert result["found"] is False
    assert "save_threat_model" in result["message"]


def test_saved_model_round_trips(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)

    assert _save_impl(str(repo), _MODEL, "Strix")["success"] is True
    result = _get_impl(str(repo))

    assert result["found"] is True
    assert result["stale"] is False
    assert "multi-tenant billing API" in result["content"]


def test_model_is_stale_after_new_revision(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    _save_impl(str(repo), _MODEL, None)

    (repo / "next.py").write_text("x = 1\n", encoding="utf-8")
    _git(repo, "add", "next.py")
    _git(repo, "commit", "-qm", "next")

    result = _get_impl(str(repo))

    assert result["found"] is True
    assert result["stale"] is True
    assert result["content"]


def test_cache_is_keyed_per_repository(tmp_path: Path) -> None:
    first = _make_repo(tmp_path, "first")
    second = _make_repo(tmp_path, "second")
    _save_impl(str(first), _MODEL, None)

    assert _get_impl(str(second))["found"] is False


def test_rejects_model_missing_required_sections(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    thin = _MODEL.replace("## Severity Calibration", "## Notes")

    result = _save_impl(str(repo), thin, None)

    assert result["success"] is False
    assert "severity calibration" in result["error"]


def test_rejects_stub_model(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)

    result = _save_impl(str(repo), "overview trust boundaries attack surface", None)

    assert result["success"] is False
    assert "too thin" in result["error"]


def test_rejects_empty_target() -> None:
    result = _get_impl("   ")
    assert result["success"] is False
    assert "target cannot be empty" in result["error"]


def test_tools_are_registered() -> None:
    assert get_threat_model in _BASE_TOOLS
    assert save_threat_model in _BASE_TOOLS


_ADDENDUM = (
    "The base model calls the webhook receiver operator-controlled. It is "
    "unauthenticated in `api/webhooks.py:31`, so treat its body as attacker-controlled."
)


def test_amendment_is_returned_with_the_model(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    _save_impl(str(repo), _MODEL, "root")

    assert _amend_impl(str(repo), _ADDENDUM, "webhook-agent")["success"] is True
    result = _get_impl(str(repo))

    assert result["content"] == _MODEL.strip()
    assert [a["content"] for a in result["amendments"]] == [_ADDENDUM]
    assert result["amendments"][0]["by"] == "webhook-agent"


def test_amendments_accumulate_without_overwriting(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    _save_impl(str(repo), _MODEL, "root")

    _amend_impl(str(repo), _ADDENDUM, "agent-a")
    second = "The `scripts/` directory ships in the container image; it is not dev-only."
    _amend_impl(str(repo), second + " See `Dockerfile:14`.", "agent-b")

    amendments = _get_impl(str(repo))["amendments"]
    assert len(amendments) == 2
    assert [a["by"] for a in amendments] == ["agent-a", "agent-b"]


def test_amend_requires_an_existing_model(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)

    result = _amend_impl(str(repo), _ADDENDUM, None)

    assert result["success"] is False
    assert "save_threat_model" in result["error"]


def test_amend_rejects_a_stub(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    _save_impl(str(repo), _MODEL, "root")

    assert _amend_impl(str(repo), "looks wrong", None)["success"] is False


def test_save_clears_amendments_and_says_so(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    _save_impl(str(repo), _MODEL, "root")
    _amend_impl(str(repo), _ADDENDUM, "agent-a")

    result = _save_impl(str(repo), _MODEL.replace("billing API", "billing service"), "root")

    assert result["amendments_cleared"] == 1
    assert "cleared" in result["message"]
    assert "amendments" not in _get_impl(str(repo))


def test_amend_tool_is_registered() -> None:
    assert amend_threat_model in _BASE_TOOLS


_BLACKBOX_MODEL = _MODEL.replace(
    "Product code lives in `api/`; `scripts/` is\ndeveloper-only tooling and is not deployed.",
    "Only the deployed surface is visible; no source. Inferred from recon.",
)


def test_blackbox_target_round_trips() -> None:
    target = "https://app.example.com"

    assert _save_impl(target, _BLACKBOX_MODEL, "recon")["success"] is True
    result = _get_impl(target)

    assert result["found"] is True
    assert result["stale"] is False, "a fresh model with no revision is not stale"
    assert result["revision"] == "unversioned"
    assert "Inferred from recon" in result["content"]


def test_blackbox_target_spellings_share_one_model() -> None:
    _save_impl("https://App.Example.com:443/", _BLACKBOX_MODEL, "recon")

    for spelling in ("https://app.example.com", "app.example.com", "https://app.example.com/"):
        assert _get_impl(spelling)["found"] is True, spelling

    assert _get_impl("https://other.example.com")["found"] is False


def test_blackbox_model_goes_stale_with_age() -> None:
    target = "https://app.example.com"
    _save_impl(target, _BLACKBOX_MODEL, "recon")

    aged = (datetime.now(UTC) - timedelta(days=threat_model_tools._MAX_AGE_DAYS + 1)).isoformat()
    path = threat_model_tools._cache_path("app.example.com:443")
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["created_at"] = aged
    path.write_text(json.dumps(payload), encoding="utf-8")

    result = _get_impl(target)

    assert result["stale"] is True
    assert "re-confirm" in result["message"]


def test_blackbox_target_can_be_amended() -> None:
    target = "https://app.example.com"
    _save_impl(target, _BLACKBOX_MODEL, "recon")

    addendum = (
        "The model infers /admin is IP-restricted. It is reachable with any "
        "authenticated session; the restriction is only on /admin/settings."
    )
    assert _amend_impl(target, addendum, "authz-agent")["success"] is True
    assert _get_impl(target)["amendments"][0]["content"] == addendum


def test_checkout_and_its_remote_are_the_same_target(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    _git(repo, "remote", "add", "origin", "https://github.com/acme/billing.git")
    _save_impl(str(repo), _MODEL, "root")

    clone = _make_repo(tmp_path, "clone")
    _git(clone, "remote", "add", "origin", "https://github.com/acme/billing.git")

    assert _get_impl(str(clone))["found"] is True


def test_path_on_a_known_host_resolves_to_the_scan_target() -> None:
    scan_targets = ["https://app.example.com"]
    _save_impl("https://app.example.com", _BLACKBOX_MODEL, "root", scan_targets)

    # An agent testing one page names that page, not the scan's target string.
    assert _get_impl("https://app.example.com/admin/login", scan_targets)["found"] is True


def test_two_scan_targets_on_one_host_stay_separate() -> None:
    scan_targets = ["https://example.com/tenant-a", "https://example.com/tenant-b"]
    _save_impl("https://example.com/tenant-a", _BLACKBOX_MODEL, "root", scan_targets)

    assert _get_impl("https://example.com/tenant-b", scan_targets)["found"] is False


def test_unknown_host_is_not_snapped_onto_the_scan_target() -> None:
    scan_targets = ["https://app.example.com"]
    _save_impl("https://app.example.com", _BLACKBOX_MODEL, "root", scan_targets)

    assert _get_impl("https://unrelated.test", scan_targets)["found"] is False


def test_empty_target_falls_back_to_a_single_scan_target() -> None:
    scan_targets = ["https://app.example.com"]
    _save_impl("", _BLACKBOX_MODEL, "root", scan_targets)

    assert _get_impl("", scan_targets)["found"] is True
    assert _get_impl("https://app.example.com")["found"] is True


def test_repository_subdirectory_shares_the_repository_model(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    (repo / "src").mkdir()
    _save_impl(str(repo), _MODEL, "root")

    assert _get_impl(str(repo / "src"))["found"] is True


def test_checkout_and_its_clone_url_are_one_identity(tmp_path: Path) -> None:
    """The model an agent saves inside the checkout must be visible to an agent
    that names the same repository by the URL it was cloned from."""
    repo = _make_repo(tmp_path)
    _git(repo, "remote", "add", "origin", "https://github.com/acme/billing.git")
    _save_impl(str(repo), _MODEL, "root")

    assert _get_impl("https://github.com/acme/billing")["found"] is True
    assert _get_impl("https://github.com/acme/billing.git")["found"] is True


def test_ssh_and_https_remotes_are_one_identity(tmp_path: Path) -> None:
    """One repository cloned over scp-style SSH and over HTTPS is one target."""
    over_ssh = _make_repo(tmp_path, "ssh-clone")
    _git(over_ssh, "remote", "add", "origin", "git@github.com:acme/billing.git")
    _save_impl(str(over_ssh), _MODEL, "root")

    over_https = _make_repo(tmp_path, "https-clone")
    _git(over_https, "remote", "add", "origin", "https://github.com/acme/billing.git")

    assert _get_impl(str(over_https))["found"] is True


def test_different_repositories_on_one_host_stay_separate(tmp_path: Path) -> None:
    first = _make_repo(tmp_path, "billing")
    _git(first, "remote", "add", "origin", "git@github.com:acme/billing.git")
    _save_impl(str(first), _MODEL, "root")

    second = _make_repo(tmp_path, "payments")
    _git(second, "remote", "add", "origin", "git@github.com:acme/payments.git")

    assert _get_impl(str(second))["found"] is False
