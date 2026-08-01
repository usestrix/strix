"""Deterministic dependency version-range verify (provider-pluggable, OSV default).

Load-bearing behaviours (a SAFE FP reducer for dep-CVE findings):
  1. In-range -> emit (real). Provider lists the CVE for the installed version.
  2. Out-of-range -> REJECT. Provider knows advisories for the version but NOT the
     cited CVE (installed version outside the range / mis-attributed).
  3. Fail-open everywhere: provider can't answer (None), empty set (coverage gap),
     missing fields, non-CVE/GHSA id, unknown ecosystem, disabled provider -> emit.
     Never suppress a real dep finding on uncertainty.
  4. Provider-pluggable: OSV default, custom URL for mirrors, 'none' disables.
"""

from __future__ import annotations

import requests

from strix.report import dep_verify as dv


def _cand(**kw):
    base = {"cve": "CVE-2021-23337", "package_name": "lodash",
            "installed_version": "4.17.20", "package_ecosystem": "npm"}
    base.update(kw)
    return base


class _FakeProvider:
    """Returns a fixed affecting-set (or None for can't-answer)."""
    def __init__(self, affecting):
        self._a = affecting

    def affecting(self, _pkg, _ecosystem, _version):
        return self._a


def _prov(affecting):
    return _FakeProvider(affecting)


# --- verdict logic (explicit provider, no network) ---

def test_in_range_emits():
    # provider lists the cited CVE as affecting this version -> real, emit.
    assert dv.verify_dependency(_cand(), _prov({"GHSA-X", "CVE-2021-23337"})) is None


def test_out_of_range_rejects():
    # provider knows advisories for this version but NOT the cited CVE -> out of range.
    out = dv.verify_dependency(_cand(), _prov({"GHSA-OTHER", "CVE-2020-0000"}))
    assert out is not None
    assert out["verify_rejected"] is True
    assert out["dep_version_out_of_range"] is True
    assert "CVE-2021-23337" in out["error"]


def test_empty_set_fails_open():
    # definitive "no advisories affect this version" -> coverage-gap risk -> emit.
    assert dv.verify_dependency(_cand(), _prov(set())) is None


def test_provider_cant_answer_fails_open():
    # None = unreachable/error/not-covered -> emit.
    assert dv.verify_dependency(_cand(), _prov(None)) is None


def test_matches_via_alias_or_id():
    assert dv.verify_dependency(_cand(cve="", ghsa="GHSA-JF85-CPCP-J695"),
                                _prov({"GHSA-JF85-CPCP-J695"})) is None


def test_missing_fields_emit():
    for miss in ("cve", "package_name", "installed_version", "package_ecosystem"):
        c = _cand()
        c[miss] = ""
        if miss == "cve":
            c["ghsa"] = ""
        # provider that WOULD reject, to prove the guard short-circuits before it
        assert dv.verify_dependency(c, _prov({"CVE-9999-0000"})) is None, miss


def test_unknown_ecosystem_emits():
    assert dv.verify_dependency(_cand(package_ecosystem="cocoapods-weird"),
                                _prov({"CVE-9999-0000"})) is None


def test_non_cve_identifier_emits():
    assert dv.verify_dependency(_cand(cve="RUSTSEC-2021-0001"),
                                _prov({"CVE-9999-0000"})) is None


# --- ecosystem normalisation ---

def test_ecosystem_normalization():
    assert dv._norm_ecosystem("PyPI") == "PyPI"
    assert dv._norm_ecosystem("pip") == "PyPI"
    assert dv._norm_ecosystem("golang") == "Go"
    assert dv._norm_ecosystem("node") == "npm"
    assert dv._norm_ecosystem("bogus") is None


# --- provider resolution (the pluggable toggle) ---

class _S:
    def __init__(self, provider="osv", osv_url="https://api.osv.dev/v1/query"):
        self.provider = provider
        self.osv_url = osv_url


def test_resolve_provider_osv_default():
    p = dv._resolve_provider(_S())
    assert isinstance(p, dv.OsvProvider)
    assert p.url == "https://api.osv.dev/v1/query"


def test_resolve_provider_custom_mirror_url():
    p = dv._resolve_provider(_S(osv_url="https://osv.internal.corp/v1/query"))
    assert isinstance(p, dv.OsvProvider)
    assert p.url == "https://osv.internal.corp/v1/query"


def test_resolve_provider_none_disables():
    assert dv._resolve_provider(_S(provider="none")) is None
    assert dv._resolve_provider(_S(provider="")) is None


def test_resolve_provider_unknown_disables():
    assert dv._resolve_provider(_S(provider="snyk")) is None


def test_osv_provider_parses_query(monkeypatch):
    # OsvProvider.affecting: mock requests.post, assert it flattens ids+aliases.
    class _R:
        status_code = 200

        def json(self):
            return {"vulns": [{"id": "GHSA-a", "aliases": ["CVE-2021-23337"]},
                              {"id": "GHSA-b"}]}
    monkeypatch.setattr(requests, "post", lambda *_a, **_k: _R())
    got = dv.OsvProvider("https://api.osv.dev/v1/query").affecting("lodash", "npm", "4.17.20")
    assert got == {"GHSA-A", "CVE-2021-23337", "GHSA-B"}


def test_osv_provider_non200_returns_none(monkeypatch):
    class _R:
        status_code = 503

        def json(self):
            return {}
    monkeypatch.setattr(requests, "post", lambda *_a, **_k: _R())
    assert dv.OsvProvider("u").affecting("p", "npm", "1.0") is None


def test_osv_provider_error_returns_none(monkeypatch):
    def _boom(*_a, **_k):
        raise requests.RequestException("timeout")
    monkeypatch.setattr(requests, "post", _boom)
    assert dv.OsvProvider("u").affecting("p", "npm", "1.0") is None
