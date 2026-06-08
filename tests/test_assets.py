"""Tests for the asset taxonomy and target-type detection."""

from __future__ import annotations

from pathlib import Path

import pytest

from strix import assets
from strix.interface.utils import infer_target_type


def test_taxonomy_has_66_unique_entries() -> None:
    keys = [a.key for a in assets.ASSET_TYPES]
    assert len(keys) == 66
    assert len(keys) == len(set(keys))


def test_prefixes_and_exts_are_unique() -> None:
    prefixes = [p for a in assets.ASSET_TYPES for p in a.prefixes]
    assert len(prefixes) == len(set(prefixes))
    exts = [e for a in assets.ASSET_TYPES for e in a.exts]
    assert len(exts) == len(set(exts))


def test_scheme_and_passthrough_keys_resolve() -> None:
    for key in assets.SCHEME_MAP.values():
        assert assets.by_key(key) is not None
    for key in assets.PASSTHROUGH_KEYS:
        assert assets.by_key(key) is not None


def test_every_kind_is_known() -> None:
    known = {"code", "file", "url", "network", "identifier", "account"}
    assert {a.kind for a in assets.ASSET_TYPES} <= known


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("https://example.com", ("web_application", {"target_url": "https://example.com"})),
        ("example.com", ("web_application", {"target_url": "https://example.com"})),
        ("192.168.1.10", ("ip_address", {"target_ip": "192.168.1.10"})),
        (
            "https://github.com/org/repo",
            ("repository", {"target_repo": "https://github.com/org/repo"}),
        ),
        (
            "git@github.com:org/repo.git",
            ("repository", {"target_repo": "git@github.com:org/repo.git"}),
        ),
    ],
)
def test_core_target_types_unchanged(target: str, expected: tuple[str, dict[str, str]]) -> None:
    assert infer_target_type(target) == expected


@pytest.mark.parametrize(
    ("target", "asset_type", "value"),
    [
        ("10.0.0.0/24", "cidr", "10.0.0.0/24"),
        ("cidr:10.0.0.0/8", "cidr", "10.0.0.0/8"),
        ("*.example.com", "wildcard", "*.example.com"),
        ("AS13335", "asn", "AS13335"),
        ("as13335", "asn", "AS13335"),
        ("0x" + "a" * 40, "smart_contract", "0x" + "a" * 40),
        ("s3://my-bucket", "s3_bucket", "s3://my-bucket"),
        ("wss://host/ws", "websocket", "wss://host/ws"),
        ("grpc:1.2.3.4:443", "grpc", "1.2.3.4:443"),
        ("apk:./app.apk", "android_apk", "./app.apk"),
        ("aws:123456789012", "aws_account", "123456789012"),
        ("k8s:https://1.2.3.4:6443", "kubernetes_cluster", "https://1.2.3.4:6443"),
    ],
)
def test_asset_detection(target: str, asset_type: str, value: str) -> None:
    ttype, details = infer_target_type(target)
    assert ttype == "asset"
    assert details == {"asset_type": asset_type, "value": value}


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("url:https://x.com", ("web_application", {"target_url": "https://x.com"})),
        ("ip:8.8.8.8", ("ip_address", {"target_ip": "8.8.8.8"})),
        (
            "source:https://github.com/o/r",
            ("repository", {"target_repo": "https://github.com/o/r"}),
        ),
    ],
)
def test_passthrough_prefixes(target: str, expected: tuple[str, dict[str, str]]) -> None:
    assert infer_target_type(target) == expected


def test_local_dir_still_local_code(tmp_path: Path) -> None:
    ttype, _details = infer_target_type(str(tmp_path))
    assert ttype == "local_code"


def test_local_file_classified_by_extension(tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")
    ttype, details = infer_target_type(str(apk))
    assert ttype == "asset"
    assert details == {"asset_type": "android_apk", "value": str(apk.resolve())}


def test_unknown_file_extension_is_other_asset(tmp_path: Path) -> None:
    f = tmp_path / "mystery.zzz"
    f.write_text("x")
    ttype, details = infer_target_type(str(f))
    assert ttype == "asset"
    assert details["asset_type"] == "other_asset"


def test_empty_target_raises() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        infer_target_type("")
