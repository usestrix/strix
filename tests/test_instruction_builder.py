"""Instruction builder: templates, catalogs and rendering of the final instruction."""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Any

import pytest


_TMP = Path(tempfile.mkdtemp(prefix="frontal-builder-"))
# Same throwaway settings as test_frontal_audit (whichever is imported first wins).
os.environ.setdefault("FRONTAL_DATABASE_URL", f"sqlite:///{_TMP / 'frontal.db'}")
os.environ.setdefault("FRONTAL_ARTIFACTS_DIR", str(_TMP / "artifacts"))

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient  # noqa: E402

from frontal.app import instruction_builder as ib  # noqa: E402
from frontal.app.main import app  # noqa: E402


# Placeholders per instruction, taken from the V9 generator's template.
COMMON = {
    "SELECT_ASSESSMENT_TYPE",
    "SELECT_ASSET_SENSITIVITY",
    "SELECT_AUDIENCE",
    "SELECT_AUTHENTICATION_METHOD",
    "SELECT_COLLECTION_LIMITS",
    "SELECT_EXCLUSIONS",
    "SELECT_INTERNET_EXPOSURE",
    "SELECT_OPERATIONAL_LIMITS",
    "SELECT_PRIORITIES",
    "SELECT_PROHIBITED_ACTIONS",
    "SELECT_PROTOCOLS",
    "SELECT_REPORT_LANGUAGE",
    "SELECT_STOP_CONDITIONS",
    "SELECT_SUMMARY_FOCUS",
    "SELECT_USER_TYPES",
    "TEXT_ACCESS_MATRIX",
    "TEXT_ACCESS_PROCEDURE",
    "TEXT_ACCOUNTS_AND_ROLES",
    "TEXT_ADDITIONAL_RESOURCES",
    "TEXT_APPLICATION_DESCRIPTION",
    "TEXT_AUTHORIZATION_MODEL",
    "TEXT_AUTHORIZATION_TEST_CASES",
    "TEXT_AUTHORIZED_TARGETS",
    "TEXT_CRITICAL_BUSINESS_FLOWS",
    "TEXT_FUNCTIONALITY_CRITICALITY",
    "TEXT_PROJECT_NAME",
    "TEXT_QUESTIONS_AND_RULES",
    "TEXT_TEST_DATA",
}
API_ONLY = {
    "SELECT_API_TYPE",
    "TEXT_API_CLIENT_COLLECTION",
    "TEXT_API_DEFINITION",
    "TEXT_API_DEPENDENCIES",
    "TEXT_API_ENVIRONMENTS_AND_VERSIONS",
    "TEXT_API_WORKFLOWS",
    "TEXT_ENDPOINT_INVENTORY",
    "TEXT_ENGAGEMENT_CONTACTS",
    "TEXT_EXPECTED_RESPONSES",
    "TEXT_OTHER_API_TYPE",
    "TEXT_VALID_REQUESTS_JSON",
}
EXPECTED = {
    "web": COMMON,
    "api": COMMON | API_ONLY,
    "authorization": COMMON,
    "web-exp": COMMON,
    "api-exp": COMMON | API_ONLY,
    "auth-exp": COMMON,
}


def _filled(template: str, **overrides: dict[str, Any]) -> dict[str, dict[str, Any]]:
    values: dict[str, dict[str, Any]] = {}
    for ph in ib.template_placeholders(template):
        spec = ib.field_spec(ph)
        assert spec is not None
        if spec["type"] == "select":
            values[ph] = {"selected": [spec["options"][0]["id"]]}
        elif spec["kind"] == "number":
            values[ph] = {"value": "3"}
        else:
            values[ph] = {"value": f"value of {ph}"}
    values.update(overrides)
    return values


@pytest.mark.parametrize("template", sorted(EXPECTED))
def test_placeholders_match_the_reference_table(template: str) -> None:
    assert set(ib.template_placeholders(template)) == EXPECTED[template]


def test_only_the_selection_fields_are_mandatory() -> None:
    """The client fills the SELECT_ ones; a TEXT_ left empty just disappears."""
    cfg = ib.builder_config()
    selects = {ph for ph, spec in cfg["fields"].items() if spec["type"] == "select"}
    assert set(cfg["mandatory"]) == selects | {"TEXT_PROJECT_NAME"}
    assert "TEXT_PROJECT_NAME" in cfg["mandatory"], "the document title is required"


def test_the_expanded_variants_run_deep() -> None:
    modes = {t["id"]: t["scan_mode"] for t in ib.builder_config()["templates"]}
    assert modes == {
        "web": "standard",
        "api": "standard",
        "authorization": "standard",
        "web-exp": "deep",
        "api-exp": "deep",
        "auth-exp": "deep",
    }


def test_protocols_and_collection_limits_accept_several_options() -> None:
    cfg = ib.builder_config()["fields"]
    for ph in ("SELECT_PROTOCOLS", "SELECT_COLLECTION_LIMITS"):
        assert cfg[ph]["selection"] == "multiple", ph
    r = ib.render_instruction(
        "web",
        _filled(
            "web",
            SELECT_PROTOCOLS={"selected": ["https", "websocket"]},
            SELECT_COLLECTION_LIMITS={"selected": ["metadata_only", "redact_passwords"]},
        ),
    )
    assert r["complete"], r["issues"]
    assert "HTTPS, only on the specified hosts" in r["instruction"]
    assert "WebSocket, only using explicitly specified" in r["instruction"]
    assert "Redact passwords from retained evidence." in r["instruction"]


def test_exclusive_and_grouped_options() -> None:
    """`none` cancels the other protocols; the retention volume is one of three."""
    r = ib.render_instruction(
        "web", _filled("web", SELECT_PROTOCOLS={"selected": ["https", "none"]})
    )
    assert "SELECT_PROTOCOLS" in r["issues"]
    r = ib.render_instruction(
        "web",
        _filled(
            "web",
            SELECT_COLLECTION_LIMITS={"selected": ["metadata_only", "three_synthetic_records"]},
        ),
    )
    assert "SELECT_COLLECTION_LIMITS" in r["issues"]
    r = ib.render_instruction(
        "web",
        _filled(
            "web",
            SELECT_COLLECTION_LIMITS={"selected": ["metadata_only", "redact_personal_data"]},
        ),
    )
    assert r["complete"], r["issues"]


def test_the_catch_all_exclusion_is_gone() -> None:
    ids = {o["id"] for o in ib.builder_config()["fields"]["SELECT_EXCLUSIONS"]["options"]}
    assert "all" not in ids


def test_the_reviewed_limits_take_the_client_text() -> None:
    r = ib.render_instruction(
        "web",
        _filled(
            "web",
            SELECT_OPERATIONAL_LIMITS={
                "selected": ["low"],
                "custom": "máximo 2 req/s, ventana 22:00-06:00",
            },
        ),
    )
    assert "engagement-specific limits: máximo 2 req/s" in r["instruction"]


def test_every_placeholder_and_default_is_defined() -> None:
    cfg = ib.builder_config()
    for tpl in cfg["templates"]:
        for ph in ib.template_placeholders(tpl["id"]):
            assert ph in cfg["fields"], ph
    for ph, spec in cfg["fields"].items():
        if spec["type"] != "select":
            assert spec["kind"] in {"line", "text", "number"}, ph
            continue
        ids = [o["id"] for o in spec["options"]]
        assert len(ids) == len(set(ids)), ph
        assert all(re.fullmatch(r"[a-z0-9_]+", i) for i in ids), ph
        assert set(spec.get("default", [])) <= set(ids), ph
        if spec["selection"] == "single":
            assert len(spec.get("default", [])) <= 1, ph


@pytest.mark.parametrize("template", sorted(EXPECTED))
def test_complete_values_resolve_every_placeholder(template: str) -> None:
    r = ib.render_instruction(template, _filled(template))
    assert r["complete"], r["issues"]
    assert "{{" not in r["instruction"] and "<!--" not in r["instruction"]
    assert r["warnings"] == []


def test_a_mandatory_field_left_empty_stays_visible() -> None:
    values = _filled("web")
    del values["TEXT_PROJECT_NAME"]
    r = ib.render_instruction("web", values)
    assert set(r["issues"]) == {"TEXT_PROJECT_NAME"}
    assert "{{TEXT_PROJECT_NAME}}" in r["instruction"]


def test_an_optional_field_left_empty_removes_its_line() -> None:
    """Only the SELECT_ fields are mandatory: an empty TEXT_ takes its line away."""
    values = _filled("web")
    values.pop("TEXT_TEST_DATA")
    r = ib.render_instruction("web", values)
    assert r["complete"], r["issues"]
    assert "TEXT_TEST_DATA" not in r["instruction"]
    assert "Authorized synthetic data and ownership" not in r["instruction"]
    assert "{{" not in r["instruction"]
    assert "\n\n\n" not in r["instruction"]


def test_an_optional_field_marked_na_removes_its_line() -> None:
    r = ib.render_instruction(
        "web", _filled("web", TEXT_TEST_DATA={"na": True, "na_reason": "no test data"})
    )
    assert r["complete"], r["issues"]
    assert "N/A" not in r["instruction"]
    assert "Authorized synthetic data and ownership" not in r["instruction"]


def test_a_mandatory_field_still_needs_its_na_reason() -> None:
    r = ib.render_instruction(
        "web", _filled("web", SELECT_PROTOCOLS={"na": True, "na_reason": "x"})
    )
    assert "SELECT_PROTOCOLS" in r["issues"]
    r = ib.render_instruction(
        "web",
        _filled("web", SELECT_PROTOCOLS={"na": True, "na_reason": "no network testing agreed"}),
    )
    assert r["complete"], r["issues"]
    assert "N/A: no network testing agreed" in r["instruction"]


def test_a_select_marked_na_requires_a_reason() -> None:
    r = ib.render_instruction(
        "web", _filled("web", SELECT_EXCLUSIONS={"na": True, "na_reason": "x"})
    )
    assert "SELECT_EXCLUSIONS" in r["issues"]
    r = ib.render_instruction(
        "web",
        _filled(
            "web",
            SELECT_EXCLUSIONS={"na": True, "na_reason": "nothing was excluded by the client"},
        ),
    )
    assert r["complete"]
    assert "N/A: nothing was excluded by the client" in r["instruction"]


def test_select_rules() -> None:
    two = ib.render_instruction(
        "web", _filled("web", SELECT_ASSESSMENT_TYPE={"selected": ["black_box", "combined"]})
    )
    assert "SELECT_ASSESSMENT_TYPE" in two["issues"]
    unknown = ib.render_instruction("web", _filled("web", SELECT_PROTOCOLS={"selected": ["ftp"]}))
    assert "SELECT_PROTOCOLS" in unknown["issues"]
    custom = ib.render_instruction(
        "web",
        _filled("web", SELECT_ASSESSMENT_TYPE={"selected": ["combined"], "custom": "with a WAF"}),
    )
    assert custom["complete"] and "with a WAF" in custom["instruction"]
    clash = ib.render_instruction(
        "web",
        _filled(
            "web",
            SELECT_OPERATIONAL_LIMITS={"selected": ["minimal", "low"]},
        ),
    )
    assert "SELECT_OPERATIONAL_LIMITS" in clash["issues"]

    # An option contributes its catalog sentence, and ordered selections are numbered.
    r = ib.render_instruction(
        "web",
        _filled(
            "web",
            SELECT_PRIORITIES={
                "selected": ["trust_boundaries", "sensitive_assets"],
                "custom": "payments first",
            },
        ),
    )
    assert (
        "in order: 1) Prioritize crossings of role, ownership and tenant boundaries; "
        "2) Prioritize paths involving the sensitive assets identified in the project context; "
        "payments first."
    ) in r["instruction"]


def test_the_other_api_type_is_optional() -> None:
    """Left empty, the `other` sub-bullet disappears instead of blocking the render."""
    values = _filled("api")
    del values["TEXT_OTHER_API_TYPE"]
    r = ib.render_instruction("api", values)
    assert r["complete"], r["issues"]
    assert "another explicitly described API style" not in r["instruction"]
    assert "- API style or interface type:" in r["instruction"]


def test_field_references_stay_readable() -> None:
    """A field named inside another field's text is referred to, not pasted in."""
    r = ib.render_instruction(
        "authorization",
        _filled("authorization", TEXT_ACCOUNTS_AND_ROLES={"value": "USER_A: customer in TENANT_A"}),
    )
    assert "account label defined in the “Accounts, roles and tenants” entry." in r["instruction"]
    assert "USER_A: customer in TENANT_A”" not in r["instruction"]


def test_the_project_name_cannot_wrap_or_be_na() -> None:
    """The project name is the document title: a newline or N/A breaks the heading."""
    r = ib.render_instruction("web", _filled("web", TEXT_PROJECT_NAME={"value": "a\nb"}))
    assert "TEXT_PROJECT_NAME" in r["issues"]
    r = ib.render_instruction(
        "web", _filled("web", TEXT_PROJECT_NAME={"na": True, "na_reason": "unnamed engagement"})
    )
    assert "TEXT_PROJECT_NAME" in r["issues"]


def test_multiline_values_stay_inside_the_bullet() -> None:
    accounts = "- USER_A: customer in TENANT_A.\n- ADMIN_A: tenant administrator."
    r = ib.render_instruction("web", _filled("web", TEXT_ACCOUNTS_AND_ROLES={"value": accounts}))
    assert (
        "- Accounts, users, roles and tenants, without secrets:\n"
        "  - USER_A: customer in TENANT_A.\n"
        "  - ADMIN_A: tenant administrator.\n"
        "- For every designated test identity"
    ) in r["instruction"]


def test_no_double_period_and_single_line_title() -> None:
    r = ib.render_instruction(
        "web", _filled("web", TEXT_TEST_DATA={"value": "ORDER_A owned by USER_A."})
    )
    assert "ownership: ORDER_A owned by USER_A.\n" in r["instruction"]


def test_secret_warnings() -> None:
    r = ib.render_instruction(
        "web",
        _filled(
            "web", TEXT_ACCESS_PROCEDURE={"value": "Log in as USER_A with password: Summer2026!"}
        ),
    )
    assert [w["field"] for w in r["warnings"]] == ["TEXT_ACCESS_PROCEDURE"]
    r = ib.render_instruction(
        "web",
        _filled(
            "web", TEXT_ACCESS_PROCEDURE={"value": "Retrieve the password from the approved vault."}
        ),
    )
    assert r["warnings"] == []


def test_unknown_template() -> None:
    with pytest.raises(ib.UnknownTemplateError):
        ib.render_instruction("nope", {})


def test_api_endpoints() -> None:
    client = TestClient(app)
    cfg = client.get("/manage/instruction-builder").json()
    assert [t["id"] for t in cfg["templates"]] == [
        "web",
        "api",
        "authorization",
        "web-exp",
        "api-exp",
        "auth-exp",
    ]
    url = "/manage/instruction-builder/render"
    r = client.post(url, json={"template": "web", "values": _filled("web")})
    assert r.status_code == 200 and r.json()["complete"]
    assert client.post(url, json={"template": "x", "values": {}}).status_code == 404
