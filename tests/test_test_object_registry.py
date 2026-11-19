from pathlib import Path

import pytest

from strix.tools.test_objects import tools as registry
from strix.tools.test_objects.tools import with_registration_reminder


def _fresh(tmp_path: Path) -> None:
    registry.hydrate_test_objects_from_disk(tmp_path)


def test_register_persists_and_rehydrates(tmp_path: Path) -> None:
    _fresh(tmp_path)
    assert registry.register("zed.qa.probe.001@example.com", "account", "agent", "a1")
    assert not registry.register("7", "record", "agent")
    # A bare word names a table, route or role, not one object the target issued.
    for word in ("users", "admin", "billing-settings"):
        assert not registry.register(word, "record", "agent")
    assert registry.register("client_01ABC", "oauth client", "agent")
    assert registry.register("qa-admin", "account", "provisioned")
    _fresh(tmp_path)
    # The saved file can be edited, so on reload nothing is provisioned and a bare word is dropped.
    assert not registry.matching_test_objects("delete qa-admin")
    assert registry.matching_test_objects("x client_01ABC")[0]["source"] == "agent"
    assert registry.matching_test_objects("login zed.qa.probe.001@example.com now") == [
        {"identifier": "zed.qa.probe.001@example.com", "kind": "account", "source": "agent"}
    ]


def test_matching_requires_whole_identifier(tmp_path: Path) -> None:
    _fresh(tmp_path)
    registry.register("3007", "account", "agent")
    assert registry.matching_test_objects('{"UserID": "3007"}')
    assert not registry.matching_test_objects('{"UserID": "13007"}')
    assert not registry.matching_test_objects('{"UserID": "30071"}')
    assert not registry.matching_test_objects("/User/Delete?id=2686")


def test_seed_provisioned_accounts(tmp_path: Path) -> None:
    _fresh(tmp_path)
    text = "<credential><username>qa.user@example.com</username></credential>"
    assert registry.seed_provisioned_accounts(text) == 1
    match = registry.matching_test_objects("user qa.user@example.com")[0]
    assert match["source"] == "provisioned"


@pytest.mark.parametrize(
    "output",
    [
        'STATUS 201\nRESP: {"client_id": "client_01ABC"}',
        '--- attacker-domain: 201 {"client_id":"client_01ABC"}',
        "HTTP/1.1 201 Created",
    ],
)
def test_reminder_added_to_output_reporting_a_create(output: str) -> None:
    result = with_registration_reminder(output)
    assert result.startswith(output)
    assert "register_test_object" in result


@pytest.mark.parametrize(
    "output",
    ["STATUS 200\n{}", "host 104.20.30.201 up", "id 12013 size=201.5", "port :201/tcp", None],
)
def test_reminder_not_added_without_a_create(output: str | None) -> None:
    assert with_registration_reminder(output) == output


def test_the_registry_is_written_as_a_spreadsheet_beside_the_report(tmp_path: Path) -> None:
    registry.hydrate_test_objects_from_disk(tmp_path / ".state")
    assert registry.register("alice@example.com", "account", "provisioned")
    assert registry.register("=cmd|'/c calc'!A1", "record", "agent")
    lines = (tmp_path / "test_objects.csv").read_text(encoding="utf-8").splitlines()
    assert lines[0] == "identifier,kind,source,created_at"
    assert lines[1].startswith("alice@example.com,account,provisioned,")
    # A cell a spreadsheet would run as a formula is kept as text.
    assert lines[2].startswith("'=cmd|'/c calc'!A1,record,agent,")
