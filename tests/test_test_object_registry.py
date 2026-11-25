import csv
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from agents.tool_context import ToolContext

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
    assert lines[0] == "identifier,kind,source,created_at,agent,details"
    assert lines[1].startswith("alice@example.com,account,provisioned,")
    # A cell a spreadsheet would run as a formula is kept as text.
    assert lines[2].startswith("'=cmd|'/c calc'!A1,record,agent,")


def test_object_details_are_kept_and_exported_without_credentials(tmp_path: Path) -> None:
    registry.hydrate_test_objects_from_disk(tmp_path / ".state")
    assert registry.register(
        "qa7f3@example.com",
        "user",
        "agent",
        "a1",
        agent_name="Signup Tester",
        details={
            "username": "qa7f3",
            "email": "qa7f3@example.com",
            "user_id": 4412,
            "password": "hunter2",
            "sessionToken": "r:abc",
            "api_key": "sk-1",
            "profile": {"role": "customer"},
            "empty": "",
        },
    )
    with (tmp_path / "test_objects.csv").open(encoding="utf-8", newline="") as file:
        row = next(iter(csv.DictReader(file)))
    assert row["agent"] == "Signup Tester"
    assert json.loads(row["details"]) == {
        "username": "qa7f3",
        "email": "qa7f3@example.com",
        "user_id": "4412",
        "profile": '{"role": "customer"}',
    }
    assert "hunter2" not in (tmp_path / ".state" / "test_objects.json").read_text(encoding="utf-8")


def test_details_that_are_not_a_map_are_ignored(tmp_path: Path) -> None:
    registry.hydrate_test_objects_from_disk(tmp_path / ".state")
    assert registry.register("order-9912", "record", "agent", details="free text")
    lines = (tmp_path / "test_objects.csv").read_text(encoding="utf-8").splitlines()
    assert lines[1].endswith(",,")


async def test_tool_stores_each_objects_own_details(tmp_path: Path) -> None:
    registry.hydrate_test_objects_from_disk(tmp_path / ".state")
    coordinator = SimpleNamespace(names={"a1": "Signup Tester"})
    ctx = ToolContext(
        context={"agent_id": "a1", "coordinator": coordinator},
        tool_name="register_test_object",
        tool_call_id="call-1",
        tool_arguments="{}",
    )
    result = await registry.register_test_object.on_invoke_tool(
        ctx,
        json.dumps(
            {
                "identifiers": ["qa7f3@example.com", "order-9912"],
                "kind": "object",
                "details": {"qa7f3@example.com": {"username": "qa7f3", "password": "x"}},
            }
        ),
    )
    assert json.loads(result)["registered"] == ["qa7f3@example.com", "order-9912"]
    with (tmp_path / "test_objects.csv").open(encoding="utf-8", newline="") as file:
        rows = list(csv.DictReader(file))
    assert json.loads(rows[0]["details"]) == {"username": "qa7f3"}
    assert rows[0]["agent"] == "Signup Tester"
    assert rows[1]["details"] == ""
