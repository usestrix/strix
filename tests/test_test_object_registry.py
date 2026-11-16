from pathlib import Path

from strix.tools.test_objects import tools as registry


def _fresh(tmp_path: Path) -> None:
    registry.hydrate_test_objects_from_disk(tmp_path)


def test_register_persists_and_rehydrates(tmp_path: Path) -> None:
    _fresh(tmp_path)
    assert registry.register("zed.qa.probe.001@example.com", "account", "agent", "a1")
    assert not registry.register("7", "record", "agent")
    _fresh(tmp_path)
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
