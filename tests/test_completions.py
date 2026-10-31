from __future__ import annotations

from typing import Any

from strix.interface.completions import completion_candidates, run_completions


def test_root_completion_candidates() -> None:
    assert completion_candidates(["cl"]) == ["cloud"]
    assert "completions" in completion_candidates([""])


def test_cloud_group_and_alias_candidates() -> None:
    candidates = completion_candidates(["cloud", "work"])
    assert candidates == ["workspace", "workspaces"]


def test_cloud_verb_candidates_include_multiword_prefixes() -> None:
    assert "test-users" in completion_candidates(["cloud", "domains", ""])
    assert completion_candidates(["cloud", "domains", "test-users", "in"]) == [
        "inbox",
        "inbox-message",
    ]


def test_cloud_leaf_flag_candidates_come_from_command_spec() -> None:
    candidates = completion_candidates(["cloud", "scans", "start", "--"])
    assert "--domain-ids" in candidates
    assert "--json" in candidates
    assert "--wait" in candidates
    assert "--source" in candidates
    assert "--approve-sha256" in candidates
    assert "--dry-run" in candidates
    assert "--include-hidden" in candidates


def test_boolean_completion_includes_positive_and_negative_flags() -> None:
    candidates = completion_candidates(["cloud", "billing", "auto-topup", "update", "--"])
    assert "--enabled" in candidates
    assert "--no-enabled" in candidates
    assert "--no-monthly-cap" in candidates


def test_session_and_workspace_use_completions_include_their_real_flags() -> None:
    credit_flags = completion_candidates(["cloud", "credits", "--"])
    assert {"--json", "--token", "--app-url", "--timeout", "--help"} <= set(credit_flags)
    assert "--json" in completion_candidates(["cloud", "logout", "--"])

    workspace_use = completion_candidates(["cloud", "workspace", "use", "--"])
    assert {"--scopes", "--json", "--token", "--app-url", "--timeout"} <= set(workspace_use)


def test_leaf_flags_remain_available_after_options_and_positionals() -> None:
    after_option = completion_candidates(["cloud", "scans", "list", "--status", "running", "--"])
    assert {"--page", "--limit", "--json"} <= set(after_option)

    after_positional = completion_candidates(["cloud", "scans", "get", "scan-1", "--"])
    assert {"--json", "--token", "--app-url", "--timeout"} <= set(after_positional)


def test_default_verbs_complete_flags_without_an_explicit_verb() -> None:
    audit = completion_candidates(["cloud", "audit", "--"])
    assert {"--page", "--limit", "--json"} <= set(audit)

    after_option = completion_candidates(["cloud", "audit", "--page", "2", "--"])
    assert {"--limit", "--format", "--json"} <= set(after_option)

    workspaces = completion_candidates(["cloud", "workspace", "--"])
    assert {"--json", "--token", "--app-url", "--timeout"} <= set(workspaces)


def test_completion_does_not_offer_flags_while_an_option_value_is_empty() -> None:
    assert completion_candidates(["cloud", "scans", "list", "--page", ""]) == []
    assert completion_candidates(["cloud", "scans", "start", "--approve-sha256", ""]) == []


def test_exact_verbs_that_are_also_prefixes_keep_their_subverbs() -> None:
    candidates = completion_candidates(["cloud", "billing", "auto-topup", ""])
    assert "update" in candidates
    assert "--json" in candidates


def test_contract_fix_flags_are_completed() -> None:
    integration_connect = completion_candidates(
        ["cloud", "integrations", "connect", "gitlab", "--"]
    )
    assert {
        "--provider-token",
        "--instance-url",
        "--account-email",
        "--installation-id",
    } <= set(integration_connect)

    disconnect = completion_candidates(["cloud", "integrations", "disconnect", "--"])
    assert "--installation-id" in disconnect

    connector = completion_candidates(["cloud", "connectors", "get", "connector-1", "--"])
    assert "--include-command" in connector
    assert "--no-include-command" in connector

    scan_wait = completion_candidates(["cloud", "scans", "start", "--"])
    assert "--wait-timeout" in scan_wait

    audit_export = completion_candidates(["cloud", "audit", "--"])
    assert {"--output", "--force"} <= set(audit_export)

    token_create = completion_candidates(["cloud", "tokens", "create", "--"])
    assert {"--expires-at", "--rbac-scopes"} <= set(token_create)


def test_filesystem_completion_for_source_output_and_data(tmp_path: Any, monkeypatch: Any) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "source tree").mkdir()
    (tmp_path / "source.txt").write_text("source", encoding="utf-8")
    (tmp_path / "request.json").write_text("{}", encoding="utf-8")

    source = completion_candidates(["cloud", "scans", "start", "--source", "sou"])
    assert source == ["source tree/"]

    output = completion_candidates(["cloud", "scans", "report", "scan-1", "--output", "req"])
    assert output == ["request.json"]

    audit_output = completion_candidates(["cloud", "audit", "--output", "req"])
    assert audit_output == ["request.json"]

    data = completion_candidates(["cloud", "scans", "start", "--data", "@req"])
    assert data == ["@request.json"]


def test_filesystem_completion_omits_terminal_control_names(
    tmp_path: Any, monkeypatch: Any, capsys: Any
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "safe.json").write_text("{}", encoding="utf-8")
    (tmp_path / "unsafe\nname.json").write_text("{}", encoding="utf-8")
    (tmp_path / "unsafe\x1b]52;c;payload\x07.json").write_text("{}", encoding="utf-8")

    words = ["cloud", "scans", "start", "--data", "@"]
    assert completion_candidates(words) == ["@safe.json"]
    assert run_completions(["--candidates", *words]) == 0
    assert capsys.readouterr().out == "@safe.json\n"


def test_completion_scripts_cover_supported_shells(capsys: Any) -> None:
    for shell in ("zsh", "bash", "fish"):
        assert run_completions([shell]) == 0
        output = capsys.readouterr().out
        assert "completions --candidates" in output


def test_bash_completion_preserves_candidates_with_spaces(capsys: Any) -> None:
    assert run_completions(["bash"]) == 0
    output = capsys.readouterr().out
    assert 'COMPREPLY=("${candidates[@]}")' in output
    assert "while IFS= read -r candidate" in output
    assert "mapfile" not in output


def test_completion_rejects_unknown_shell(capsys: Any) -> None:
    assert run_completions(["powershell\x1b]52;c;payload\x07"]) == 2
    error = capsys.readouterr().err
    assert "Choose zsh, bash, or fish" in error
    assert "\x1b" not in error
    assert "\\x1b" in error
