from strix.skills.runtime_tooling import build_tooling_preflight_message, get_tooling_preflight


def test_get_tooling_preflight_loads_new_tool_skills() -> None:
    actions = [
        {
            "toolName": "terminal_execute",
            "args": {"command": "nmap -Pn -sV --open -p 80,443 target.tld"},
        },
        {
            "toolName": "terminal_execute",
            "args": {"command": "httpx -u https://target.tld -sc -title -silent"},
        },
    ]

    preflight = get_tooling_preflight(actions, already_loaded_skills=set())

    assert preflight.skills_to_load == ["tooling/nmap", "tooling/httpx"]
    assert preflight.tools_with_new_skills == ["nmap", "httpx"]
    assert preflight.help_requested_tools == []


def test_get_tooling_preflight_handles_wrappers_and_assignments() -> None:
    actions = [
        {
            "toolName": "terminal_execute",
            "args": {
                "command": (
                    "sudo -u pentester timeout 30s "
                    "FOO=bar naabu -host target.tld -p 80"
                ),
            },
        },
    ]

    preflight = get_tooling_preflight(actions, already_loaded_skills=set())

    assert preflight.skills_to_load == ["tooling/naabu"]
    assert preflight.tools_with_new_skills == ["naabu"]


def test_get_tooling_preflight_detects_help_flags() -> None:
    actions = [
        {
            "toolName": "terminal_execute",
            "args": {"command": "katana -h"},
        },
        {
            "toolName": "terminal_execute",
            "args": {"command": "nuclei \u2014help"},
        },
    ]

    preflight = get_tooling_preflight(actions, already_loaded_skills=set())

    assert preflight.tools_with_new_skills == ["katana", "nuclei"]
    assert preflight.help_requested_tools == ["katana", "nuclei"]


def test_get_tooling_preflight_ignores_non_tool_mentions() -> None:
    actions = [
        {
            "toolName": "terminal_execute",
            "args": {"command": "grep -E 'nmap|nuclei|ffuf' notes.txt"},
        },
        {
            "toolName": "terminal_execute",
            "args": {"command": 'echo "run nmap later"'},
        },
    ]

    preflight = get_tooling_preflight(actions, already_loaded_skills=set())

    assert preflight.skills_to_load == []
    assert preflight.tools_with_new_skills == []
    assert preflight.help_requested_tools == []


def test_get_tooling_preflight_skips_already_loaded_skills() -> None:
    actions = [
        {
            "toolName": "terminal_execute",
            "args": {"command": "ffuf -w words.txt -u https://target/FUZZ -ac"},
        },
    ]

    preflight = get_tooling_preflight(actions, already_loaded_skills={"tooling/ffuf"})

    assert preflight.skills_to_load == []
    assert preflight.tools_with_new_skills == []


def test_build_tooling_preflight_message_includes_docs_and_help_guidance() -> None:
    message = build_tooling_preflight_message(
        tools_with_new_skills=["nmap", "katana"],
        help_requested_tools=["katana"],
    )

    assert "https://nmap.org/book/man-briefoptions.html" in message
    assert "https://docs.projectdiscovery.io/opensource/katana/overview" in message
    assert "Prefer loaded syntax over help flags" in message
