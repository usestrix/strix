"""Shell completion scripts and candidates for the Strix CLI."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from strix.interface.cloud.spec import DEFAULT_VERBS, SPEC, Cmd
from strix.interface.terminal_text import has_terminal_control, sanitize_terminal_text


_ROOT_COMMANDS = ("cloud", "auth", "view", "completions", "completion")
_SESSION_COMMANDS = ("login", "logout", "whoami", "session", "credits")
_COMMON_FLAGS = (
    "--json",
    "--token",
    "--workspace-id",
    "--app-url",
    "--timeout",
    "-h",
    "--help",
)
_COMMON_VALUE_FLAGS = frozenset({"--token", "--workspace-id", "--app-url", "--timeout"})
_WORKSPACE_USE_FLAGS = (*_COMMON_FLAGS, "--scopes", "--scope-profile", "--show-scopes")


def run_completions(argv: list[str]) -> int:
    """Print a shell integration script or hidden completion candidates."""
    if argv and argv[0] == "--candidates":
        for candidate in completion_candidates(argv[1:]):
            sys.stdout.write(candidate + "\n")
        return 0
    if not argv or argv[0] in ("-h", "--help", "help"):
        sys.stdout.write(
            "Usage: strix completions <zsh|bash|fish>\n\n"
            "Enable tab completion for the current shell:\n"
            "  zsh:  source <(strix completions zsh)\n"
            "  bash: source <(strix completions bash)\n"
            "  fish: strix completions fish | source\n"
        )
        return 0
    shell = argv[0].lower()
    scripts = {"zsh": _zsh_script, "bash": _bash_script, "fish": _fish_script}
    generator = scripts.get(shell)
    if generator is None:
        sys.stderr.write(
            f"Unknown shell: {sanitize_terminal_text(shell)}. Choose zsh, bash, or fish.\n"
        )
        return 2
    sys.stdout.write(generator())
    return 0


def completion_candidates(words: list[str]) -> list[str]:
    """Return candidates for words after the ``strix`` executable."""
    prior, current = _split_cursor(words)
    if not prior:
        candidates = _matching(_ROOT_COMMANDS, current)
    elif prior[0] != "cloud":
        candidates = []
    else:
        candidates = _cloud_candidates(prior[1:], current)
    # The line-oriented shell protocol cannot represent these names safely.
    # Omitting them is preferable to returning a sanitized path that does not exist.
    return [candidate for candidate in candidates if not has_terminal_control(candidate)]


def _split_cursor(words: list[str]) -> tuple[list[str], str]:
    if not words:
        return [], ""
    return words[:-1], words[-1]


def _cloud_candidates(prior: list[str], current: str) -> list[str]:  # noqa: PLR0911
    groups = (*_SESSION_COMMANDS, *SPEC, "workspace")
    if not prior:
        return _matching(groups, current)
    group = "workspaces" if prior[0] == "workspace" else prior[0]
    rest = prior[1:]
    if group in _SESSION_COMMANDS:
        return _session_candidates(group, rest, current)
    commands = SPEC.get(group)
    if commands is None:
        return _matching(groups, current)
    default_verb = DEFAULT_VERBS.get(group)
    default_is_active = (rest and rest[0].startswith("-")) or (not rest and current.startswith("-"))
    if default_verb is not None and default_is_active:
        return _command_candidates(commands[default_verb], rest, current)

    command_paths = sorted(
        ((verb.split(), cmd) for verb, cmd in commands.items()),
        key=lambda item: len(item[0]),
        reverse=True,
    )
    for path, cmd in command_paths:
        if rest[: len(path)] == path:
            command_candidates = _command_candidates(cmd, rest[len(path) :], current)
            if rest == path:
                nested_words = {
                    candidate_path[len(path)]
                    for candidate_path, _candidate_cmd in command_paths
                    if len(candidate_path) > len(path) and candidate_path[: len(path)] == path
                }
                return sorted({*command_candidates, *_matching(nested_words, current)})
            return command_candidates
    if group == "workspaces" and rest[:1] == ["use"]:
        return _flag_candidates(
            _WORKSPACE_USE_FLAGS,
            rest[1:],
            current,
            value_flags=_COMMON_VALUE_FLAGS | {"--scopes"},
        )

    verb_paths = [path for path, _cmd in command_paths]
    if group == "workspaces":
        verb_paths.append(["use"])
    matching_paths = [path for path in verb_paths if path[: len(rest)] == rest]
    if not matching_paths:
        return []
    next_words = sorted({path[len(rest)] for path in matching_paths if len(path) > len(rest)})
    return _matching(next_words, current)


def _session_candidates(group: str, prior: list[str], current: str) -> list[str]:
    if group == "session":
        if not prior:
            return _matching(("show", "scopes", "help", *_COMMON_FLAGS, "--show-scopes"), current)
        if prior[:1] == ["scopes"] and len(prior) == 1:
            return _matching(("set", *_COMMON_FLAGS, "--show-scopes"), current)
        if prior[:2] == ["scopes", "set"]:
            return _matching(
                ("minimal", "recommended", "full", "--scopes", *_COMMON_FLAGS, "--show-scopes"),
                current,
            )
        return _flag_candidates(
            (*_COMMON_FLAGS, "--show-scopes"),
            prior,
            current,
            value_flags=_COMMON_VALUE_FLAGS | {"--scopes"},
        )
    flags = _session_flags(group)
    value_flags: frozenset[str] = frozenset()
    if group == "login":
        value_flags = frozenset({"--scopes", "--scope-profile", "--workspace", "--device-name"})
    elif group == "credits":
        value_flags = _COMMON_VALUE_FLAGS
    return _flag_candidates(flags, prior, current, value_flags=value_flags)


def _session_flags(group: str) -> tuple[str, ...]:
    if group == "login":
        return (
            "--no-browser",
            "--scopes",
            "--scope-profile",
            "--workspace",
            "--device-name",
            "-h",
            "--help",
        )
    if group == "whoami":
        return ("--json", "--show-scopes", "-h", "--help")
    if group == "logout":
        return ("--json", "--local-only", "-h", "--help")
    if group == "credits":
        return _COMMON_FLAGS
    return ("-h", "--help")


def _command_candidates(cmd: Cmd, prior: list[str], current: str) -> list[str]:
    filesystem = _filesystem_candidates(cmd, prior, current)
    if filesystem is not None:
        return filesystem
    return _flag_candidates(
        _command_flags(cmd),
        prior,
        current,
        value_flags=_command_value_flags(cmd),
    )


def _flag_candidates(
    flags: tuple[str, ...],
    prior: list[str],
    current: str,
    *,
    value_flags: frozenset[str],
) -> list[str]:
    if prior and prior[-1] in value_flags and not current.startswith("-"):
        return []
    return _matching(flags, current)


def _command_flags(cmd: Cmd) -> tuple[str, ...]:
    flags: list[str] = list(_COMMON_FLAGS)
    for param in cmd.query + cmd.body:
        flag = "--" + (param.flag or _kebab(param.name))
        flags.append(flag)
        if param.kind == "bool":
            flags.append("--no-" + flag.removeprefix("--"))
    if cmd.method in ("POST", "PUT", "PATCH"):
        flags.append("--data")
    if cmd.idempotent:
        flags.append("--idempotency-key")
    if cmd.binary or cmd.path == "/audit":
        flags.extend(("--output", "--force"))
    if cmd.link:
        flags.append("--no-browser")
    if cmd.wait_path or cmd.wait_self:
        flags.extend(("--wait", "--wait-timeout"))
    if cmd.path == "/billing/topup":
        flags.extend(("--yes", "--no-pay", "--payment-method"))
    if cmd.path == "/scans" and cmd.method == "POST":
        flags.extend(
            (
                "--source",
                "--approve-sha256",
                "--dry-run",
                "--yes",
                "--show-files",
                "--exclude",
                "--include-hidden",
                "--include-sensitive",
                "--include-archives",
            )
        )
    if cmd.path == "/billing/auto-topup" and cmd.method == "PUT":
        flags.append("--no-monthly-cap")
    return tuple(dict.fromkeys(flags))


def _command_value_flags(cmd: Cmd) -> frozenset[str]:
    flags = set(_COMMON_VALUE_FLAGS)
    for param in cmd.query + cmd.body:
        if param.kind != "bool":
            flags.add("--" + (param.flag or _kebab(param.name)))
    if cmd.method in ("POST", "PUT", "PATCH"):
        flags.add("--data")
    if cmd.idempotent:
        flags.add("--idempotency-key")
    if cmd.binary or cmd.path == "/audit":
        flags.add("--output")
    if cmd.wait_path or cmd.wait_self:
        flags.add("--wait-timeout")
    if cmd.path == "/billing/topup":
        flags.add("--payment-method")
    if cmd.path == "/scans" and cmd.method == "POST":
        flags.update(("--source", "--approve-sha256", "--exclude"))
    return frozenset(flags)


def _filesystem_candidates(  # noqa: PLR0911
    cmd: Cmd, prior: list[str], current: str
) -> list[str] | None:
    inline = (
        ("--source=", True, ""),
        ("--output=", False, ""),
        ("--data=@", False, "@"),
    )
    for option, directories_only, marker in inline:
        if current.startswith(option):
            value = current.removeprefix(option)
            return [
                option + candidate.removeprefix(marker)
                for candidate in _path_candidates(
                    marker + value,
                    directories_only=directories_only,
                    marker=marker,
                )
            ]

    if not prior or current.startswith("-"):
        return None
    option = prior[-1]
    if option == "--source" and cmd.path == "/scans" and cmd.method == "POST":
        return _path_candidates(current, directories_only=True)
    if option == "--output" and (cmd.binary or cmd.path == "/audit"):
        return _path_candidates(current)
    if option == "--data" and cmd.method in ("POST", "PUT", "PATCH"):
        if not current:
            return ["@"]
        if current.startswith("@"):
            return _path_candidates(current, marker="@")
        return []
    return None


def _path_candidates(
    value: str,
    *,
    directories_only: bool = False,
    marker: str = "",
) -> list[str]:
    raw = value.removeprefix(marker) if marker else value
    ends_with_separator = raw.endswith(("/", "\\"))
    expanded = Path(raw or ".").expanduser()
    directory = expanded if ends_with_separator else expanded.parent
    name_prefix = "" if ends_with_separator else expanded.name
    raw_base = raw if ends_with_separator else raw[: len(raw) - len(name_prefix)]
    try:
        entries = directory.iterdir()
        matches = [
            entry
            for entry in entries
            if entry.name.startswith(name_prefix) and (not directories_only or entry.is_dir())
        ]
    except OSError:
        return []

    candidates: list[str] = []
    for entry in sorted(matches, key=lambda item: item.name.casefold()):
        candidate = marker + raw_base + entry.name
        if entry.is_dir():
            candidate += "/"
        candidates.append(candidate)
    return candidates


def _kebab(value: str) -> str:
    output: list[str] = []
    for char in value:
        if char.isupper():
            output.extend(("-", char.lower()))
        else:
            output.append("-" if char == "_" else char)
    return "".join(output)


def _matching(candidates: Any, prefix: str) -> list[str]:
    return sorted({str(candidate) for candidate in candidates if str(candidate).startswith(prefix)})


def _zsh_script() -> str:
    return r"""#compdef strix
_strix() {
  local -a candidates
  candidates=("${(@f)$($words[1] completions --candidates "${words[@]:2}")}")
  _describe 'strix' candidates
}
compdef _strix strix
"""


def _bash_script() -> str:
    return r"""_strix_completion() {
  local -a candidates
  local candidate
  while IFS= read -r candidate; do
    candidates+=("$candidate")
  done < <(strix completions --candidates "${COMP_WORDS[@]:1:$COMP_CWORD}")
  COMPREPLY=("${candidates[@]}")
  for candidate in "${COMPREPLY[@]}"; do
    if [[ $candidate == */ ]]; then
      if type compopt >/dev/null 2>&1; then
        compopt -o nospace
      fi
      break
    fi
  done
}
complete -F _strix_completion strix
"""


def _fish_script() -> str:
    return r"""function __strix_candidates
  set -l words (commandline -opc)
  set -e words[1]
  command strix completions --candidates $words (commandline -ct)
end
complete -c strix -f -a '(__strix_candidates)'
"""
