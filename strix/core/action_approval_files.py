"""Read the sandbox files a command names, without executing shell input.

The check is told what a command would run. Shell has no end of ways to start a
file (a wrapper, a pipe, a prefix assignment), so besides the direct interpreter
forms every file the command names is offered, and the reader keeps the text ones.
"""

from __future__ import annotations

import logging
import posixpath
import re
import shlex
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


def _script_argument(name: str, args: list[str], cwd: str) -> list[str]:
    while args and args[0].startswith("-"):
        option = args.pop(0)
        if option in {"-", "-c", "-m", "-e", "--eval"}:
            if option == "-c" and name in {"bash", "sh", "zsh", "dash"} and args:
                return script_paths(args[0], cwd)
            return []
        if option in {"-W", "-X", "-r", "--require", "--import"} and args:
            args.pop(0)
        if option == "--":
            break
    # `bash < x.sh` runs the file as surely as `bash x.sh`.
    if args[:1] == ["<"]:
        args = args[1:]
    if not args or args[0].startswith(("<", ">")):
        return []
    return [posixpath.normpath(posixpath.join(cwd, args[0]))]


def _without_heredocs(command: str) -> str:
    lines = command.splitlines(keepends=True)
    result: list[str] = []
    delimiter: str | None = None
    for line in lines:
        if delimiter is not None:
            if line.strip() == delimiter:
                delimiter = None
            continue
        result.append(line)
        match = re.search(r"<<-?\s*(['\"]?)(\w+)\1", line)
        if match:
            delimiter = match[2]
    return "".join(result)


_INTERPRETER_RE = re.compile(r"(?:python(?:\d+(?:\.\d+)*)?|bash|sh|zsh|dash|node|ruby|perl)")


def _interpreter(tokens: list[str]) -> int | None:
    return next(
        (i for i, t in enumerate(tokens) if _INTERPRETER_RE.fullmatch(posixpath.basename(t))),
        None,
    )


_MAX_PATHS = 8
_NAMED_FILE_RE = re.compile(r"(?:^~?\.{0,2}/|/|\.[A-Za-z0-9]{1,5}$)")


def _named_files(args: list[str], cwd: str, depth: int) -> list[str]:
    """Every argument that reads as a file, wherever it sits in the command."""
    paths: list[str] = []
    written = False
    for arg in args:
        if arg in {">", ">>", ">&", "&>"}:
            written = True
            continue
        target, written = written, False
        if target or arg.startswith("-") or "://" in arg or "=" in arg:
            continue
        if _NAMED_FILE_RE.search(arg):
            paths.append(posixpath.normpath(posixpath.join(cwd, arg)))
        # A quoted string can be a command of its own: sh -c '...', eval "...".
        if depth < 2 and re.search(r"\s", arg):
            paths.extend(script_paths(arg, cwd, _depth=depth + 1))
    return paths


def script_paths(command: str, workdir: str = ".", *, _depth: int = 0) -> list[str]:
    """Extract the literal file paths a shell command chain names."""
    try:
        lexer = shlex.shlex(_without_heredocs(command), posix=True, punctuation_chars="();<>|&\n")
        lexer.whitespace = " \t\r"
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return []
    paths: list[str] = []
    segment: list[str] = []
    cwd = workdir
    for token in [*tokens, ";"]:
        if token.strip() and token not in {";", "&&", "||", "|", "(", ")"}:
            segment.append(token)
            continue
        if not segment:
            continue
        executable, *args = segment
        segment_tokens, segment = segment, []
        if executable == "cd" and len(args) == 1:
            cwd = posixpath.normpath(posixpath.join(cwd, args[0]))
            continue
        name = posixpath.basename(executable)
        named = _named_files(segment_tokens, cwd, _depth)
        if executable in {".", "source"}:
            if args:
                paths.append(posixpath.normpath(posixpath.join(cwd, args[0])))
        elif (at := _interpreter(segment_tokens)) is not None:
            # The interpreter can sit behind any wrapper: sudo, env, timeout, a prefix assignment.
            name = posixpath.basename(segment_tokens[at])
            paths.extend(_script_argument(name, segment_tokens[at + 1 :], cwd))
        else:
            path = executable if executable.startswith(("./", "../", "/")) else ""
            if path:
                paths.append(posixpath.normpath(posixpath.join(cwd, path)))
        paths.extend(named)
    usable = dict.fromkeys(path for path in paths if not any(c in path for c in "$`*?[]\n&|;"))
    return list(usable)[:_MAX_PATHS]


async def command_files(session: Any, args: dict[str, Any]) -> dict[str, str]:
    if session is None or not isinstance(args.get("cmd"), str):
        return {}
    workdir = args.get("workdir") or "."
    if not isinstance(workdir, str):
        return {}
    files: dict[str, str] = {}
    for path in script_paths(args["cmd"], workdir):
        try:
            with await session.read(Path(path)) as stream:
                data = stream.read()
            text = data.decode("utf-8") if isinstance(data, bytes) else data
            if isinstance(text, str) and "\x00" not in text:
                files[path] = text
        except Exception:  # noqa: BLE001 - unavailable context must not prevent judging.
            logger.debug("Could not read an approval script", exc_info=True)
    return files
