"""Read directly invoked sandbox scripts without executing shell input."""

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


def script_paths(command: str, workdir: str = ".") -> list[str]:
    """Extract literal script paths from simple shell command chains."""
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
        segment = []
        if executable == "cd" and len(args) == 1:
            cwd = posixpath.normpath(posixpath.join(cwd, args[0]))
            continue
        name = posixpath.basename(executable)
        if executable in {".", "source"}:
            if args:
                paths.append(posixpath.normpath(posixpath.join(cwd, args[0])))
        elif re.fullmatch(r"(?:python(?:\d+(?:\.\d+)*)?|bash|sh|zsh|dash|node|ruby|perl)", name):
            paths.extend(_script_argument(name, args, cwd))
        else:
            path = executable if executable.startswith(("./", "../", "/")) else ""
            if path:
                paths.append(posixpath.normpath(posixpath.join(cwd, path)))
    return list(dict.fromkeys(path for path in paths if not any(c in path for c in "$`*?[]\n")))


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
