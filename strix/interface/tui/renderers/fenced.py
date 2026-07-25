import re

from pygments.lexer import Lexer
from pygments.lexers import PythonLexer, get_lexer_by_name, guess_lexer
from pygments.lexers.special import TextLexer
from pygments.util import ClassNotFound


_FENCE_RE = re.compile(r"^```([^\n`]*)\n(.*?)\n?```$", re.DOTALL)


def parse_fenced_code(raw: str) -> tuple[str | None, str]:
    """Split an optionally fenced code string into ``(language, code)``.

    Agent-generated code fields (e.g. ``poc_script_code``) are stored wrapped in
    a markdown fence carrying the language, like ``` ```python\n...\n``` ```.
    Return the fence's language tag and the inner code, or ``(None, raw)`` when
    the value isn't fenced.
    """
    match = _FENCE_RE.match(raw.strip())
    if not match:
        return None, raw
    info = match.group(1).strip()
    language = info.split()[0] if info else None
    return (language or None), match.group(2)


def resolve_lexer(language: str | None, code: str) -> Lexer:
    """Pick a pygments lexer for ``code``.

    Prefer the explicit fence ``language`` when it names a known lexer, otherwise
    auto-detect from the source. Fall back to Python when detection is
    inconclusive, since legacy (unfenced) PoC scripts are Python.
    """
    if language:
        try:
            return get_lexer_by_name(language)
        except ClassNotFound:
            pass
    try:
        lexer = guess_lexer(code)
    except ClassNotFound:
        return PythonLexer()
    # ``guess_lexer`` returns the plain-text lexer when it can't detect anything.
    if isinstance(lexer, TextLexer):
        return PythonLexer()
    return lexer


def guess_language_name(code: str) -> str:
    """Return a markdown fence tag for ``code``, defaulting to ``python`` when
    auto-detection is inconclusive."""
    try:
        lexer = guess_lexer(code)
    except ClassNotFound:
        return "python"
    if isinstance(lexer, TextLexer) or not lexer.aliases:
        return "python"
    return str(lexer.aliases[0])
