import re


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
