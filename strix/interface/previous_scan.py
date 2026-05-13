from pathlib import Path


DEFAULT_PREVIOUS_SCAN_CONTEXT_LIMIT = 20_000
_SECTION_LIMITS = {
    "Final Report": 5_000,
    "Vulnerabilities": 9_000,
    "Wiki Notes": 5_000,
}


def resolve_previous_scan_dir(scan_ref: str, base_dir: Path | None = None) -> Path:
    """Resolve a previous scan reference as either a path or a run name."""
    base = base_dir or Path.cwd()
    raw_path = Path(scan_ref).expanduser()

    candidates = []
    if raw_path.is_absolute():
        candidates.append(raw_path)
    else:
        candidates.append((base / raw_path).resolve())
        candidates.append((base / "strix_runs" / scan_ref).resolve())

    for candidate in candidates:
        if candidate.is_dir():
            return candidate

    tried = ", ".join(str(candidate) for candidate in candidates)
    raise ValueError(f"Previous scan '{scan_ref}' was not found. Tried: {tried}")


def build_previous_scan_context(
    scan_ref: str,
    base_dir: Path | None = None,
    max_chars: int = DEFAULT_PREVIOUS_SCAN_CONTEXT_LIMIT,
) -> str:
    run_dir = resolve_previous_scan_dir(scan_ref, base_dir)
    sections = []

    final_report = _read_file_section(run_dir / "penetration_test_report.md", "Final Report")
    if final_report:
        sections.append(final_report)

    vulnerabilities = _read_directory_section(run_dir / "vulnerabilities", "Vulnerabilities")
    if vulnerabilities:
        sections.append(vulnerabilities)

    wiki_notes = _read_directory_section(run_dir / "wiki", "Wiki Notes")
    if wiki_notes:
        sections.append(wiki_notes)

    if not sections:
        sections.append(
            "No final report, vulnerability markdown files, or wiki notes were found in this run."
        )

    body = "\n\n".join(sections)
    if len(body) > max_chars:
        body = body[:max_chars].rstrip() + "\n\n[previous scan context truncated]"

    return (
        "<previous_scan_context>\n"
        f"<source>{run_dir}</source>\n"
        "<instructions>\n"
        "Use this as prior context for the current scan. Do not duplicate completed work unless "
        "needed to verify or deepen a finding. Prioritize unresolved leads, follow-up testing, "
        "and validation of previously reported issues.\n"
        "</instructions>\n"
        f"{body}\n"
        "</previous_scan_context>"
    )


def _read_file_section(path: Path, title: str) -> str | None:
    if not path.is_file():
        return None

    return _format_section(title, path.read_text(encoding="utf-8", errors="replace"))


def _read_directory_section(path: Path, title: str) -> str | None:
    if not path.is_dir():
        return None

    files = sorted(file for file in path.glob("*.md") if file.is_file())
    if not files:
        return None

    parts = []
    for file in files:
        content = file.read_text(encoding="utf-8", errors="replace").strip()
        if content:
            parts.append(f"### {file.name}\n{content}")

    if not parts:
        return None

    return _format_section(title, "\n\n".join(parts))


def _format_section(title: str, content: str) -> str:
    content = content.strip()
    limit = _SECTION_LIMITS.get(title)
    if limit is not None and len(content) > limit:
        content = content[:limit].rstrip() + "\n[section truncated]"

    return f"## {title}\n{content}"
