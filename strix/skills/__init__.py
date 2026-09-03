import logging
import re
import threading
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import TypeGuard

import yaml

from strix.telemetry import posthog, scarf
from strix.utils.resource_paths import get_strix_resource_path


logger = logging.getLogger(__name__)

_FRONTMATTER_PATTERN = re.compile(r"^---\s*\n(?P<body>.*?)\n---\s*\n", re.DOTALL)

_INTERNAL_SKILL_CATEGORIES: frozenset[str] = frozenset({"scan_modes", "coordination", "analysis"})
_ROOT_SKILL_CATEGORY = "root"

_EXTRA_SKILL_DIRS: list[Path] = []
_SKILL_METADATA_CACHE: dict[tuple[Path, int, int], dict[str, str]] = {}


def _is_frontmatter_mapping(value: object) -> TypeGuard[dict[object, object]]:
    return isinstance(value, dict)


def register_skill_dir(path: str | Path) -> None:
    """Add a directory searched for skills ahead of the built-in set.

    The directory uses the same layout as the packaged skills
    (``<root>/<category>/<name>.md``). Skills found in a registered
    directory shadow packaged skills with the same relative path, so
    callers can both add new skills and override existing ones without
    editing the package. The most recently registered directory has the
    highest precedence.
    """
    resolved = Path(path)
    if resolved not in _EXTRA_SKILL_DIRS:
        _EXTRA_SKILL_DIRS.append(resolved)
        logger.info("Registered extra skill dir: %s", resolved)


def registered_skill_dirs() -> tuple[Path, ...]:
    """Return registered extra skill directories, highest precedence first."""
    return tuple(reversed(_EXTRA_SKILL_DIRS))


def skill_search_dirs() -> tuple[Path, ...]:
    """All existing skill roots, highest precedence first (built-in last)."""
    roots = [d for d in registered_skill_dirs() if d.is_dir()]
    builtin = get_strix_resource_path("skills")
    if builtin.is_dir():
        roots.append(builtin)
    return tuple(roots)


def _iter_user_skill_files() -> Iterator[tuple[str, str]]:
    """Yield ``(category_name, skill_name)`` for every user-selectable skill."""
    seen: set[tuple[str, str]] = set()
    for skills_dir in skill_search_dirs():
        for file_path in sorted(skills_dir.glob("*.md")):
            if file_path.name.startswith("__") or file_path.name == "README.md":
                continue
            key = (_ROOT_SKILL_CATEGORY, file_path.stem)
            if key in seen:
                continue
            seen.add(key)
            yield key

        for category_dir in sorted(skills_dir.iterdir()):
            if not category_dir.is_dir() or category_dir.name.startswith("__"):
                continue
            if category_dir.name in _INTERNAL_SKILL_CATEGORIES:
                continue
            for file_path in sorted(category_dir.glob("*.md")):
                key = (category_dir.name, file_path.stem)
                if key in seen:
                    continue
                seen.add(key)
                yield key


def _is_selectable_root_skill_file(file_path: Path) -> bool:
    return file_path.suffix == ".md" and not (
        file_path.name.startswith("__") or file_path.name == "README.md"
    )


def _qualified_skill_file(skills_dir: Path, category: str, name: str) -> Path | None:
    if category == _ROOT_SKILL_CATEGORY:
        candidate = skills_dir / f"{name}.md"
        if candidate.exists() and _is_selectable_root_skill_file(candidate):
            return candidate
        return None

    candidate = skills_dir / category / f"{name}.md"
    return candidate if candidate.exists() else None


def get_all_skill_names() -> set[str]:
    """Return every user-selectable skill name (bare, no category prefix)."""
    return {name for _, name in _iter_user_skill_files()}


def _get_all_skill_keys() -> set[str]:
    keys: set[str] = set()
    for category, name in _iter_user_skill_files():
        keys.add(f"{category}/{name}")
    return keys


def _get_ambiguous_skill_names() -> set[str]:
    counts = Counter(name for _, name in _iter_user_skill_files())
    return {name for name, count in counts.items() if count > 1}


def _qualified_skill_file_for_name(skill_name: str) -> Path | None:
    category, _, name = skill_name.partition("/")
    for skills_dir in skill_search_dirs():
        candidate = _qualified_skill_file(skills_dir, category, name)
        if candidate is not None:
            return candidate
    return None


def _qualified_skill_files(skill_name: str) -> list[Path]:
    candidate = _qualified_skill_file_for_name(skill_name)
    return [candidate] if candidate is not None else []


def _bare_skill_files(skill_name: str) -> list[Path]:
    seen: set[tuple[str, str]] = set()
    candidates: list[Path] = []
    for skills_dir in skill_search_dirs():
        for category_dir in sorted(skills_dir.iterdir()):
            if not category_dir.is_dir() or category_dir.name.startswith("__"):
                continue
            if category_dir.name in _INTERNAL_SKILL_CATEGORIES:
                continue
            key = (category_dir.name, skill_name)
            if key in seen:
                continue
            candidate = category_dir / f"{skill_name}.md"
            if candidate.exists():
                seen.add(key)
                candidates.append(candidate)

        key = (_ROOT_SKILL_CATEGORY, skill_name)
        if key in seen:
            continue
        root_candidate = _qualified_skill_file(skills_dir, _ROOT_SKILL_CATEGORY, skill_name)
        if root_candidate is not None:
            seen.add(key)
            candidates.append(root_candidate)
    return candidates


def _parse_skill_content(content: str, source: Path | None = None) -> tuple[dict[str, str], str]:
    """Parse skill frontmatter once and return metadata plus markdown body."""
    frontmatter = _FRONTMATTER_PATTERN.match(content)
    if frontmatter is None:
        return {}, content.lstrip()

    try:
        parsed: object = yaml.safe_load(frontmatter.group("body"))
    except yaml.YAMLError as error:
        logger.warning("Failed to parse skill frontmatter %s: %s", source or "<content>", error)
        parsed = None
    if not _is_frontmatter_mapping(parsed):
        logger.warning("Skill frontmatter is not a mapping: %s", source or "<content>")
        return {}, content[frontmatter.end() :].lstrip()

    metadata = {str(key): "" if value is None else str(value) for key, value in parsed.items()}
    return metadata, content[frontmatter.end() :].lstrip()


def _read_skill_metadata(file_path: Path) -> dict[str, str]:
    try:
        stat = file_path.stat()
    except OSError:
        logger.warning("Skill file disappeared while reading metadata: %s", file_path)
        return {}
    cache_key = (file_path, stat.st_mtime_ns, stat.st_size)
    cached = _SKILL_METADATA_CACHE.get(cache_key)
    if cached is not None:
        return cached
    try:
        content = file_path.read_text(encoding="utf-8")
    except (OSError, ValueError):
        logger.warning("Failed to read skill metadata: %s", file_path)
        return {}
    metadata, _ = _parse_skill_content(content, file_path)
    _SKILL_METADATA_CACHE[cache_key] = metadata
    return metadata


def get_available_skills() -> dict[str, list[dict[str, str]]]:
    grouped: dict[str, list[dict[str, str]]] = {}
    for category, name in _iter_user_skill_files():
        file_path = _qualified_skill_file_for_name(f"{category}/{name}")
        if file_path is None:
            logger.warning(
                "Skill disappeared while gathering available skills: %s/%s",
                category,
                name,
            )
            continue
        metadata = _read_skill_metadata(file_path)
        description = " ".join(metadata.get("description", "").split())
        grouped.setdefault(category, []).append({"name": name, "description": description})
    return grouped


def validate_requested_skills(skill_list: list[str], max_skills: int = 5) -> str | None:
    """Validate a list of user-passed skill names.

    Returns ``None`` on success, or a model-readable error message
    describing what was wrong (count exceeded, unknown names).
    """
    if len(skill_list) > max_skills:
        return (
            f"Cannot specify more than {max_skills} skills per agent; "
            f"got {len(skill_list)}. Aim for 1-3 related skills per specialist."
        )
    if not skill_list:
        return None
    available = get_all_skill_names()
    available_keys = _get_all_skill_keys()
    invalid = sorted({s for s in skill_list if s not in available and s not in available_keys})
    if invalid:
        return f"Invalid skill name(s): {invalid}. Available skills: {sorted(available)}"
    ambiguous = sorted({s for s in skill_list if "/" not in s} & _get_ambiguous_skill_names())
    if ambiguous:
        return (
            f"Ambiguous skill name(s): {ambiguous}. Use category-qualified names from: "
            f"{sorted(available_keys)}"
        )
    return None


def _track_skill_loaded(skill_name: str, file_path: Path) -> None:
    builtin = get_strix_resource_path("skills")
    if not file_path.is_relative_to(builtin):
        skill_name = "custom"

    def _send() -> None:
        posthog.skill_loaded(skill_name)
        scarf.skill_loaded(skill_name)

    threading.Thread(target=_send, daemon=True).start()


def _candidate_skill_files(skill_name: str) -> list[Path]:
    """Resolve *skill_name* to effective matching files."""
    if "/" in skill_name:
        return _qualified_skill_files(skill_name)
    return _bare_skill_files(skill_name)


def load_skills(skill_names: list[str]) -> dict[str, str]:
    """Load skill markdown bodies (frontmatter stripped) by name.

    Skill files live at ``strix/skills/<category>/<name>.md`` (or any
    directory added via :func:`register_skill_dir`, searched first).
    Names can be ``"name"`` (any category), ``"category/name"``, or a
    bare file at the skills root. Missing skills are logged and skipped.
    """
    search_dirs = skill_search_dirs()
    if not search_dirs:
        return {}

    skill_content: dict[str, str] = {}
    for skill_name in skill_names:
        candidates = _candidate_skill_files(skill_name)
        if not candidates:
            logger.warning("Skill not found: %s", skill_name)
            continue
        if len(candidates) > 1:
            logger.warning("Ambiguous skill name %s; use a category-qualified name", skill_name)
            continue
        file_path = candidates[0]

        try:
            content = file_path.read_text(encoding="utf-8")
        except (OSError, ValueError) as e:
            logger.warning("Failed to load skill %s: %s", skill_name, e)
            continue

        var_name = skill_name.split("/")[-1]
        _, skill_body = _parse_skill_content(content, file_path)
        skill_content[var_name] = skill_body
        logger.debug("Loaded skill: %s -> %s", skill_name, var_name)
        _track_skill_loaded(var_name, file_path)

    logger.debug("load_skills: %d skill(s) resolved", len(skill_content))
    return skill_content
