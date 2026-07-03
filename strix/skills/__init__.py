"""safe skill-path resolver for strix load_skills — defense-in-depth.

Drop-in addition for strix/skills/__init__.py::load_skills().

The current path-resolution for skill files is:

    if "/" in skill_name:
        rel_path = f"{skill_name}.md"
    ...
    if rel_path is None or not (skills_dir / rel_path).exists():
        ...
    try:
        content = (skills_dir / rel_path).read_text(encoding="utf-8")

That relies on the caller-side `validate_requested_skills()` to reject
unknown skill names before they reach load_skills(). That's correct for
the current call graph, but it's brittle: any future caller that calls
load_skills() without first validating would inherit a path-traversal
vulnerability (skill_name="../../etc/passwd" -> reads passwd — well,
the .md variant would not exist, but a clever attacker can construct
branches with predictable .md paths).

This patch adds a runtime safe-path check that is independent of
validate_requested_skills.
"""
from __future__ import annotations

from pathlib import Path


def _safe_skill_path(skills_dir: Path, rel_path: str) -> Path | None:
    """Return a resolved path inside skills_dir, or None if it escapes.

    Defense in depth: even if `validate_requested_skills()` is bypassed
    or has a bug, this guarantees we never `read_text()` a file outside
    of skills_dir.

    Args:
        skills_dir: The directory where skill files are expected to live.
        rel_path: A relative path (constructed from user-supplied skill_name).

    Returns:
        The resolved absolute path inside skills_dir, or None if the path
        escapes via `..` or symlinks.

    Edge cases handled:
    - Empty rel_path -> None.
    - Absolute rel_path -> None (we never expect absolute skill paths).
    - `..` traversal -> None.
    - Symlinks pointing outside skills_dir -> None (via .resolve()).
    """
    if not rel_path or not rel_path.strip():
        return None
    # Reject absolute paths explicitly — we expect rel paths only.
    p = Path(rel_path)
    if p.is_absolute():
        return None
    # Resolve to a canonical absolute path. This collapses `..` segments
    # and follows symlinks (which is what we want — we want to detect
    # escape via either).
    try:
        target = (skills_dir / p).resolve(strict=False)
        skills_dir_real = skills_dir.resolve(strict=False)
    except (OSError, RuntimeError):
        return None
    # Check containment. Path.is_relative_to() is the canonical check
    # on Python 3.9+; supports `..` resolution correctly.
    try:
        target.relative_to(skills_dir_real)
    except ValueError:
        return None
    return target


# Smoke test (run as `python3 03_fix_skills_safe_path.py`)
if __name__ == "__main__":
    import tempfile, os

    with tempfile.TemporaryDirectory() as tmp:
        skills = Path(tmp) / "skills"
        skills.mkdir()

        # 1. Plain path inside skills_dir
        (skills / "ok.md").write_text("ok")

        # 2. Symlink escape — should be None (resolve() chases the link)
        os.symlink("/etc/passwd", skills / "evil.md")
        # 3. Plain `..` traversal — should be None
        # (no need to create a file, .resolve() would still escape)

        cases = {
            "ok.md": True,
            "../etc/passwd.md": False,
            "../../etc/passwd.md": False,
            "/etc/passwd.md": False,        # absolute
            "subdir/foo.md": True,          # nested
            "subdir/../../escape.md": False,
            "evil.md": False,               # symlink to /etc/passwd
        }

        for rel, should_pass in cases.items():
            got = _safe_skill_path(skills, rel)
            ok = (got is not None) == should_pass
            print(f"  {'OK' if ok else 'FAIL'}: rel={rel!r}  expected={'pass' if should_pass else 'reject'}  got={'pass' if got else 'reject'}")
            if not ok:
                raise SystemExit(1)
        print("All cases passed.")
