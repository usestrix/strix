"""Safety-mode local workspace isolation."""

from __future__ import annotations

from pathlib import Path

import pytest

from strix.runtime.local_dir_staging import materialize_isolated_sources
from strix.runtime.session_manager import build_bind_mounts


def test_isolated_copy_does_not_modify_original(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    original = source / "app.py"
    original.write_text("before\n", encoding="utf-8")
    run_dir = tmp_path / "runs" / "scan"

    [staged] = materialize_isolated_sources(
        [
            {
                "source_path": str(source),
                "workspace_subdir": "source",
                "protect_metadata": True,
            }
        ],
        run_dir=run_dir,
    )
    staged_file = Path(staged["source_path"]) / "app.py"
    staged_file.write_text("after\n", encoding="utf-8")

    assert original.read_text(encoding="utf-8") == "before\n"
    assert staged_file.read_text(encoding="utf-8") == "after\n"
    assert staged["original_source_path"] == str(source.resolve())
    assert staged["workspace_mode"] == "isolated_copy"


def test_isolated_copy_keeps_metadata_read_only(tmp_path: Path) -> None:
    source = tmp_path / "source"
    (source / ".git").mkdir(parents=True)
    (source / ".git" / "config").write_text("[core]\n", encoding="utf-8")
    (source / ".agents").mkdir()
    (source / ".agents" / "rules.md").write_text("instructions\n", encoding="utf-8")

    [staged] = materialize_isolated_sources(
        [
            {
                "source_path": str(source),
                "workspace_subdir": "source",
                "protect_metadata": True,
            }
        ],
        run_dir=tmp_path / "runs" / "scan",
    )

    assert staged["protect_metadata"] is True
    read_only = {mount["target"] for mount in build_bind_mounts([staged]) if mount.get("read_only")}
    assert "/workspace/source/.git" in read_only
    assert "/workspace/source/.agents" in read_only


def test_isolated_copy_drops_out_of_tree_symlink(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text("secret", encoding="utf-8")
    (source / "escape").symlink_to(secret)

    [staged] = materialize_isolated_sources(
        [
            {
                "source_path": str(source),
                "workspace_subdir": "source",
                "protect_metadata": True,
            }
        ],
        run_dir=tmp_path / "runs" / "scan",
    )

    assert not (Path(staged["source_path"]) / "escape").exists()


def test_repeated_materialization_preserves_the_true_origin(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("code\n", encoding="utf-8")
    run_dir = tmp_path / "runs" / "scan"
    sources = [{"source_path": str(source), "workspace_subdir": "source", "protect_metadata": True}]

    # Staging runs in prepare_run and again in run_strix_scan on the same entries.
    staged = materialize_isolated_sources(sources, run_dir=run_dir)
    [restaged] = materialize_isolated_sources(staged, run_dir=run_dir)

    assert restaged["original_source_path"] == str(source.resolve())
    assert restaged["source_path"] == staged[0]["source_path"]
    assert restaged["source_path"] != restaged["original_source_path"]


def test_restaging_without_a_completion_marker_recopies_the_source(tmp_path: Path) -> None:
    """A second pass that treats the copy as its own origin clears the destination and
    then reads it back empty, silently handing the agent an empty workspace."""
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("code\n", encoding="utf-8")
    run_dir = tmp_path / "runs" / "scan"

    [staged] = materialize_isolated_sources(
        [{"source_path": str(source), "workspace_subdir": "source", "protect_metadata": True}],
        run_dir=run_dir,
    )
    destination = Path(staged["source_path"])
    (destination.parent / f".{destination.name}.complete").unlink()

    [restaged] = materialize_isolated_sources([staged], run_dir=run_dir)

    assert (Path(restaged["source_path"]) / "app.py").read_text(encoding="utf-8") == "code\n"
    assert restaged["original_source_path"] == str(source.resolve())


@pytest.mark.parametrize("workspace_subdir", [".", "../victim", "../../../../victim"])
def test_isolated_copy_rejects_workspace_traversal(tmp_path: Path, workspace_subdir: str) -> None:
    source = tmp_path / "source"
    source.mkdir()
    run_dir = tmp_path / "runs" / "scan"
    workspace_root = run_dir / ".state" / "workspaces"
    victim = (workspace_root / workspace_subdir).resolve()
    victim.mkdir(parents=True, exist_ok=True)
    sentinel = victim / "sentinel.txt"
    sentinel.write_text("keep", encoding="utf-8")

    with pytest.raises(ValueError, match="workspace_subdir"):
        materialize_isolated_sources(
            [
                {
                    "source_path": str(source),
                    "workspace_subdir": workspace_subdir,
                    "protect_metadata": True,
                }
            ],
            run_dir=run_dir,
        )

    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_isolated_copy_rejects_absolute_workspace_subdir(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    victim = tmp_path / "victim"
    victim.mkdir()
    sentinel = victim / "sentinel.txt"
    sentinel.write_text("keep", encoding="utf-8")

    with pytest.raises(ValueError, match="workspace_subdir"):
        materialize_isolated_sources(
            [
                {
                    "source_path": str(source),
                    "workspace_subdir": str(victim),
                    "protect_metadata": True,
                }
            ],
            run_dir=tmp_path / "runs" / "scan",
        )

    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_isolated_copy_rejects_workspace_symlink_escape(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    run_dir = tmp_path / "runs" / "scan"
    workspace_root = run_dir / ".state" / "workspaces"
    workspace_root.mkdir(parents=True)
    victim = tmp_path / "victim"
    victim.mkdir()
    sentinel = victim / "sentinel.txt"
    sentinel.write_text("keep", encoding="utf-8")
    (workspace_root / "source").symlink_to(victim, target_is_directory=True)

    with pytest.raises(ValueError, match="workspace_subdir"):
        materialize_isolated_sources(
            [
                {
                    "source_path": str(source),
                    "workspace_subdir": "source",
                    "protect_metadata": True,
                }
            ],
            run_dir=run_dir,
        )

    assert sentinel.read_text(encoding="utf-8") == "keep"
