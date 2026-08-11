"""Command-line argument parsing for the ``strix`` scan entrypoint."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from strix.config import apply_config_override
from strix.config.settings import DEFAULT_MAX_TURNS
from strix.core.paths import run_dir_for, runtime_state_dir
from strix.i18n import t
from strix.interface.scan_setup import attach_workspace_mount, build_targets_info
from strix.interface.update_check import self_update
from strix.interface.utils import (
    check_mountable_dir,
    collect_local_sources,
    validate_config_file,
)


def _pre_resolve_language() -> None:
    """Set language from --language/-l before argparse runs.

    Argparse evaluates help text at parse time, so we must set the language
    BEFORE parse_args() is called. This pre-scans sys.argv for the flag.
    """
    argv = sys.argv[1:]
    for i, arg in enumerate(argv):
        if arg in ("-l", "--language") and i + 1 < len(argv):
            from strix.i18n import set_language
            set_language(argv[i + 1])
            return
        # Handle --language=pt form
        if arg.startswith("--language="):
            from strix.i18n import set_language
            set_language(arg.split("=", 1)[1])
            return


def get_version() -> str:
    try:
        from importlib.metadata import version

        return version("strix-agent")
    except Exception:
        return "unknown"


def _positive_budget(value: str) -> float:
    try:
        budget = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid float value: {value!r}") from exc
    import math

    if not math.isfinite(budget) or budget <= 0:
        raise argparse.ArgumentTypeError("must be a finite number greater than 0")
    return budget


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid int value: {value!r}") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be an integer greater than 0")
    return parsed


def parse_arguments() -> argparse.Namespace:
    # Pre-scan for --language before argparse runs so help text can be translated
    _pre_resolve_language()

    parser = argparse.ArgumentParser(
        description=t("cli.description"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Web application penetration test
  strix --target https://example.com

  # GitHub repository analysis
  strix --target https://github.com/user/repo
  strix --target git@github.com:user/repo.git

  # Local code analysis
  strix --target ./my-project

  # API spec test (OpenAPI/Swagger file or Postman collection export)
  strix --target ./openapi.yaml --target https://api.example.com
  strix --target ./collection.postman_collection.json

  # Postman collection pulled live by id (needs POSTMAN_API_KEY); optional environment
  strix --target postman://<collection-uuid> --target https://api.example.com
  strix --target "postman://<collection-uuid>?env=<environment-uuid>"

  # Domain penetration test
  strix --target example.com

  # IP address penetration test
  strix --target 192.168.1.42

  # Multiple targets (e.g., white-box testing with source and deployed app)
  strix --target https://github.com/user/repo --target https://example.com
  strix --target ./my-project --target https://staging.example.com --target https://prod.example.com

  # Targets from a file, one target per non-empty, non-comment line
  strix --target-list ./targets.txt

  # Custom instructions (inline)
  strix --target example.com --instruction "Focus on authentication vulnerabilities"

  # Custom instructions (from file)
  strix --target example.com --instruction-file ./instructions.txt
  strix --target https://app.com --instruction-file /path/to/detailed_instructions.md
        """,
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"strix {get_version()}",
    )

    parser.add_argument(
        "--update",
        action="store_true",
        help=t("cli.update_help"),
    )

    parser.add_argument(
        "-l",
        "--language",
        type=str,
        default=None,
        help=t("cli.language_help"),
    )

    parser.add_argument(
        "-t",
        "--target",
        type=str,
        action="append",
        help=t("cli.target_help"),
    )
    parser.add_argument(
        "--target-list",
        type=str,
        action="append",
        metavar="PATH",
        help=t("cli.target_list_help"),
    )
    parser.add_argument(
        "--instruction",
        type=str,
        help=t("cli.instruction_help"),
    )

    parser.add_argument(
        "--instruction-file",
        type=str,
        help=t("cli.instruction_file_help"),
    )

    parser.add_argument(
        "-n",
        "--non-interactive",
        action="store_true",
        help=t("cli.non_interactive_help"),
    )

    parser.add_argument(
        "-m",
        "--scan-mode",
        type=str,
        choices=["quick", "standard", "deep"],
        default="deep",
        help=t("cli.scan_mode_help"),
    )

    parser.add_argument(
        "--scope-mode",
        type=str,
        choices=["auto", "diff", "full"],
        default="auto",
        help=t("cli.scope_mode_help"),
    )

    parser.add_argument(
        "--diff-base",
        type=str,
        help=t("cli.diff_base_help"),
    )

    parser.add_argument(
        "--config",
        type=str,
        help=t("cli.config_help"),
    )

    parser.add_argument(
        "--max-budget",
        "--max-budget-usd",
        dest="max_budget_usd",
        metavar="USD",
        type=_positive_budget,
        default=None,
        help=t("cli.max_budget_help"),
    )

    parser.add_argument(
        "--max-turns",
        dest="max_turns",
        metavar="N",
        type=_positive_int,
        default=DEFAULT_MAX_TURNS,
        help=t("cli.max_turns_help"),
    )

    parser.add_argument(
        "--resume",
        type=str,
        metavar="RUN_NAME",
        help=t("cli.resume_help"),
    )

    args = parser.parse_args()
    # Startup-resolved state lives alongside the parsed flags. The full schema
    # is established here so downstream code reads attributes directly.
    args.needs_setup = False
    args.targets_info = []
    args.local_sources = []
    args.diff_scope = {"active": False}
    args.run_name = None

    if args.config:
        apply_config_override(validate_config_file(args.config))

    if args.update:
        sys.exit(0 if self_update() else 1)

    if args.instruction and args.instruction_file:
        parser.error(
            "Cannot specify both --instruction and --instruction-file. Use one or the other."
        )

    if args.instruction_file:
        instruction_path = Path(args.instruction_file)
        try:
            with instruction_path.open(encoding="utf-8") as f:
                args.instruction = f.read().strip()
                if not args.instruction:
                    parser.error(f"Instruction file '{instruction_path}' is empty")
        except Exception as e:
            parser.error(f"Failed to read instruction file '{instruction_path}': {e}")

    args.user_explicit_instruction = args.instruction if args.resume else None
    # What the user actually asked for, kept apart from args.instruction because
    # prepare_run prepends the diff-scope preamble to that. This is the text the
    # transcript shows as their opening message.
    args.user_instruction = args.instruction or None

    if args.resume:
        if args.target or args.target_list:
            parser.error(
                "Cannot combine --resume with --target/--target-list. "
                "--resume picks up where the prior run left off, including the "
                "original target list."
            )
        _load_resume_state(args, parser)
        agents_path = runtime_state_dir(run_dir_for(args.resume)) / "agents.json"
        if not agents_path.exists():
            parser.error(
                f"--resume {args.resume}: missing {agents_path}. The run was "
                f"persisted but never reached its first agent snapshot — "
                f"there's nothing to resume from. Pick a fresh --run-name "
                f"or remove --resume to start over with the same targets."
            )
    else:
        if not args.target and not args.target_list:
            if args.non_interactive:
                parser.error(
                    "the following arguments are required: -t/--target or --target-list "
                    "(or use --resume <run_name> to continue a prior scan)"
                )
            # Interactive launch with no target: open the normal TUI on its
            # start screen, where the user gives a target or a bare prompt
            # before the scan starts.
            args.needs_setup = True
            return args

        try:
            build_targets_info(args)
        except ValueError as e:
            parser.error(str(e))

    return args


def _load_resume_state(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Populate ``args.targets_info`` and friends from a prior run's run.json."""
    from strix.report.writer import read_run_record

    run_dir = run_dir_for(args.resume)
    state_path = run_dir / "run.json"
    if not state_path.exists():
        parser.error(
            f"--resume {args.resume}: no such run "
            f"(missing {state_path}; remove --resume for a fresh start)"
        )
    try:
        state = read_run_record(run_dir)
    except RuntimeError as exc:
        parser.error(f"--resume {args.resume}: run.json unreadable: {exc}")

    args.targets_info = state.get("targets_info") or []
    # A target-less run has no targets_info at all. It is driven by its
    # instruction, over a mounted working directory or over nothing when the
    # mount was declined, so either of those is enough to resume it.
    workspace_mount = state.get("workspace_mount") or None
    if not args.targets_info and not workspace_mount and not state.get("user_instruction"):
        parser.error(f"--resume {args.resume}: run.json has no targets_info")

    for target in args.targets_info:
        if not isinstance(target, dict):
            continue
        details = target.get("details") or {}
        if target.get("type") == "local_code" and details.get("target_path"):
            try:
                check_mountable_dir(Path(details["target_path"]).expanduser())
            except ValueError as exc:
                parser.error(f"--resume {args.resume}: {exc}")
            continue
        if target.get("type") != "repository":
            continue
        cloned = details.get("cloned_repo_path")
        if not cloned:
            continue
        if not Path(cloned).expanduser().exists():
            parser.error(
                f"--resume {args.resume}: cloned repo at {cloned} is missing. "
                f"It was deleted between runs. Pick a fresh --run-name to "
                f"re-clone, or restore the directory before resuming."
            )

    if args.instruction is None:
        args.instruction = state.get("instruction")
    if not getattr(args, "user_instruction", None):
        args.user_instruction = state.get("user_instruction") or None
    args.local_sources = collect_local_sources(args.targets_info)
    # Remount the workspace the run was started with. The user already confirmed
    # this directory, so the target mount guard does not apply to it; it only has
    # to still be there.
    args.workspace_mount = workspace_mount
    if workspace_mount:
        if not Path(workspace_mount).expanduser().is_dir():
            parser.error(
                f"--resume {args.resume}: the working directory {workspace_mount} "
                f"is missing. Restore it before resuming, or start a fresh run."
            )
        attach_workspace_mount(args)
    if state.get("diff_scope"):
        args.diff_scope = state.get("diff_scope")
    persisted_scan_mode = state.get("scan_mode")
    if persisted_scan_mode and args.scan_mode == "deep":
        args.scan_mode = persisted_scan_mode
