"""Command-line argument parsing for the ``strix`` scan entrypoint."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from strix.config import apply_config_override
from strix.config.settings import DEFAULT_MAX_TURNS
from strix.core.paths import RUNS_DIR_NAME, run_dir_for, runtime_state_dir
from strix.i18n import t
from strix.interface.scan_setup import attach_workspace_mount, build_targets_info
from strix.interface.update_check import self_update
from strix.interface.utils import (
    check_mountable_dir,
    collect_local_sources,
    resolve_workspace_files,
    validate_config_file,
)
from strix.report.runs import list_run_summaries


# Severities ``--fail-on`` accepts, most severe first.
FAIL_ON_SEVERITIES = ("critical", "high", "medium", "low", "info")

# Translate argparse's built-in strings (usage, options, error, help/version)
# through the i18n layer. argparse routes these through ``gettext.gettext``,
# so replacing ``argparse._`` with a ``t()``-backed lookup localizes them.
_ARGPARSE_MESSAGE_KEYS: dict[str, str] = {
    "usage: ": "cli.argparse_usage",
    "options": "cli.argparse_options",
    "show this help message and exit": "cli.argparse_help",
    "show program's version number and exit": "cli.argparse_version",
    "%(prog)s: error: %(message)s\n": "cli.argparse_error",
    "unrecognized arguments: %s": "cli.argparse_unrecognized",
    "the following arguments are required: %s": "cli.argparse_required",
    "invalid choice: %(value)r (choose from %(choices)s)": "cli.argparse_invalid_choice",
    "argument %(argument_name)s: %(message)s": "cli.argparse_argument_error",
    "expected one argument": "cli.argparse_expected_one",
    "expected at most one argument": "cli.argparse_expected_at_most",
    "expected at least one argument": "cli.argparse_expected_at_least",
    "unexpected option string: %s": "cli.argparse_unexpected_option",
}


def _translate_argparse(message: str) -> str:
    """Return the localized form of an argparse built-in string."""
    key = _ARGPARSE_MESSAGE_KEYS.get(message)
    if key is None:
        return message
    translated = t(key)
    return translated if translated != key else message


argparse._ = _translate_argparse  # type: ignore[attr-defined]


# A minimal parser used to resolve --language/--config BEFORE the full parser
# renders help text. It reuses argparse's own abbreviation rules (e.g.
# ``--conf`` -> ``--config``), so language resolution accepts exactly what the
# real parse accepts. ``exit_on_error=False`` makes a malformed known option
# raise instead of printing, so the full parser reports it once.
_ABBREV_PARSER = argparse.ArgumentParser(add_help=False, allow_abbrev=True, exit_on_error=False)
_ABBREV_PARSER.add_argument("-l", "--language")
_ABBREV_PARSER.add_argument("--config")


def _pre_resolve_language() -> None:
    """Resolve language from --language/-l and --config before argparse runs.

    Argparse evaluates help text at parse time, so we must resolve the language
    BEFORE parse_args() is called. A minimal parser resolves the same option
    abbreviations the real parse accepts (e.g. ``--conf`` -> ``--config``).
    Priority matches ``_detect_language``: --language > STRIX_LANGUAGE env >
    --config file > default config > system locale.
    """
    from strix.i18n import set_config_path, set_language

    # Reset prior CLI overrides before re-evaluating argv so repeated calls stay clean.
    set_language(None)
    set_config_path(None)

    raw_args = sys.argv[1:]
    # Options after ``--`` are positional arguments, never flags.
    pre_args = raw_args[: raw_args.index("--")] if "--" in raw_args else raw_args

    try:
        namespace, _ = _ABBREV_PARSER.parse_known_args(pre_args)
    except argparse.ArgumentError:
        # A malformed --language/--config; the full parser reports it.
        return

    if namespace.language:
        set_language(namespace.language)
    if namespace.config:
        set_config_path(namespace.config)


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
        raise argparse.ArgumentTypeError(t("cli.invalid_float", value=value)) from exc
    import math

    if not math.isfinite(budget) or budget <= 0:
        raise argparse.ArgumentTypeError(t("cli.finite_number"))
    return budget


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(t("cli.invalid_int", value=value)) from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError(t("cli.positive_integer"))
    return parsed


def parse_arguments() -> argparse.Namespace:
    # Pre-scan for --language before argparse runs so help text can be translated
    _pre_resolve_language()

    parser = argparse.ArgumentParser(
        description=t("cli.description"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{t("cli.examples_header")}
  # {t("cli.example_web_app")}
  strix --target https://example.com

  # {t("cli.example_github")}
  strix --target https://github.com/user/repo
  strix --target git@github.com:user/repo.git

  # {t("cli.example_local_code")}
  strix --target ./my-project

  # {t("cli.example_api_spec")}
  strix --target ./openapi.yaml --target https://api.example.com
  strix --target ./collection.postman_collection.json

  # {t("cli.example_postman")}
  strix --target postman://<collection-uuid> --target https://api.example.com
  strix --target "postman://<collection-uuid>?env=<environment-uuid>"

  # {t("cli.example_domain")}
  strix --target example.com

  # {t("cli.example_ip")}
  strix --target 192.168.1.42

  # {t("cli.example_multiple")}
  strix --target https://github.com/user/repo --target https://example.com
  strix --target ./my-project --target https://staging.example.com --target https://prod.example.com

  # {t("cli.example_file")}
  strix --target-list ./targets.txt

  # {t("cli.example_instruction_inline")}
  strix --target example.com --instruction "Focus on authentication vulnerabilities"

  # {t("cli.example_instruction_file")}
  strix --target example.com --instruction-file ./instructions.txt
  strix --target https://app.com --instruction-file /path/to/detailed_instructions.md

  # {t("cli.example_workspace")}
  strix --target ./my-project --workspace-file ./wordlist.txt
  strix --target https://app.com --workspace-file ./openapi.yaml:specs/openapi.yaml

Strix Cloud:
  strix cloud login
  strix cloud scans start --source . --yes --wait
  strix cloud                      # {t("cli.example_cloud_list")}

  {t("cli.example_cloud_run"):<32} https://app.strix.ai
  {t("cli.example_cloud_enterprise"):<32} https://strix.ai/demo
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
        "--workspace-file",
        type=str,
        action="append",
        metavar="PATH[:DEST]",
        help=t("cli.workspace_file_help"),
    )

    parser.add_argument(
        "-n",
        "--non-interactive",
        action="store_true",
        help=t("cli.non_interactive_help"),
    )

    parser.add_argument(
        "--fail-on",
        dest="fail_on",
        type=str.lower,
        choices=FAIL_ON_SEVERITIES,
        default=None,
        metavar="SEVERITY",
        help=t("cli.fail_on_help"),
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
        "--mcp-config",
        type=str,
        metavar="PATH",
        help=t("cli.mcp_config_help"),
    )

    parser.add_argument(
        "--mcp-server",
        dest="mcp_server",
        action="append",
        metavar="NAME",
        help=t("cli.mcp_server_help"),
    )

    parser.add_argument(
        "--mcp-exclude",
        dest="mcp_exclude",
        action="append",
        metavar="NAME",
        help=t("cli.mcp_exclude_help"),
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
        "-r",
        "--resume",
        type=str,
        nargs="?",
        const="",
        metavar="RUN_NAME",
        help=t("cli.resume_help"),
    )

    args = parser.parse_args()
    # Startup-resolved state lives alongside the parsed flags. The full schema
    # is established here so downstream code reads attributes directly.
    args.needs_setup = False
    args.resume_picker = False
    args.targets_info = []
    args.local_sources = []
    args.diff_scope = {"active": False}
    args.run_name = None

    if args.config:
        apply_config_override(validate_config_file(args.config))

    if args.mcp_config:
        mcp_config_path = Path(args.mcp_config).expanduser()
        if not mcp_config_path.is_file():
            parser.error(t("cli.error_mcp_config_not_found", path=args.mcp_config))
        # The MCP loader reads this env var as its config-path override, so
        # setting it here makes the flag win over the default location.
        os.environ["STRIX_MCP_CONFIG"] = str(mcp_config_path)

    # The MCP loader reads these as its per-run include/exclude selection.
    if args.mcp_server:
        os.environ["STRIX_MCP_ONLY"] = ",".join(args.mcp_server)
    if args.mcp_exclude:
        os.environ["STRIX_MCP_EXCLUDE"] = ",".join(args.mcp_exclude)

    if args.update:
        sys.exit(0 if self_update() else 1)

    if args.fail_on and not args.non_interactive and terminal_attached():
        # Without a terminal main() switches to headless anyway, so the
        # flag is only out of place when the TUI would actually open.
        parser.error(t("cli.error_fail_on_headless_only"))

    if args.instruction and args.instruction_file:
        parser.error(t("cli.error_instruction_conflict"))

    if args.instruction_file:
        instruction_path = Path(args.instruction_file)
        try:
            with instruction_path.open(encoding="utf-8") as f:
                args.instruction = f.read().strip()
                if not args.instruction:
                    parser.error(t("cli.error_empty_instruction_file", path=instruction_path))
        except Exception as e:
            parser.error(t("cli.error_read_instruction_file", path=instruction_path, error=e))

    try:
        args.workspace_files = resolve_workspace_files(getattr(args, "workspace_file", None))
    except ValueError as error:
        parser.error(f"--workspace-file: {error}")

    args.user_explicit_instruction = args.instruction if args.resume is not None else None
    # What the user actually asked for, kept apart from args.instruction because
    # prepare_run prepends the diff-scope preamble to that. This is the text the
    # transcript shows as their opening message.
    args.user_instruction = args.instruction or None

    if args.resume is not None:
        if args.target or args.target_list:
            parser.error(t("cli.error_resume_with_target"))
        if not args.resume.strip():
            # A bare --resume: main() opens the inline picker of prior runs
            # before anything launches; headless has nobody to pick, so it
            # lists them.
            args.resume = None
            args.resume_picker = True
            if args.non_interactive:
                parser.error(resume_run_list_message(t("cli.error_resume_headless_needs_name")))
            if not list_run_summaries():
                parser.error(t("cli.error_resume_no_runs", dir=RUNS_DIR_NAME))
            return args
        try:
            load_resume_state(args)
        except ResumeError as exc:
            parser.error(str(exc))
    else:
        if not args.target and not args.target_list:
            if args.non_interactive:
                parser.error(t("cli.error_no_target_headless"))
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


def terminal_attached() -> bool:
    """Whether the TUI can take over the terminal: a tty on both ends, not dumb."""
    if os.environ.get("TERM", "").strip().lower() == "dumb":
        return False
    return all(hasattr(stream, "isatty") and stream.isatty() for stream in (sys.stdin, sys.stdout))


class ResumeError(ValueError):
    """A prior run cannot be resumed as recorded; the message names why."""


def resume_run_list_message(lead: str) -> str:
    """``lead`` followed by the runs that ``--resume <name>`` would accept."""
    runs = list_run_summaries()
    if not runs:
        return t("cli.resume_no_runs_available", lead=lead, dir=RUNS_DIR_NAME)
    name_width = max(len(run.run_name) for run in runs)
    status_width = max(len(run.status) for run in runs)
    lines = [t("cli.resume_runs_in_dir", lead=lead, dir=RUNS_DIR_NAME)]
    lines.extend(
        f"  {run.run_name:<{name_width}}  {run.status:<{status_width}}  "
        f"{run.started_at[:19]:<19}  {run.target}".rstrip()
        for run in runs
    )
    return "\n".join(lines)


def load_resume_state(args: argparse.Namespace) -> None:
    """Populate ``args.targets_info`` and friends from a prior run's run.json.

    Raises :class:`ResumeError` when the run is missing, unreadable, or its
    recorded workspace is gone.
    """
    from strix.report.writer import read_run_record

    run_dir = run_dir_for(args.resume)
    state_path = run_dir / "run.json"
    if not state_path.exists():
        raise ResumeError(t("cli.error_resume_missing_run", name=args.resume, path=state_path))
    try:
        state = read_run_record(run_dir)
    except (RuntimeError, TypeError) as exc:
        raise ResumeError(t("cli.error_resume_unreadable", name=args.resume, error=exc)) from exc

    args.targets_info = state.get("targets_info") or []
    # A target-less run has no targets_info at all. It is driven by its
    # instruction, over a mounted working directory or over nothing when the
    # mount was declined, so either of those is enough to resume it.
    workspace_mount = state.get("workspace_mount") or None
    if not args.targets_info and not workspace_mount and not state.get("user_instruction"):
        raise ResumeError(t("cli.error_resume_no_targets", name=args.resume))

    for target in args.targets_info:
        if not isinstance(target, dict):
            continue
        details = target.get("details") or {}
        if target.get("type") == "local_code" and details.get("target_path"):
            try:
                check_mountable_dir(Path(details["target_path"]).expanduser())
            except ValueError as exc:
                raise ResumeError(f"--resume {args.resume}: {exc}") from exc
            continue
        if target.get("type") != "repository":
            continue
        cloned = details.get("cloned_repo_path")
        if not cloned:
            continue
        if not Path(cloned).expanduser().exists():
            raise ResumeError(t("cli.error_resume_missing_repo", name=args.resume, path=cloned))

    if args.instruction is None:
        args.instruction = state.get("instruction")
    if not getattr(args, "user_instruction", None):
        args.user_instruction = state.get("user_instruction") or None
    args.local_sources = collect_local_sources(args.targets_info)
    # Remount the workspace the run was started with. The user already confirmed
    # this directory, so the target mount guard does not apply to it; it only has
    # to still be there.
    args.workspace_mount = workspace_mount

    # Replace the workspace files the run started with, unless this resume names
    # its own. The persisted record is revalidated like a fresh flag, so an
    # edited run.json cannot widen what a resume places. A file deleted between
    # runs is dropped rather than fatal: it is context for the agent, not scope.
    if not getattr(args, "workspace_files", None):
        restored = [
            f"{source_path}:{workspace_path}"
            for workspace_file in state.get("workspace_files") or []
            if isinstance(workspace_file, dict)
            and (source_path := Path(str(workspace_file.get("source_path") or ""))).is_file()
            and (workspace_path := str(workspace_file.get("workspace_path") or ""))
        ]
        try:
            args.workspace_files = resolve_workspace_files(restored)
        except ValueError as error:
            raise ResumeError(
                t("cli.error_resume_invalid_workspace_file", name=args.resume, error=error)
            ) from error
    if workspace_mount:
        if not Path(workspace_mount).expanduser().is_dir():
            raise ResumeError(
                t("cli.error_resume_missing_workdir", name=args.resume, path=workspace_mount)
            )
        attach_workspace_mount(args)
    if state.get("diff_scope"):
        args.diff_scope = state.get("diff_scope")
    persisted_scan_mode = state.get("scan_mode")
    if persisted_scan_mode and args.scan_mode == "deep":
        args.scan_mode = persisted_scan_mode
    agents_path = runtime_state_dir(run_dir) / "agents.json"
    if not agents_path.exists():
        raise ResumeError(t("cli.error_resume_missing_agents", name=args.resume, path=agents_path))
