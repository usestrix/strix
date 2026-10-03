"""Wire a bug-bounty program into a run.

Two halves, mirroring how scope wiring works (flag → env → load at run start):

* :func:`bootstrap_bounty` runs at CLI parse time. It loads the program, runs the
  ROE gate (failing before any scan starts when automated testing is prohibited and
  the policy is ``refuse``), compiles the scope, writes the artifacts under
  ``~/.strix/bounty/<slug>/``, sets the environment so the rest of the run picks
  them up, and returns the agent instruction preamble.
* :func:`activate_bounty_from_env` runs at run start (from ``strix2_ext``). It
  rehydrates the :class:`BountyContext` and the known-reports store from the files /
  env ``bootstrap_bounty`` wrote, so the agent tools work regardless of process
  model — exactly as ``load_active_policy`` rehydrates the scope policy from env.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from strix.bounty.compile import CompiledScope, compile_to_scope
from strix.bounty.dedupe import (
    KnownReport,
    load_known_reports_file,
    render_dedupe_md,
    reset_known_reports,
)
from strix.bounty.loaders import load_program, load_program_file
from strix.bounty.loaders.errors import BountyLoadError
from strix.bounty.roe import AutomatedPolicy, RoeGate, evaluate_roe
from strix.bounty.runtime import BountyContext, set_bounty_context


if TYPE_CHECKING:
    from strix.bounty.schema import BountyProgram


logger = logging.getLogger(__name__)

ENV_PROGRAM = "STRIX2_BOUNTY_PROGRAM"
ENV_KNOWN_REPORTS = "STRIX2_BOUNTY_KNOWN_REPORTS"
ENV_AUTOMATED_POLICY = "STRIX2_BOUNTY_AUTOMATED_POLICY"
ENV_INTRUSIVE_POLICY = "STRIX2_BOUNTY_INTRUSIVE_POLICY"


class BountyBootstrapError(RuntimeError):
    """Raised when a bounty engagement cannot be set up."""


@dataclass
class BootstrapResult:
    """What ``bootstrap_bounty`` resolved — the caller prints warnings and may stop."""

    proceed: bool
    program: BountyProgram
    gate: RoeGate
    compiled: CompiledScope
    preamble: str
    warnings: list[str]
    bounty_dir: Path


def _bounty_dir(program: BountyProgram) -> Path:
    return Path.home() / ".strix" / "bounty" / program.slug


_H1_HEADER_RE = re.compile(r"x-bug-bounty", re.IGNORECASE)
_RATE_RE = re.compile(
    r"(\d+(?:\.\d+)?)\s*(?:requests?\s*)?(?:per\s*second|/\s*s\b|req/s|rps)", re.IGNORECASE
)


def _derive_http_roe(program: BountyProgram, *, username: str | None) -> BountyProgram:
    """Fill in machine-readable HTTP ROE from the free-text policy (gaps only).

    Detects the HackerOne ``X-Bug-Bounty: HackerOne-<username>`` identifying-header
    convention (substituting the hunter's real username for the policy's placeholder)
    and a ``N per second`` rate cap. Only fills values the program/ROE file left unset,
    so an explicit ROE override always wins.
    """
    roe = program.roe
    policy = roe.notes or ""
    updates: dict[str, object] = {}
    if not roe.required_headers and _H1_HEADER_RE.search(policy):
        uname = username or "<your-hackerone-username>"
        updates["required_headers"] = {"X-Bug-Bounty": f"HackerOne-{uname}"}
    if roe.rate_limit_rps is None:
        m = _RATE_RE.search(policy)
        if m:
            with contextlib.suppress(ValueError):
                updates["rate_limit_rps"] = float(m.group(1))
    if not updates:
        return program
    return program.model_copy(update={"roe": roe.model_copy(update=updates)})


def _build_preamble(program: BountyProgram, gate: RoeGate) -> str:
    name = program.name or program.handle
    parts = [
        f'This is an authorized BUG-BOUNTY engagement against the {program.platform} '
        f'program "{program.handle}" ({name}).',
        "",
        "Operate strictly within the program's scope and rules of engagement.",
        "",
        gate.render_constraints_md().rstrip(),
        "",
        "Workflow:",
        "1. Call `bounty_scope_status` first to load the authorized scope, the "
        "out-of-scope exclusions, and the rules of engagement.",
        "2. Follow the `bounty/bounty_hunting` skill. Delegate one specialist per "
        "in-scope domain (Strix 2 domain delegation), giving each the "
        "`bounty/bounty_hunting` skill alongside its domain skill.",
        "3. Before treating any finding as submittable, call `check_duplicate` and "
        "confirm it is novel against the program's disclosed reports.",
        "4. Produce submission-ready evidence for each validated finding.",
        "",
        "Scope is enforced at the tool boundaries; out-of-scope targets are refused.",
    ]
    if not gate.active_tools_allowed:
        parts.append(
            "RECON-ONLY: this program prohibits automated scanning, so do NOT fire "
            "active scanners or exploitation — map, dedupe, and produce a manual test plan."
        )
    return "\n".join(parts)


def bootstrap_bounty(
    spec: str,
    *,
    roe_path: str | None = None,
    known_reports_path: str | None = None,
    automated_policy: AutomatedPolicy = "refuse",
    intrusive_policy: str = "auto",
    allow_intrusive: bool = False,
) -> BootstrapResult:
    """Load + gate + compile a program and wire the environment for the run."""
    try:
        program = load_program(
            spec,
            hackerone_username=os.environ.get("HACKERONE_API_USERNAME"),
            hackerone_token=os.environ.get("HACKERONE_API_TOKEN"),
            bugcrowd_token=os.environ.get("BUGCROWD_API_TOKEN"),
            roe_path=roe_path,
        )
    except BountyLoadError as exc:
        raise BountyBootstrapError(str(exc)) from exc

    program = _derive_http_roe(program, username=os.environ.get("HACKERONE_API_USERNAME"))
    gate = evaluate_roe(program, automated_policy=automated_policy)
    compiled = compile_to_scope(program, intrusive_policy=intrusive_policy)

    known_reports: list[KnownReport] = []
    if known_reports_path:
        try:
            known_reports = load_known_reports_file(known_reports_path)
        except BountyLoadError as exc:
            raise BountyBootstrapError(str(exc)) from exc

    bounty_dir = _bounty_dir(program)
    bounty_dir.mkdir(parents=True, exist_ok=True)
    scope_path = bounty_dir / "scope.yaml"
    program_path = bounty_dir / "program.json"
    scope_path.write_text(
        yaml.safe_dump(compiled.policy.model_dump(), sort_keys=False), encoding="utf-8"
    )
    program_path.write_text(program.model_dump_json(indent=2), encoding="utf-8")
    (bounty_dir / "dedupe.md").write_text(render_dedupe_md(known_reports), encoding="utf-8")
    known_path = bounty_dir / "known_reports.json"
    if known_reports:
        known_path.write_text(
            "[" + ",".join(r.model_dump_json() for r in known_reports) + "]", encoding="utf-8"
        )

    # Wire the environment: the scope engine reads STRIX_SCOPE_CONFIG; strix2_ext
    # reads the STRIX2_BOUNTY_* vars to rehydrate the context at run start.
    os.environ["STRIX_SCOPE_CONFIG"] = str(scope_path)
    if compiled.policy.allow_intrusive or allow_intrusive:
        os.environ["STRIX_ALLOW_INTRUSIVE"] = "1"
    os.environ[ENV_PROGRAM] = str(program_path)
    os.environ[ENV_AUTOMATED_POLICY] = automated_policy
    os.environ[ENV_INTRUSIVE_POLICY] = intrusive_policy
    if known_reports:
        os.environ[ENV_KNOWN_REPORTS] = str(known_path)
    else:
        os.environ.pop(ENV_KNOWN_REPORTS, None)

    return BootstrapResult(
        proceed=gate.proceed,
        program=program,
        gate=gate,
        compiled=compiled,
        preamble=_build_preamble(program, gate),
        warnings=list(gate.warnings),
        bounty_dir=bounty_dir,
    )


def activate_bounty_from_env() -> bool:
    """Bind the bounty context + known reports from the environment, if any.

    Called at run start by ``strix2_ext``. Returns True when a bounty program was
    activated. Safe to call when no bounty run is configured (returns False).
    """
    program_path = os.environ.get(ENV_PROGRAM)
    if not program_path or not Path(program_path).is_file():
        return False
    try:
        program = load_program_file(program_path)
    except BountyLoadError:
        logger.exception("bounty: could not load %s; bounty context not bound", program_path)
        return False

    automated_policy: AutomatedPolicy = os.environ.get(ENV_AUTOMATED_POLICY, "refuse")  # type: ignore[assignment]
    intrusive_policy = os.environ.get(ENV_INTRUSIVE_POLICY, "auto")
    gate = evaluate_roe(program, automated_policy=automated_policy)
    compiled = compile_to_scope(program, intrusive_policy=intrusive_policy)
    set_bounty_context(BountyContext(program=program, gate=gate, compiled=compiled))

    known_path = os.environ.get(ENV_KNOWN_REPORTS)
    if known_path and Path(known_path).is_file():
        try:
            reset_known_reports(load_known_reports_file(known_path))
        except BountyLoadError:
            logger.exception("bounty: could not load known reports from %s", known_path)
    logger.info("Bounty context activated for program %s", program.handle)
    return True
