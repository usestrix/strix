"""Turn a program's rules of engagement into a go/no-go gate + a constraint block.

:func:`evaluate_roe` is the behavioral counterpart to
:func:`strix.bounty.compile.compile_to_scope`: the compiler decides *where* a run may
go, this decides *how* it may behave there. It answers one hard question — may the
automated engine run at all? — and produces the constraints the agents must obey
(rate limit, prohibited techniques, ineligible bug classes, intrusive posture).

The one genuine authorization line is automated testing. A bug-bounty authorization
is conditional on the program's rules, so when a program **explicitly prohibits**
scanners/automation, firing active tools at it is outside that authorization. The
built-in default is therefore :data:`DEFAULT_AUTOMATED_POLICY` = ``"refuse"``; an
operator may override per run to ``"recon_only"`` (map + dedupe + plan, no active
tools) or ``"warn_and_proceed"`` (run anyway, loudly warned) — but that override is a
deliberate, logged choice, never a silent default.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal


if TYPE_CHECKING:
    from strix.bounty.schema import BountyProgram


AutomatedPolicy = Literal["refuse", "recon_only", "warn_and_proceed"]

DEFAULT_AUTOMATED_POLICY: AutomatedPolicy = "refuse"


@dataclass
class RoeGate:
    """The decision and the constraints for a bounty run.

    ``proceed`` is the go/no-go. ``active_tools_allowed`` is False in recon-only mode
    (read/map/dedupe/plan but do not fire active scanners/exploits). ``warnings`` are
    surfaced to the operator before the run; ``constraints`` are injected into the
    agents' briefing as hard rules.
    """

    proceed: bool
    mode: Literal["normal", "recon_only", "warn_and_proceed", "refused"]
    active_tools_allowed: bool
    warnings: list[str] = field(default_factory=list)
    constraints: list[str] = field(default_factory=list)

    def render_constraints_md(self) -> str:
        """Render the constraint block for the agent briefing."""
        lines = ["## Rules of engagement (hard constraints)", ""]
        lines.extend(f"- {item}" for item in self.constraints)
        if self.mode == "recon_only":
            lines.append(
                "- **Recon-only mode:** do NOT run active scanners or exploitation. "
                "Read public information, map the attack surface, dedupe against known "
                "reports, and produce a manual test plan — nothing that touches the "
                "target with an active payload."
            )
        return "\n".join(lines) + "\n"


def _base_constraints(program: BountyProgram) -> list[str]:
    roe = program.roe
    out: list[str] = [
        "Stay strictly within the authorized scope — out-of-scope targets are denied "
        "at the tool boundaries, and you must not try to work around that.",
    ]
    if roe.rate_limit_rps is not None:
        out.append(
            f"Respect the program rate limit of {roe.rate_limit_rps} request(s)/second; "
            "throttle scans and avoid bursts (the engine refuses fuzzers with no rate flag)."
        )
    if roe.required_headers:
        hdrs = ", ".join(f"{k}: {v}" for k, v in roe.required_headers.items())
        out.append(
            f"Set the required identifying header(s) on EVERY request: {hdrs}. The engine "
            "refuses HTTP tool calls that omit them and injects them into proxy replays."
        )
    if roe.prohibited_actions:
        out.append(
            "Prohibited techniques (never perform): " + ", ".join(roe.prohibited_actions) + "."
        )
    if not roe.state_changing_poc_allowed:
        out.append(
            "Non-intrusive only: demonstrate impact without changing target state or "
            "exfiltrating real data — a minimal, safe proof is enough."
        )
    if roe.ineligible_vuln_types:
        out.append(
            "Do not submit known-ineligible issue types: "
            + ", ".join(roe.ineligible_vuln_types)
            + "."
        )
    if roe.pii_handling:
        out.append(f"PII handling: {roe.pii_handling}")
    out.append(
        "Every submitted finding needs a clear, reproducible proof and an impact "
        "statement, and must be checked against known/disclosed reports to avoid a "
        "duplicate."
    )
    return out


def evaluate_roe(
    program: BountyProgram,
    *,
    automated_policy: AutomatedPolicy = DEFAULT_AUTOMATED_POLICY,
) -> RoeGate:
    """Decide whether (and how) the automated engine may run against ``program``."""
    constraints = _base_constraints(program)
    roe = program.roe

    if roe.automated_testing_allowed is False:
        banner = (
            f"Program '{program.handle}' EXPLICITLY PROHIBITS automated testing / "
            "scanners. Running active tooling against it is outside the program's "
            "authorization: submissions may be rejected and the account banned."
        )
        if automated_policy == "refuse":
            return RoeGate(
                proceed=False,
                mode="refused",
                active_tools_allowed=False,
                warnings=[
                    banner,
                    "Refusing to start the automated engine (default safe policy). "
                    "Re-run with --bounty-automated-policy recon_only to map + plan "
                    "without active tools, or warn_and_proceed to override deliberately.",
                ],
                constraints=constraints,
            )
        if automated_policy == "recon_only":
            return RoeGate(
                proceed=True,
                mode="recon_only",
                active_tools_allowed=False,
                warnings=[banner, "Proceeding in recon-only mode: no active tools will be fired."],
                constraints=constraints,
            )
        # warn_and_proceed
        return RoeGate(
            proceed=True,
            mode="warn_and_proceed",
            active_tools_allowed=True,
            warnings=[
                banner,
                "Proceeding anyway because --bounty-automated-policy warn_and_proceed "
                "was set. This is your deliberate, authorized-by-you choice.",
            ],
            constraints=constraints,
        )

    warnings: list[str] = []
    if roe.automated_testing_allowed is None:
        warnings.append(
            f"Program '{program.handle}' does not state whether automated testing is "
            "allowed. Verify the policy before a noisy scan; defaulting to a careful, "
            "rate-aware run."
        )
    return RoeGate(
        proceed=True,
        mode="normal",
        active_tools_allowed=True,
        warnings=warnings,
        constraints=constraints,
    )
