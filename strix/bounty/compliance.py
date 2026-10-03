"""Enforce a bug-bounty program's HTTP rules of engagement at the tool boundary.

Some programs require an identifying header on every request (e.g.
``X-Bug-Bounty: HackerOne-<username>``) and/or cap the request rate. The scope
engine says *where* a run may go; this says *how* its HTTP traffic must look. It is
enforced at the two chokepoints the engine owns:

* ``exec_command`` — a sandbox CLI (``curl``/``httpx``/``nuclei``/``ffuf``/…) that
  targets a host but omits a required header, or a high-volume fuzzer with no rate
  flag, is **refused** with the exact flag to add (wired in ``agents.factory``).
* the Caido ``repeat_request`` replay tool — the required headers are injected into
  every replayed request (also wired in ``agents.factory``).

Pure browser navigation is not forced here (it is recon, not active testing); the
agent is told in its briefing to set the header there too. Everything is a no-op
unless a bounty run bound required headers / a rate limit.
"""

from __future__ import annotations

import re

from strix.bounty.runtime import get_bounty_context


# HTTP request-making CLIs shipped in the sandbox.
_HTTP_TOOL_RE = re.compile(
    r"\b(curl|wget|httpx|nuclei|ffuf|sqlmap|nikto|wpscan|dirsearch|feroxbuster"
    r"|gobuster|wfuzz|katana|gospider|arjun)\b"
)
# Of those, the ones that fan out into many requests (so a rate cap applies).
_VOLUME_TOOLS = frozenset(
    {"httpx", "nuclei", "ffuf", "sqlmap", "nikto", "wpscan", "dirsearch",
     "feroxbuster", "gobuster", "wfuzz", "katana", "gospider", "arjun"}
)
_RATE_FLAG_RE = re.compile(r"(?:^|\s)(--?rl|--?rate(?:-limit)?|--?delay|--throttle)\b")
# Only enforce when the command actually names a target (skip `curl --help` etc.).
_TARGETED_RE = re.compile(
    r"://|\b\d{1,3}(?:\.\d{1,3}){3}\b|\b[a-z0-9-]+\.[a-z]{2,}\b", re.IGNORECASE
)


def _http_tool(command: str) -> str | None:
    m = _HTTP_TOOL_RE.search(command or "")
    return m.group(1) if m else None


def check_http_compliance(
    command: str,
    *,
    required_headers: dict[str, str],
    rate_limit_rps: float | None,
) -> str | None:
    """Return a refusal reason for a non-compliant HTTP command, or ``None``.

    Pure (no globals) so it is directly unit-testable.
    """
    if not (required_headers or rate_limit_rps):
        return None
    tool = _http_tool(command)
    if tool is None or not _TARGETED_RE.search(command):
        return None

    low = command.lower()
    for name, value in required_headers.items():
        if name.lower() not in low:
            return (
                f"this program requires the identifying header '{name}: {value}' on "
                f"all requests, and this {tool} command omits it. Add it "
                f"(curl/httpx/nuclei/ffuf: -H '{name}: {value}'; wget: "
                f"--header='{name}: {value}')."
            )

    if rate_limit_rps is not None and tool in _VOLUME_TOOLS and not _RATE_FLAG_RE.search(command):
        r = int(rate_limit_rps) if float(rate_limit_rps).is_integer() else rate_limit_rps
        return (
            f"this program caps requests at <= {r}/s and this {tool} command has no "
            f"rate flag. Add one (nuclei -rl {r}, ffuf -rate {r}, httpx -rl {r}, "
            f"feroxbuster --rate-limit {r}, dirsearch/sqlmap --delay)."
        )
    return None


def _active_roe() -> tuple[dict[str, str], float | None]:
    ctx = get_bounty_context()
    if ctx is None:
        return {}, None
    roe = ctx.program.roe
    return dict(roe.required_headers), roe.rate_limit_rps


def enforce_bounty_http(command: str) -> str | None:
    """Check a sandbox shell command against the active bounty HTTP ROE.

    Returns a refusal reason, or ``None`` when there is no bounty run or the command
    complies.
    """
    headers, rate = _active_roe()
    return check_http_compliance(command, required_headers=headers, rate_limit_rps=rate)


def required_headers_for_run() -> dict[str, str]:
    """The headers the active bounty run requires on every request ({} if none)."""
    return _active_roe()[0]
