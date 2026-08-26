"""Target-scoped threat models — cached under ``~/.strix/threat-models``.

A threat model describes the target, not the scan: a host, an application, an
API, a repository, or whatever else the engagement is pointed at. It stays
valid across unrelated runs against the same target, so it is keyed by target
identity rather than by run id — one agent derives it, every later agent in
this run and in future runs against the same target reads it back instead of
re-deriving trust boundaries from scratch.

Where the target is a checkout, the model is additionally pinned to the git
revision, so a moved ``HEAD`` marks it stale. Black-box targets have no
revision to pin to; those age out instead.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import subprocess
import tempfile
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from agents import RunContextWrapper, function_tool

from strix.core.agents import AgentCoordinator


logger = logging.getLogger(__name__)


_CACHE_DIR = Path.home() / ".strix" / "threat-models"
_MAX_MODEL_BYTES = 512 * 1024
_MIN_MODEL_CHARS = 400
_MIN_AMENDMENT_CHARS = 80
_MAX_AMENDMENTS = 40
_GIT_TIMEOUT_SECONDS = 10
_UNVERSIONED = "unversioned"
_MAX_AGE_DAYS = 14
_DEFAULT_PORTS = {"http": "80", "https": "443"}
_cache_lock = threading.RLock()

_REQUIRED_SECTIONS = (
    "overview",
    "trust boundaries",
    "attack surface",
    "severity calibration",
)


def _git(repo: Path, args: list[str]) -> str | None:
    try:
        result = subprocess.run(  # noqa: S603
            ["git", "-C", str(repo), *args],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
            timeout=_GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        logger.debug("git %s failed in %s", args, repo, exc_info=True)
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def _local_directory(target: str) -> Path | None:
    """Return the target as a local directory, or None if it is not one."""
    if "://" in target:
        return None
    try:
        resolved = Path(target).expanduser().resolve()
    except OSError:
        return None
    return resolved if resolved.is_dir() else None


def _remote_authority(target: str) -> str:
    """The ``host[:port]`` a remote target lives on, or "" if it has none."""
    candidate = target if "://" in target else f"//{target}"
    parts = urlsplit(candidate)
    host = (parts.hostname or "").lower()
    if not host:
        return ""
    scheme = (parts.scheme or "https").lower()
    port = str(parts.port) if parts.port else _DEFAULT_PORTS.get(scheme, "")
    return f"{host}:{port}" if port else host


def _normalize_remote_target(target: str) -> str:
    """Collapse the spellings of one remote target onto a single cache key."""
    authority = _remote_authority(target)
    if not authority:
        return re.sub(r"\s+", " ", target.lower()).strip()
    candidate = target if "://" in target else f"//{target}"
    path = urlsplit(candidate).path.rstrip("/")
    return f"{authority}{path}"


def _normalize_git_remote(remote: str) -> str:
    """Collapse a git remote URL onto the same key its clone URL would produce.

    A remote reaches us in whichever spelling the clone used —
    ``git@github.com:org/repo.git``, ``https://github.com/org/repo``,
    ``ssh://git@github.com/org/repo.git`` — and each is the same repository.
    Rewriting scp-style syntax into a URL and dropping the ``.git`` suffix and
    any embedded credentials lets :func:`_normalize_remote_target` produce one
    identity for all of them, and crucially the *same* identity a caller gets
    when it names the repository by its remote URL rather than by a checkout
    path. Without that, the model saved by an agent working in the checkout is
    invisible to an agent that asks for the repository by URL, and the two
    derive conflicting models of one target.
    """
    candidate = remote.strip()
    scp_style = re.match(r"^(?:[^@/]+@)?(?P<host>[^:/]+):(?P<path>.+)$", candidate)
    if scp_style and "://" not in candidate:
        candidate = f"https://{scp_style['host']}/{scp_style['path'].lstrip('/')}"
    elif "://" in candidate:
        # The transport a clone happened to use says nothing about which
        # repository this is, and each scheme carries a different default
        # port into the authority. Collapsing them all onto https keeps one
        # repository on one key however it was cloned.
        candidate = f"https://{candidate.split('://', 1)[1]}"
    normalized = _normalize_remote_target(candidate)
    return normalized.removesuffix(".git")


def _target_identity(target: str) -> tuple[str, str]:
    """Return the (stable identity, revision) pair a cached model is keyed on.

    A checkout is keyed on its remote (so the same repository cloned to two
    paths shares one model, and a subdirectory resolves to the whole tree) and
    pinned to ``HEAD``. Everything else — a host, a URL, an API base, a named
    scope — is keyed on its normalized form and carries no revision. Both
    routes run through the same normalization, so a checkout and the URL it
    was cloned from land on one key.
    """
    directory = _local_directory(target)
    if directory is None:
        return _normalize_remote_target(target).removesuffix(".git"), _UNVERSIONED
    remote = _git(directory, ["config", "--get", "remote.origin.url"])
    revision = _git(directory, ["rev-parse", "HEAD"]) or _UNVERSIONED
    if remote:
        return _normalize_git_remote(remote), revision
    toplevel = _git(directory, ["rev-parse", "--show-toplevel"])
    return toplevel or str(directory), revision


def _cache_path(identity: str) -> Path:
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    return _CACHE_DIR / f"{digest}.json"


def _snap_to_scan_target(raw: str, scan_targets: list[str]) -> str:
    """Pull a target onto the scan's own spelling of it.

    Agents name the same target differently — one passes the URL it was given,
    the next the page it happens to be testing, a third the checkout path. Left
    alone those become separate cache keys, every lookup misses, and each agent
    quietly derives its own model, which is the exact failure the shared model
    exists to prevent. So a target that is recognisably one of the scan's own
    targets is resolved to that target instead.
    """
    identity, _ = _target_identity(raw)
    scoped = [(target, _target_identity(target)[0]) for target in scan_targets]
    if any(known == identity for _, known in scoped):
        return raw

    authority = _remote_authority(raw)
    if authority:
        hosted = [target for target, _ in scoped if _remote_authority(target) == authority]
        # Two scan targets on one host are distinguished only by their paths,
        # so snapping to "the host" would merge two distinct models into one.
        return hosted[0] if len(hosted) == 1 else raw

    directory = _local_directory(raw)
    if directory is not None:
        enclosing = [
            target
            for target, known in scoped
            if known == identity or _local_directory(target) == directory
        ]
        if enclosing:
            return enclosing[0]
    return raw


def _resolve_target(
    target: str, scan_targets: list[str] | None = None
) -> tuple[str | None, str | None]:
    raw = (target or "").strip()
    known = [t for t in (scan_targets or []) if t.strip()]
    if not raw:
        if len(known) == 1:
            return known[0], None
        return None, (
            "target cannot be empty - pass the host, URL, application, or "
            "repository path this model describes"
            + (f". This scan is scoped to: {', '.join(known)}" if known else "")
        )
    return (_snap_to_scan_target(raw, known) if known else raw), None


def _is_expired(created_at: str | None) -> bool:
    if not created_at:
        return True
    try:
        created = datetime.fromisoformat(created_at)
    except ValueError:
        return True
    if created.tzinfo is None:
        created = created.replace(tzinfo=UTC)
    return datetime.now(UTC) - created > timedelta(days=_MAX_AGE_DAYS)


def _missing_sections(content: str) -> list[str]:
    lowered = content.lower()
    return [section for section in _REQUIRED_SECTIONS if section not in lowered]


def _read_cache(path: Path) -> dict[str, Any] | None:
    """Load a cached model. Callers must already hold ``_cache_lock``."""
    if not path.is_file():
        return None
    try:
        cached = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        logger.exception("threat model cache at %s is unreadable", path)
        return None
    return cached if isinstance(cached, dict) else None


def _write_cache(path: Path, payload: dict[str, Any]) -> str | None:
    """Atomically persist a model. Callers must already hold ``_cache_lock``."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as tmp:
            tmp.write(json.dumps(payload, ensure_ascii=False))
            tmp_path = Path(tmp.name)
        tmp_path.replace(path)
    except OSError as exc:
        logger.exception("threat model persist to %s failed", path)
        return f"Failed to persist threat model: {exc}"
    return None


def _amendments_of(cached: dict[str, Any]) -> list[dict[str, Any]]:
    raw = cached.get("amendments")
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, dict)]


def _not_found(identity: str, revision: str) -> dict[str, Any]:
    return {
        "success": True,
        "found": False,
        "target": identity,
        "revision": revision,
        "message": (
            "No threat model cached for this target. Derive one — from the code if "
            "you have it, from recon output if you do not — and persist it with "
            "save_threat_model, so every agent on this scan shares one view of the "
            "trust boundaries instead of each inventing their own."
        ),
    }


def _staleness(cached: dict[str, Any], revision: str) -> tuple[bool, str | None]:
    """Decide whether a cached model can still be trusted, and why not."""
    if revision != _UNVERSIONED:
        if cached.get("revision") == revision:
            return False, None
        return True, (
            "This model was derived against a different revision. Use it as a "
            "starting point, re-check the boundaries it names against the current "
            "tree, and save the corrected version."
        )
    created_at = cached.get("created_at")
    if not _is_expired(created_at if isinstance(created_at, str) else None):
        return False, None
    return True, (
        f"This model is more than {_MAX_AGE_DAYS} days old and there is no revision "
        "to pin it to, so the target may have moved under it. Treat its surface "
        "inventory as a lead list to re-confirm during recon, not as fact, and save "
        "the corrected version."
    )


def _get_impl(target: str, scan_targets: list[str] | None = None) -> dict[str, Any]:
    resolved, error = _resolve_target(target, scan_targets)
    if resolved is None:
        return {"success": False, "error": error}

    identity, revision = _target_identity(resolved)
    path = _cache_path(identity)
    with _cache_lock:
        cached = _read_cache(path)
    if cached is None:
        return _not_found(identity, revision)
    content = cached.get("content")
    if not isinstance(content, str) or not content.strip():
        return _not_found(identity, revision)

    stale, stale_message = _staleness(cached, revision)
    result: dict[str, Any] = {
        "success": True,
        "found": True,
        "target": identity,
        "revision": revision,
        "cached_revision": cached.get("revision"),
        "created_at": cached.get("created_at"),
        "stale": stale,
        "content": content,
    }
    amendments = _amendments_of(cached)
    if amendments:
        result["amendments"] = amendments
        result["amendments_note"] = (
            "Addenda recorded by agents after the base model was written. They "
            "correct or extend it and have not been folded in yet - read them as "
            "part of the model, and prefer the later one where they conflict."
        )
    if stale_message:
        result["message"] = stale_message
    return result


def _save_impl(
    target: str,
    content: str,
    agent_name: str | None,
    scan_targets: list[str] | None = None,
) -> dict[str, Any]:
    resolved, error = _resolve_target(target, scan_targets)
    if resolved is None:
        return {"success": False, "error": error}

    body = (content or "").strip()
    if len(body) < _MIN_MODEL_CHARS:
        return {
            "success": False,
            "error": (
                f"Threat model is too thin ({len(body)} chars). It has to be usable by "
                "an agent seeing this target for the first time: what it is, who the "
                "actors are, where the trust boundaries sit, which inputs are "
                "attacker-controlled, and what a critical bug looks like here."
            ),
        }
    if len(body.encode("utf-8")) > _MAX_MODEL_BYTES:
        return {"success": False, "error": "Threat model exceeds 512KB; tighten it."}

    missing = _missing_sections(body)
    if missing:
        return {
            "success": False,
            "error": (
                "Threat model is missing required section(s): "
                f"{', '.join(missing)}. Cover Overview, Trust Boundaries and "
                "Assumptions, Attack Surface and Attacker Stories, and Severity "
                "Calibration."
            ),
        }

    identity, revision = _target_identity(resolved)
    path = _cache_path(identity)
    payload: dict[str, Any] = {
        "target": identity,
        "revision": revision,
        "created_at": datetime.now(UTC).isoformat(),
        "created_by": agent_name,
        "content": body,
    }
    with _cache_lock:
        existing = _read_cache(path)
        folded = len(_amendments_of(existing)) if existing else 0
        error = _write_cache(path, payload)
    if error:
        return {"success": False, "error": error}

    message = (
        "Threat model saved. Subagents should call get_threat_model before they "
        "start, and treat its trust boundaries as the shared baseline."
    )
    if folded:
        message += (
            f" This replaced a model carrying {folded} amendment(s), which are now "
            "cleared - make sure what they said survives in the text you just wrote."
        )
    return {
        "success": True,
        "target": identity,
        "revision": revision,
        "amendments_cleared": folded,
        "message": message,
    }


def _append_amendment(
    path: Path, amendment: dict[str, Any]
) -> tuple[list[dict[str, Any]] | None, str | None]:
    """Add an amendment to the cached model. Returns (amendments, error)."""
    with _cache_lock:
        cached = _read_cache(path)
        if cached is None or not str(cached.get("content", "")).strip():
            return None, (
                "No threat model exists for this target yet, so there is nothing to "
                "amend. Derive the base model and call save_threat_model instead."
            )
        amendments = _amendments_of(cached)
        if len(amendments) >= _MAX_AMENDMENTS:
            return None, (
                f"This model already carries {len(amendments)} amendments. Fold them "
                "into the base model with save_threat_model before adding more."
            )
        amendments.append(amendment)
        cached["amendments"] = amendments
        if len(json.dumps(cached, ensure_ascii=False).encode("utf-8")) > _MAX_MODEL_BYTES:
            return None, "Threat model with this amendment exceeds 512KB; tighten it."
        return amendments, _write_cache(path, cached)


def _amend_impl(
    target: str,
    addendum: str,
    agent_name: str | None,
    scan_targets: list[str] | None = None,
) -> dict[str, Any]:
    resolved, error = _resolve_target(target, scan_targets)
    if resolved is None:
        return {"success": False, "error": error}

    body = (addendum or "").strip()
    if len(body) < _MIN_AMENDMENT_CHARS:
        return {
            "success": False,
            "error": (
                f"Amendment is too thin ({len(body)} chars). Say what the base model "
                "got wrong or left out, and name the endpoint, host, file, or control "
                "that makes your correction true."
            ),
        }

    identity, revision = _target_identity(resolved)
    amendments, amend_error = _append_amendment(
        _cache_path(identity),
        {
            "at": datetime.now(UTC).isoformat(),
            "by": agent_name,
            "revision": revision,
            "content": body,
        },
    )
    if amendments is None or amend_error:
        return {"success": False, "error": amend_error}

    return {
        "success": True,
        "target": identity,
        "revision": revision,
        "amendment_count": len(amendments),
        "message": (
            "Amendment recorded. Agents calling get_threat_model will now see it "
            "alongside the base model."
        ),
    }


def _caller_agent_name(ctx: RunContextWrapper) -> str | None:
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    agent_id = inner.get("agent_id")
    coordinator = inner.get("coordinator")
    if not isinstance(agent_id, str) or not isinstance(coordinator, AgentCoordinator):
        return None
    return coordinator.names.get(agent_id)


def _scan_targets(ctx: RunContextWrapper) -> list[str]:
    """The targets this scan was authorized against, as the runner spelled them."""
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    targets = inner.get("scan_targets")
    if not isinstance(targets, list):
        return []
    return [target for target in targets if isinstance(target, str) and target.strip()]


@function_tool(timeout=30)
async def get_threat_model(ctx: RunContextWrapper, target: str) -> str:
    """Read the cached threat model for a target, if one exists.

    A threat model belongs to the target, not to this scan — the same
    trust boundaries hold across unrelated runs against the same host
    or application. Call this before you start hunting so you inherit
    the shared view instead of re-deriving it, and so every agent on
    this run agrees on what "attacker-controlled" means here.

    Works black-box or white-box. The target can be a host, a URL, an
    API base, or a repository path; equivalent spellings of the same
    host resolve to the same model, and a checkout resolves to its
    remote, so a model derived white-box is read back by a black-box
    agent testing the deployment.

    Returns ``found: false`` when nothing is cached — derive one and
    persist it with ``save_threat_model``. ``stale: true`` means the
    checkout moved to a different revision, or that a model with no
    revision to pin to has aged out: use it as a starting point,
    re-confirm what it claims, and save the corrected version.

    Any ``amendments`` in the response are corrections other agents
    recorded after the base model was written. They are part of the
    model — read them, and prefer the later statement where one
    contradicts the base text.

    Args:
        target: What the model describes — a host or URL
            (``https://app.example.com``), or a repository path
            (``/workspace/myrepo``). Use the same value the scan was
            pointed at, so agents converge on one model.
    """
    return json.dumps(
        await asyncio.to_thread(_get_impl, target, _scan_targets(ctx)),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def save_threat_model(ctx: RunContextWrapper, target: str, content: str) -> str:
    """Persist a target-scoped threat model for reuse by other agents.

    Keyed by target identity, so a later scan of the same host or tree
    reads it back instead of paying to derive it again.

    **This replaces the whole document, and clears any amendments** —
    it is for the agent establishing the baseline (normally root,
    before subagents start), or for folding accumulated amendments back
    into the body. If a model already exists and you only need to
    correct or extend part of it, call ``amend_threat_model`` instead;
    saving over it will silently discard whatever other agents added.

    **Write it from whatever evidence you have.** With source, ground
    it in the code and name the files, entrypoints, and controls that
    make each claim true. Black-box, ground it in recon: the hosts and
    ports that answered, the technology fingerprints, the observed
    roles and tenants, the authentication and session model, the
    endpoints and parameters you enumerated. A black-box model is
    necessarily provisional — say which parts are inferred rather than
    observed, and let later agents amend it as the picture fills in.

    **Scope it to the target, not to this scan.** Do not centre it on
    the diff you were handed, the subsystem you were assigned, or the
    one host that happened to answer first. With source, distinguish
    real product and runtime surfaces from test, docs, example, and
    developer-tooling paths — in a monorepo, do not let ``tests/`` or
    one-off scripts become the centre of gravity unless the code shows
    they are genuinely deployed. Where the target documents its own
    boundary — an ``AGENTS`` file, a specific ``SECURITY.md``, a
    published API spec, an engagement scope — build on it rather than
    inventing a competing story.

    Structure the content in Markdown with these sections:

    - **Overview** — what the target actually is, its real-world usage,
      and which parts are product/runtime versus tooling or
      non-production.
    - **Trust Boundaries and Assumptions** — the boundaries, the actors
      on either side, and the invariants that must hold. Separate
      attacker-controlled, operator-controlled, and
      developer-controlled inputs explicitly. Black-box, this is the
      role, tenant, and privilege model: who can reach what before
      authenticating, as a low-privilege user, and across tenants.
    - **Attack Surface and Attacker Stories** — the exposed surfaces
      (hosts, endpoints, parameters, integrations, or the code-level
      entrypoints and sinks), the mitigations already present that
      materially change severity or reach, realistic attacker stories,
      and the stories that are *not* realistic here and why.
    - **Severity Calibration** — what critical / high / medium / low
      look like for *this* target, with a concrete example at each
      level. Where a vulnerability class needs attacker control that
      does not exist in real usage, say so here.

    Args:
        target: What the model describes — a host or URL
            (``https://app.example.com``), or a repository path
            (``/workspace/myrepo``). Use the same value the scan was
            pointed at.
        content: The full threat model in Markdown.
    """
    return json.dumps(
        await asyncio.to_thread(
            _save_impl, target, content, _caller_agent_name(ctx), _scan_targets(ctx)
        ),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def amend_threat_model(ctx: RunContextWrapper, target: str, addendum: str) -> str:
    """Correct or extend the existing threat model without replacing it.

    The baseline is written before anyone starts hunting, so it is
    written with the least information anyone will ever have. That is
    doubly true black-box, where the model starts as inference over
    recon output and only becomes real as agents authenticate, map
    roles, and reach the surfaces behind them. When your work
    contradicts the model or fills in something it missed, record that
    here — every agent that calls ``get_threat_model`` afterwards sees
    your addendum next to the base model.

    Amendments are append-only and attributed, so two agents amending
    at once both survive. That is the difference from
    ``save_threat_model``, which overwrites the document and drops
    every amendment on it.

    Worth amending:

    - A boundary the model calls trusted that you found is
      attacker-reachable, or vice versa.
    - A host, endpoint, parameter, role, sink, or shared control the
      model does not mention.
    - Something the model only inferred that you have now observed — or
      that turned out not to be true.
    - A severity call the model got wrong for this target, with the
      reason.
    - An assumption you disproved — the model says input is validated
      upstream and you found the path that skips it.

    Not worth amending: individual findings (those are reports), or
    restating what the model already says.

    Args:
        target: What the model describes — the same host, URL, or
            repository path used to save it.
        addendum: The correction, in Markdown. State what the base
            model says, what is actually true, and the endpoint, host,
            file, or control that proves it.
    """
    return json.dumps(
        await asyncio.to_thread(
            _amend_impl, target, addendum, _caller_agent_name(ctx), _scan_targets(ctx)
        ),
        ensure_ascii=False,
        default=str,
    )
