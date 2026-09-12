"""Run-scoped threat models — mirrored to ``{state_dir}/threat_models.json``.

A threat model is the scan's shared answer to who the attacker is, where the
trust boundaries sit, and what counts as critical for the target. One agent
derives it and every other agent on the same run reads it back instead of
re-deriving trust boundaries from scratch.

It does not outlive the scan. The mirror lives in the run's own state directory
and exists only so a resumed scan keeps the baseline its earlier agents agreed
on; a new scan against the same host or checkout starts with no model and
derives its own. Agents do spell one target several ways within a run — the URL
they were handed, the page they happen to be testing, a checkout path — so a
model is keyed by a normalized target identity to keep them converging on one
document instead of each starting a fresh one.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import subprocess
import tempfile
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from agents import RunContextWrapper, function_tool

from strix.core.agents import AgentCoordinator


logger = logging.getLogger(__name__)


_MAX_MODEL_BYTES = 512 * 1024
_MIN_MODEL_CHARS = 400
_MIN_AMENDMENT_CHARS = 80
_MAX_AMENDMENTS = 40
_GIT_TIMEOUT_SECONDS = 10
_DEFAULT_PORTS = {"http": "80", "https": "443"}

_store_lock = threading.RLock()

# The whole store: target identity -> model. It holds exactly the models this
# scan derived, and is mirrored to the run's state directory for resume.
_MODELS: dict[str, dict[str, Any]] = {}
_store_path: Path | None = None

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
    """Collapse the spellings of one remote target onto a single key."""
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


def _target_identity(target: str) -> str:
    """Return the stable identity a model is stored under.

    A checkout is keyed on its remote, so the same repository checked out at
    two paths shares one model and a subdirectory resolves to the whole tree.
    Everything else — a host, a URL, an API base, a named scope — is keyed on
    its normalized form. Both routes run through the same normalization, so a
    checkout and the URL it was cloned from land on one key.
    """
    directory = _local_directory(target)
    if directory is None:
        return _normalize_remote_target(target).removesuffix(".git")
    remote = _git(directory, ["config", "--get", "remote.origin.url"])
    if remote:
        return _normalize_git_remote(remote)
    toplevel = _git(directory, ["rev-parse", "--show-toplevel"])
    return toplevel or str(directory)


def _snap_to_scan_target(raw: str, scan_targets: list[str]) -> str:
    """Pull a target onto the scan's own spelling of it.

    Agents name the same target differently — one passes the URL it was given,
    the next the page it happens to be testing, a third the checkout path. Left
    alone those become separate keys, every lookup misses, and each agent
    quietly derives its own model, which is the exact failure the shared model
    exists to prevent. So a target that is recognisably one of the scan's own
    targets is resolved to that target instead.
    """
    identity = _target_identity(raw)
    scoped = [(target, _target_identity(target)) for target in scan_targets]
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


def hydrate_threat_models_from_disk(state_dir: Path) -> None:
    """Point the store at this run's mirror and load whatever it already holds.

    A resumed scan is the same scan, so its agents have to keep the baseline
    the earlier ones agreed on. The mirror lives under the run directory, so a
    different scan never reads it.
    """
    global _store_path  # noqa: PLW0603
    _store_path = state_dir / "threat_models.json"
    with _store_lock:
        _MODELS.clear()
        if not _store_path.is_file():
            return
        try:
            data = json.loads(_store_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.exception(
                "threat_models.json at %s is unreadable; starting with no models",
                _store_path,
            )
            return
        if not isinstance(data, dict):
            return
        _MODELS.update(
            {
                identity: model
                for identity, model in data.items()
                if isinstance(identity, str) and isinstance(model, dict)
            }
        )
        logger.info("threat models hydrated from %s (%d)", _store_path, len(_MODELS))


def _persist_locked() -> None:
    """Mirror the store to disk. Callers must already hold ``_store_lock``.

    Serializing and renaming in one critical section keeps a writer holding an
    older serialization from winning the rename and dropping a concurrent
    agent's model or amendment.
    """
    path = _store_path
    if path is None:
        return
    try:
        payload = json.dumps(_MODELS, ensure_ascii=False, default=str)
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as tmp:
            tmp.write(payload)
            tmp_path = Path(tmp.name)
        tmp_path.replace(path)
    except OSError:
        logger.exception("threat model mirror to %s failed", path)


def _missing_sections(content: str) -> list[str]:
    lowered = content.lower()
    return [section for section in _REQUIRED_SECTIONS if section not in lowered]


def _amendments_of(model: dict[str, Any]) -> list[dict[str, Any]]:
    raw = model.get("amendments")
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, dict)]


def _not_found(identity: str) -> dict[str, Any]:
    return {
        "success": True,
        "found": False,
        "target": identity,
        "message": (
            "No threat model for this target on this scan. Nothing carries over "
            "from other scans, so derive one — from the code if you have it, from "
            "recon output if you do not — and share it with save_threat_model, so "
            "every agent on this scan works from one view of the trust boundaries "
            "instead of each inventing their own."
        ),
    }


def _get_impl(target: str, scan_targets: list[str] | None = None) -> dict[str, Any]:
    resolved, error = _resolve_target(target, scan_targets)
    if resolved is None:
        return {"success": False, "error": error}

    identity = _target_identity(resolved)
    with _store_lock:
        model = _MODELS.get(identity)
        if model is None:
            return _not_found(identity)
        content = model.get("content")
        amendments = list(_amendments_of(model))
    if not isinstance(content, str) or not content.strip():
        return _not_found(identity)

    result: dict[str, Any] = {
        "success": True,
        "found": True,
        "target": identity,
        "content": content,
    }
    if amendments:
        result["amendments"] = amendments
        result["amendments_note"] = (
            "Addenda recorded by agents after the base model was written. They "
            "correct or extend it and have not been folded in yet - read them as "
            "part of the model, and prefer the later one where they conflict."
        )
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

    identity = _target_identity(resolved)
    with _store_lock:
        existing = _MODELS.get(identity)
        folded = len(_amendments_of(existing)) if existing else 0
        _MODELS[identity] = {
            "target": identity,
            "written_at": datetime.now(UTC).isoformat(),
            "written_by": agent_name,
            "content": body,
        }
        _persist_locked()

    message = (
        "Threat model shared with this scan. Subagents should call get_threat_model "
        "before they start, and treat its trust boundaries as the shared baseline."
    )
    if folded:
        message += (
            f" This replaced a model carrying {folded} amendment(s), which are now "
            "cleared - make sure what they said survives in the text you just wrote."
        )
    return {
        "success": True,
        "target": identity,
        "amendments_cleared": folded,
        "message": message,
    }


def _append_amendment(
    identity: str, amendment: dict[str, Any]
) -> tuple[list[dict[str, Any]] | None, str | None]:
    """Add an amendment to the stored model. Returns (amendments, error)."""
    with _store_lock:
        model = _MODELS.get(identity)
        if model is None or not str(model.get("content", "")).strip():
            return None, (
                "No threat model exists for this target yet, so there is nothing to "
                "amend. Derive the base model and call save_threat_model instead."
            )
        amendments = _amendments_of(model)
        if len(amendments) >= _MAX_AMENDMENTS:
            return None, (
                f"This model already carries {len(amendments)} amendments. Fold them "
                "into the base model with save_threat_model before adding more."
            )
        candidate = [*amendments, amendment]
        sized = {**model, "amendments": candidate}
        if len(json.dumps(sized, ensure_ascii=False).encode("utf-8")) > _MAX_MODEL_BYTES:
            return None, "Threat model with this amendment exceeds 512KB; tighten it."
        model["amendments"] = candidate
        _persist_locked()
        return candidate, None


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

    identity = _target_identity(resolved)
    amendments, amend_error = _append_amendment(
        identity,
        {
            "at": datetime.now(UTC).isoformat(),
            "by": agent_name,
            "content": body,
        },
    )
    if amendments is None or amend_error:
        return {"success": False, "error": amend_error}

    return {
        "success": True,
        "target": identity,
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
    """Read this scan's threat model for a target, if an agent has derived one.

    The threat model is this run's shared answer to who the attacker
    is, where the trust boundaries sit, and what counts as critical
    here. Call it before you start hunting so you inherit the shared
    view instead of re-deriving it, and so every agent on this run
    agrees on what "attacker-controlled" means.

    It is scoped to this scan and nothing is carried over from an
    earlier run, so an empty result means no agent has derived one yet.

    Works black-box or white-box. The target can be a host, a URL, an
    API base, or a repository path; equivalent spellings of the same
    host resolve to the same model, and a checkout resolves to its
    remote, so a model derived white-box by one agent is read back by
    another testing the deployment.

    Returns ``found: false`` when nothing has been derived yet — derive
    one and share it with ``save_threat_model``.

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
    """Share a target-scoped threat model with the other agents on this scan.

    The model lives for this run only — it is not written to disk and a
    later scan of the same host or tree starts without it.

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

    **Scope it to the target, not to your slice of it.** Do not centre
    it on the diff you were handed, the subsystem you were assigned, or
    the one host that happened to answer first. With source, distinguish
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
