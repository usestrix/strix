"""Compatibility boundary between Strix and the ``openai-agents`` SDK.

Strix's sandbox runtime and agent tooling are built directly on the ``agents``
package (PyPI: ``openai-agents``), pinned in ``pyproject.toml`` as
``openai-agents[litellm]>=0.19.0,<0.20``. Most of that surface is the SDK's
documented public API (``agents.sandbox.entries``, ``agents.sandbox.manifest``,
``agents.sandbox.capabilities.Filesystem``/``Shell``, ``agents.tool.*``, etc.),
but a few pieces of Strix code reach past the public API into internal or
undocumented shapes of the SDK's sandbox implementation. Those places do not
fail loudly if the SDK changes them — they silently misbehave (wrong
container capabilities, broken entrypoint handling, or a crash deep in a
scan) instead. This module exists to make an incompatible SDK version fail
immediately and clearly at startup, and to give a future maintainer a single
place to check before bumping the SDK version.

Run ``assert_compatible_sdk_version()`` early — it is wired into
``strix.interface.main.main()`` — so an unsupported ``agents`` version is
reported before a scan starts, not mid-scan.

Concrete internals depended on beyond the SDK's public API
============================================================

``strix/runtime/docker_client.py`` (``StrixDockerSandboxClient``):

- ``agents.sandbox.sandboxes.docker.DockerSandboxClient._create_container``
  — Strix's ``_create_container`` is a **verbatim copy of the SDK method
  body** (see the "BEGIN/END VERBATIM COPY" markers in that file), not a
  call to the parent implementation, because the SDK gives no hook to extend
  ``create_kwargs`` before ``containers.create(**create_kwargs)`` runs.
  Strix's copy assumes the SDK still funnels container creation through this
  single private method with this exact body shape (image pull, manifest
  volume mounts, FUSE/SYS_ADMIN handling, exposed-port mapping). If the SDK
  restructures ``_create_container`` — renames it, splits it, changes the
  order/meaning of its steps, or changes what ``create_kwargs`` accepts —
  Strix's copy silently drifts out of sync with upstream behavior instead of
  raising an error.
- Private helper functions imported directly from
  ``agents.sandbox.sandboxes.docker``: ``_build_docker_volume_mounts``,
  ``_docker_port_key``, ``_manifest_requires_fuse``,
  ``_manifest_requires_sys_admin``. All four are underscore-prefixed
  (unstable, non-public) module functions that Strix's verbatim copy of
  ``_create_container`` calls to reproduce the SDK's own logic.
- ``session._inner`` and ``session._inner.state.container_id`` — the public
  ``SandboxSession`` wraps a private ``_inner`` implementation object; Strix
  reaches through it (in ``create()`` to swap the inner session's class for
  ``StrixDockerSandboxSession``, and in ``delete()`` to read the container id
  for a best-effort ``docker kill``).
- ``DockerSandboxSession`` is subclassed (``StrixDockerSandboxSession``) to
  override ``_resolve_exposed_port``, a private method, so that host-gateway
  network resolution can look up the container's IP on a custom Docker
  network (``STRIX_DOCKER_SANDBOX_NETWORK``).
- The module docstring in ``docker_client.py`` itself already flags this and
  historically named a specific pinned SDK patch version to re-merge against
  on every SDK bump — keep that pin annotation current whenever
  ``SUPPORTED_AGENTS_SDK_RANGE`` below changes.

``strix/agents/factory.py``:

- ``agents.sandbox.SandboxAgent``, ``agents.sandbox.capabilities.Filesystem``,
  ``agents.sandbox.capabilities.Shell`` — these are public, but the shell
  execution (``exec_command``, ``write_stdin``), patch application
  (``apply_patch``), and filesystem tools Strix's agents use are **not
  Strix's own tool implementations**. They are the SDK's ``Shell`` and
  ``Filesystem`` sandbox capability classes' built-in tool sets, wired up
  via each capability's ``configure_tools`` hook
  (``_configure_shell_tools`` / ``_configure_filesystem_tools``). Strix
  inspects each toolset with ``vars(toolset)`` (an implementation detail of
  how the SDK stores its generated tools as attributes) and pattern-matches
  on tool names (``"exec_command"``, ``"write_stdin"``) and error types
  (``InvalidManifestPathError``) that are not part of a documented, versioned
  tool-name contract.
- ``agents.tool.CustomTool`` / ``agents.tool.FunctionTool`` — Strix reaches
  into instance attributes (``tool.on_invoke_tool``, ``tool.strict_json_schema``,
  ``tool.params_json_schema``) and monkeypatches ``on_invoke_tool`` in place
  to add result-bounding, argument coercion, and error-as-result behavior.
  These are public dataclass-like fields today, but there is no documented
  guarantee the SDK keeps this exact shape across versions.
- ``agents.agent.ToolsToFinalOutputResult`` is used to implement a custom
  ``tool_use_behavior``; this is public API but its exact semantics
  (when the SDK calls it, what fields matter) are tied to the SDK's run loop
  internals.

``strix/runtime/session_manager.py`` and ``strix/runtime/backends.py`` mostly
use the SDK's documented public API (``agents.sandbox.entries.{BaseEntry,
File, LocalDir}``, ``agents.sandbox.manifest.{Environment, Manifest}``,
``DockerSandboxClientOptions``, ``session.resolve_exposed_port()``,
``session.start()``). The one soft dependency is ``getattr(client,
"docker_client", None)`` in ``session_manager.cleanup()`` — a defensive,
non-raising reach for a low-level client attribute so the underlying
``docker`` SDK client gets closed; it degrades gracefully (no-op) if the
attribute disappears.

What to do when bumping the SDK version
========================================

1. Update ``SUPPORTED_AGENTS_SDK_RANGE`` below and the matching constraint in
   ``pyproject.toml`` together.
2. Re-read ``agents/sandbox/sandboxes/docker.py`` in the new SDK version and
   diff it against the verbatim copy in ``docker_client.py``'s
   ``_create_container`` — re-merge any upstream changes into the Strix
   deltas.
3. Re-check that ``_build_docker_volume_mounts``, ``_docker_port_key``,
   ``_manifest_requires_fuse``, and ``_manifest_requires_sys_admin`` still
   exist with the same signatures.
4. Re-check that ``session._inner`` and ``session._inner.state.container_id``
   still resolve the way ``docker_client.py`` expects.
5. Re-check that the ``Shell``/``Filesystem`` capabilities' generated
   toolsets still expose tools named ``exec_command`` / ``write_stdin`` /
   ``apply_patch`` with the same argument shapes that
   ``strix/agents/factory.py`` special-cases.
6. Run the full test suite, especially ``tests/test_docker_client_delete.py``,
   ``tests/test_agent_factory_shell.py``, and this module's tests.

See also ``docs/adr/0001-openai-agents-sdk-coupling.md`` for the
architectural rationale and longer-term direction.
"""

from __future__ import annotations

from importlib import metadata as importlib_metadata

import agents


_DISTRIBUTION_NAME = "openai-agents"

#: Matches the ``openai-agents[litellm]>=0.19.0,<0.20`` constraint in
#: ``pyproject.toml``. Keep these in sync — this tuple is the single source of
#: truth this module checks against, and the docstring above lists exactly
#: what needs re-verifying whenever this range moves.
SUPPORTED_AGENTS_SDK_RANGE = (">=0.19.0", "<0.20")


def _parse_version(version: str) -> tuple[int, ...]:
    """Parse a dotted numeric version prefix into a comparable tuple.

    Only the release segment (leading dotted integers) is used, e.g.
    ``"0.19.0"`` -> ``(0, 19, 0)`` and ``"0.19.0.dev1"`` -> ``(0, 19, 0)``.
    This is intentionally simple (no pre-release ordering) since it only
    needs to place a version inside or outside a narrow numeric range.
    """
    parts: list[int] = []
    for chunk in version.split("."):
        digits = ""
        for char in chunk:
            if char.isdigit():
                digits += char
            else:
                break
        if not digits:
            break
        parts.append(int(digits))
    if not parts:
        msg = f"Could not parse a numeric version from {version!r}"
        raise ValueError(msg)
    return tuple(parts)


def _pad(version: tuple[int, ...], length: int) -> tuple[int, ...]:
    return version + (0,) * (length - len(version))


def _compare(installed: tuple[int, ...], bound: tuple[int, ...]) -> int:
    length = max(len(installed), len(bound))
    left = _pad(installed, length)
    right = _pad(bound, length)
    if left < right:
        return -1
    if left > right:
        return 1
    return 0


def _satisfies(installed: str, specifiers: tuple[str, ...]) -> bool:
    installed_version = _parse_version(installed)
    for spec in specifiers:
        for op in (">=", "<=", "==", "!=", ">", "<"):
            if spec.startswith(op):
                bound = _parse_version(spec[len(op) :])
                cmp = _compare(installed_version, bound)
                ok = {
                    ">=": cmp >= 0,
                    "<=": cmp <= 0,
                    "==": cmp == 0,
                    "!=": cmp != 0,
                    ">": cmp > 0,
                    "<": cmp < 0,
                }[op]
                if not ok:
                    return False
                break
        else:  # pragma: no cover - defensive; every spec above starts with an op
            msg = f"Unrecognized version specifier: {spec!r}"
            raise ValueError(msg)
    return True


def installed_agents_sdk_version() -> str:
    """Return the installed ``openai-agents`` distribution version.

    Prefers ``agents.__version__`` (what the package itself exposes) and
    falls back to ``importlib.metadata`` (the distribution name differs from
    the import name: ``openai-agents`` ships the ``agents`` module).
    """
    version = getattr(agents, "__version__", None)
    if isinstance(version, str) and version:
        return version
    return importlib_metadata.version(_DISTRIBUTION_NAME)


def assert_compatible_sdk_version() -> None:
    """Raise ``RuntimeError`` if the installed ``agents`` SDK is unsupported.

    Strix's sandbox runtime (``strix/runtime/docker_client.py``) and agent
    tool wiring (``strix/agents/factory.py``) depend on internal shapes of
    the ``openai-agents`` SDK that are not guaranteed stable across versions
    (see this module's docstring for the concrete list). Call this once,
    early at startup — before any sandbox or agent code runs — so an
    incompatible SDK version is reported immediately with a clear,
    actionable message instead of failing unpredictably mid-scan.
    """
    installed = installed_agents_sdk_version()
    try:
        compatible = _satisfies(installed, SUPPORTED_AGENTS_SDK_RANGE)
    except ValueError as exc:
        msg = (
            f"Could not verify openai-agents SDK compatibility: installed version "
            f"{installed!r} could not be parsed ({exc}). Strix requires "
            f"openai-agents {', '.join(SUPPORTED_AGENTS_SDK_RANGE)}. "
            "See strix/runtime/sdk_compat.py for details."
        )
        raise RuntimeError(msg) from exc

    if not compatible:
        msg = (
            f"Incompatible openai-agents SDK version: installed {installed!r}, "
            f"but Strix requires {', '.join(SUPPORTED_AGENTS_SDK_RANGE)}. "
            "Strix's sandbox runtime (strix/runtime/docker_client.py) and agent "
            "tool wiring (strix/agents/factory.py) depend on internal shapes of "
            "this SDK that change across versions. Install a supported version "
            '(e.g. `uv pip install "openai-agents[litellm]>=0.19.0,<0.20"`) or, '
            "if you are intentionally bumping the SDK, update "
            "SUPPORTED_AGENTS_SDK_RANGE in strix/runtime/sdk_compat.py after "
            "re-verifying the checklist documented in that file's module "
            "docstring."
        )
        raise RuntimeError(msg)
