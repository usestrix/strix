"""Emit the MCP connection configs that point Strix at the Strix 2 wrapper servers.

Strix connects to the MCP servers listed in ``~/.strix/mcp-servers.json`` (or a file
named by ``--mcp-config`` / ``$STRIX_MCP_CONFIG``). This module builds the
:class:`~strix.tools.mcp.config.McpConnectionConfig` entries for the host-side
wrappers so an operator (or a future auto-wire hook) can register them without
hand-writing JSON, each launched as ``<python> -m strix.mcp_servers.<name>`` with a
tight ``allowed_tools`` allowlist.

Scope config is passed through to the subprocess so the wrapper enforces the same
authorized scope as the parent run: ``STRIX_SCOPE_CONFIG`` and
``STRIX_ALLOW_INTRUSIVE`` are forwarded from the current environment when set. The
subprocess otherwise inherits AWS credential resolution from the host environment
and shared config.
"""

from __future__ import annotations

import os
import sys

from strix.mcp_servers import aws
from strix.scope.enforcement import get_active_policy
from strix.tools.mcp.config import McpConnectionConfig


# Environment variables forwarded from the parent into every wrapper subprocess so
# it resolves and enforces the same authorized scope. Credentials are NOT listed
# here: boto3 picks those up from the inherited host environment / shared config.
_SCOPE_ENV_PASSTHROUGH = ("STRIX_SCOPE_CONFIG", "STRIX_ALLOW_INTRUSIVE")

# Set to a falsey value to stop Strix auto-attaching the built-in wrappers to a run.
_AUTO_WRAPPERS_ENV = "STRIX2_AUTO_WRAPPERS"


def _passthrough_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {key: os.environ[key] for key in _SCOPE_ENV_PASSTHROUGH if os.environ.get(key)}
    if extra:
        env.update(extra)
    return env


def aws_wrapper_config(
    *,
    python_executable: str | None = None,
    region: str | None = None,
    extra_env: dict[str, str] | None = None,
) -> McpConnectionConfig:
    """Build the connection config for the read-only AWS wrapper.

    Args:
        python_executable: Interpreter to launch the server with; defaults to the
            current one so the subprocess shares this venv (and thus boto3 + strix).
        region: Optional default AWS region, forwarded as ``AWS_DEFAULT_REGION``.
        extra_env: Extra environment variables for the subprocess.
    """
    env = _passthrough_env(extra_env)
    if region:
        env.setdefault("AWS_DEFAULT_REGION", region)
    return McpConnectionConfig(
        name="strix-aws",
        transport="stdio",
        command=python_executable or sys.executable,
        args=["-m", "strix.mcp_servers.aws"],
        env=env,
        allowed_tools=list(aws.TOOL_NAMES),
        active_tools=list(aws.TOOL_NAMES),
        notes=(
            "Host-side AWS read-only checks across S3, IAM, EC2, RDS, KMS and Secrets "
            "Manager (identity/recon, public-exposure signals, bounded object read), "
            "scope-gated on cloud.aws_account_ids and fail-closed without a scope.yaml. "
            "Credentials stay on the host. Read-only: use results to file candidates "
            "(e.g. s3_get_bucket_public_status, rds_list_public_instances, "
            "kms_analyze_key_policy) and validated findings (s3_get_object_head)."
        ),
        session_timeout_seconds=120.0,
    )


def builtin_wrapper_configs() -> list[McpConnectionConfig]:
    """Return every host-side wrapper Strix 2 ships (currently the AWS wrapper)."""
    return [aws_wrapper_config()]


def _auto_wrappers_enabled() -> bool:
    return os.environ.get(_AUTO_WRAPPERS_ENV, "1").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )


def _aws_in_scope() -> bool:
    """Whether the active scope authorizes at least one AWS account."""
    policy = get_active_policy()
    return bool(policy and policy.cloud.aws_account_ids)


def applicable_builtin_configs(existing_names: set[str]) -> list[McpConnectionConfig]:
    """The built-in wrappers to auto-attach to this run.

    Context-aware and conservative: a wrapper is attached only when the engagement
    actually needs it (the AWS wrapper only when the active scope authorizes an AWS
    account, so a pure web run never spawns a cloud subprocess), never when the user
    already configured a connection of that name (their entry wins), and never when
    ``STRIX2_AUTO_WRAPPERS`` is set to a falsey value. Scope must be loaded first
    (``install_strix2_extensions`` does this before the run builds MCP requests).
    """
    if not _auto_wrappers_enabled():
        return []
    configs: list[McpConnectionConfig] = []
    if "strix-aws" not in existing_names and _aws_in_scope():
        configs.append(aws_wrapper_config())
    return configs


def configs_with_builtins(
    user_configs: list[McpConnectionConfig],
) -> list[McpConnectionConfig]:
    """Append the applicable built-in wrappers to the user's MCP configs.

    The user's own configs come first and win name collisions (mirroring the
    loader's first-wins de-dup). Used on the command-line run path so the agent can
    reach the built-in wrappers without hand-editing ``~/.strix/mcp-servers.json``.
    """
    existing = {config.name for config in user_configs}
    return [*user_configs, *applicable_builtin_configs(existing)]
