"""Host-side AWS read-only MCP wrapper (Strix 2, Phase 1).

Exposes a tight, **read-only** set of AWS checks over ``stdio`` MCP so the pentest
agent can produce cloud *evidence* without cloud tooling or credentials ever
entering the sandbox. Every tool:

- runs under the operator's own AWS credentials (standard boto3 resolution: env
  vars, shared config, SSO, instance role) held **on the host**, never shipped
  into the container;
- is gated by ``scope.yaml``, fail-closed: the acting principal's account (from
  STS ``GetCallerIdentity``) must be listed in ``cloud.aws_account_ids``, and with
  no scope loaded every tool refuses;
- is **non-intrusive** — no create / update / delete. State-changing proofs are
  deliberately out of scope for this wrapper.

The wrapper returns structured evidence; it does not itself file candidates or
findings. Per the validator semantics (``docs/strix2/04-validator-semantics.md``
§4.3): a "looks public" signal from ``s3_get_bucket_public_status`` is a
**candidate** the agent files with ``create_candidate``; a captured bounded read
from ``s3_get_object_head`` (request + response head + hash) is the evidence that
promotes it to a **validated** finding via ``create_vulnerability_report``.

Run as a subprocess: ``python -m strix.mcp_servers.aws`` (see
:mod:`strix.mcp_servers.registry` for the connection config Strix uses).
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from typing import TYPE_CHECKING, Any

from strix.mcp_servers.base import ScopeGuard, build_server, error, ok


if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP


logger = logging.getLogger(__name__)

# Decision 4.3b: a cloud read PoC captures only metadata + a bounded head, never
# full object contents. Object reads are clamped to this many bytes.
_MAX_HEAD_BYTES = 1024

# The read-only tool names this wrapper exposes; also its allowlist in the
# connection config, so the allowlist and the implementation cannot drift.
TOOL_NAMES = (
    "aws_whoami",
    "s3_list_buckets",
    "s3_get_bucket_public_status",
    "s3_get_object_head",
    "iam_list_principals",
    "iam_analyze_principal",
    "ec2_list_open_security_groups",
    "ec2_list_public_snapshots",
    "secretsmanager_list_secrets",
    "rds_list_public_instances",
    "rds_list_public_snapshots",
    "kms_list_keys",
    "kms_analyze_key_policy",
)

_INSTRUCTIONS = (
    "Read-only AWS checks for authorized cloud pentesting. Credentials stay on the "
    "host; every call is scope-gated on the caller's AWS account id. S3: "
    "s3_get_bucket_public_status files a candidate, s3_get_object_head captures the "
    "bounded read that validates it. IAM: iam_list_principals for recon, "
    "iam_analyze_principal flags over-permissive (wildcard/admin) policies as a "
    "candidate. EC2: ec2_list_open_security_groups flags inbound rules open to "
    "0.0.0.0/0, ec2_list_public_snapshots flags EBS snapshots shared publicly "
    "(candidates). RDS: rds_list_public_instances flags publicly-accessible DBs, "
    "rds_list_public_snapshots flags snapshots restorable by all (candidates). KMS: "
    "kms_list_keys for recon, kms_analyze_key_policy flags a wildcard-principal key "
    "policy (candidate). Secrets Manager: secretsmanager_list_secrets enumerates "
    "secret names/metadata (never values). All regional tools take an optional "
    "region. No state-changing actions."
)

# Seam so tests inject a fake boto3 client without real AWS. Signature:
# factory(service_name, region_or_none) -> client.
_client_factory: Any = None

# Cached (account, arn) for the acting principal, resolved once via STS.
_identity: tuple[str, str] | None = None

_guard_instance: ScopeGuard | None = None


def set_client_factory(factory: Any) -> None:
    """Test seam: install a callable ``factory(service, region)`` returning a client."""
    global _client_factory  # noqa: PLW0603
    _client_factory = factory


def reset_state() -> None:
    """Test seam: clear the cached identity and guard so a test starts clean."""
    global _identity, _guard_instance  # noqa: PLW0603
    _identity = None
    _guard_instance = None


def _client(service: str, region: str | None = None) -> Any:
    if _client_factory is not None:
        return _client_factory(service, region)
    import boto3

    return boto3.client(service, region_name=region)


def _guard() -> ScopeGuard:
    global _guard_instance  # noqa: PLW0603
    if _guard_instance is None:
        _guard_instance = ScopeGuard.load()
    return _guard_instance


def _get_identity() -> tuple[str, str]:
    """Resolve and cache the acting principal's ``(account, arn)`` via STS."""
    global _identity  # noqa: PLW0603
    if _identity is None:
        ident = _client("sts").get_caller_identity()
        _identity = (str(ident.get("Account") or ""), str(ident.get("Arn") or ""))
    return _identity


def _authorize() -> tuple[str, str, None] | tuple[None, None, str]:
    """Resolve the caller and check its account is in scope (fail-closed).

    Returns ``(account, arn, None)`` when authorized, or ``(None, None, error)``
    where ``error`` is a ready-to-return tool result.
    """
    from botocore.exceptions import BotoCoreError, ClientError

    try:
        account, arn = _get_identity()
    except (BotoCoreError, ClientError) as exc:
        return None, None, error(f"could not resolve AWS caller identity: {exc}")
    if not account:
        return None, None, error("AWS returned no account id for the caller identity")
    denial = _guard().check(f"aws:{account}", domain="cloud")
    if denial is not None:
        return None, None, denial
    return account, arn, None


def aws_whoami() -> str:
    """Return the acting AWS principal (account, ARN, user id) via STS GetCallerIdentity.

    Read-only. This is the principal every finding must name (validator semantics
    §4.3a). Refused if the caller's account is not authorized in scope.
    """
    account, arn, denial = _authorize()
    if denial is not None:
        return denial
    return ok(account=account, arn=arn)


def s3_list_buckets() -> str:
    """List S3 bucket names owned by the acting account. Read-only recon.

    Each bucket is a lead to triage, not a finding. Refused if the caller's account
    is not in scope.
    """
    from botocore.exceptions import BotoCoreError, ClientError

    account, _arn, denial = _authorize()
    if denial is not None:
        return denial
    try:
        response = _client("s3").list_buckets()
    except (BotoCoreError, ClientError) as exc:
        return error(f"s3 list_buckets failed: {exc}")
    buckets = [str(b.get("Name") or "") for b in response.get("Buckets", [])]
    return ok(account=account, bucket_count=len(buckets), buckets=buckets)


def _acl_public_grants(grants: list[dict[str, Any]]) -> list[str]:
    """Return the permissions granted to 'all users' / 'authenticated users' groups."""
    public_uris = (
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    )
    public: list[str] = []
    for grant in grants:
        grantee = grant.get("Grantee") or {}
        if grantee.get("Type") == "Group" and grantee.get("URI") in public_uris:
            public.append(f"{grantee.get('URI', '').rsplit('/', 1)[-1]}:{grant.get('Permission')}")
    return public


def s3_get_bucket_public_status(bucket: str, region: str | None = None) -> str:
    """Read a bucket's public-exposure signals (ACL, policy status, public-access block).

    Read-only. Composes a ``looks_public`` signal from the bucket ACL grants, the
    bucket policy status, and the public-access-block config. A true result is a
    *candidate* (file it with create_candidate) — it is not yet a validated finding;
    prove impact with s3_get_object_head on an actual object. Refused if the
    caller's account is not in scope.

    Args:
        bucket: The S3 bucket name.
        region: Optional bucket region (e.g. ``us-east-1``).
    """
    from botocore.exceptions import BotoCoreError, ClientError

    account, _arn, denial = _authorize()
    if denial is not None:
        return denial
    if not (bucket or "").strip():
        return error("bucket is required")

    client = _client("s3", region)
    signals: dict[str, Any] = {}

    try:
        pab = client.get_public_access_block(Bucket=bucket)
        signals["public_access_block"] = pab.get("PublicAccessBlockConfiguration", {})
    except (BotoCoreError, ClientError) as exc:
        signals["public_access_block"] = f"unavailable: {exc}"

    acl_public: list[str] = []
    try:
        acl = client.get_bucket_acl(Bucket=bucket)
        acl_public = _acl_public_grants(acl.get("Grants", []))
        signals["acl_public_grants"] = acl_public
    except (BotoCoreError, ClientError) as exc:
        signals["acl_public_grants"] = f"unavailable: {exc}"

    policy_is_public = False
    try:
        status = client.get_bucket_policy_status(Bucket=bucket)
        policy_is_public = bool(status.get("PolicyStatus", {}).get("IsPublic", False))
        signals["policy_is_public"] = policy_is_public
    except (BotoCoreError, ClientError) as exc:
        signals["policy_is_public"] = f"unavailable: {exc}"

    looks_public = bool(acl_public) or policy_is_public
    return ok(
        account=account,
        bucket=bucket,
        looks_public=looks_public,
        signals=signals,
        note=(
            "Candidate signal only. Prove impact with s3_get_object_head on a "
            "specific object before treating this as a finding."
        ),
    )


def s3_get_object_head(
    bucket: str,
    key: str,
    region: str | None = None,
    max_bytes: int = _MAX_HEAD_BYTES,
) -> str:
    """Read a bounded head of an S3 object as validation evidence. Read-only (GET).

    Captures the request, the response metadata, and up to ``max_bytes`` (hard-capped
    at 1024 per validator semantics §4.3b) of the object body plus its SHA-256 — the
    evidence that a should-be-private object is actually readable by the acting
    principal. Never returns full object contents. Refused if the caller's account is
    not in scope.

    Args:
        bucket: The S3 bucket name.
        key: The object key to read.
        region: Optional bucket region (e.g. ``us-east-1``).
        max_bytes: Bytes of the object head to capture (1..1024).
    """
    from botocore.exceptions import BotoCoreError, ClientError

    account, arn, denial = _authorize()
    if denial is not None:
        return denial
    if not (bucket or "").strip() or not (key or "").strip():
        return error("bucket and key are required")

    capped = max(1, min(int(max_bytes), _MAX_HEAD_BYTES))
    byte_range = f"bytes=0-{capped - 1}"
    try:
        response = _client("s3", region).get_object(Bucket=bucket, Key=key, Range=byte_range)
        body = response["Body"].read(capped)
    except (BotoCoreError, ClientError) as exc:
        return error(f"s3 get_object failed: {exc}", bucket=bucket, key=key)

    head = bytes(body)[:capped]
    return ok(
        account=account,
        principal_arn=arn,
        bucket=bucket,
        key=key,
        request={"method": "GET", "operation": "s3:GetObject", "range": byte_range},
        response_metadata={
            "content_type": response.get("ContentType"),
            "content_length": response.get("ContentLength"),
            "content_range": response.get("ContentRange"),
            "etag": response.get("ETag"),
            "last_modified": response.get("LastModified"),
        },
        bytes_captured=len(head),
        sha256=hashlib.sha256(head).hexdigest(),
        body_head_base64=base64.b64encode(head).decode("ascii"),
        note="Bounded read evidence (<=1024 bytes). Read-only proof of access.",
    )


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, list) else [value]


def _coerce_policy_document(document: Any) -> dict[str, Any]:
    """Return an IAM policy document as a dict.

    IAM returns policy documents inconsistently — a dict, or a URL-encoded JSON
    string (``get_policy_version`` in particular) — so normalize both here.
    """
    if isinstance(document, dict):
        return document
    if isinstance(document, str):
        from urllib.parse import unquote

        try:
            parsed = json.loads(unquote(document))
        except (ValueError, TypeError):
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _concerning_statements(document: dict[str, Any], source: str) -> list[dict[str, Any]]:
    """Flag over-permissive ``Allow`` statements in one policy document.

    Concerning = an ``Allow`` with a full action wildcard (``"*"``), or a service
    wildcard (``"s3:*"``) on all resources. ``admin`` marks the classic ``*``/``*``.
    """
    flagged: list[dict[str, Any]] = []
    for statement in _as_list(document.get("Statement")):
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        actions = [str(a) for a in _as_list(statement.get("Action"))]
        resources = [str(r) for r in _as_list(statement.get("Resource"))]
        action_star = "*" in actions
        service_wildcard = any(a.endswith(":*") for a in actions)
        resource_star = "*" in resources
        if action_star or (service_wildcard and resource_star):
            flagged.append(
                {
                    "source": source,
                    "actions": actions,
                    "resources": resources,
                    "admin": action_star and resource_star,
                    "action_wildcard": action_star,
                    "resource_wildcard": resource_star,
                }
            )
    return flagged


def iam_list_principals() -> str:
    """List IAM users and roles in the acting account. Read-only recon.

    Each principal is a lead to triage with iam_analyze_principal, not a finding.
    Refused if the caller's account is not in scope.
    """
    from botocore.exceptions import BotoCoreError, ClientError

    account, _arn, denial = _authorize()
    if denial is not None:
        return denial
    iam = _client("iam")
    try:
        users = [
            {"name": str(u.get("UserName") or ""), "arn": str(u.get("Arn") or "")}
            for u in iam.list_users().get("Users", [])
        ]
        roles = [
            {"name": str(r.get("RoleName") or ""), "arn": str(r.get("Arn") or "")}
            for r in iam.list_roles().get("Roles", [])
        ]
    except (BotoCoreError, ClientError) as exc:
        return error(f"iam list principals failed: {exc}", account=account)
    return ok(account=account, user_count=len(users), users=users, roles=roles)


def iam_analyze_principal(name: str, principal_type: str) -> str:
    """Analyze an IAM user/role's policies for over-permissive (wildcard/admin) grants.

    Read-only. Reads the principal's attached managed policies and inline policies,
    then flags ``Allow`` statements with a full action wildcard or a service wildcard
    on all resources. A true ``overly_permissive`` is a **candidate** (file it with
    create_candidate) — validate it by demonstrating a should-be-denied action as the
    least-privilege principal before filing a finding. Refused if the caller's account
    is not in scope.

    Args:
        name: The IAM user name or role name (without path).
        principal_type: ``user`` or ``role``.
    """
    from botocore.exceptions import BotoCoreError, ClientError

    account, _arn, denial = _authorize()
    if denial is not None:
        return denial
    ptype = (principal_type or "").strip().lower()
    if ptype not in ("user", "role"):
        return error("principal_type must be 'user' or 'role'")
    if not (name or "").strip():
        return error("name is required")

    iam = _client("iam")
    concerning: list[dict[str, Any]] = []
    examined: list[str] = []
    errors: list[str] = []

    try:
        if ptype == "user":
            attached = iam.list_attached_user_policies(UserName=name).get("AttachedPolicies", [])
            inline_names = iam.list_user_policies(UserName=name).get("PolicyNames", [])
        else:
            attached = iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", [])
            inline_names = iam.list_role_policies(RoleName=name).get("PolicyNames", [])
    except (BotoCoreError, ClientError) as exc:
        return error(f"iam list policies failed for {ptype} {name!r}: {exc}", account=account)

    for policy in attached:
        arn = str(policy.get("PolicyArn") or "")
        pname = str(policy.get("PolicyName") or arn)
        try:
            default_version = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
            document = iam.get_policy_version(PolicyArn=arn, VersionId=default_version)[
                "PolicyVersion"
            ]["Document"]
        except (BotoCoreError, ClientError, KeyError) as exc:
            errors.append(f"managed:{pname}: {exc}")
            continue
        examined.append(f"managed:{pname}")
        concerning.extend(
            _concerning_statements(_coerce_policy_document(document), f"managed:{pname}")
        )

    for inline_name in inline_names:
        try:
            if ptype == "user":
                document = iam.get_user_policy(UserName=name, PolicyName=inline_name)[
                    "PolicyDocument"
                ]
            else:
                document = iam.get_role_policy(RoleName=name, PolicyName=inline_name)[
                    "PolicyDocument"
                ]
        except (BotoCoreError, ClientError, KeyError) as exc:
            errors.append(f"inline:{inline_name}: {exc}")
            continue
        examined.append(f"inline:{inline_name}")
        concerning.extend(
            _concerning_statements(_coerce_policy_document(document), f"inline:{inline_name}")
        )

    return ok(
        account=account,
        principal={"type": ptype, "name": name},
        overly_permissive=bool(concerning),
        concerning_statements=concerning,
        policies_examined=examined,
        errors=errors,
        note=(
            "Candidate signal only (over-permissive IAM). Validate by demonstrating an "
            "action the policy should not allow, as the least-privilege principal, "
            "before filing a finding."
        ),
    )


def _open_ingress_rules(permissions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return the inbound rules open to the whole internet (``0.0.0.0/0`` or ``::/0``)."""
    open_rules: list[dict[str, Any]] = []
    for perm in permissions:
        rule = {
            "protocol": str(perm.get("IpProtocol", "")),
            "from_port": perm.get("FromPort"),
            "to_port": perm.get("ToPort"),
        }
        open_rules.extend(
            {**rule, "cidr": "0.0.0.0/0"}
            for entry in _as_list(perm.get("IpRanges"))
            if entry.get("CidrIp") == "0.0.0.0/0"
        )
        open_rules.extend(
            {**rule, "cidr": "::/0"}
            for entry in _as_list(perm.get("Ipv6Ranges"))
            if entry.get("CidrIpv6") == "::/0"
        )
    return open_rules


def ec2_list_open_security_groups(region: str | None = None) -> str:
    """List EC2 security groups with inbound rules open to the whole internet. Read-only.

    Flags security groups whose ingress allows ``0.0.0.0/0`` (or ``::/0``), with the
    exposed protocol/port range. A world-open group is a **candidate** (file it with
    create_candidate) — validate by demonstrating an actual exposed service, not the
    rule alone. Refused if the caller's account is not in scope.

    Args:
        region: AWS region to inspect (e.g. ``us-east-1``). Security groups are regional.
    """
    from botocore.exceptions import BotoCoreError, ClientError

    account, _arn, denial = _authorize()
    if denial is not None:
        return denial
    try:
        groups = _client("ec2", region).describe_security_groups().get("SecurityGroups", [])
    except (BotoCoreError, ClientError) as exc:
        return error(f"ec2 describe_security_groups failed: {exc}", account=account, region=region)

    world_open = []
    for group in groups:
        open_ingress = _open_ingress_rules(group.get("IpPermissions", []))
        if open_ingress:
            world_open.append(
                {
                    "group_id": str(group.get("GroupId") or ""),
                    "group_name": str(group.get("GroupName") or ""),
                    "vpc_id": str(group.get("VpcId") or ""),
                    "open_ingress": open_ingress,
                }
            )
    return ok(
        account=account,
        region=region,
        has_world_open=bool(world_open),
        world_open_groups=world_open,
        note="Candidate signal only. Demonstrate an actual exposed service to validate.",
    )


def secretsmanager_list_secrets(region: str | None = None) -> str:
    """List Secrets Manager secret names and metadata (never values). Read-only recon.

    Enumerating secrets you can see is a **candidate**/recon signal. This tool
    deliberately never calls GetSecretValue — reading a secret's value is sensitive
    exfiltration and is out of scope for this read-only wrapper. Refused if the
    caller's account is not in scope.

    Args:
        region: AWS region to inspect (e.g. ``us-east-1``). Secrets are regional.
    """
    from botocore.exceptions import BotoCoreError, ClientError

    account, _arn, denial = _authorize()
    if denial is not None:
        return denial
    try:
        secret_list = _client("secretsmanager", region).list_secrets().get("SecretList", [])
    except (BotoCoreError, ClientError) as exc:
        return error(f"secretsmanager list_secrets failed: {exc}", account=account, region=region)

    secrets = [
        {
            "name": str(item.get("Name") or ""),
            "arn": str(item.get("ARN") or ""),
            "rotation_enabled": bool(item.get("RotationEnabled", False)),
        }
        for item in secret_list
    ]
    return ok(
        account=account,
        region=region,
        secret_count=len(secrets),
        secrets=secrets,
        note="Names/metadata only (values never read). Recon/candidate signal.",
    )


def _snapshot_create_volume_groups(attribute: dict[str, Any]) -> list[str]:
    """Return the groups an EBS snapshot's createVolumePermission is shared with."""
    return [
        str(perm.get("Group") or "")
        for perm in _as_list(attribute.get("CreateVolumePermissions"))
        if perm.get("Group")
    ]


def ec2_list_public_snapshots(region: str | None = None) -> str:
    """List EBS snapshots owned by the account that are shared publicly. Read-only.

    For each snapshot the account owns, reads its ``createVolumePermission``
    attribute; a snapshot whose permissions grant the ``all`` group is public and a
    **candidate** (file it with create_candidate) — a public EBS snapshot can expose
    whole-disk contents. Validate by demonstrating a volume created/read from it as
    an unrelated principal, not the permission alone. Refused if the caller's account
    is not in scope.

    Args:
        region: AWS region to inspect (e.g. ``us-east-1``). Snapshots are regional.
    """
    from botocore.exceptions import BotoCoreError, ClientError

    account, _arn, denial = _authorize()
    if denial is not None:
        return denial
    ec2 = _client("ec2", region)
    try:
        snapshots = ec2.describe_snapshots(OwnerIds=["self"]).get("Snapshots", [])
    except (BotoCoreError, ClientError) as exc:
        return error(f"ec2 describe_snapshots failed: {exc}", account=account, region=region)

    public: list[dict[str, Any]] = []
    errors: list[str] = []
    for snap in snapshots:
        snap_id = str(snap.get("SnapshotId") or "")
        try:
            attribute = ec2.describe_snapshot_attribute(
                SnapshotId=snap_id, Attribute="createVolumePermission"
            )
        except (BotoCoreError, ClientError) as exc:
            errors.append(f"{snap_id}: {exc}")
            continue
        groups = _snapshot_create_volume_groups(attribute)
        if "all" in groups:
            public.append(
                {
                    "snapshot_id": snap_id,
                    "volume_id": str(snap.get("VolumeId") or ""),
                    "volume_size": snap.get("VolumeSize"),
                    "groups": groups,
                }
            )
    return ok(
        account=account,
        region=region,
        has_public_snapshots=bool(public),
        public_snapshots=public,
        errors=errors,
        note="Candidate signal only. A public EBS snapshot can expose disk contents.",
    )


def rds_list_public_instances(region: str | None = None) -> str:
    """List RDS DB instances reachable from the public internet. Read-only.

    Flags instances with ``PubliclyAccessible=True`` — a publicly reachable managed
    database is a **candidate** (file it with create_candidate); validate by
    demonstrating an actually reachable/authenticating endpoint, not the flag alone
    (a public instance behind a closed security group is not yet exposed). Refused if
    the caller's account is not in scope.

    Args:
        region: AWS region to inspect (e.g. ``us-east-1``). RDS is regional.
    """
    from botocore.exceptions import BotoCoreError, ClientError

    account, _arn, denial = _authorize()
    if denial is not None:
        return denial
    try:
        instances = _client("rds", region).describe_db_instances().get("DBInstances", [])
    except (BotoCoreError, ClientError) as exc:
        return error(f"rds describe_db_instances failed: {exc}", account=account, region=region)

    public = [
        {
            "db_instance_identifier": str(db.get("DBInstanceIdentifier") or ""),
            "engine": str(db.get("Engine") or ""),
            "endpoint": (db.get("Endpoint") or {}).get("Address"),
            "port": (db.get("Endpoint") or {}).get("Port"),
            "vpc_security_groups": [
                str(group.get("VpcSecurityGroupId") or "")
                for group in _as_list(db.get("VpcSecurityGroups"))
            ],
        }
        for db in instances
        if db.get("PubliclyAccessible") is True
    ]
    return ok(
        account=account,
        region=region,
        has_public_instances=bool(public),
        public_instances=public,
        note=(
            "Candidate signal only. Confirm the endpoint is actually reachable "
            "(security group + route) to validate."
        ),
    )


def _snapshot_restore_values(attributes: dict[str, Any]) -> list[str]:
    """Return an RDS snapshot's ``restore`` attribute values (who may restore it)."""
    result = attributes.get("DBSnapshotAttributesResult", {})
    for attribute in _as_list(result.get("DBSnapshotAttributes")):
        if attribute.get("AttributeName") == "restore":
            return [str(value) for value in _as_list(attribute.get("AttributeValues"))]
    return []


def rds_list_public_snapshots(region: str | None = None) -> str:
    """List manual RDS snapshots shared publicly (restorable by all). Read-only.

    Enumerates the account's manual DB snapshots and reads each one's ``restore``
    attribute; a snapshot whose restore list includes ``all`` is public and a
    **candidate** (file it with create_candidate) — a public DB snapshot can leak an
    entire database. Validate by demonstrating a restore/read as an unrelated
    principal. Refused if the caller's account is not in scope.

    Args:
        region: AWS region to inspect (e.g. ``us-east-1``). Snapshots are regional.
    """
    from botocore.exceptions import BotoCoreError, ClientError

    account, _arn, denial = _authorize()
    if denial is not None:
        return denial
    rds = _client("rds", region)
    try:
        snapshots = rds.describe_db_snapshots(SnapshotType="manual").get("DBSnapshots", [])
    except (BotoCoreError, ClientError) as exc:
        return error(f"rds describe_db_snapshots failed: {exc}", account=account, region=region)

    public: list[dict[str, Any]] = []
    errors: list[str] = []
    for snap in snapshots:
        snap_id = str(snap.get("DBSnapshotIdentifier") or "")
        try:
            attributes = rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=snap_id)
        except (BotoCoreError, ClientError) as exc:
            errors.append(f"{snap_id}: {exc}")
            continue
        restore = _snapshot_restore_values(attributes)
        if "all" in restore:
            public.append(
                {
                    "db_snapshot_identifier": snap_id,
                    "engine": str(snap.get("Engine") or ""),
                    "restore": restore,
                }
            )
    return ok(
        account=account,
        region=region,
        has_public_snapshots=bool(public),
        public_snapshots=public,
        errors=errors,
        note="Candidate signal only. A public DB snapshot can expose an entire database.",
    )


def kms_list_keys(region: str | None = None) -> str:
    """List KMS keys and their aliases in the acting account. Read-only recon.

    Each key is a lead to triage with kms_analyze_key_policy, not a finding. Refused
    if the caller's account is not in scope.

    Args:
        region: AWS region to inspect (e.g. ``us-east-1``). KMS keys are regional.
    """
    from botocore.exceptions import BotoCoreError, ClientError

    account, _arn, denial = _authorize()
    if denial is not None:
        return denial
    kms = _client("kms", region)
    try:
        keys = kms.list_keys().get("Keys", [])
        aliases = kms.list_aliases().get("Aliases", [])
    except (BotoCoreError, ClientError) as exc:
        return error(f"kms list keys/aliases failed: {exc}", account=account, region=region)

    alias_by_key: dict[str, list[str]] = {}
    for alias in aliases:
        target = str(alias.get("TargetKeyId") or "")
        if target:
            alias_by_key.setdefault(target, []).append(str(alias.get("AliasName") or ""))
    key_list = [
        {
            "key_id": str(key.get("KeyId") or ""),
            "aliases": alias_by_key.get(str(key.get("KeyId") or ""), []),
        }
        for key in keys
    ]
    return ok(
        account=account,
        region=region,
        key_count=len(key_list),
        keys=key_list,
        note="Recon/candidate signal. Analyze a key's policy with kms_analyze_key_policy.",
    )


def _kms_wildcard_principal_statements(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Flag KMS key-policy statements exposing the key to any AWS principal.

    Concerning = an ``Allow`` whose ``Principal`` is the wildcard ``"*"`` (or
    ``{"AWS": "*"}``) with no ``Condition`` confining it — the key is usable by any
    principal. A confining ``Condition`` (an org id / source account / etc.) makes it
    a deliberate cross-account grant, so those are not flagged.
    """
    flagged: list[dict[str, Any]] = []
    for statement in _as_list(document.get("Statement")):
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        values: list[str] = []
        if isinstance(principal, str):
            values = [principal]
        elif isinstance(principal, dict):
            for entry in principal.values():
                values.extend(str(value) for value in _as_list(entry))
        if "*" not in values or statement.get("Condition"):
            continue
        flagged.append(
            {
                "sid": str(statement.get("Sid") or ""),
                "actions": [str(action) for action in _as_list(statement.get("Action"))],
                "principal_wildcard": True,
            }
        )
    return flagged


def kms_analyze_key_policy(key_id: str, region: str | None = None) -> str:
    """Analyze a KMS key policy for a wildcard-principal (any-account) grant. Read-only.

    Reads the key's default key policy and flags ``Allow`` statements open to any
    principal (``Principal: "*"``) with no confining condition — an externally-usable
    CMK is a **candidate** (file it with create_candidate); validate by demonstrating
    use of the key from an unrelated principal before filing a finding. Refused if
    the caller's account is not in scope.

    Args:
        key_id: The KMS key id or ARN.
        region: AWS region (e.g. ``us-east-1``). KMS keys are regional.
    """
    from botocore.exceptions import BotoCoreError, ClientError

    account, _arn, denial = _authorize()
    if denial is not None:
        return denial
    if not (key_id or "").strip():
        return error("key_id is required")
    try:
        policy = _client("kms", region).get_key_policy(KeyId=key_id, PolicyName="default")
    except (BotoCoreError, ClientError) as exc:
        return error(f"kms get_key_policy failed: {exc}", account=account, key_id=key_id)

    document = _coerce_policy_document(policy.get("Policy"))
    concerning = _kms_wildcard_principal_statements(document)
    return ok(
        account=account,
        region=region,
        key_id=key_id,
        externally_exposed=bool(concerning),
        concerning_statements=concerning,
        note=(
            "Candidate signal only (wildcard-principal KMS key policy). Validate by "
            "demonstrating key use from an unrelated principal before filing a finding."
        ),
    )


def build() -> FastMCP:
    """Build the AWS wrapper server with its read-only tools registered."""
    server = build_server("strix-aws", _INSTRUCTIONS)
    server.tool()(aws_whoami)
    server.tool()(s3_list_buckets)
    server.tool()(s3_get_bucket_public_status)
    server.tool()(s3_get_object_head)
    server.tool()(iam_list_principals)
    server.tool()(iam_analyze_principal)
    server.tool()(ec2_list_open_security_groups)
    server.tool()(ec2_list_public_snapshots)
    server.tool()(secretsmanager_list_secrets)
    server.tool()(rds_list_public_instances)
    server.tool()(rds_list_public_snapshots)
    server.tool()(kms_list_keys)
    server.tool()(kms_analyze_key_policy)
    return server


def main() -> None:
    """Entry point: load scope in this subprocess and serve over stdio."""
    _guard()  # load scope policy now so a misconfig surfaces at startup, on stderr
    build().run()


if __name__ == "__main__":
    main()
