"""Tests for the read-only AWS MCP wrapper and its connection config.

No real AWS: a fake client factory is injected so tools exercise the scope gating,
argument handling, and evidence shaping without credentials or network.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

import pytest
from botocore.exceptions import ClientError

from strix.mcp_servers import aws
from strix.mcp_servers.base import ScopeGuard
from strix.mcp_servers.registry import (
    applicable_builtin_configs,
    aws_wrapper_config,
    builtin_wrapper_configs,
    configs_with_builtins,
)
from strix.scope.enforcement import get_active_policy, set_active_policy
from strix.scope.schema import ScopePolicy
from strix.tools.mcp.config import McpConnectionConfig


if TYPE_CHECKING:
    from collections.abc import Iterator

_ACCOUNT = "123456789012"
_ARN = "arn:aws:iam::123456789012:user/pentester"
_ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"


class _FakeBody:
    def __init__(self, content: bytes) -> None:
        self._content = content

    def read(self, amt: int | None = None) -> bytes:
        return self._content if amt is None else self._content[:amt]


class _FakeSTS:
    def __init__(self, identity: dict[str, Any]) -> None:
        self._identity = identity

    def get_caller_identity(self) -> dict[str, Any]:
        return self._identity


class _FakeS3:
    def __init__(self, *, obj: bytes = b"", public_acl: bool = False) -> None:
        self._obj = obj
        self._public_acl = public_acl

    def list_buckets(self) -> dict[str, Any]:
        return {"Buckets": [{"Name": "secret-bucket"}, {"Name": "logs"}]}

    def get_public_access_block(self, **_: Any) -> dict[str, Any]:
        return {"PublicAccessBlockConfiguration": {"BlockPublicAcls": False}}

    def get_bucket_acl(self, **_: Any) -> dict[str, Any]:
        grants: list[dict[str, Any]] = []
        if self._public_acl:
            grants.append(
                {"Grantee": {"Type": "Group", "URI": _ALL_USERS}, "Permission": "READ"}
            )
        return {"Grants": grants}

    def get_bucket_policy_status(self, **_: Any) -> dict[str, Any]:
        return {"PolicyStatus": {"IsPublic": False}}

    def get_object(self, **kwargs: Any) -> dict[str, Any]:
        self.last_range = kwargs.get("Range")
        return {
            "Body": _FakeBody(self._obj),
            "ContentType": "text/plain",
            "ContentLength": len(self._obj),
            "ContentRange": f"bytes 0-{len(self._obj) - 1}/{len(self._obj)}",
            "ETag": '"abc"',
        }


class _FakeIAM:
    def __init__(
        self,
        *,
        users: list[dict[str, Any]] | None = None,
        roles: list[dict[str, Any]] | None = None,
        attached: list[dict[str, Any]] | None = None,
        inline: list[str] | None = None,
        managed_docs: dict[str, Any] | None = None,
        inline_docs: dict[str, Any] | None = None,
    ) -> None:
        self._users = users or []
        self._roles = roles or []
        self._attached = attached or []
        self._inline = inline or []
        self._managed_docs = managed_docs or {}
        self._inline_docs = inline_docs or {}

    def list_users(self, **_: Any) -> dict[str, Any]:
        return {"Users": self._users}

    def list_roles(self, **_: Any) -> dict[str, Any]:
        return {"Roles": self._roles}

    def list_attached_user_policies(self, **_: Any) -> dict[str, Any]:
        return {"AttachedPolicies": self._attached}

    list_attached_role_policies = list_attached_user_policies

    def list_user_policies(self, **_: Any) -> dict[str, Any]:
        return {"PolicyNames": self._inline}

    list_role_policies = list_user_policies

    def get_policy(self, **_: Any) -> dict[str, Any]:
        return {"Policy": {"DefaultVersionId": "v1"}}

    def get_policy_version(self, **kwargs: Any) -> dict[str, Any]:
        return {"PolicyVersion": {"Document": self._managed_docs.get(kwargs.get("PolicyArn"), {})}}

    def get_user_policy(self, **kwargs: Any) -> dict[str, Any]:
        return {"PolicyDocument": self._inline_docs.get(kwargs.get("PolicyName"), {})}

    def get_role_policy(self, **kwargs: Any) -> dict[str, Any]:
        return {"PolicyDocument": self._inline_docs.get(kwargs.get("PolicyName"), {})}


class _FakeEC2:
    def __init__(
        self,
        groups: list[dict[str, Any]] | None = None,
        *,
        snapshots: list[dict[str, Any]] | None = None,
        snapshot_permissions: dict[str, list[dict[str, Any]]] | None = None,
    ) -> None:
        self._groups = groups or []
        self._snapshots = snapshots or []
        self._snapshot_permissions = snapshot_permissions or {}

    def describe_security_groups(self, **_: Any) -> dict[str, Any]:
        return {"SecurityGroups": self._groups}

    def describe_snapshots(self, **_: Any) -> dict[str, Any]:
        return {"Snapshots": self._snapshots}

    def describe_snapshot_attribute(self, **kwargs: Any) -> dict[str, Any]:
        return {
            "CreateVolumePermissions": self._snapshot_permissions.get(kwargs.get("SnapshotId"), [])
        }


class _FakeRDS:
    def __init__(
        self,
        *,
        instances: list[dict[str, Any]] | None = None,
        snapshots: list[dict[str, Any]] | None = None,
        snapshot_restore: dict[str, list[str]] | None = None,
    ) -> None:
        self._instances = instances or []
        self._snapshots = snapshots or []
        self._snapshot_restore = snapshot_restore or {}

    def describe_db_instances(self, **_: Any) -> dict[str, Any]:
        return {"DBInstances": self._instances}

    def describe_db_snapshots(self, **_: Any) -> dict[str, Any]:
        return {"DBSnapshots": self._snapshots}

    def describe_db_snapshot_attributes(self, **kwargs: Any) -> dict[str, Any]:
        values = self._snapshot_restore.get(kwargs.get("DBSnapshotIdentifier"), [])
        return {
            "DBSnapshotAttributesResult": {
                "DBSnapshotAttributes": [
                    {"AttributeName": "restore", "AttributeValues": values}
                ]
            }
        }


class _FakeKMS:
    def __init__(
        self,
        *,
        keys: list[dict[str, Any]] | None = None,
        aliases: list[dict[str, Any]] | None = None,
        policies: dict[str, Any] | None = None,
    ) -> None:
        self._keys = keys or []
        self._aliases = aliases or []
        self._policies = policies or {}

    def list_keys(self, **_: Any) -> dict[str, Any]:
        return {"Keys": self._keys}

    def list_aliases(self, **_: Any) -> dict[str, Any]:
        return {"Aliases": self._aliases}

    def get_key_policy(self, **kwargs: Any) -> dict[str, Any]:
        document = self._policies.get(kwargs.get("KeyId"), {"Statement": []})
        policy = document if isinstance(document, str) else json.dumps(document)
        return {"Policy": policy}


class _FakeSecretsManager:
    def __init__(self, secrets: list[dict[str, Any]] | None = None) -> None:
        self._secrets = secrets or []

    def list_secrets(self, **_: Any) -> dict[str, Any]:
        return {"SecretList": self._secrets}


def _factory(
    *,
    sts: _FakeSTS | None = None,
    s3: _FakeS3 | None = None,
    iam: _FakeIAM | None = None,
    ec2: _FakeEC2 | None = None,
    rds: _FakeRDS | None = None,
    kms: _FakeKMS | None = None,
    secretsmanager: _FakeSecretsManager | None = None,
) -> Any:
    sts = sts or _FakeSTS({"Account": _ACCOUNT, "Arn": _ARN, "UserId": "AIDA"})
    s3 = s3 or _FakeS3()
    iam = iam or _FakeIAM()
    ec2 = ec2 or _FakeEC2()
    rds = rds or _FakeRDS()
    kms = kms or _FakeKMS()
    secretsmanager = secretsmanager or _FakeSecretsManager()
    clients = {
        "sts": sts,
        "s3": s3,
        "iam": iam,
        "ec2": ec2,
        "rds": rds,
        "kms": kms,
        "secretsmanager": secretsmanager,
    }

    def factory(service: str, _region: str | None) -> Any:
        try:
            return clients[service]
        except KeyError:
            raise AssertionError(f"unexpected service {service!r}") from None

    return factory


def _policy(**overrides: object) -> ScopePolicy:
    base: dict[str, object] = {"cloud": {"aws_account_ids": [_ACCOUNT]}}
    base.update(overrides)
    return ScopePolicy.model_validate(base)


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    saved = get_active_policy()
    aws.reset_state()
    aws.set_client_factory(_factory())
    # A plain guard reads the active policy live; avoids reloading scope.yaml from disk.
    monkeypatch.setattr(aws, "_guard", ScopeGuard)
    try:
        yield
    finally:
        aws.reset_state()
        aws.set_client_factory(None)
        set_active_policy(saved)


# --- scope gating ------------------------------------------------------------

def test_whoami_refused_without_scope() -> None:
    set_active_policy(None)
    body = json.loads(aws.aws_whoami())
    assert body["success"] is False
    assert body["refused"] == "no_scope"


def test_whoami_in_scope() -> None:
    set_active_policy(_policy())
    body = json.loads(aws.aws_whoami())
    assert body["success"] is True
    assert body["account"] == _ACCOUNT
    assert body["arn"] == _ARN


def test_whoami_out_of_scope_account() -> None:
    set_active_policy(_policy(cloud={"aws_account_ids": ["999999999999"]}))
    body = json.loads(aws.aws_whoami())
    assert body["success"] is False
    assert body["refused"] == "out_of_scope"


def test_identity_error_is_reported() -> None:
    class _Boom(_FakeSTS):
        def get_caller_identity(self) -> dict[str, Any]:
            raise ClientError({"Error": {"Code": "AccessDenied"}}, "GetCallerIdentity")

    set_active_policy(_policy())
    aws.set_client_factory(_factory(sts=_Boom({})))
    body = json.loads(aws.aws_whoami())
    assert body["success"] is False
    assert "caller identity" in body["error"]


# --- s3 recon ----------------------------------------------------------------

def test_list_buckets() -> None:
    set_active_policy(_policy())
    body = json.loads(aws.s3_list_buckets())
    assert body["success"] is True
    assert body["bucket_count"] == 2
    assert "secret-bucket" in body["buckets"]


def test_bucket_public_status_flags_public_acl() -> None:
    set_active_policy(_policy())
    aws.set_client_factory(_factory(s3=_FakeS3(public_acl=True)))
    body = json.loads(aws.s3_get_bucket_public_status("secret-bucket"))
    assert body["success"] is True
    assert body["looks_public"] is True
    assert any("AllUsers" in g for g in body["signals"]["acl_public_grants"])


def test_bucket_public_status_private_bucket() -> None:
    set_active_policy(_policy())
    body = json.loads(aws.s3_get_bucket_public_status("logs"))
    assert body["success"] is True
    assert body["looks_public"] is False


# --- s3 bounded read evidence ------------------------------------------------

def test_get_object_head_captures_bounded_evidence() -> None:
    set_active_policy(_policy())
    content = b"TOP SECRET credentials: hunter2"
    aws.set_client_factory(_factory(s3=_FakeS3(obj=content)))
    body = json.loads(aws.s3_get_object_head("secret-bucket", "creds.txt", max_bytes=8))
    assert body["success"] is True
    assert body["bytes_captured"] == 8
    head = content[:8]
    assert base64.b64decode(body["body_head_base64"]) == head
    assert body["sha256"] == hashlib.sha256(head).hexdigest()
    assert body["principal_arn"] == _ARN
    assert body["request"]["range"] == "bytes=0-7"


def test_get_object_head_clamps_to_1024_bytes() -> None:
    set_active_policy(_policy())
    aws.set_client_factory(_factory(s3=_FakeS3(obj=b"x" * 5000)))
    body = json.loads(aws.s3_get_object_head("b", "k", max_bytes=5000))
    assert body["bytes_captured"] == 1024
    assert body["request"]["range"] == "bytes=0-1023"


def test_get_object_head_refused_out_of_scope() -> None:
    set_active_policy(_policy(cloud={"aws_account_ids": ["999999999999"]}))
    body = json.loads(aws.s3_get_object_head("b", "k"))
    assert body["success"] is False
    assert body["refused"] == "out_of_scope"


def test_get_object_head_requires_bucket_and_key() -> None:
    set_active_policy(_policy())
    body = json.loads(aws.s3_get_object_head("", ""))
    assert body["success"] is False


# --- server + config ---------------------------------------------------------

async def test_build_registers_only_allowlisted_tools() -> None:
    server = aws.build()
    assert server.name == "strix-aws"
    tools = await server.list_tools()
    assert {t.name for t in tools} == set(aws.TOOL_NAMES)


def test_aws_wrapper_config_shape() -> None:
    config = aws_wrapper_config()
    assert config.name == "strix-aws"
    assert config.transport == "stdio"
    assert config.command == sys.executable
    assert config.args == ["-m", "strix.mcp_servers.aws"]
    assert config.allowed_tools == list(aws.TOOL_NAMES)


def test_config_forwards_scope_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_SCOPE_CONFIG", "engagement-scope.yaml")
    monkeypatch.setenv("STRIX_ALLOW_INTRUSIVE", "1")
    config = aws_wrapper_config(region="us-east-1")
    assert config.env["STRIX_SCOPE_CONFIG"] == "engagement-scope.yaml"
    assert config.env["STRIX_ALLOW_INTRUSIVE"] == "1"
    assert config.env["AWS_DEFAULT_REGION"] == "us-east-1"


def test_builtin_wrapper_configs() -> None:
    configs = builtin_wrapper_configs()
    assert [c.name for c in configs] == ["strix-aws"]


# --- iam recon ---------------------------------------------------------------

_ADMIN_DOC = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
_BENIGN_DOC = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:x"}]}
_SERVICE_WILDCARD_DOC = {"Statement": {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}}
_DENY_STAR_DOC = {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}


def test_iam_list_principals() -> None:
    set_active_policy(_policy())
    iam = _FakeIAM(
        users=[{"UserName": "alice", "Arn": "arn:aws:iam::123456789012:user/alice"}],
        roles=[{"RoleName": "deploy", "Arn": "arn:aws:iam::123456789012:role/deploy"}],
    )
    aws.set_client_factory(_factory(iam=iam))
    body = json.loads(aws.iam_list_principals())
    assert body["success"] is True
    assert body["user_count"] == 1
    assert body["users"][0]["name"] == "alice"
    assert body["roles"][0]["name"] == "deploy"


def test_iam_list_principals_refused_out_of_scope() -> None:
    set_active_policy(_policy(cloud={"aws_account_ids": ["999999999999"]}))
    assert json.loads(aws.iam_list_principals())["refused"] == "out_of_scope"


# --- iam policy analysis (through the public tool) ----------------------------

def _analyze(iam: _FakeIAM, name: str = "alice", ptype: str = "user") -> dict[str, Any]:
    set_active_policy(_policy())
    aws.set_client_factory(_factory(iam=iam))
    return json.loads(aws.iam_analyze_principal(name, ptype))


def _iam_with_managed(policy_name: str, document: Any) -> _FakeIAM:
    arn = f"arn:aws:iam::123456789012:policy/{policy_name}"
    return _FakeIAM(
        attached=[{"PolicyName": policy_name, "PolicyArn": arn}],
        managed_docs={arn: document},
    )


def test_iam_analyze_flags_admin_managed_policy() -> None:
    body = _analyze(_iam_with_managed("admin", _ADMIN_DOC))
    assert body["overly_permissive"] is True
    stmt = body["concerning_statements"][0]
    assert stmt["admin"] is True
    assert stmt["source"] == "managed:admin"


def test_iam_analyze_benign_policy_not_flagged() -> None:
    assert _analyze(_iam_with_managed("ro", _BENIGN_DOC))["overly_permissive"] is False


def test_iam_analyze_flags_inline_admin() -> None:
    iam = _FakeIAM(inline=["god"], inline_docs={"god": _ADMIN_DOC})
    body = _analyze(iam)
    assert body["overly_permissive"] is True
    assert body["concerning_statements"][0]["source"] == "inline:god"


def test_iam_analyze_flags_service_wildcard_on_all_resources() -> None:
    body = _analyze(_iam_with_managed("s3all", _SERVICE_WILDCARD_DOC))  # single-dict statement
    stmt = body["concerning_statements"][0]
    assert stmt["admin"] is False
    assert stmt["action_wildcard"] is False
    assert stmt["resource_wildcard"] is True


def test_iam_analyze_deny_star_not_flagged() -> None:
    assert _analyze(_iam_with_managed("deny", _DENY_STAR_DOC))["overly_permissive"] is False


def test_iam_analyze_decodes_urlencoded_document() -> None:
    # get_policy_version can return the document URL-encoded; it must still be analyzed.
    iam = _iam_with_managed("admin", quote(json.dumps(_ADMIN_DOC)))
    assert _analyze(iam)["overly_permissive"] is True


def test_iam_analyze_rejects_bad_principal_type() -> None:
    assert json.loads(aws.iam_analyze_principal("alice", "group"))["success"] is False


def test_iam_analyze_requires_name() -> None:
    set_active_policy(_policy())
    assert json.loads(aws.iam_analyze_principal("", "user"))["success"] is False


def test_iam_analyze_refused_out_of_scope() -> None:
    set_active_policy(_policy(cloud={"aws_account_ids": ["999999999999"]}))
    assert json.loads(aws.iam_analyze_principal("alice", "user"))["refused"] == "out_of_scope"


def test_iam_analyze_records_policy_fetch_errors() -> None:
    class _RaisingIAM(_FakeIAM):
        def get_policy(self, **_: Any) -> dict[str, Any]:
            raise ClientError({"Error": {"Code": "AccessDenied"}}, "GetPolicy")

    arn = "arn:aws:iam::123456789012:policy/x"
    iam = _RaisingIAM(attached=[{"PolicyName": "x", "PolicyArn": arn}])
    body = _analyze(iam)
    assert body["success"] is True
    assert body["overly_permissive"] is False
    assert any("managed:x" in e for e in body["errors"])


# --- ec2 security groups -----------------------------------------------------

def _ec2(groups: list[dict[str, Any]]) -> dict[str, Any]:
    set_active_policy(_policy())
    aws.set_client_factory(_factory(ec2=_FakeEC2(groups)))
    return json.loads(aws.ec2_list_open_security_groups("us-east-1"))


def test_ec2_flags_world_open_sg() -> None:
    perm = {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
    }
    body = _ec2([{"GroupId": "sg-1", "GroupName": "web", "IpPermissions": [perm]}])
    assert body["has_world_open"] is True
    group = body["world_open_groups"][0]
    assert group["group_id"] == "sg-1"
    assert group["open_ingress"][0]["from_port"] == 22
    assert group["open_ingress"][0]["cidr"] == "0.0.0.0/0"


def test_ec2_ignores_restricted_sg() -> None:
    perm = {
        "IpProtocol": "tcp",
        "FromPort": 3306,
        "ToPort": 3306,
        "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
    }
    body = _ec2([{"GroupId": "sg-2", "GroupName": "db", "IpPermissions": [perm]}])
    assert body["has_world_open"] is False


def test_ec2_flags_ipv6_world_open() -> None:
    perm = {"IpProtocol": "-1", "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}
    body = _ec2([{"GroupId": "sg-3", "GroupName": "v6", "IpPermissions": [perm]}])
    assert body["has_world_open"] is True
    assert body["world_open_groups"][0]["open_ingress"][0]["cidr"] == "::/0"


def test_ec2_refused_out_of_scope() -> None:
    set_active_policy(_policy(cloud={"aws_account_ids": ["999999999999"]}))
    refused = json.loads(aws.ec2_list_open_security_groups("us-east-1"))
    assert refused["refused"] == "out_of_scope"


# --- secrets manager ---------------------------------------------------------

def test_secretsmanager_lists_names_only() -> None:
    set_active_policy(_policy())
    secrets = [{"Name": "prod/db", "ARN": "arn:...:prod/db", "RotationEnabled": True}]
    aws.set_client_factory(_factory(secretsmanager=_FakeSecretsManager(secrets)))
    body = json.loads(aws.secretsmanager_list_secrets("us-east-1"))
    assert body["success"] is True
    assert body["secret_count"] == 1
    assert body["secrets"][0]["name"] == "prod/db"
    assert body["secrets"][0]["rotation_enabled"] is True
    assert "value" not in body["secrets"][0]  # never reads secret values


def test_secretsmanager_refused_out_of_scope() -> None:
    set_active_policy(_policy(cloud={"aws_account_ids": ["999999999999"]}))
    refused = json.loads(aws.secretsmanager_list_secrets("us-east-1"))
    assert refused["refused"] == "out_of_scope"


# --- ec2 public snapshots ----------------------------------------------------

def test_ec2_flags_public_ebs_snapshot() -> None:
    set_active_policy(_policy())
    ec2 = _FakeEC2(
        snapshots=[{"SnapshotId": "snap-1", "VolumeId": "vol-1", "VolumeSize": 8}],
        snapshot_permissions={"snap-1": [{"Group": "all"}]},
    )
    aws.set_client_factory(_factory(ec2=ec2))
    body = json.loads(aws.ec2_list_public_snapshots("us-east-1"))
    assert body["success"] is True
    assert body["has_public_snapshots"] is True
    assert body["public_snapshots"][0]["snapshot_id"] == "snap-1"


def test_ec2_ignores_private_ebs_snapshot() -> None:
    set_active_policy(_policy())
    ec2 = _FakeEC2(
        snapshots=[{"SnapshotId": "snap-2", "VolumeId": "vol-2"}],
        snapshot_permissions={"snap-2": [{"UserId": "123456789012"}]},
    )
    aws.set_client_factory(_factory(ec2=ec2))
    body = json.loads(aws.ec2_list_public_snapshots("us-east-1"))
    assert body["has_public_snapshots"] is False


def test_ec2_public_snapshots_refused_out_of_scope() -> None:
    set_active_policy(_policy(cloud={"aws_account_ids": ["999999999999"]}))
    assert json.loads(aws.ec2_list_public_snapshots())["refused"] == "out_of_scope"


# --- rds public exposure -----------------------------------------------------

def test_rds_flags_public_instance() -> None:
    set_active_policy(_policy())
    rds = _FakeRDS(
        instances=[
            {
                "DBInstanceIdentifier": "prod",
                "Engine": "postgres",
                "PubliclyAccessible": True,
                "Endpoint": {"Address": "prod.rds.amazonaws.com", "Port": 5432},
                "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-1"}],
            },
            {"DBInstanceIdentifier": "internal", "PubliclyAccessible": False},
        ]
    )
    aws.set_client_factory(_factory(rds=rds))
    body = json.loads(aws.rds_list_public_instances("us-east-1"))
    assert body["success"] is True
    assert body["has_public_instances"] is True
    assert len(body["public_instances"]) == 1
    inst = body["public_instances"][0]
    assert inst["db_instance_identifier"] == "prod"
    assert inst["port"] == 5432
    assert inst["vpc_security_groups"] == ["sg-1"]


def test_rds_no_public_instances() -> None:
    set_active_policy(_policy())
    rds = _FakeRDS(instances=[{"DBInstanceIdentifier": "internal", "PubliclyAccessible": False}])
    aws.set_client_factory(_factory(rds=rds))
    assert json.loads(aws.rds_list_public_instances())["has_public_instances"] is False


def test_rds_flags_public_snapshot() -> None:
    set_active_policy(_policy())
    rds = _FakeRDS(
        snapshots=[
            {"DBSnapshotIdentifier": "snap-pub", "Engine": "mysql"},
            {"DBSnapshotIdentifier": "snap-priv", "Engine": "mysql"},
        ],
        snapshot_restore={"snap-pub": ["all"], "snap-priv": ["123456789012"]},
    )
    aws.set_client_factory(_factory(rds=rds))
    body = json.loads(aws.rds_list_public_snapshots("us-east-1"))
    assert body["has_public_snapshots"] is True
    assert [s["db_snapshot_identifier"] for s in body["public_snapshots"]] == ["snap-pub"]


def test_rds_snapshot_attribute_error_recorded() -> None:
    class _RaisingRDS(_FakeRDS):
        def describe_db_snapshot_attributes(self, **_: Any) -> dict[str, Any]:
            raise ClientError({"Error": {"Code": "AccessDenied"}}, "DescribeDBSnapshotAttributes")

    set_active_policy(_policy())
    rds = _RaisingRDS(snapshots=[{"DBSnapshotIdentifier": "snap-x"}])
    aws.set_client_factory(_factory(rds=rds))
    body = json.loads(aws.rds_list_public_snapshots())
    assert body["success"] is True
    assert body["has_public_snapshots"] is False
    assert any("snap-x" in e for e in body["errors"])


def test_rds_refused_out_of_scope() -> None:
    set_active_policy(_policy(cloud={"aws_account_ids": ["999999999999"]}))
    assert json.loads(aws.rds_list_public_instances())["refused"] == "out_of_scope"


# --- kms ---------------------------------------------------------------------

_WILDCARD_KEY_POLICY = {
    "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "kms:Decrypt"}]
}
_WILDCARD_WITH_CONDITION = {
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": "kms:Decrypt",
            "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-123"}},
        }
    ]
}
_SCOPED_KEY_POLICY = {
    "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "Action": "*"}
    ]
}


def test_kms_list_keys_with_aliases() -> None:
    set_active_policy(_policy())
    kms = _FakeKMS(
        keys=[{"KeyId": "key-1"}, {"KeyId": "key-2"}],
        aliases=[{"AliasName": "alias/prod", "TargetKeyId": "key-1"}],
    )
    aws.set_client_factory(_factory(kms=kms))
    body = json.loads(aws.kms_list_keys("us-east-1"))
    assert body["success"] is True
    assert body["key_count"] == 2
    by_id = {k["key_id"]: k for k in body["keys"]}
    assert by_id["key-1"]["aliases"] == ["alias/prod"]
    assert by_id["key-2"]["aliases"] == []


def test_kms_flags_wildcard_principal_policy() -> None:
    set_active_policy(_policy())
    kms = _FakeKMS(policies={"key-1": _WILDCARD_KEY_POLICY})
    aws.set_client_factory(_factory(kms=kms))
    body = json.loads(aws.kms_analyze_key_policy("key-1", "us-east-1"))
    assert body["externally_exposed"] is True
    assert body["concerning_statements"][0]["principal_wildcard"] is True


def test_kms_wildcard_with_condition_not_flagged() -> None:
    set_active_policy(_policy())
    kms = _FakeKMS(policies={"key-1": _WILDCARD_WITH_CONDITION})
    aws.set_client_factory(_factory(kms=kms))
    assert json.loads(aws.kms_analyze_key_policy("key-1"))["externally_exposed"] is False


def test_kms_scoped_policy_not_flagged() -> None:
    set_active_policy(_policy())
    kms = _FakeKMS(policies={"key-1": _SCOPED_KEY_POLICY})
    aws.set_client_factory(_factory(kms=kms))
    assert json.loads(aws.kms_analyze_key_policy("key-1"))["externally_exposed"] is False


def test_kms_analyze_requires_key_id() -> None:
    set_active_policy(_policy())
    assert json.loads(aws.kms_analyze_key_policy(""))["success"] is False


def test_kms_refused_out_of_scope() -> None:
    set_active_policy(_policy(cloud={"aws_account_ids": ["999999999999"]}))
    assert json.loads(aws.kms_list_keys())["refused"] == "out_of_scope"


# --- auto-wire (applicable_builtin_configs / configs_with_builtins) -----------

def test_applicable_builtins_attaches_aws_when_in_scope() -> None:
    set_active_policy(_policy())  # has cloud.aws_account_ids
    configs = applicable_builtin_configs(set())
    assert [c.name for c in configs] == ["strix-aws"]


def test_applicable_builtins_empty_without_aws_scope() -> None:
    set_active_policy(ScopePolicy.model_validate({"web": {"domains": ["example.com"]}}))
    assert applicable_builtin_configs(set()) == []


def test_applicable_builtins_empty_without_policy() -> None:
    set_active_policy(None)
    assert applicable_builtin_configs(set()) == []


def test_applicable_builtins_skips_user_configured_name() -> None:
    set_active_policy(_policy())
    assert applicable_builtin_configs({"strix-aws"}) == []


def test_auto_wrappers_env_opt_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX2_AUTO_WRAPPERS", "0")
    set_active_policy(_policy())
    assert applicable_builtin_configs(set()) == []


def test_configs_with_builtins_appends_and_user_wins() -> None:
    set_active_policy(_policy())
    user = [McpConnectionConfig(name="github", transport="stdio", command="x")]
    assert [c.name for c in configs_with_builtins(user)] == ["github", "strix-aws"]

    # A user's own strix-aws entry wins: no duplicate is appended.
    mine = [McpConnectionConfig(name="strix-aws", transport="stdio", command="mine")]
    merged = configs_with_builtins(mine)
    assert [c.name for c in merged] == ["strix-aws"]
    assert merged[0].command == "mine"
