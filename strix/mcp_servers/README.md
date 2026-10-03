# Strix 2 host-side MCP wrapper servers

These are small, standalone **`stdio` MCP servers** that wrap host-side security tooling and are reached by
the pentest agent through the generic MCP bridge (`call_mcp`). They run as subprocesses in Strix's own
virtualenv, so — unlike the in-sandbox tools — they can hold the operator's credentials **on the host**
(never shipped into the sandbox container) and reuse the scope engine (`strix.scope`) in-process.

Only host-side tooling belongs here (cloud first). Network/infra CLIs already live in the sandbox image and
are reached via `exec_command`; a host-side subprocess cannot see them, so they are **not** wrapped here —
see `docs/strix2/01-design-log.md` (Phase 1) for the architecture decision.

## Scope is mandatory and fail-closed

Every wrapped tool refuses to act unless an authorized `scope.yaml` is loaded **and** authorizes the
target. This is stricter than upstream's web/MCP boundary (which is a deliberate no-op without a policy).
Point Strix at a scope file with `--scope-config PATH` (or `STRIX_SCOPE_CONFIG`); intrusive/state-changing
actions additionally require `--allow-intrusive`.

## AWS wrapper (`strix.mcp_servers.aws`)

Read-only AWS checks under the operator's own credentials (standard boto3 resolution), gated on the acting
account being listed in `cloud.aws_account_ids`:

| Tool | What it does | Tier |
|---|---|---|
| `aws_whoami` | STS caller identity (names the principal) | — |
| `s3_list_buckets` | list bucket names | recon |
| `s3_get_bucket_public_status` | ACL / policy-status / public-access-block → `looks_public` | **candidate** signal |
| `s3_get_object_head` | bounded ≤1 KiB object read + SHA-256 (request + response captured) | **validated** evidence |
| `iam_list_principals` | list IAM users and roles | recon |
| `iam_analyze_principal` | read a user/role's managed + inline policies, flag wildcard/admin (`*`) grants | **candidate** signal |
| `ec2_list_open_security_groups` | inbound rules open to `0.0.0.0/0` / `::/0`, with port range | **candidate** signal |
| `ec2_list_public_snapshots` | EBS snapshots whose `createVolumePermission` is shared with `all` | **candidate** signal |
| `rds_list_public_instances` | DB instances with `PubliclyAccessible=True` | **candidate** signal |
| `rds_list_public_snapshots` | manual DB snapshots whose `restore` attribute includes `all` | **candidate** signal |
| `kms_list_keys` | list KMS keys + aliases | recon |
| `kms_analyze_key_policy` | flag a key policy that allows a wildcard principal (`*`) with no condition | **candidate** signal |
| `secretsmanager_list_secrets` | secret names + metadata (never values) | recon |

The wrapper returns evidence; the agent files it with `create_candidate` / `create_vulnerability_report`.

## Registering it

Add an entry to `~/.strix/mcp-servers.json` (a JSON **list**), or write a file and pass it with
`--mcp-config`. Generate an accurate entry for your environment:

```bash
python -c "import json; from strix.mcp_servers.registry import aws_wrapper_config; \
print(json.dumps([aws_wrapper_config(region='us-east-1').model_dump(exclude_none=True, exclude_defaults=True)], indent=2))"
```

Example:

```json
[
  {
    "name": "strix-aws",
    "transport": "stdio",
    "command": "python",
    "args": ["-m", "strix.mcp_servers.aws"],
    "env": { "STRIX_SCOPE_CONFIG": "scope.yaml", "AWS_DEFAULT_REGION": "us-east-1" },
    "allowed_tools": ["aws_whoami", "s3_list_buckets", "s3_get_bucket_public_status", "s3_get_object_head"]
  }
]
```

AWS credentials come from the host environment / shared config (env vars, `~/.aws`, SSO, instance role) —
the wrapper never receives them from Strix and never puts them in the sandbox.
