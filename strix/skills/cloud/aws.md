---
name: aws
description: AWS cloud security testing covering IAM misconfigurations, S3 exposure, metadata abuse, and privilege escalation paths
---

# AWS Cloud Security

AWS misconfigurations frequently expose credentials, data, and lateral movement paths. This skill covers direct AWS API testing and post-compromise enumeration from EC2/Lambda/container workloads. For SSRF-mediated metadata access, combine with the ssrf skill.

## Attack Surface

**Identity**
- IAM users, roles, groups, policies (inline and managed)
- Access keys, session tokens, SSO/SAML federation
- Cross-account roles, trust policies, permission boundaries

**Storage & Data**
- S3 buckets, objects, bucket policies, ACLs, Block Public Access settings
- EBS snapshots, RDS snapshots, AMIs shared publicly
- Secrets Manager, SSM Parameter Store, KMS keys

**Compute**
- EC2 instances, Lambda functions, ECS/EKS tasks
- Instance metadata service (IMDSv1/v2) at `169.254.169.254`
- User data, launch templates, AMIs

**Network**
- Security groups, NACLs, VPC endpoints, public subnets
- ELB/ALB/CloudFront misconfigurations

**Management**
- CloudTrail, Config, GuardDuty gaps
- Cognito user pools, API Gateway, AppSync

## Reconnaissance

**Credential Discovery**
- Environment variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
- `~/.aws/credentials`, `~/.aws/config`, CI/CD env vars, `.env` files
- Hardcoded keys in source, mobile apps, JavaScript bundles

**Unauthenticated Enumeration**

Use two separate checks — they answer different questions and must not be conflated:

**1. Bucket existence (does the name resolve?)**

Goal: learn whether a bucket name exists in AWS, without needing `s3:ListBucket`.
- `head-bucket` or `curl -I` HTTP status is the signal — not `aws s3 ls`.
- `403 Forbidden` → bucket exists but you lack access (private or wrong account).
- `404 Not Found` → bucket does not exist in that region, or name is wrong.

```
aws s3api head-bucket --bucket target-bucket --no-sign-request 2>&1
curl -I https://target-bucket.s3.amazonaws.com/
```

**2. Public listing (is ListBucket granted to anonymous users?)**

Goal: confirm `s3:ListBucket` is publicly granted — a separate and stronger finding than existence alone.
- Only run `aws s3 ls` for this step; a successful listing returns object keys/prefixes.
- Failure here does not disprove existence (a private bucket still returns 403 on list).

```
aws s3 ls s3://target-bucket --no-sign-request
```

**Authenticated Enumeration (with any credentials)**
```
aws sts get-caller-identity
aws iam get-account-authorization-details 2>/dev/null
aws iam list-users
aws iam list-roles
aws iam list-attached-user-policies --user-name <user>
aws s3 ls
aws ec2 describe-instances
```

## Key Vulnerabilities

### S3 Misconfigurations

- Public read/write buckets (ACL `public-read`, policy `"Principal":"*"`)
- AuthenticatedUsers group grants (`http://acs.amazonaws.com/groups/global/AuthenticatedUsers`)
- ListBucket enabled publicly → object key enumeration
- Sensitive object keys guessable: `backup/`, `db/`, `.env`, `config/`, `logs/`

**Test:**
```
aws s3 ls s3://BUCKET --no-sign-request
aws s3 cp s3://BUCKET/sensitive-file . --no-sign-request
curl https://BUCKET.s3.amazonaws.com/
```

### IAM Privilege Escalation

Common escalation paths (verify with `aws iam simulate-principal-policy` when possible):

| Permission | Escalation |
|------------|------------|
| `iam:CreatePolicyVersion` | Attach admin policy version to self |
| `iam:SetDefaultPolicyVersion` | Roll back to older permissive policy version |
| `iam:PassRole` + `lambda:CreateFunction` | Create Lambda with admin role, invoke |
| `iam:PassRole` + `ec2:RunInstances` | Launch EC2 with instance profile |
| `sts:AssumeRole` on overprivileged role | Cross-account or same-account pivot |
| `iam:UpdateAssumeRolePolicy` | Add self to trust policy of privileged role |
| `iam:AttachUserPolicy` / `PutUserPolicy` | Self-grant admin |

**Test:**
```
aws iam list-attached-user-policies --user-name $(aws sts get-caller-identity --query Arn --output text | cut -d/ -f2)
aws iam simulate-principal-policy --policy-source-arn <arn> --action-names iam:CreateAccessKey --resource-arns "*"
```

### Instance Metadata Abuse

**IMDSv1 (no token required)**
```
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
curl http://169.254.169.254/latest/user-data
```

**IMDSv2 bypass contexts**
- SSRF with header injection if server forwards `X-aws-ec2-metadata-token`
- Container sidecars without hop limit enforcement
- Misconfigured proxies allowing link-local access

### Snapshot and Backup Exposure

- Public EBS/RDS snapshots: `aws ec2 describe-snapshots --restorable-by-user-names all`
- AMIs with `Public` launch permission containing secrets or keys
- Backup vaults cross-account without proper isolation

### Lambda and Serverless

- Overprivileged execution roles (`AdministratorAccess` on Lambda role)
- Environment variables containing secrets (visible via `lambda:GetFunctionConfiguration`)
- Function URLs or API Gateway without auth
- Event source mappings triggering on attacker-controlled events

### Cognito Misconfigurations

- Self-signup enabled with elevated default group membership
- Missing app client secret on confidential flows
- Custom attribute write permissions allowing privilege fields (`custom:role`, `custom:admin`)
- ID token custom claims trusted by backend without verification

### KMS and Secrets

- KMS key policies allowing `Principal: *` or overly broad accounts
- Secrets Manager secrets readable by unintended roles
- SSM parameters under `/` with `GetParameter` for unauthenticated or low-priv callers

## Advanced Techniques

**Cross-Account Role Assumption**
- Find roles trusting `*` or external accounts broadly
- Confused deputy: service assumes role without external ID validation

**CloudFront Origin Exposure**
- Origin pointing directly to S3 website or ALB bypassing WAF
- Signed URL/cookie misconfiguration allowing object access

**Resource-Based Policy Gaps**
- S3 bucket policy allowing `s3:GetObject` from unintended principals
- Lambda resource policy `Principal: *` with weak condition keys

## Testing Methodology

1. **Discover credentials** — Keys in code, env, metadata, or SSRF
2. **Identify principal** — `get-caller-identity`, map effective permissions
3. **Enumerate resources** — S3, EC2, IAM, Lambda within policy bounds
4. **Escalation paths** — Run escalation checklist against attached policies
5. **Data exposure** — Public buckets, snapshots, secrets, user-data scripts
6. **Persistence** — New access keys, backdoor roles, Lambda triggers (only in authorized scope)

## Validation

1. Demonstrate unauthorized read/write of S3 objects or snapshots with evidence (object keys, ETags)
2. Show IAM escalation from low-priv to higher-priv with exact API calls and resulting permissions
3. Prove metadata credential theft path (SSRF or IMDS) with redacted temporary credentials scope
4. Document resource ARN, policy statement, and misconfiguration root cause
5. Confirm fix would block the specific principal/action/resource combination

## False Positives

- Intentionally public static assets bucket with no sensitive keys
- Read-only `s3:ListBucket` on empty marketing bucket
- Metadata endpoint unreachable from tested context (no SSRF, IMDSv2 enforced with hop limit)
- Simulated escalation blocked by permission boundary or SCP
- 403 on S3 that indicates existence but not readable content (still note for recon, not data breach)

## Impact

- Mass data exfiltration from S3/RDS/snapshots
- Full account or organization compromise via IAM escalation
- Persistent backdoor access through new keys or roles
- Regulatory exposure (PII/PCI in unencrypted public buckets)

## Pro Tips

1. Always run `get-caller-identity` first to know your effective principal
2. Distinguish 403 vs 404 on S3 — both are useful, mean different things
3. Check instance profile role, not just user credentials, from metadata
4. Review trust policies on roles, not just permission policies
5. Combine with subdomain takeover — dangling S3 bucket names in DNS CNAMEs

## Tooling

Prefer credential-light, install-once CLIs. The sandbox has `awscli`/`python`/`pipx`/`go` and build-time egress.

- **awscli** — the primary enumeration tool (used throughout this skill). Always start with `aws sts get-caller-identity`.
- **enumerate-iam** (andresriancho) — tiny script that brute-forces which API calls a set of keys can make when you can't read your own policy:
  ```
  git clone https://github.com/andresriancho/enumerate-iam && cd enumerate-iam
  pip install -r requirements.txt
  python enumerate-iam.py --access-key AKIA... --secret-key ...
  ```
- **cloudsplaining** (Salesforce) — offline IAM policy risk analysis; finds privilege-escalation/resource-exposure in the auth-details JSON:
  ```
  pipx install cloudsplaining
  aws iam get-account-authorization-details > auth.json
  cloudsplaining scan --input-file auth.json
  ```
- **CloudFox** (BishopFox) — single Go binary for fast post-compromise inventory and "what can I do from here" surfacing: `cloudfox aws --profile <profile> all-checks`
- **Pacu** (Rhino Security Labs) — the standard AWS exploitation framework; heavier, but its `iam__privesc_scan` module automates the escalation table above. Use for a full exploitation session (`run iam__enum_permissions`, then `run iam__privesc_scan`).

## Summary

AWS security requires least-privilege IAM, blocked public data paths, IMDSv2 with hop limits, and tight resource policies. Enumerate from any credential found — even limited read access often reveals escalation chains.
