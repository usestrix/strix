---
name: iam_privilege_escalation
description: Cross-cloud IAM privilege-escalation chains (AWS, Azure, GCP) covering confused-deputy, service-account impersonation, PIM gaps, and Cognito unauthenticated-role abuse — deepens the aws/azure/gcp skills, doesn't duplicate them
---

# Cloud IAM Privilege Escalation (Cross-Cloud)

The `aws`, `azure`, and `gcp` skills cover per-provider misconfiguration classes; this skill focuses specifically on **escalation chains** — the sequence of individually-plausible permissions that combine into "low-priv identity becomes admin." Load this alongside the relevant provider skill, not instead of it. Every technique here assumes you already have *some* credential (a leaked key, an SSRF-reached metadata endpoint, a low-priv service account) — the question is how far it goes.

## AWS: IAM Privilege-Escalation Methods

These are the concrete, individually-documented paths from a set of IAM permissions to effective admin. Check the actual attached policy (not just role name) for each — a role named `ReadOnlyAuditor` with one of these permissions attached is still exploitable.

| # | Permission(s) | Path |
|---|---|---|
| 1 | `iam:CreatePolicyVersion` | Create a new default policy version granting `*:*` on your own attached policy |
| 2 | `iam:SetDefaultPolicyVersion` | Roll back to a previously-created permissive policy version |
| 3 | `iam:CreateAccessKey` | Create access key for a higher-privileged user you have this permission on |
| 4 | `iam:CreateLoginProfile` | Set console password for a user with no existing login profile |
| 5 | `iam:UpdateLoginProfile` | Reset console password for a user with an existing profile |
| 6 | `iam:AttachUserPolicy` / `AttachGroupPolicy` / `AttachRolePolicy` | Attach `AdministratorAccess` to self/own group/own role |
| 7 | `iam:PutUserPolicy` / `PutGroupPolicy` / `PutRolePolicy` | Inline-policy equivalent of #6 |
| 8 | `iam:AddUserToGroup` | Add self to a privileged group |
| 9 | `iam:UpdateAssumeRolePolicy` + `sts:AssumeRole` | Modify a role's trust policy to allow yourself, then assume it |
| 10 | `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` (or an auto-invoking trigger) | Pass a privileged role to a new Lambda, invoke it, execute arbitrary code with that role's permissions |
| 11 | `iam:PassRole` + `lambda:CreateFunction` + `lambda:UpdateFunctionCode` | Same as #10 targeting an *existing* function's code |
| 12 | `iam:PassRole` + `ec2:RunInstances` | Launch EC2 with a privileged instance profile, retrieve credentials via IMDS |
| 13 | `iam:PassRole` + `glue:CreateDevEndpoint` | Glue dev endpoint with SSH access runs with the passed role |
| 14 | `iam:PassRole` + `glue:UpdateJob`/`glue:CreateJob` + `glue:StartJobRun` | Run arbitrary code via Glue job with the passed role |
| 15 | `iam:PassRole` + `datapipeline:CreatePipeline`+ related | Data Pipeline equivalent of the Glue path |
| 16 | `iam:PassRole` + `cloudformation:CreateStack` | Stack executes with the passed role, can contain arbitrary resource creation |
| 17 | `iam:PassRole` + `sagemaker:CreateNotebookInstance` (or `CreatePresignedNotebookInstanceUrl`) | Notebook runs with attached role, gives interactive code execution |
| 18 | `iam:PassRole` + `codestar:CreateProject` | Legacy CodeStar project-creation path |
| 19 | `sts:AssumeRole` on an overprivileged same/cross-account role with a broad trust policy | Direct pivot, no other permission needed |
| 20 | `organizations:*` on a management-account principal | Cross-account escalation across the entire AWS Organization |

**Verification without executing:** `aws iam simulate-principal-policy --policy-source-arn <your-arn> --action-names <candidate-action> --resource-arns "*"` confirms whether a path is actually allowed before you act on it.

## AWS Cognito Identity Pool: Unauthenticated-Role Abuse Chain

A distinct, frequently-missed AWS escalation path that doesn't require any pre-existing credential — it starts from an app's public Cognito Identity Pool ID (often visible in JS bundles/mobile app configs):
```
1. GetId              — cognito-identity.<region>.amazonaws.com, using the public IdentityPoolId,
                         no auth required if "unauthenticated identities" are enabled on the pool
2. GetCredentialsForIdentity — exchange the identity ID for temporary AWS credentials
3. sts get-caller-identity — confirm the assumed role, then enumerate what that role can actually do
```
The unauthenticated role is frequently over-scoped (intended for "read a public config" but attached a broader policy). Enumerate its effective permissions the same as any other found credential — this is a zero-credential entry point into the escalation table above.

## Azure: Managed Identity, PIM, and Role-Chain Escalation

- **Managed Identity abuse via SSRF** — if an app is vulnerable to SSRF and runs on Azure compute with a system/user-assigned Managed Identity, the IMDS-equivalent endpoint (`http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=<resource>`, requiring `Metadata: true` header) yields an OAuth token for that identity — same pattern as AWS IMDS, different header requirement.
- **PIM (Privileged Identity Management) eligible-role gaps** — a user "eligible" for a role but not currently "active" in it still represents a viable target: check whether self-activation requires approval/MFA or is auto-approved, and whether the eligible assignment itself was scoped too broadly (subscription-level eligibility for a role only meant for one resource group).
- **Owner-on-subscription-via-Contributor chains** — `Contributor` role does *not* grant RBAC role-assignment rights by default, but specific resource-level permissions can still chain to broader control: a Contributor able to deploy an ARM/Bicep template that includes a `Microsoft.Authorization/roleAssignments` resource, if the deployment's own permissions allow it, self-escalates to Owner.
- **App Registration / Service Principal credential abuse** — an Azure AD user with `Application Administrator` (or even more narrowly, ownership of a single App Registration) can add a new client secret/certificate to any Service Principal the app is tied to, inheriting whatever Azure RBAC roles or Graph API permissions that Service Principal holds.

## GCP: Service-Account Impersonation Chains

- **`iam.serviceAccounts.actAs` abuse** — the GCP equivalent of AWS `iam:PassRole`: any principal with this permission on a service account can attach it to a new resource (Compute instance, Cloud Function, Cloud Run service) and that resource then runs with the service account's permissions.
- **Service-account impersonation chains** — `roles/iam.serviceAccountTokenCreator` on SA-B, granted to SA-A, lets SA-A mint OAuth tokens *as* SA-B directly (`gcloud auth print-access-token --impersonate-service-account=SA-B`) without deploying any resource at all. Walk the IAM policy graph for chained `serviceAccountTokenCreator` grants — these compose (A can impersonate B, B can impersonate C).
- **Cloud Build default service account over-permission** — the default Cloud Build SA historically carries Editor-equivalent project permissions; anyone who can trigger a Cloud Build job (including via a connected GitHub repo with weak trigger restrictions) gets that SA's permissions inside the build.
- **Enumeration**: `gcloud projects get-iam-policy <project> --format=json` then trace every `serviceAccountUser`/`serviceAccountTokenCreator`/`actAs`-equivalent binding for chains, the same way you'd trace AWS `PassRole` + resource-creation pairs.

## Cross-Account / Cross-Tenant Confused-Deputy Patterns

Common to AWS cross-account roles and Azure/GCP cross-tenant delegation alike: a trust policy that grants access to any principal from a third-party account **without** an external-ID/condition check lets any tenant of that third-party service assume the role, not just the intended customer.
```
# AWS: flag any trust policy missing an ExternalId condition on a cross-account principal
"Principal": {"AWS": "arn:aws:iam::<third-party-account>:root"}   # no "Condition": {"StringEquals": {"sts:ExternalId": ...}}
```

## IMDSv1-vs-v2 (AWS) as the Credential-Theft Vector Feeding Every Chain Above

Every AWS escalation path in this skill assumes a starting credential — SSRF-to-IMDS is frequently that starting point:
```
# IMDSv1 — no token, directly SSRF-able with a simple GET
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>

# IMDSv2 — requires a PUT for a session token first; still SSRF-able if the
# vulnerable endpoint allows arbitrary methods/headers (many proxy-based SSRF
# primitives do not, which is IMDSv2's actual mitigation value)
curl -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
```
Confirm which IMDS version is enforced and whether the specific SSRF primitive you have can perform a PUT with custom headers — this determines whether IMDSv2 actually blocks the chain or not.

## Testing Methodology

1. **Establish starting identity** — whatever credential/token you have, confirm it (`get-caller-identity` / token introspection / `gcloud auth list`).
2. **Enumerate attached/effective permissions** — not just the role name; pull the actual policy document.
3. **Match against the escalation tables above** — check each row's required permission(s) against what you have.
4. **Verify before acting** — use policy-simulation calls (`iam simulate-principal-policy`, Azure `Microsoft.Authorization/roleAssignments` read, GCP `testIamPermissions`) to confirm a path is real before executing it.
5. **Walk chains, not single hops** — service-account/role impersonation composes; trace the full graph (A can act as B, B can act as C) rather than stopping at the first hop.
6. **Check the zero-credential entry points** — Cognito unauthenticated identity pools, publicly-triggerable Cloud Build, SSRF-reachable metadata endpoints — before assuming you need a leaked credential to start.

## Validation

1. Show the specific permission(s) matched against the specific escalation-table row, with the actual policy document excerpt as evidence.
2. Demonstrate the resulting elevated access with one bounded action (e.g. `get-caller-identity` after assuming the new role) — not a destructive or persistent change.
3. For chains, document every hop with its own evidence, not just the final privileged state.

## False Positives

- Permission present in policy but blocked by a Service Control Policy (AWS), Azure Policy/deny assignment, or GCP Organization Policy constraint at a higher scope — always verify with a simulation call, not just the identity-level policy.
- `iam:PassRole` present but scoped to a resource ARN/tag condition that excludes the privileged role you're targeting.
- Cross-account trust policy has a broad principal but a strong `ExternalId` condition that isn't guessable/known.

## Impact

Every path in this skill ends the same way: a low-privilege identity becomes a fully privileged one, typically account/subscription/project-admin equivalent. Combined with the fact that many of these paths require only a single specific permission (not a broad role), they're frequently missed by role-name-based reviews that never check the actual attached policy documents.

## Pro Tips

1. Always pull the actual policy JSON — role and permission *names* lie ("ReadOnlyAuditor" with `iam:PutUserPolicy` attached is not read-only).
2. Chains compose — don't stop enumerating after finding one non-escalating permission; the escalation may need two or three hops across service-account/role impersonation.
3. The Cognito unauthenticated-identity-pool path needs zero starting credential and is commonly missed because it's not "IAM" in the traditional sense — check it on any app using AWS-backed mobile/web auth.
4. IMDSv2 is a mitigation, not a fix — confirm whether your specific SSRF primitive can actually perform the required PUT-with-headers before assuming it blocks the chain.

## Tooling

Provider CLIs (`awscli`, `az`, `gcloud`) cover everything in this skill; no additional tooling needed beyond what the `aws`/`azure`/`gcp` skills already reference.
```
pip install pmapper    # AWS IAM privilege-escalation graph analysis, offline against pulled policy data
```
- **PMapper** (NCC Group) — builds a graph of IAM principals and their effective escalation paths offline from `iam get-account-authorization-details` output; directly automates the AWS table above (`pmapper graph create`, `pmapper query "who can do iam:CreatePolicyVersion"`).
- **ScoutSuite** — cross-provider (AWS/Azure/GCP) configuration auditing if a broader sweep is needed before narrowing to specific escalation chains.

## Summary

IAM privilege escalation is a graph-traversal problem, not a single-permission lookup: establish your starting identity, pull its actual effective policy (not its name), match against the documented per-provider escalation paths, and walk chains across service-account/role impersonation rather than stopping at the first hop. Check the zero-credential entry points (Cognito unauthenticated pools, SSRF-to-IMDS, publicly-triggerable Cloud Build) before assuming a leaked credential is required to start.
