---
name: gcp
description: GCP cloud security testing covering IAM misconfigurations, public storage buckets, metadata abuse, and service account privilege escalation
---

# Google Cloud Platform (GCP)

GCP misconfigurations expose project data, service account keys, and lateral movement paths across Compute, Cloud Storage, Cloud Functions, and GKE. This skill covers direct GCP API testing and post-compromise enumeration from VMs/containers. For SSRF-mediated metadata access, combine with the `ssrf` skill.

## Attack Surface

**Identity**
- IAM policies: project/folder/org level bindings
- Service accounts, keys (JSON), Workload Identity, impersonation
- OAuth scopes on compute instances and Cloud Functions

**Storage & Data**
- Cloud Storage (GCS) buckets and objects
- BigQuery datasets, Cloud SQL instances, Firestore (see `firebase_firestore` skill)
- Secret Manager, Cloud KMS keys

**Compute**
- Compute Engine VMs, Cloud Run, Cloud Functions, GKE clusters
- Metadata server at `http://metadata.google.internal/computeMetadata/v1/`
- Startup scripts, instance templates, custom images

**Management**
- Cloud Console, gcloud CLI, Deployment Manager, Terraform state buckets
- Cloud Logging, Error Reporting, Cloud Build triggers

## Reconnaissance

**Credential Discovery**
- Service account JSON keys in repos, CI/CD, `.env`, backup buckets
- `GOOGLE_APPLICATION_CREDENTIALS` environment variable
- Default Compute Engine service account on VMs (often overprivileged)
- OAuth tokens in browser/local `gcloud` config (`~/.config/gcloud/`)

**Unauthenticated Enumeration**

Avoid `gsutil` for anonymous checks — it can use ambient `gcloud` or application-default credentials and produce false public-bucket findings. Unset `GOOGLE_APPLICATION_CREDENTIALS` and use unauthenticated HTTP instead.

```
# GCS bucket existence (403 = exists but private, 404 = not found/wrong region)
curl -I https://storage.googleapis.com/target-bucket/

# Anonymous listing (no Authorization header; confirms allUsers/allAuthenticatedUsers List)
curl https://storage.googleapis.com/target-bucket/

# Alternate URL forms
curl -I https://target-bucket.storage.googleapis.com/
```

**Authenticated Enumeration**
```
gcloud auth list
gcloud config get-value project
gcloud projects get-iam-policy PROJECT_ID
gcloud iam service-accounts list
gcloud storage ls
gcloud compute instances list
gcloud container clusters list
```

## Key Vulnerabilities

### Cloud Storage Misconfigurations

- Public buckets: `allUsers` or `allAuthenticatedUsers` with `roles/storage.objectViewer` or `objectAdmin`
- Listable buckets revealing object keys: backups, `.env`, `terraform.tfstate`, SA keys
- Uniform bucket-level access disabled with legacy ACL public-read
- Signed URL with excessive TTL or overly broad object prefix

**Test:**
```
gsutil iam get gs://BUCKET          # requires credentials
curl https://storage.googleapis.com/BUCKET/   # anonymous listing check
curl -I https://storage.googleapis.com/BUCKET/sensitive.sql
```

### IAM Privilege Escalation

Common escalation paths (verify with `gcloud iam` / policy simulator):

| Permission | Escalation |
|------------|------------|
| `iam.serviceAccounts.actAs` + `compute.instances.create` | VM with privileged SA |
| `iam.serviceAccountKeys.create` | Export key for higher-priv SA |
| `iam.serviceAccounts.setIamPolicy` | Grant yourself roles on SA |
| `cloudfunctions.functions.create` + `actAs` | Deploy function as privileged SA |
| `run.services.create` (Cloud Run) + `actAs` | Deploy service with admin SA |
| `storage.buckets.update` + `setIamPolicy` | Open bucket to public or self |

**Test:**
```
gcloud projects get-iam-policy PROJECT --flatten="bindings[].members" --filter="bindings.members:user:YOU"
gcloud iam roles list --project=PROJECT
```

### Metadata Server Abuse

From any code execution on a GCP VM, Cloud Run (if metadata accessible), or compromised pod:

```
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email
```

- Default compute SA may have `editor` role on project (legacy projects)
- Requested OAuth scopes may allow `cloud-platform` full access
- Workload Identity misconfiguration in GKE → cross-namespace SA token theft

### GKE Misconfigurations

- Dashboard/UI exposed, anonymous RBAC (see `kubernetes` skill for K8s layer)
- Workload Identity not enforced; pods use node SA with broad GCP permissions
- `kubectl` proxy or `kubelet` read-only port exposed
- Secrets in ConfigMaps; GCR/Artifact Registry images pulling without auth

### Cloud Functions / Cloud Run

- HTTP-triggered functions without authentication (`--allow-unauthenticated`)
- Environment variables containing API keys (`gcloud functions describe`)
- Overprivileged runtime service account (`roles/editor`)
- Event triggers accepting attacker-controlled Pub/Sub messages

### BigQuery & Cloud SQL

- Public datasets (`allUsers` on dataset IAM)
- Cloud SQL public IP with weak/no password
- Exported snapshots in public GCS buckets

### Secret Manager & KMS

- `secretmanager.versions.access` granted to unintended principals
- Secrets replicated to logs via misconfigured Cloud Functions env vars
- KMS cryptoKey IAM with `allAuthenticatedUsers`

## Advanced Techniques

**Terraform State in GCS**
- `terraform.tfstate` in listable bucket → all resource addresses, sometimes secrets in plain text

**Service Account Impersonation Chain**
- `roles/iam.serviceAccountTokenCreator` on target SA → short-lived access tokens

**Org/Fold Policy Gaps**
- Project-level deny policies not applied; child project inherits permissive folder IAM

## Testing Methodology

1. **Discover credentials** — Keys in code, metadata, SSRF, public buckets
2. **Identify principal** — `gcloud auth list`, effective project IAM
3. **Enumerate storage** — Public/listable buckets, sensitive object names
4. **Escalation paths** — Map `actAs`, key creation, function deploy permissions
5. **Metadata** — From any shell in GCP workload, fetch SA token and scopes
6. **GKE layer** — Pivot from GCP IAM to cluster (combine with `kubernetes` skill)

## Validation

1. Demonstrate unauthorized GCS object read/list with bucket URL and object key
2. Show IAM escalation path with exact role/member binding and resulting access
3. Prove metadata token theft from compute context with redacted token scope
4. Document project ID, resource name, and IAM binding root cause
5. Confirm fix blocks the specific principal/permission/resource combination

## False Positives

- Intentionally public static asset bucket with no sensitive objects
- Metadata server unreachable from tested context (no RCE/SSRF)
- SA token from metadata has only `devstorage.read_only` on single bucket (note scope, not full breach)
- `403` on bucket HEAD indicating existence but not readable content

## Impact

- Mass data exfiltration from GCS/BigQuery/Cloud SQL backups
- Project or org compromise via SA key theft or IAM escalation
- Lateral movement from GKE pod to cloud control plane
- Regulatory exposure (PII in public buckets or exports)

## Pro Tips

1. Always check both `gsutil iam get` and anonymous `curl` — IAM and ACL layers differ
2. Search public buckets for `*.json` service account keys and `terraform.tfstate`
3. Default compute SA email: `PROJECT_NUMBER-compute@developer.gserviceaccount.com`
4. Combine with `kubernetes` skill when target runs on GKE
5. Firebase-hosted apps often use GCP project underneath — pivot from web to GCP project ID in configs

## Summary

GCP security requires least-privilege IAM, no public data paths, tight metadata/scopes on compute, and protected service account keys. Enumerate from any credential or shell — even read-only GCS access often reveals escalation artifacts.
