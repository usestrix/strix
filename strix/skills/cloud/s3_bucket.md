---
name: s3_bucket
description: AWS S3 bucket testing - ACL/policy misconfig, public listing, object exposure, write/takeover, and credential discovery
---

# AWS S3 Bucket Security Testing

An S3 bucket is a globally-named object store reachable over HTTPS at predictable virtual-host and path-style endpoints. The attacker objective is to convert a bucket name (often leaked in HTML, JS, mobile apps, or DNS) into unauthorized read, write, or full control of objects: list the namespace, exfiltrate sensitive data, overwrite assets served to other users, hijack a dangling bucket reference, or pivot through credentials/IAM trust found inside. Misconfigured bucket ACLs, broad bucket policies, disabled Block Public Access, and the legacy `AllUsers`/`AuthenticatedUsers` grants remain extremely common.

## Attack Surface

**Scope**
- Bucket itself: ACL, bucket policy, Block Public Access (BPA) settings, ACL ownership, website hosting
- Object namespace: listing (`ListBucket`), per-object reads (`GetObject`), versions, ACLs
- Write surface: `PutObject`, `DeleteObject`, multipart uploads, policy/ACL writes
- Reference integrity: dangling CNAMEs/origins pointing at unclaimed bucket names (takeover)

**Endpoints (a bucket answers on several hosts)**
- Virtual-host: `https://<bucket>.s3.amazonaws.com/` and regional `https://<bucket>.s3.<region>.amazonaws.com/`
- Path-style: `https://s3.<region>.amazonaws.com/<bucket>/`
- Static website: `http://<bucket>.s3-website-<region>.amazonaws.com/` (or `.s3-website.<region>.`)
- Dualstack/IPv6, transfer-acceleration, and Access Point ARNs as additional aliases

**Where bucket names leak**
- Hardcoded in HTML/JS bundles, `<img>/<script>/<link>` src, CSS, sourcemaps
- Mobile app resources (decompiled APK/IPA), CI logs, Terraform/CloudFormation, git history
- DNS: CNAMEs to `*.s3.amazonaws.com` / `*.cloudfront.net` fronting a bucket
- Predictable naming: `companyname-{prod,dev,backup,logs,assets,terraform-state,cdn}`

## Recon & Enumeration

Install the asset-specific tools (most others are already in the sandbox):
```
pip install awscli s3scanner          # awscli, s3scanner enumerator
pip install prowler                    # account-wide AWS posture (if creds obtained)
GO111MODULE=on go install github.com/sa7mon/S3Scanner@latest   # alt enumerator
```

Resolve and classify the endpoint (region, existence, public bit) with httpx:
```
httpx -u "https://<bucket>.s3.amazonaws.com/" -sc -title -location -ct -server -fr
```
- `404 NoSuchBucket` = unclaimed (takeover candidate). `403 AccessDenied` = exists, locked.
- `200` + `<ListBucketResult>` XML = public listing. `301` body reveals the real region (`<Endpoint>`).

Anonymous listing (no creds) via path-style and virtual-host:
```
curl -s "https://s3.amazonaws.com/<bucket>/"                    # path-style list
curl -s "https://<bucket>.s3.<region>.amazonaws.com/?list-type=2&max-keys=1000"
aws s3 ls "s3://<bucket>" --no-sign-request --recursive | head
aws s3api list-objects-v2 --bucket <bucket> --no-sign-request --max-items 50
```

Read ACL / policy / config anonymously and with creds:
```
aws s3api get-bucket-acl    --bucket <bucket> --no-sign-request
aws s3api get-bucket-policy --bucket <bucket> --no-sign-request
aws s3api get-bucket-policy-status        --bucket <bucket>
aws s3api get-public-access-block         --bucket <bucket>
aws s3api get-bucket-website --bucket <bucket> --no-sign-request
aws s3api get-bucket-versioning --bucket <bucket> --no-sign-request
```

Bulk/automated enumeration:
```
s3scanner scan --bucket <bucket>                       # perms matrix (read/write/acl)
s3scanner scan -f buckets.txt -threads 30 -enumerate
nuclei -u "https://<bucket>.s3.amazonaws.com/" -tags s3,aws,bucket,exposure -severity medium,high,critical -silent
```

Discover candidate bucket names:
```
katana -u https://target.tld -jc -d 3 -silent | grep -Eio '[a-z0-9.-]+\.s3[.-][a-z0-9.-]*amazonaws\.com|s3\.amazonaws\.com/[a-z0-9.-]+'
subfinder -d target.tld -silent | dnsx -cname -resp-only | grep -i 's3\|amazonaws\|cloudfront'
ffuf -w names.txt -u "https://FUZZ.s3.amazonaws.com/" -mc 200,403 -t 40
trufflehog filesystem ./app-bundle --only-verified        # AWS keys near bucket refs
gitleaks detect --source . --no-banner                    # keys + bucket names in git
```

## Methodology

1. **Collect bucket names.** Crawl the app (katana), grep JS/HTML, decompile mobile apps, scan repos (gitleaks/trufflehog), resolve DNS (dnsx), and generate permutations from the org name. Build `buckets.txt`.
2. **Confirm existence and region.** httpx each candidate; a `301` returns the canonical region in the XML `<Endpoint>` element. Distinguish `NoSuchBucket` (takeover) from `AccessDenied` (locked) from `200` (open).
3. **Test anonymous read.** Try `list-objects-v2` and `get-bucket-acl --no-sign-request`. A successful list is the highest-value, lowest-effort finding.
4. **Read config.** Pull ACL, policy, BPA, versioning, website config. Map exactly which principals (`AllUsers`, `AuthenticatedUsers`, account/ARN, `Principal:"*"`) have which actions.
5. **Test authenticated-user read.** If you hold ANY valid AWS account (even a free personal one), retry without `--no-sign-request`. `AuthenticatedUsers` grants apply to every AWS account on earth, not just the target's.
6. **Test write.** Carefully probe `PutObject` with a benign marker, `PutObjectAcl`, `PutBucketPolicy`, and `DeleteObject`. Writable buckets serving site assets are critical (stored XSS / supply-chain).
7. **Enumerate object contents.** For readable lists, pull versions and sample object ACLs; scan downloaded objects for secrets (trufflehog/gitleaks), credentials, backups, PII.
8. **Exploit credentials.** Any discovered AWS keys → `aws sts get-caller-identity` → `prowler` / enumerate IAM, other buckets, secrets. Treat as account pivot, minimal-impact only.
9. **Check takeover.** For dangling references (CNAME/origin to an unclaimed name), validate you can register the bucket name in your own account.

## Key Weaknesses / Techniques

### Public listing (ListBucket to AllUsers)
The bucket policy or ACL grants `s3:ListBucket` to everyone. Enumerate the full keyspace, paginating past 1000 keys:
```
aws s3api list-objects-v2 --bucket <bucket> --no-sign-request --query 'Contents[].Key' --output text
aws s3api list-object-versions --bucket <bucket> --no-sign-request   # deleted/old sensitive versions
```
Listing exposes filenames (often revealing customers, backups, internal tooling) even when individual objects are private.

### Object read exposure (GetObject to AllUsers/AuthenticatedUsers)
Objects readable even when listing is denied — guess/enumerate keys from leaked references:
```
curl -s "https://<bucket>.s3.amazonaws.com/<key>" -o obj.dat
aws s3 cp "s3://<bucket>" ./loot --no-sign-request --recursive    # if list+get open
```
The `AuthenticatedUsers` grant is the classic trap: appears "non-public" in the console but is readable by any AWS account. Always retry with your own signed creds.

### Anonymous / authenticated write (PutObject)
Writable buckets enable defacement, stored XSS (if HTML/JS is served to users), or malware/supply-chain injection. Validate non-destructively with a unique marker file:
```
echo "poc-$(date +%s)" > poc.txt
aws s3 cp poc.txt "s3://<bucket>/poc-$(openssl rand -hex 4).txt" --no-sign-request
curl -s -X PUT "https://<bucket>.s3.amazonaws.com/poc-marker.txt" --data "ownership-check"
```
If the bucket fronts a website/CDN, overwriting an existing `.js`/`.html` object can yield stored XSS against real users — demonstrate with a benign overwrite, never live JS.

### Policy / ACL takeover
`s3:PutBucketPolicy`, `s3:PutBucketAcl`, or `s3:PutObjectAcl` granted to `*` lets an attacker grant themselves full control. Confirm the permission exists; do not actually rewrite production policy.

### Bucket takeover (dangling reference)
A site CNAME/CloudFront origin points to a bucket name that no longer exists (`404 NoSuchBucket`). Register that exact name in your own account in the matching region, host content, and you control what victims load. Confirm the dangling reference first via `dig`/`httpx`.

### Credentials & misconfig inside objects
Backups, `.env`, `terraform.tfstate`, `.git`, DB dumps, and config frequently sit in readable buckets:
```
trufflehog s3 --bucket <bucket> --no-verification           # if you have read creds
grep -rEi 'AKIA[0-9A-Z]{16}|aws_secret|password|BEGIN .* PRIVATE KEY' ./loot
```

### Related misconfigs
- BPA disabled at account or bucket level (lets ACLs go public)
- `BucketOwnerPreferred`/ACLs-enabled with cross-account `WRITE`
- Pre-signed URLs with long TTLs leaked in logs/referrers
- Website hosting enabling open redirect via routing rules

## Validation

1. **Listing:** Capture the `<ListBucketResult>` XML or `list-objects-v2` JSON showing real keys. Note whether anonymous (`--no-sign-request`) or authenticated, and via which endpoint.
2. **Read:** Download one non-sensitive object and record HTTP 200 + a content hash; for sensitive data, document the key name and a redacted snippet only — do not exfiltrate at scale.
3. **Write:** Upload a uniquely-named, benign marker (`poc-<random>.txt`), re-fetch it over HTTPS to prove persistence, then delete it if you also hold delete rights. Record request/response.
4. **Principal mapping:** Save the exact ACL grant or policy statement (`Principal`, `Action`, `Resource`) that authorized the access — this is the root-cause evidence.
5. **Takeover:** Show the dangling reference (`dig`/curl returning `NoSuchBucket`) and, in your own account, that the name is registrable; serve a harmless marker page to confirm victim-path control.
6. **Credentials:** `aws sts get-caller-identity --output json` proves a discovered key is live and shows the account/principal it maps to.

## False Positives

- `403 AccessDenied` on root `/` is NOT a finding — the bucket exists but is locked; many buckets answer 403 by design.
- `200` with an empty `<ListBucketResult>` (`<KeyCount>0</KeyCount>`) = public but empty; low/no impact unless writable.
- CloudFront-fronted buckets returning 403 directly while serving fine via the CDN are usually intentional (Origin Access Control).
- Objects meant to be public (marketing assets, public website files) — read access is expected; rule out by intended use.
- A "writable" result that is actually a misleading 200 from a proxy/WAF, not S3 — confirm the object is retrievable from the canonical `s3.amazonaws.com` host.
- Pre-signed URL access is time-bounded and intended; not a misconfig unless the URL is leaked/over-long-lived.
- Buckets owned by AWS or third parties out of scope — verify ownership before reporting.

## Chaining & Impact

- Public listing → object read → secrets (`.env`, keys, tfstate) → `sts get-caller-identity` → IAM/account pivot → other buckets, RDS snapshots, Secrets Manager.
- Writable asset bucket served via CDN → overwrite JS → stored XSS / drive-by against every site visitor → session/account takeover.
- Bucket takeover of a dangling origin → serve attacker content under the victim's domain → phishing, cookie theft, supply-chain.
- tfstate read → full infra map + embedded secrets → broad cloud compromise.
- Cross-account write/ACL grant → persistence and lateral movement within the target AWS org.
- Versioning + readable old versions → recover data that was "deleted," including rotated credentials still valid.

## Pro Tips

1. Always retry every read/list both anonymously (`--no-sign-request`) AND with a signed throwaway AWS account — `AuthenticatedUsers` grants are invisible to the first method and are extremely common.
2. A `301` is a gift: parse the `<Endpoint>`/`<Bucket>` XML to get the canonical region instead of brute-forcing all regions.
3. `list-object-versions` and delete markers expose data that simple listing hides; check them whenever versioning is on.
4. Bucket names are a global namespace — leaked names from dev/staging/CI (`-dev`, `-backup`, `-logs`, `-terraform-state`) are often far more exposed than prod.
5. Distinguish bucket ACL vs object ACL vs bucket policy vs BPA: a "private" bucket can still have individual world-readable objects (per-object ACL).
6. When a bucket fronts a website, test `?list-type=2` on both the REST endpoint and the `s3-website-` endpoint — behavior and exposure differ.
7. Keep write PoCs to uniquely-named marker files and clean up; never overwrite or delete existing production objects to prove the point.
8. Feed discovered AWS keys to `prowler` for fast, read-only account-wide posture rather than manually walking the API.
9. Use `httpx -fr` so redirects to the real regional endpoint are followed and classified in one pass.
