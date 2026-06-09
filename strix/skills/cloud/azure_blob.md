---
name: azure_blob
description: Azure Blob/Storage testing - container access levels, SAS exposure, public blobs, anonymous enumeration, and credential pivots
---

# Azure Blob / Storage Testing

Azure Blob Storage exposes data over predictable HTTPS endpoints (`https://<account>.blob.core.windows.net/<container>/<blob>`). Given a storage account name, container, blob URL, or a leaked SAS token, the objective is to assess the effective access level: whether containers allow anonymous read/list, whether a SAS grants more than intended (write/delete/account-wide), and whether storage data or keys can be pivoted into Azure control-plane access. Anonymous public access on a single container is the most common real finding; over-scoped SAS tokens and leaked account keys are the highest impact. For SSRF-mediated access to Azure IMDS/MSI, see the ssrf skill.

## Attack Surface

**Endpoints (per account, all share the account name)**
- Blob: `https://<account>.blob.core.windows.net/`
- File: `https://<account>.file.core.windows.net/`
- Queue: `https://<account>.queue.core.windows.net/`
- Table: `https://<account>.table.core.windows.net/`
- Static website: `https://<account>.z<NN>.web.core.windows.net/`
- Data Lake Gen2 (HNS): `https://<account>.dfs.core.windows.net/`
- Sovereign/gov clouds: `.blob.core.usgovcloudapi.net`, `.blob.core.chinacloudapi.cn`

**Access levels (container `publicAccess`)**
- `private` (None): no anonymous access; auth required
- `blob`: anonymous read of a blob if the exact name is known, but no listing
- `container`: anonymous read AND list of all blobs (worst case)

**Authorization material**
- SAS tokens in URLs (`?sv=...&sig=...`): service, account, or user-delegation SAS
- Storage account keys (`key1`/`key2`, base64, ~88 chars)
- Connection strings (`DefaultEndpointsProtocol=https;AccountName=...;AccountKey=...`)
- Microsoft Entra (Azure AD) RBAC tokens (`Storage Blob Data Reader/Contributor`)

**Where exposure leaks in**
- Hardcoded SAS/keys/connection strings in JS bundles, mobile apps, git history, CI logs
- CDN origins (`*.azureedge.net`) fronting a public container
- CORS-enabled containers consumed by SPAs (account name in network tab)

## Recon & Enumeration

Install Azure tooling and storage-focused enumerators if absent:
```
# Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | bash
# AzureHound / cloud audit
pipx install scoutsuite
git clone https://github.com/NetSPI/MicroBurst.git    # PowerShell, account name brute force
git clone https://github.com/initstring/cloud_enum.git && pip install -r cloud_enum/requirements.txt
```

Discover account/container names from a target:
```
# Pull JS and config for endpoints, SAS, connection strings
katana -u https://target.tld -d 3 -jc -o katana.txt
grep -ahoE 'https://[a-z0-9]{3,24}\.(blob|file|queue|table|dfs|z[0-9]+\.web)\.core\.windows\.net[^"'\'' ]*' katana.txt | sort -u
trufflehog filesystem ./repo --only-verified            # finds AccountKey / SAS in source
gitleaks detect --source ./repo --redact
# Multi-cloud name permutation (Azure blob/file/queue/table + public access check)
python3 cloud_enum/cloud_enum.py -k targetname -k target-prod -k targetcdn --quickscan
```

Confirm endpoints resolve and probe at HTTP layer:
```
echo "https://acct.blob.core.windows.net" | httpx -title -status-code -tech-detect -server
nuclei -u https://acct.blob.core.windows.net -tags azure,exposure -severity medium,high,critical -j -o nuclei_azure.jsonl
```

Anonymous list/read against a known container (no creds, REST API):
```
# List blobs in a container (works only if publicAccess=container)
curl -s "https://acct.blob.core.windows.net/CONTAINER?restype=container&comp=list" | xmllint --format -
# Read a specific blob (works if publicAccess=blob or container)
curl -s -o out.bin "https://acct.blob.core.windows.net/CONTAINER/path/to/blob"
# Account-level container list is NOT anonymous; requires SAS/key
```

Brute-force container names against an account (anonymous):
```
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt \
  -u "https://acct.blob.core.windows.net/FUZZ?restype=container&comp=list" \
  -mc 200,403 -t 40 -o containers.json
# 200 = listable (publicAccess=container); 403 = exists but private/blob-level; 404 = no such container
```

If you hold a SAS or key, drive the full surface with `az`:
```
az storage container list --account-name acct --sas-token "?sv=..." -o table
az storage blob list -c CONTAINER --account-name acct --sas-token "?sv=..." -o table
az storage blob list -c CONTAINER --connection-string "DefaultEndpointsProtocol=...;AccountKey=..." -o table
```

## Methodology

1. **Collect identifiers** - account name(s), container names, full blob URLs, and any SAS/keys/connection strings from JS, mobile bundles, git history, CI logs, and CDN configs.
2. **Resolve endpoints** - confirm each `<account>.<service>.core.windows.net` resolves (CNAME via `dnsx`) and which services (blob/file/queue/table/dfs/web) are active.
3. **Classify container access** - for each known container, test `restype=container&comp=list`: 200 = `container` (list+read), 403 with valid blob read = `blob`, 403/404 = private. Never assume; verify per container.
4. **Enumerate listable content** - parse the XML blob list; flag backups (`.bak`, `.sql`, `.zip`, `.tar.gz`), configs (`web.config`, `.env`, `appsettings.json`), keys, terraform state, and DB dumps.
5. **Assess every SAS** - decode the query params to read exact permissions, scope, and expiry. Test what the SAS actually allows vs. its intended use.
6. **Test write/delete where the SAS or access level permits** - upload a benign canary blob (authorized scope only) to prove write; never overwrite real data.
7. **Pivot keys to control plane** - if an account key or connection string is found, enumerate all containers, check for Data Lake ACLs, and test whether the key principal maps to broader Azure RBAC.
8. **Check downstream wiring** - static website hosting, CORS `*`, CDN origin trust, Event Grid/Function triggers fired by blob upload.

## Key Weaknesses / Techniques

### Public container (anonymous list + read)
The default-deny was overridden to `container`. Anyone can enumerate and download everything.
```
curl -s "https://acct.blob.core.windows.net/backups?restype=container&comp=list&maxresults=5000" \
  | grep -oE '<Name>[^<]+' | sed 's/<Name>//'
# Recursively pull listed blobs
for b in $(curl -s "https://acct.blob.core.windows.net/backups?restype=container&comp=list" | grep -oE '<Name>[^<]+' | sed 's/<Name>//'); do
  curl -s -o "dl/$(basename "$b")" "https://acct.blob.core.windows.net/backups/$b"; done
```

### Public blob (read without list)
`publicAccess=blob`: listing 403s, but any guessed/leaked blob name is readable. Combine with name leaks from JS, sitemaps, or predictable paths (`/avatars/<userid>.png`, `/invoices/<seq>.pdf`) to harvest objects via IDOR-style enumeration.

### Over-scoped or stale SAS
Decode and judge the token. Key fields: `sp` (permissions: `r`/`w`/`d`/`l`/`a`/`c`/`u`/`p`), `sr` (resource: `b`=blob, `c`=container), `srt`+`ss` (account SAS scope), `se` (expiry), `sip` (IP restriction), `spr` (protocol), `sig` (HMAC).
```
# Split the query string into readable params
python3 -c "import urllib.parse,sys; [print(k,'=',v) for k,v in urllib.parse.parse_qsl(sys.argv[1].lstrip('?'))]" "?sv=2022-11-02&ss=bfqt&srt=sco&sp=rwdlacupx&se=2030-01-01T00:00:00Z&sig=..."
```
Red flags: `sp` includes `w`/`d`/`c`/`a` (write/delete/create); `srt=sco` + `ss=bfqt` (account SAS over all services); `se` far in the future or already expired but still honored; no `sip`; `spr=https,http`.

### Leaked account key / connection string
Account keys are god-mode for the storage account: full read/write/delete on every container, queue, table, file share, plus ability to mint new SAS tokens. Validate scope (read-only proof) with `az storage container list`.

### Public access not blocked at account level
If `allowBlobPublicAccess=true` at the account, any container can be flipped public by anyone with `Storage Account Contributor`. Note in findings even when no container is currently public.

### Static website / `$web` and CDN origin
`$web` serves files at `<account>.z<NN>.web.core.windows.net`. Check the underlying container for over-broad upload rights and for `azureedge.net` CDNs that cache and re-serve a (now private) origin's stale public objects.

### Data Lake Gen2 POSIX ACLs
On HNS accounts (`.dfs.core.windows.net`), RBAC may say private while a permissive ACL (`other: r-x`) still allows access. Test the `dfs` endpoint separately from `blob`.

## Validation

1. **Public list**: show a `200` XML `EnumerationResults` from `?restype=container&comp=list` with the source IP being the sandbox, not a browser. Capture 1-2 blob names as proof.
2. **Public/leaked read**: download a single non-sensitive object and record its `Content-Length`, `ETag`, and `Last-Modified` from response headers.
3. **SAS write proof (authorized scope only)**: upload a tiny canary, then delete it.
```
curl -s -X PUT -H "x-ms-blob-type: BlockBlob" -H "Content-Length: 11" \
  --data-binary "auth-check" "https://acct.blob.core.windows.net/CONTAINER/_authz_check.txt?<SAS>"
# Confirm, then clean up
curl -s -X DELETE "https://acct.blob.core.windows.net/CONTAINER/_authz_check.txt?<SAS>"
```
4. **Key scope**: `az storage container list --account-name acct --account-key <KEY> -o table` listing containers proves account-key validity. Stop at read-level proof.
5. Record exact account, container, access level, SAS permission string, and expiry in the finding.

## False Positives

- `403 AuthenticationFailed`/`ResourceNotFound` on `comp=list` means the container is private or blob-level, not public. Do not report list-403 as a finding.
- A readable blob whose container is `blob`-level is working as designed if the content is genuinely meant to be public (CDN assets, public site media). Judge by content sensitivity, not reachability.
- OAST/callback "hits" sourced from the tester's own browser rather than a server confirm nothing about the storage account.
- An expired SAS that returns `403 Signature... expired` is not exploitable.
- `sig` mismatch (`AuthenticationFailed`) on a truncated/copied token means the SAS is invalid, not that access was granted.
- `404` for a brute-forced container name only means the name does not exist.
- Public static-website assets in `$web` are intentional; flag only writable origins or stale-cached private data.

## Chaining & Impact

- Public/listable container -> backups, DB dumps, terraform state -> hardcoded creds -> broader environment compromise.
- Leaked `.env`/`appsettings.json` in a blob -> app/DB credentials, API keys, additional connection strings -> lateral movement.
- Account key or `srt=sco/ss=bfqt` account SAS -> full storage takeover; mint long-lived SAS for persistence; read every container/table/queue.
- Writable container behind a static site or app deployment slot -> overwrite JS/HTML -> stored XSS or supply-chain code execution for site visitors.
- Writable container that triggers an Event Grid -> Azure Function -> deserialization/command path in the consumer.
- Terraform state (`*.tfstate`) in a public container -> plaintext secrets, resource IDs, and the storage RBAC graph for further pivots.
- Storage creds -> Azure Resource Manager only if the principal also holds management-plane RBAC; storage keys alone do not grant ARM access.

## Pro Tips

1. The account name is global and guessable - brute force `targetname`, `target-prod`, `targetbackup`, `targetcdn`, `targetdev` permutations; account names are 3-24 lowercase alphanumerics.
2. Always test `comp=list` AND a direct blob GET separately - they map to two different access levels (`container` vs `blob`).
3. Decode every SAS before using it; the `sp` and `srt`/`ss` fields tell you the blast radius instantly, and an account SAS (`srt=sco`) is far worse than a single-blob service SAS.
4. SAS tokens cannot be revoked individually unless tied to a stored access policy - a long-`se` token in old JS is often still live; check `se` against today's date.
5. Snapshots and versions persist deleted data: append `?comp=list&include=snapshots,versions,deleted` when you have list rights.
6. Check all four services per account - data hides in `table`/`queue`/`file`, not just `blob`; the `dfs` endpoint can differ from `blob` due to POSIX ACLs.
7. `x-ms-version` header changes behavior; if an API rejects a request, retry with a recent version like `2022-11-02`.
8. Grep JS bundles for `core.windows.net`, `?sv=`, `AccountKey=`, and `BlobEndpoint=` - the account name in a SPA's network tab is the start of the whole assessment.
9. Use `cloud_enum` for fast public/private classification across blob/file/queue/table in one pass before manual digging.
