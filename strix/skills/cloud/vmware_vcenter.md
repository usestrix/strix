---
name: vmware_vcenter
description: VMware vCenter Server and ESXi security testing covering unauth RCE fingerprinting, default credentials, vSphere API abuse, and vSAN exposure
---

# VMware vCenter / ESXi

vCenter is the single management plane for an entire virtualization estate — compromise it and you own every VM, datastore, and often the domain controllers that run on top of it. Most real-world vCenter compromises are version/patch-level driven (a handful of critical unauth RCEs over the years) or default-credential driven, not novel exploitation. Fingerprint precisely before anything else.

## Attack Surface

**vCenter Server**
- vSphere Client (HTML5) — `https://<vcenter>/ui/`
- vCenter Server Appliance Management Interface (VAMI) — `https://<vcenter>:5480/`
- vSphere API / SDK — `https://<vcenter>/sdk` (SOAP), `https://<vcenter>/rest/` and `/api/` (REST, vSphere 7+)
- vCenter Single Sign-On (SSO/PSC) — `https://<vcenter>/websso/`, STS endpoint
- Legacy Flash client and deprecated plugin architecture (historic RCE surface)

**ESXi hosts**
- ESXi host client — `https://<esxi>/ui/`
- SLP (Service Location Protocol, port 427) — historic heap-overflow surface (CVE-2019-5544, CVE-2020-3992)
- SSH (often disabled by default, frequently re-enabled for ops)
- NFC (Network File Copy, port 902) — VM file transfer
- vMotion/vSAN network — should be isolated, frequently is not

**vSAN**
- vSAN Health/Performance Service APIs
- vSAN datastore direct access if the management network is flat

## Reconnaissance

**Version fingerprinting (do this first — almost everything downstream is patch-level gated)**
```
curl -sk https://<vcenter>/sdk/vimServiceVersions.xml
curl -sk https://<vcenter>/ui/ -I                    # Server header, redirect chain
curl -sk https://<vcenter>:5480/                     # VAMI banner
curl -sk 'https://<vcenter>/sdk' -H 'SOAPAction: urn:vim25/6.7' -d '<Envelope>...</Envelope>'
```
Also pull build number from `/ui/` page source (`buildNumber` in embedded JSON) and cross-reference against VMware's published KB for that build — vCenter build-to-version-to-CVE mapping is public and precise.

**ESXi fingerprinting**
```
curl -sk https://<esxi>/ | grep -i 'VMware ESXi'
nmap -sV -p 427 <esxi>                                # SLP version banner
```

## Key Vulnerabilities

### Unauthenticated RCE (version-gated)

vCenter has had several critical pre-auth RCE classes; treat each as a *class* to confirm by exact build number, not a payload to fire blind:
- **vCenter Server plugin / vmdir-related RCE class** (multiple CVEs across vSphere Client plugin framework, `/ui/vsphere-client/...` deserialization and file-upload paths) — confirm via build number against the vendor advisory before attempting any PoC; these are typically unauthenticated file-write-then-execute chains through a specific plugin endpoint.
- **vCenter SSO/vmdir LDAP-adjacent issues** — vmdir (embedded directory service) historically exposed misconfigurations reachable without full vCenter auth.
- **ESXi SLP heap overflow** (CVE-2019-5544/CVE-2020-3992) — reachable if port 427/UDP+TCP is exposed; disable-SLP is the standard remediation, so exposure alone is often the finding even without a working exploit in your environment.

**Do not weaponize an RCE class against a production appliance without explicit authorization for destructive testing — vCenter has no meaningful redundancy in most environments, and a crashed vpxd is a full outage.** Confirm via build number and vendor advisory; report the version-based exposure if you cannot safely validate further.

### Default / Weak Credentials

- `administrator@vsphere.local` with vendor-default or trivially guessable passwords (post-install defaults are sometimes never rotated)
- ESXi `root` with default or blank password, especially on appliances deployed via automation/IaC templates that bake in a fixed password
- Local OS accounts on the VCSA (`root` over SSH on port 22 if enabled)

```
# vSphere API auth probe (do not brute force in production — single low-rate checks only)
curl -sk -X POST https://<vcenter>/rest/com/vmware/cis/session -u 'administrator@vsphere.local:<candidate>'
```

### vCenter API Enumeration

Once authenticated (even with a low-privilege read-only account):
```
# REST session token
TOKEN=$(curl -sk -X POST https://<vcenter>/api/session -u '<user>:<pass>' | tr -d '"')
curl -sk https://<vcenter>/api/vcenter/vm -H "vmware-api-session-id: $TOKEN"
curl -sk https://<vcenter>/api/vcenter/host -H "vmware-api-session-id: $TOKEN"
curl -sk https://<vcenter>/api/vcenter/datastore -H "vmware-api-session-id: $TOKEN"
curl -sk https://<vcenter>/api/appliance/system/version -H "vmware-api-session-id: $TOKEN"
```
Look for: VM console/guest-ops permissions granted too broadly (`GuestOps.Query`/`GuestOps.Modify` lets you run commands inside guest VMs if guest creds or passwordless guest auth is set), snapshot access exposing VM memory dumps with credentials in RAM, and datastore browsing exposing `.vmdk`/`.nvram`/`.vmsn` files directly.

### Session / Token Handling

- vSphere API session tokens (`vmware-api-session-id`) with excessive TTL and no IP binding
- SAML token reuse across the SSO domain if PSC is shared across multiple vCenters
- STS token signing certificate exposure via `/websso/SAML2/Metadata/vsphere.local`

### vSAN Exposure

- vSAN Health Service API reachable without additional auth beyond vCenter session
- Flat management network allowing direct vSAN VMkernel interface (typically not routable from a normal management segment — note as a network-segmentation finding, not a vSAN bug, if reachable)

## Testing Methodology

1. **Fingerprint exact build** — vCenter build number and ESXi version via unauthenticated banners/SDK version doc; cross-reference the CVE list for that specific build before anything else.
2. **Default credential sweep** — low-rate, single attempts per account against vSphere Client, VAMI, and ESXi host client; never lock out `administrator@vsphere.local` (SSO account lockout can be organization-wide).
3. **Authenticated enumeration** — with any valid account, pull VM/host/datastore inventory via REST API; map effective privileges (`GuestOps`, `Snapshot`, `Datastore.FileManagement`).
4. **Guest-ops pivot** — if `GuestOps.Modify` + guest credentials/passwordless auth are available, treat this as a direct path to arbitrary command execution inside every VM the account can reach.
5. **Datastore browse** — check for direct `.vmdk`/snapshot file access that bypasses guest OS auth entirely (offline disk-image credential extraction).

## Validation

1. Show the exact build number and the CVE/KB it maps to before claiming an unauth-RCE finding — a version match without a working demonstration is a lower-confidence finding, state it as such.
2. For credential findings, show the single successful low-rate authentication attempt, not a brute-force transcript.
3. For guest-ops pivots, demonstrate one benign in-guest command execution with output captured, then stop.
4. Tie every finding to a specific object (VM MoRef, host, datastore path), not "vCenter is misconfigured."

## False Positives

- SLP port open but host already has SLP service disabled per KB (banner-only false positive)
- Build number matches a CVE range but the fix was backported via a hotfix not reflected in the marketing version string — check the specific KB patch level field, not just the version.
- REST API session succeeds but privileges are read-only with no `GuestOps`/`Snapshot`/`Datastore.FileManagement` — inventory read alone is often expected/intended for the tested account.

## Impact

- Full virtualization estate compromise: every VM's disk, memory, and running state accessible
- Guest-ops abuse gives command execution inside every reachable guest without touching the guest OS's own auth
- Snapshot/`.vmdk` access allows offline extraction of credentials, keys, and data from powered-off VM disk images
- A crashed vpxd or ESXi host from an unvalidated destructive PoC is a full production outage — treat exploitation of unauth-RCE classes as high-DoS-risk requiring an explicit heads-up under the engagement rules

## Pro Tips

1. Build number is the whole game — get it first, everything else is confirmation work against a known CVE list.
2. `GuestOps.Modify` + stored/passwordless guest credentials is the fastest real path to code execution once you have any vCenter session — check this before hunting for RCE CVEs.
3. Datastore file browsing bypassing guest auth entirely is an underrated finding class — a powered-off VM's `.vmdk` is just a disk image you can mount and read offline.
4. SSO account lockout policy is often domain-wide across every vCenter sharing a PSC — never brute-force `administrator@vsphere.local`.

## Tooling

The sandbox has no vSphere-specific tooling by default; standard `curl`/Python is sufficient for the API calls above.
```
pip install pyvmomi          # official vSphere SOAP API Python bindings, for scripted inventory/guest-ops
```
- **pyVmomi** — the reference Python SDK for the legacy SOAP vSphere API (`/sdk`); use when REST API coverage (vCenter 7+) is incomplete for an object type.
- **curl** — sufficient for the REST API (`/api/`, `/rest/`) calls throughout this skill; no dedicated CLI needed for enumeration.

## Summary

vCenter/ESXi compromise is overwhelmingly a build-number and credential problem, not a novel-exploit problem. Fingerprint the exact build first, check it against the vendor CVE list, sweep default credentials at low rate, then pivot through guest-ops or datastore file access once authenticated. Treat any live exploitation of an unauth-RCE class against production as high-DoS-risk and flag it before pushing further.
