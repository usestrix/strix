---
name: enterprise_vpn_appliances
description: SSL VPN / remote-access gateway fingerprinting and version-to-CVE mapping for Cisco ASA, FortiGate, Citrix NetScaler, Palo Alto GlobalProtect, Pulse/Ivanti, SonicWall, and F5 BIG-IP
---

# Enterprise VPN / Remote-Access Appliances

SSL VPN and remote-access gateways are consistently the most common initial-access point in real-world intrusions — they sit unauthenticated-reachable on the internet by design, run infrequently-patched vendor firmware, and a single pre-auth CVE on them is a direct path past the entire perimeter. This skill is fingerprint-first: identify vendor and exact version precisely, then map to the known CVE class for that build. Do not fire exploit code blind.

## Attack Surface

- **Cisco ASA / AnyConnect / Firepower** — `webvpn` login portal, `/+CSCOE+/`, `/+webvpn+/`
- **Fortinet FortiGate / FortiOS SSL-VPN** — `/remote/login`, `/remote/fgt_lang`
- **Citrix NetScaler / ADC (Gateway)** — `/vpn/index.html`, `/logon/LogonPoint/`
- **Palo Alto GlobalProtect** — `/global-protect/login.esp`, `/ssl-vpn/prelogin.esp`
- **Pulse Secure / Ivanti Connect Secure** — `/dana-na/auth/url_default/welcome.cgi`
- **SonicWall SMA/SSL-VPN** — `/cgi-bin/welcome`
- **F5 BIG-IP (APM)** — `/my.policy`, TMUI at `/tmui/login.jsp`

## Fingerprinting

Version identification comes from a combination of banner strings, static asset hashes, and login-page markup — vendors rarely advertise the exact patch level directly, so triangulate.

```
# Generic banner/header sweep
curl -sk -I https://<target>/
curl -sk https://<target>/ | grep -iE 'version|build|release'

# Cisco ASA
curl -sk https://<target>/+CSCOE+/logon.html | grep -i version
curl -sk https://<target>/+CSCOE+/session_password.html -I

# FortiGate
curl -sk https://<target>/remote/login -I
curl -sk https://<target>/remote/fgt_lang?lang=en | head -c 200   # build string often embedded

# Citrix NetScaler
curl -sk https://<target>/vpn/index.html | grep -iE 'ns_gui|platform'
curl -sk https://<target>/logon/LogonPoint/tmindex.html -I

# Palo Alto GlobalProtect
curl -sk https://<target>/global-protect/login.esp | grep -iE 'version'
curl -sk 'https://<target>/global-protect/getconfig.esp' -d 'user=&passwd=' -I

# Pulse/Ivanti Connect Secure
curl -sk https://<target>/dana-na/auth/url_default/welcome.cgi -I

# F5 BIG-IP
curl -sk https://<target>/tmui/login.jsp | grep -iE 'BIGIP|version'
```

**Static-asset hashing** — when a version string isn't directly exposed, hash a stable, versioned static asset (a specific CSS/JS file the login page loads) and diff against known-version hash databases (build your own corpus per engagement by checking a lab instance of each version you have access to, or cross-reference public vulnerability-scanner signature databases). This is the most reliable non-destructive method when banners are stripped.

## Version-to-CVE Mapping Workflow

1. Get vendor + exact build/version from fingerprinting above.
2. Cross-reference the vendor's own security advisory list for that product (each vendor publishes a CVE-to-fixed-version table — check it directly rather than relying on memory of past CVEs, since this changes monthly).
3. Classify the CVE class before attempting confirmation: **path traversal / arbitrary file read** (safe to confirm — read a known-benign file, don't pivot to credential files without instruction), **pre-auth RCE** (confirm via a non-destructive proof primitive — e.g. a timing/DNS-callback proof-of-execution rather than a full shell — before escalating), **SSRF via the VPN's own proxy/relay functionality**, **auth bypass** (session/cookie forgery, default-cert trust issues).
4. **Never fire a destructive or full-RCE PoC against a production gateway without a heads-up** — these appliances often have no HA pair, and crashing one is a full remote-access outage for the organization. This is exactly the DoS-risk category the engagement rules call out: throttle, and flag before pushing further.

## Configuration Disclosure Paths (per vendor, confirm before probing)

- **Cisco ASA**: `/CSCOSSLC/config-auth`, exposed `+CSCOE+/errormsg.html` (session/user leakage), `/admin/exec/show%20running-config` if a management path is accidentally web-exposed
- **FortiGate**: `.action` and legacy CGI paths that leaked config in older CVE classes; check current advisories for the live equivalent
- **NetScaler**: `/vpn/../vpns/cfg/smb.conf` style traversal patterns (confirm current live-CVE equivalents, historic class)
- **Pulse/Ivanti**: `/dana-na/../dana/html5acc/guacamole/` and adjacent traversal-prone paths (historic CVE-2019-11510 class — confirm patch level, don't assume unpatched)
- **F5 BIG-IP**: `/mgmt/tm/util/bash` if TMUI RCE class is unpatched (confirm build first)

## Default Credential Checklist

- Cisco ASA: no meaningful "default" cred (cert/AAA-backed usually), but check for weak local fallback accounts
- FortiGate: `admin` / blank or `admin`/`<serial-derived>` on unconfigured units
- NetScaler: `nsroot` / `nsroot` on fresh appliances
- Pulse/Ivanti: vendor-default admin realm credentials if never rotated post-deployment
- SonicWall: `admin` / `password` on unconfigured units

## Testing Methodology

1. **Identify** — vendor + product line from the login portal path/markup alone (no auth needed).
2. **Fingerprint exact version** — banner, static-asset hash, or config-disclosure path if available.
3. **Map to CVE class** — cross-reference current vendor advisory for that build; classify by severity/type (info-disclosure vs RCE vs auth-bypass).
4. **Confirm non-destructively** — path traversal on a known-benign file; RCE via a non-destructive execution proof (DNS callback, timing) rather than a shell, unless explicitly authorized for deeper PoC.
5. **Flag before escalating** — any RCE-class confirmation attempt against production gets a heads-up per engagement rules before proceeding.
6. **Default-credential sweep** — single low-rate attempt per vendor's known defaults; stop immediately on any lockout signal.

## Validation

1. State vendor, product, and exact fingerprinted build/version with the evidence (banner, hash, disclosed config value).
2. Cite the specific CVE(s) the build maps to, from the vendor's own advisory, not from memory.
3. Show the non-destructive confirmation primitive and its result — not a full exploit chain unless explicitly authorized.
4. Note HA/redundancy status if discoverable (single point of failure changes the DoS-risk calculus materially).

## False Positives

- Version string visible but already patched per the vendor's advisory (fixed-in version ≤ observed version)
- Banner/asset hash ambiguous between two adjacent patch levels — report as a range, not a false precision
- Default-credential login form present but backed by external AAA/RADIUS (form exists regardless of local-account state)

## Impact

- Pre-auth RCE on a perimeter VPN gateway is direct initial access to the internal network, bypassing every other control
- Config disclosure frequently contains LDAP/RADIUS bind credentials, internal network topology, and route tables
- These appliances are the single most common real-world initial-access vector — a confirmed unpatched instance is a critical finding regardless of whether full exploitation was demonstrated

## Pro Tips

1. Vendor security-advisory pages are the ground truth for version-to-CVE mapping — always check the live page for the engagement date, not a cached memory of past CVEs.
2. Static-asset hashing beats banner-grabbing once vendors start stripping version strings from login pages (a growing trend post-2023).
3. A single unpatched perimeter VPN appliance is often the entire finding for an engagement — don't rush past fingerprinting to look for something more "interesting."
4. Always check for an HA pair before any RCE-confirmation attempt; a single appliance with no failover multiplies the DoS-risk classification.

## Tooling

No dedicated CLI ships in the sandbox; `curl`/`nmap`/Python cover fingerprinting.
```
sudo apt-get install -y nmap
```
- **nmap** with `-sV --script=http-title,http-headers` for a fast first-pass banner sweep across a range of candidate gateways.
- **curl** — sufficient for every fingerprinting request in this skill.

## Summary

Treat every enterprise VPN gateway as a fingerprint-then-map problem: identify vendor and exact build without touching anything destructive, cross-reference the vendor's own current advisory list, confirm non-destructively, and flag before any RCE-class exploitation attempt against production. These appliances are the most common real-world initial-access point precisely because they're unauthenticated-reachable by design — treat a confirmed unpatched instance as critical on its own.
