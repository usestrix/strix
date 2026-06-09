---
name: vpn_gateway
description: VPN / remote access gateway testing - fingerprinting, known-CVE validation, auth exposure, and pre-auth RCE chains
---

# VPN / Remote Access Gateway

VPN and remote-access gateways (Ivanti Connect Secure/Pulse, Fortinet FortiGate SSL-VPN, Citrix NetScaler/ADC Gateway, Cisco ASA/AnyConnect, Palo Alto GlobalProtect, SonicWall SMA/NSA, OpenVPN Access Server, WireGuard front-ends) sit on the network perimeter and terminate untrusted inbound traffic, then bridge it into the internal network. They are high-value because a single pre-auth flaw yields a foothold inside the trust boundary, and because they hold credentials, session tokens, and routing into protected segments. The attacker objective is to fingerprint the exact product and build, validate any applicable known CVE, and probe authentication surfaces (web portal, IKE/IPsec, captive endpoints) for bypass, credential abuse, or pre-auth code execution that turns the appliance into a pivot.

## Attack Surface

**Exposed services**
- TCP 443 / 10443 / 8443 - SSL-VPN web portal, admin UI, AnyConnect/GlobalProtect/FortiClient endpoints
- UDP 500 / 4500 - IKEv1/IKEv2 and IPsec NAT-T (aggressive mode, vendor ID leaks)
- UDP 1194 / TCP 1194 - OpenVPN
- UDP 51820 - WireGuard
- TCP 1723 + GRE (proto 47) - legacy PPTP
- TCP 22 / 8443 / custom - appliance management plane, REST/XML API

**Entry points**
- Unauthenticated portal endpoints (login, EPA/host-checker, language files, error pages, SAML ACS)
- Vendor API paths (`/remote/`, `/dana-na/`, `/api/v1/`, `/global-protect/`, `/+CSCOE+/`)
- IKE handshake (no auth required to negotiate phase 1, leaks fingerprint and sometimes usernames)
- Client provisioning / auto-update channels (FortiClient, AnyConnect downloader, profile XML)

**What is exposed**
- Product, version, and patch level via banners, TLS certs, JS asset hashes, and HTTP headers
- User enumeration via timing and distinct error strings on login / IKE aggressive mode
- Session cookies (`DSID`, `webvpn`, `SVPNCOOKIE`, `PHPSESSID`) that may be replayable
- Backup configs, system logs, and `/etc/passwd`-equivalents via path traversal in known CVEs

## Recon & Enumeration

```
# Service/port discovery (TCP + key UDP)
naabu -host gw.target.tld -p 443,10443,8443,4443,22,1194,1723 -silent -o ports.txt
nmap -Pn -sS -sU -p T:443,10443,8443,22,1723,U:500,4500,1194,51820 -sV --version-all gw.target.tld -oA vpn_scan

# IKE/IPsec fingerprint (aggressive mode leaks vendor + sometimes user)
ike-scan -M gw.target.tld
ike-scan --aggressive --id=testgroup -P psk.hash gw.target.tld   # capture PSK hash for offline crack

# TLS + HTTP fingerprint of the portal
httpx -u https://gw.target.tld:443 -title -tech-detect -status-code -tls-grab -favicon -jarm -o httpx.txt
echo | openssl s_client -connect gw.target.tld:443 2>/dev/null | openssl x509 -noout -subject -issuer -dates

# Identify vendor-specific endpoints
ffuf -u https://gw.target.tld/FUZZ -w vpn_paths.txt -mc 200,301,302,401,403 -fs 0
# vpn_paths.txt: dana-na/auth/url_default/welcome.cgi, remote/login, remote/fgt_lang,
#   global-protect/login.esp, +CSCOE+/logon.html, cgi-bin/welcome, api/v1/totp/user-backup-code

# Spider portal for build hashes / version strings
katana -u https://gw.target.tld -jc -d 2 -o katana.txt
```

Asset-specific tooling install (Kali):
- `apt-get install -y ike-scan` - IKE/IPsec enumeration and PSK capture
- `pip install scapy` - custom IKE/ESP packet crafting
- `git clone https://github.com/SpiderLabs/ikeforce && pip install -r ikeforce/requirements.txt` - IKE aggressive-mode user enumeration and PSK brute
- `hashcat -m 5300/5400` - crack IKE aggressive-mode PSK hashes (no extra install in Kali)

```
# CVE + misconfig sweep with version-aware templates
nuclei -u https://gw.target.tld -tags fortinet,ivanti,pulse,citrix,cisco,sonicwall,paloalto -s critical,high -j -o nuclei_vpn.jsonl
nuclei -u https://gw.target.tld -as -s critical,high -rl 30 -c 10 -bs 10 -timeout 10 -retries 1 -j -o nuclei_auto.jsonl

# WAF / reverse-proxy in front of the appliance
wafw00f https://gw.target.tld
```

## Methodology

1. **Map exposure** - `naabu`/`nmap` the gateway for the SSL-VPN port set and IKE UDP ports; confirm what is actually reachable versus filtered.
2. **Fingerprint precisely** - Pull the TLS cert CN/SAN, favicon hash, JS/CSS asset hashes, HTTP `Server`/`Set-Cookie` patterns, and vendor endpoints. Cross-reference the favicon hash and welcome-page build string to nail the exact major.minor.patch. IKE vendor-ID payloads independently confirm the product.
3. **Pin the build to CVEs** - Map the resolved version to advisories (FortiOS, Ivanti ICS, NetScaler, ASA/FTD, PAN-OS, SMA). Prefer pre-auth and version-gated CVEs. Validate with targeted `nuclei` templates before any exploitation.
4. **Probe authentication exposure** - Test the login flow for user enumeration, default/weak creds, missing lockout, MFA placement, and SAML/OIDC trust issues. Run IKE aggressive mode to capture PSK hashes and enumerate group/user IDs.
5. **Test pre-auth endpoints** - Hit language-file, host-checker, error, and API endpoints for path traversal, auth bypass, and template/command injection that known CVEs exploit.
6. **Validate, do not assume** - Confirm each candidate with a non-destructive PoC (read a benign file, observe a version-distinct response, capture a hash). Avoid web-shell drops; demonstrate reach instead.
7. **Assess session handling** - Check cookie scope, fixation, and replay; verify whether a captured session token works from a different IP/UA.
8. **Establish impact / pivot** - From a valid session or pre-auth read, demonstrate access to internal routes, config secrets, or credential material, then stop at proof.

## Key Weaknesses / Techniques

### Known-CVE pre-auth RCE / file read (validate the build first)
- **Ivanti Connect Secure** CVE-2023-46805 + CVE-2024-21887 (auth bypass + command injection, `/api/v1/totp/user-backup-code`), CVE-2025-0282 (stack overflow pre-auth RCE). Probe: `curl -sk 'https://gw/api/v1/totp/user-backup-code/../../system/system-information'` and check for an authenticated response without a session.
- **Fortinet FortiOS SSL-VPN** CVE-2022-42475 / CVE-2023-27997 (pre-auth heap overflow). Banner-pin the FortiOS build; validate with the vendor-specific nuclei template, not by crashing the device.
- **Citrix NetScaler** CVE-2023-3519 (pre-auth RCE) and CVE-2023-4966 "Citrix Bleed" (session token leak via oversized `Host`/buffer in `/oauth/idp/.well-known/openid-configuration`). Citrix Bleed PoC: send the crafted request and inspect the response for leaked `NSC_AAAC`/session material.
- **Cisco ASA/FTD** CVE-2020-3452 (WebVPN path traversal, unauth file read): `curl -sk 'https://gw/+CSCOU+/../+CSCOE+/files/file_list.json?path=/sessions'`.
- **Palo Alto GlobalProtect** CVE-2024-3400 (command injection via `SESSID` cookie path traversal in telemetry). CVE-2019-1579 (format-string in `sslmgr`).

```
# Example: Cisco ASA unauth path-read validation (read a known static resource only)
curl -sk "https://gw.target.tld/+CSCOU+/../+CSCOE+/files/file_list.json?path=/+CSCOE+/portal_inc.lua"

# Confirm a version-gated CVE without exploitation
nuclei -u https://gw.target.tld -t http/cves/2023/CVE-2023-4966.yaml -j -o citrixbleed.jsonl
```

### Authentication exposure
- **User enumeration**: distinct login error strings or response timing for valid vs invalid users; IKE aggressive mode returns a hash only for valid group/user IDs.
- **Missing lockout / weak creds**: rate-limited but unbounded login attempts; test default vendor creds (admin/admin, admin/<blank>, maintenance accounts) before any brute force, and only against an authorized account.
- **MFA placement flaws**: MFA enforced on the UI but not on the API or thick-client provisioning endpoint; or MFA bypassable by replaying a pre-MFA session cookie.
- **SAML/OIDC trust**: unsigned/altered assertions accepted at the ACS, audience/recipient not validated, or IdP-initiated flows allowing assertion replay. See the authentication_jwt skill for token tampering.

```
# IKE aggressive-mode user/PSK enumeration
python3 ikeforce/ikeforce.py -e -w users.txt gw.target.tld     # enumerate valid group/user IDs
ike-scan --aggressive --id=valid_group -P psk.txt gw.target.tld # capture PSK hash
hashcat -m 5300 psk.txt /usr/share/wordlists/rockyou.txt        # offline PSK crack (authorized)
```

### Path traversal / LFI in portal endpoints
- Language-pack, theme, and host-checker parameters frequently allow `../` traversal to read configs and session DBs (see CVE list above). Test with encoded traversal (`..%2f`, `..%252f`, `....//`).

### Information disclosure
- Backup config download, verbose error pages leaking internal hostnames/IPs, debug endpoints, and client profile XML exposing internal DNS, split-tunnel routes, and RADIUS server addresses.

## Validation

1. **Fingerprint proof** - Capture the exact build (TLS cert + favicon hash + welcome-page version string + IKE vendor ID agreeing) so the CVE mapping is defensible.
2. **CVE proof** - For file-read CVEs, retrieve a benign, version-distinct file (a vendor static asset or a config key that should not be public) and show it could not be obtained unauthenticated by design. For Citrix Bleed, show the leaked session token bytes in the response.
3. **Auth-bypass proof** - Demonstrate an authenticated-only API response returned without a valid session, or a session cookie minted without completing MFA, and confirm it grants portal access.
4. **PSK/credential proof** - Show a captured IKE aggressive-mode hash and (if authorized) a cracked PSK that completes phase 1, or a default credential that logs in.
5. **Reproducibility** - Record the exact request (method, path, headers, cookie) and the distinguishing response field. Re-run to confirm it is stable, not a transient 5xx.

## False Positives

- A vendor nuclei template firing on **banner/version alone** when the build is actually patched (backported fix keeps the version string). Confirm with a behavioral check, not the version banner.
- 401/403 on a CVE endpoint means the auth bypass did **not** work - the appliance is responding correctly.
- A WAF or reverse proxy returning a vendor-looking page; the real appliance may be patched or absent. `wafw00f` and `jarm` help distinguish edge from origin.
- IKE returning a response to any ID (some stacks reply uniformly) - not user enumeration unless valid vs invalid responses differ.
- Login timing differences caused by network jitter rather than backend logic; require a consistent, statistically separated delta across many samples.
- Self-signed cert or default hostname is a hygiene note, not a vulnerability by itself.

## Chaining & Impact

- **Pre-auth file read -> session theft -> full VPN access**: Citrix Bleed / Ivanti traversal leaks an active session token; replay it to enter the internal network as a legitimate user, bypassing MFA entirely.
- **Pre-auth RCE -> appliance foothold -> pivot**: FortiOS/NetScaler/Ivanti pre-auth code execution gives a shell on the perimeter device with routes into protected segments; from there enumerate internal hosts (see nmap/naabu) and reach domain controllers and metadata endpoints (see ssrf skill).
- **IKE PSK crack -> IPsec tunnel**: a cracked aggressive-mode PSK plus a valid credential establishes a full tunnel, granting the same access as a trusted remote worker.
- **Config / credential disclosure -> lateral movement**: leaked client profiles and backup configs reveal internal DNS, RADIUS/LDAP servers, and split-tunnel routes that scope follow-on attacks. Harvested LDAP/RADIUS creds enable Active Directory access.
- **Persistence**: appliance compromise frequently survives reboots and patching if web-shells or implants are planted - in authorized testing, demonstrate reach and stop; do not install persistence.

## Pro Tips

1. Pin the build with **multiple independent signals** (TLS cert, favicon hash, JS asset hash, IKE vendor ID) before mapping CVEs - version strings lie after backported patches.
2. IKE **aggressive mode** is the highest-signal unauthenticated probe: it leaks vendor, often valid group/user IDs, and a crackable PSK hash without touching the web portal.
3. The thick-client and API endpoints are frequently **less hardened** than the browser portal - test MFA and rate-limiting there, not just on the HTML login.
4. Many gateway CVEs are **version-gated path traversals**; reach for `..%252f` (double-encoding) and `....//` when single `../` is filtered.
5. Distinguish **edge from origin**: a CDN/WAF can mask both the real product and its patch level; correlate `jarm`, cert chain, and timing.
6. Validate destructively-classed CVEs (heap/stack overflow RCE) with **vendor-published detection templates**, never by sending a crash payload against production.
7. A leaked **active session token** is more valuable and quieter than RCE - it inherits the user's MFA-completed trust; prioritize session-leak CVEs for clean proof.
8. Check the **client auto-update / provisioning** channel - poisoned profiles and update endpoints can be a supply-chain path to every connecting endpoint.
