---
name: cidr
description: Network range (CIDR) assessment - host discovery, port/service enumeration, and pivoting across the block
---

# CIDR / Network Range

A CIDR asset is a contiguous block of IP space (e.g. `10.0.0.0/16`, `203.0.113.0/24`) owned or operated by the target. The objective is to convert the bare prefix into a map of live hosts, open ports, and identified services, then assess each exposed service for missing patches, default/weak credentials, misconfiguration, and trust relationships that allow lateral movement deeper into the block. Treat the range as a layered problem: sweep wide and cheap first, then enrich only what answers, and stop noise from drowning real findings. Stay strictly inside the authorized prefix at all times.

## Attack Surface

**Scope**
- Live hosts across the prefix (responsive to ICMP/ARP/TCP/UDP probes; many will be silent and need `-Pn`)
- TCP and UDP services on each host (web, SSH, RDP, SMB, RPC, databases, mail, DNS, SNMP, NTP, mDNS)
- Network infrastructure: routers, switches, firewalls, load balancers, VPN concentrators, management/IPMI/iDRAC/iLO interfaces
- Virtualization and orchestration endpoints exposed on the block (ESXi, vCenter, Docker 2375/2376, Kubernetes 6443/10250, etcd 2379)
- Trust boundaries: NFS/SMB shares, LDAP/Kerberos, internal CAs, syslog/SNMP managers, jump hosts

**Entry Points**
- Internet-facing or internal hosts with unpatched or end-of-life services
- Default, reused, or weak credentials on admin panels, databases, and network gear
- Anonymous/guest access (SMB null sessions, anonymous FTP, open NFS exports, unauthenticated Redis/Mongo/Elastic)
- Forgotten dev/staging hosts, decommissioned-but-live systems, and shadow IT
- Misconfigured TLS, exposed management planes, and leaked service banners revealing internal naming

**What Is Exposed**
- Service banners and versions (map directly to CVEs)
- Hostnames and internal DNS via reverse lookups, TLS SAN/CN, SMB/LDAP, and SNMP
- Network topology hints from TTLs, traceroutes, and routing/SNMP data
- Authentication surfaces (SSH, RDP, web logins, VPN portals, database listeners)

## Recon & Enumeration

Define scope once and reuse it. Keep all targets confined to the authorized CIDR.

```
echo "203.0.113.0/24" > scope.txt          # one CIDR or host per line
mkdir -p recon && cd recon
```

**Host discovery (alive hosts only, cheap first):**
```
# Fast ping + ARP-style discovery within scope (no port scan)
nmap -sn -n -PE -PS22,80,443 -PA80,443 -T4 -iL ../scope.txt -oA hosts_alive
# Pull just the live IPs for downstream tools
grep "Up$" hosts_alive.gnmap | cut -d' ' -f2 > alive.txt
# fping is a fast alternative when ICMP is allowed
fping -a -g 203.0.113.0/24 2>/dev/null > alive_fping.txt
```

**Port discovery across the block (broad, then verify):**
```
# naabu CONNECT scan, top ports, verified, JSON for parsing
naabu -list alive.txt -top-ports 200 -scan-type c -Pn -rate 500 -c 25 \
  -timeout 1000 -retries 1 -verify -silent -j -o naabu.jsonl
# Reduce to host:port pairs for enrichment
jq -r '"\(.host):\(.port)"' naabu.jsonl > openports.txt
# masscan for very large ranges when raw sockets are available (bound the rate)
sudo masscan 203.0.113.0/24 -p1-65535 --rate 1000 -oL masscan.txt   # apt-get install -y masscan
```

**Service/version + script enrichment (only on discovered ports):**
```
# Feed naabu output back to nmap for accurate fingerprints
nmap -n -Pn -sV -sC --version-intensity 5 --script-timeout 30s --host-timeout 5m \
  -iL alive.txt -p $(jq -r '.port' naabu.jsonl | sort -un | paste -sd,) -oA services
```

**UDP sweep (slow, scope tightly to high-value services):**
```
nmap -n -Pn -sU --top-ports 25 -T4 --host-timeout 5m -iL alive.txt -oA udp
# Targets of interest: 53 DNS, 69 TFTP, 123 NTP, 161 SNMP, 500 IKE, 1900 SSDP, 5353 mDNS
```

**Web layer (probe every web-ish port, fingerprint, scan):**
```
httpx -l openports.txt -sc -title -server -td -fr -timeout 10 -retries 1 \
  -rl 50 -t 25 -silent -j -o httpx.jsonl
jq -r 'select(.status_code!=null) | .url' httpx.jsonl > weburls.txt
wafw00f -i weburls.txt                                  # WAF/CDN identity
nuclei -l weburls.txt -as -s critical,high -rl 50 -c 20 -bs 20 \
  -timeout 10 -retries 1 -silent -j -o nuclei.jsonl
katana -list weburls.txt -d 2 -jc -silent -o crawl.txt  # crawl for content/params
ffuf -u FUZZ/ -w weburls.txt:FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302,401,403 -of json -o ffuf.json
```

**DNS / naming (resolve hostnames, find vhosts):**
```
# Reverse DNS across the block
dnsx -l alive.txt -ptr -resp -silent -o ptr.txt          # apt-get install -y dnsx  (or projectdiscovery release)
# Internal zone enumeration if a resolver is in scope
dnsrecon -r 203.0.113.0/24 -n <internal-dns-ip>          # apt-get install -y dnsrecon
# TLS SAN/CN harvest reveals internal names and adjacent hosts
tlsx -l openports.txt -san -cn -silent -o tls_names.txt   # apt-get install -y tlsx
```

**Asset-specific probes (install as needed in the Kali sandbox):**
```
apt-get install -y snmp smbclient ldap-utils nbtscan onesixtyone enum4linux-ng
pip install impacket                                      # smbexec, secretsdump, GetUserSPNs, rpcdump
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt -i alive.txt   # SNMP community brute
snmpwalk -v2c -c public <host> 1.3.6.1.2.1                # if 'public' answers
nbtscan -r 203.0.113.0/24                                 # NetBIOS sweep
enum4linux-ng -A <host>                                   # SMB/RPC/LDAP enumeration
smbclient -L //<host> -N                                  # null-session share list
showmount -e <host>                                       # NFS exports
ldapsearch -x -H ldap://<host> -s base namingContexts     # anonymous LDAP base
```

## Methodology

1. **Confirm and bound scope.** Expand the CIDR to its host count (`nmap --script targets-asn` or `ipcalc 203.0.113.0/24`). Never probe outside the authorized prefix; split very large blocks into /24 chunks for tractable, restartable runs.
2. **Discover live hosts.** Layered discovery (ICMP, ARP on-LAN, TCP SYN/ACK to common ports). Keep a list of hosts that answer and a separate list that may be filtered (re-test with `-Pn`).
3. **Sweep ports cheaply.** Run `naabu`/`masscan` top-ports first to get coverage fast; reserve full `1-65535` for hosts that warrant it. Verify open ports before enrichment.
4. **Fingerprint services.** Feed verified ports to `nmap -sV -sC` for versions, banners, and safe NSE checks. Record product + version per host:port.
5. **Triage by exposure.** Bucket findings: web apps, management/admin planes, databases, file shares, network gear, auth services. Prioritize unauthenticated and high-CVSS surfaces.
6. **Enumerate each service class.** Web (httpx/nuclei/katana/ffuf), SMB/RPC (enum4linux-ng/impacket), SNMP (snmpwalk), LDAP/Kerberos (ldapsearch/GetUserSPNs), NFS (showmount), databases (native clients), TLS (tlsx/sslscan).
7. **Assess credentials and config.** Check defaults, anonymous access, and weak auth. Validate misconfigurations (open shares, debug endpoints, exposed admin UIs).
8. **Map trust and pivot.** Identify shared credentials, internal CAs, jump hosts, and segmentation gaps that let one foothold reach deeper subnets.
9. **Validate and document.** Reproduce each finding with a minimal, non-destructive PoC and capture exact host:port, version, and request/response evidence.

## Key Weaknesses / Techniques

**Unpatched / end-of-life services** — Version banners map to CVEs. Confirm exploitability before claiming impact.
```
nmap -n -Pn -sV --script vulners -p <ports> <host>        # NSE vulners (needs internet)
nuclei -u https://<host> -tags cve -s critical,high -silent
# searchsploit for offline correlation
searchsploit "OpenSSH 8.2" ; searchsploit apache 2.4.49
```

**Default / weak credentials** on admin panels, gear, and databases.
```
hydra -L users.txt -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt \
  ssh://<host> -t 4 -f                                     # throttle: -t 4, stop on first hit -f
nuclei -l weburls.txt -tags default-login -silent          # default web logins
# Network gear often ships admin/admin, cisco/cisco, root/calvin (iDRAC)
```

**Anonymous / unauthenticated data stores.**
```
redis-cli -h <host> -p 6379 INFO                           # open Redis: no AUTH required
curl -s http://<host>:9200/_cat/indices                    # open Elasticsearch
mongosh "mongodb://<host>:27017" --eval 'db.adminCommand("listDatabases")'
smbclient //<host>/<share> -N -c 'ls'                       # readable null-session share
```

**SMB / RPC exposure** — null sessions, signing not required, EternalBlue-era patch levels.
```
nmap -n -Pn -p445 --script smb-protocols,smb-security-mode,smb2-security-mode,smb-vuln-ms17-010 <host>
impacket-rpcdump <host>                                     # enumerate RPC endpoints
impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <host> -request   # Kerberoast if domain-joined
```

**SNMP information leak / write community.**
```
snmpwalk -v2c -c public <host> 1.3.6.1.2.1.1               # sysDescr, contact, location
snmpwalk -v2c -c public <host> 1.3.6.1.2.1.25.4.2.1.2     # running processes (host MIB)
# A writable community (often 'private') can alter device config — validate read-only first.
```

**TLS / certificate weaknesses** — expired, self-signed-on-prod, weak ciphers, internal names leaking topology.
```
sslscan <host>:443 ; nmap -n -Pn -p443 --script ssl-enum-ciphers <host>
tlsx -u <host>:443 -san -cn -expired -self-signed -silent
```

**Exposed management / virtualization planes** — ESXi/vCenter, IPMI, Docker API, Kubernetes (see kubernetes skill).
```
curl -sk https://<host>:2376/version                       # Docker TLS API exposed
nmap -n -Pn -p623 --script ipmi-version,ipmi-cipher-zero <host>   # IPMI cipher-0 auth bypass
```

## Validation

1. Prove the host is live and the port is genuinely open/serving (`nmap -sV` banner + a real protocol handshake, not just a SYN-ACK).
2. For a CVE, demonstrate the vulnerable version is present and, where safe, run a read-only/version-check exploit or a Nuclei template that returns a positive matcher — capture the matched response.
3. For credentials, show a successful authenticated action (e.g. `ssh` banner + `id`, a readable share listing, a database `listDatabases`) — never modify or exfiltrate data; one harmless read is sufficient.
4. For misconfiguration, capture the exact request/response that exposes the issue (open share `ls`, unauthenticated API JSON, SNMP sysDescr).
5. Record `host:port`, product, version, and the reproduction command so the finding is independently repeatable.

## False Positives

- **Filtered ≠ open.** Firewalls and SYN-ACK from middleboxes/honeypots can fake open ports. Confirm with a real service handshake (`-sV`).
- **Stale DHCP / decommissioned hosts** that answer one probe then vanish — re-test before reporting.
- **Banner spoofing and WAF/CDN interception** — the version shown may be a proxy, not the origin. Cross-check with behavior, not just the banner string.
- **Vulners/NSE version-based matches** flag CVEs by banner alone; backported patches (common on RHEL/Debian) leave the banner unchanged. Confirm actual exploitability.
- **Decoy/honeypot hosts** advertising many open ports with implausible service combinations.
- **Out-of-scope IPs** that resolve into the block via shared CDN/load-balancer addresses — verify ownership before acting.
- **UDP "open|filtered"** is inherently ambiguous; treat as unconfirmed until a protocol response is observed.

## Chaining & Impact

- **Recon → unpatched service → RCE → foothold:** a single CVE on one host becomes a shell; from there re-scan adjacent subnets that were previously unreachable.
- **Open share / SNMP / LDAP → credential harvest → credential reuse:** leaked configs, backups, or community strings yield credentials that often unlock SSH/RDP/SMB across many hosts in the block (password reuse is rampant on flat networks).
- **Management plane access → mass compromise:** vCenter/IPMI/Docker/K8s control planes can power on, image, or exec into many workloads at once.
- **Foothold → pivot → segmentation bypass:** use the compromised host as a jump point (`ssh -D`, chisel, ligolo-ng) to reach internal-only ranges, repeating the discovery loop one hop deeper.
- **Database / file-share read → data exposure:** open Mongo/Elastic/Redis/NFS frequently hold PII, secrets, or tokens that further the chain into cloud and SaaS.

## Pro Tips

1. Sweep wide and cheap, enrich narrow and deep. Top-ports `naabu`/`masscan` across the whole block, then `nmap -sV -sC` only on what answered — this is faster and far quieter than running version detection on every IP.
2. Always pass discovered ports back to `nmap` with `-p`; never let it re-scan its own default port list and miss your findings.
3. Chunk large prefixes into /24s and run per-chunk with output files — runs stay restartable and a single slow host can't stall the whole job.
4. Reverse DNS, TLS SAN/CN, and SMB/LDAP hostnames reveal the internal naming scheme; clusters of `db01`, `dc01`, `bak01` point straight at high-value targets.
5. UDP is where the easy wins hide (SNMP, NTP monlist, mDNS, SSDP) precisely because most scans skip it — but keep it tightly scoped, it is slow.
6. Throttle credential attempts hard (`-t 4 -f`) and watch for lockout policies; one locked admin account can end an engagement's goodwill.
7. Re-run host discovery after every foothold — newly reachable internal subnets often appear once you are past the perimeter.
8. Diff scans over time: a host that opens a new port or changes a banner mid-engagement may indicate a deploy, a defender response, or a honeypot.
9. Keep `-Pn` in your back pocket: many production hosts drop ICMP but answer TCP — a "no live hosts" result on a populated block usually means discovery was too conservative.
