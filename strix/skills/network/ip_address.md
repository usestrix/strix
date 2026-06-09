---
name: ip_address
description: Methodology for assessing a single IP address asset — port/service discovery then per-service exploitation.
---

# IP Address (Network Host)

An IP address asset is a single routable host: a bare network endpoint with no implied application context. The attacker's objective is to enumerate every reachable port, fingerprint the service behind each one, and then drive each service down its own exploitation path — unauthenticated RCE, default/weak credentials, exposed admin/management planes, info leaks, and protocol-specific abuse. Treat the IP as the root of a tree: the port/service scan is breadth, and every confirmed service spawns a focused depth assessment. Resolve the IP to its host context first (PTR, certificate SANs, vhosts) because the same socket often fronts many logical apps.

## Attack Surface

- **TCP/UDP service ports** — web (80/443/8080/8443), SSH (22), databases (3306/5432/1433/27017/6379/9200/11211), RPC/SMB (135/139/445), RDP (3389), mail (25/110/143/465/587/993), DNS (53), SNMP (161/udp), LDAP (389/636), VPN/IPsec (500/4500/udp), Docker/k8s (2375/2379/10250).
- **Management & admin planes** — IPMI/iDRAC/iLO, vCenter, router/switch web UIs, Redis/Memcached with no auth, exposed `/metrics`, Kubelet, Consul/etcd, Jenkins, monitoring stacks.
- **Virtual-host multiplexing** — one IP fronting many TLS SNI hosts or HTTP `Host` vhosts; the IP-default response often differs from the intended apps.
- **Network identity leakage** — PTR records, TLS cert CN/SAN, service banners, SNMP sysDescr, SMB/NetBIOS names that map the host into an org and reveal sibling assets.
- **UDP services** — frequently skipped, often unauthenticated (SNMP, DNS, NTP, IKE, mDNS, NetBIOS), and commonly amplification/info-leak vectors.

## Recon & Enumeration

Most tooling below ships in the Kali sandbox. Install lines are given for service-specific tools.

**Pass 1 — broad TCP discovery (fast, then verify):**
```
naabu -host <ip> -top-ports 1000 -scan-type c -Pn -rate 300 -c 25 -timeout 1000 -retries 1 -verify -silent -j -o naabu.jsonl
naabu -host <ip> -p - -scan-type c -Pn -rate 500 -c 25 -timeout 1000 -retries 1 -verify -silent   # full sweep when scope allows
```

**Pass 2 — service/version + default scripts on the discovered ports only:**
```
nmap -n -Pn -sV -sC -p <comma_ports> --version-intensity 5 --script-timeout 30s --host-timeout 5m -oA nmap_services <ip>
```

**UDP top ports (slow — keep tight):**
```
sudo nmap -n -Pn -sU --top-ports 50 --open -T4 --max-retries 1 --host-timeout 5m -oA nmap_udp <ip>
```

**Host identity & DNS context:**
```
dnsx -ptr -l <(echo <ip>) -resp -silent          # reverse DNS
nmap -n -Pn -p 443,8443 --script ssl-cert <ip>   # cert CN/SAN reveals vhosts/org
openssl s_client -connect <ip>:443 -showcerts </dev/null 2>/dev/null | openssl x509 -noout -text | grep -A1 'Subject Alternative'
```

**Web-port triage (run after ports are known):**
```
httpx -l <(printf '%s\n' <ip>:80 <ip>:443 <ip>:8080 <ip>:8443) -sc -title -tech-detect -server -tls-grab -favicon -json -o httpx.json
wafw00f https://<ip>
```

**Vuln sweep across all live services:**
```
nuclei -u <ip> -as -s critical,high -rl 50 -c 20 -bs 20 -timeout 10 -retries 1 -silent -j -o nuclei.jsonl
nuclei -u <ip> -tags network,default-login,exposure,misconfig -s critical,high,medium -silent -j -o nuclei_net.jsonl
```

**Service-specific installs:**
- TLS: `testssl.sh https://<ip>:443` (`apt install testssl.sh`).
- SMB/RPC: `apt install smbclient enum4linux-ng` then `enum4linux-ng -A <ip>`; `nmap --script smb-vuln-* -p445 <ip>`.
- SNMP: `apt install snmp onesixtyone` then `onesixtyone -c community.txt <ip>` and `snmpwalk -v2c -c public <ip>`.
- LDAP/AD: `apt install ldap-utils python3-impacket` then `ldapsearch -x -H ldap://<ip> -s base namingcontexts`.
- SSH posture: `pip install ssh-audit` then `ssh-audit <ip>`.
- DBs: `redis-cli -h <ip> ping`, `mongosh "mongodb://<ip>:27017"`, `psql -h <ip> -U postgres`.

## Methodology

1. **Establish scope & identity** — confirm the IP is in scope, capture PTR, ASN/owner, and TLS SAN so you know which org and which sibling hosts the asset belongs to.
2. **Discover ports (breadth)** — `naabu` top-1000 with `-verify`, then a full `-p -` sweep if scope permits. Never enrich ports you have not verified open.
3. **Fingerprint services (depth entry)** — `nmap -sV -sC` against only the open ports to get exact product/version, then add UDP top-50 separately.
4. **Branch per service** — for each open port, switch into its specific assessment (web → katana/ffuf/nuclei; SMB → enum4linux-ng; DB → auth probe; etc.). The IP scan exists to produce these branches.
5. **Version-to-CVE mapping** — feed exact versions to `nuclei -as` and targeted CVE templates; cross-check `nmap --script vuln`.
6. **Auth & defaults** — test default/weak credentials on every authenticated service (SSH, RDP, DBs, admin panels, SNMP communities) using small, scoped wordlists.
7. **Web vhost resolution** — if 80/443 serve a generic/default page, brute `Host`/SNI to surface the real applications behind the IP.
8. **Validate & PoC** — confirm each candidate with a minimal, non-destructive proof and capture reproducible evidence.
9. **Chain** — pivot a single foothold (creds, file read, SSRF-able service) into deeper access across the host and into the network.

## Key Weaknesses / Techniques

**Unauthenticated/exposed data stores** — Redis, Memcached, Elasticsearch, MongoDB, etcd bound to the public IP with no auth.
```
redis-cli -h <ip> info server            # version + CONFIG GET dir/dbfilename → RDB write primitive
curl -s http://<ip>:9200/_cat/indices    # Elasticsearch index/data exposure
curl -s http://<ip>:2379/v2/keys/?recursive=true   # etcd keys (often k8s secrets)
```

**Default / weak credentials** on management services — test conservatively against SSH, RDP, web admin, DBs, SNMP.
```
hydra -L users.txt -P pass-small.txt -t 4 -f ssh://<ip>
nmap -p 161 --script snmp-brute --script-args snmp-brute.communitiesdb=community.txt <ip>
```

**Service-version CVEs** — map the exact banner to known unauthenticated RCEs (e.g. exposed Jenkins, GitLab, Confluence, Exchange, vCenter, RDP/SMB). Drive with version-pinned templates.
```
nuclei -u https://<ip>:8443 -t http/cves/ -s critical,high -silent -j -o cve.jsonl
nmap -p445 --script smb-vuln-ms17-010,smb-vuln-cve-2020-0796 <ip>
```

**TLS/transport flaws** — expired/self-signed certs, weak ciphers, Heartbleed, certs leaking internal hostnames and additional vhosts.
```
testssl.sh --severity HIGH https://<ip>:443
```

**SMB/RPC exposure** — null sessions, anonymous share read, signing disabled, OS/user enumeration.
```
enum4linux-ng -A <ip>
smbclient -N -L //<ip>/
```

**SNMP info leak** — `public`/`private` communities exposing routes, processes, ARP, and sometimes write access for config theft.
```
snmpwalk -v2c -c public <ip> 1.3.6.1.2.1.25.4.2.1.2   # running processes
```

**Docker/Kubelet plane** — unauthenticated Docker API or Kubelet read = container/host takeover.
```
curl -s http://<ip>:2375/version && curl -s http://<ip>:2375/containers/json
curl -sk https://<ip>:10250/pods                       # Kubelet pod listing
```

**Web behind the IP** — once a web port is confirmed, treat it as a web target: crawl, content-discover, and look for the usual classes (SQLi, SSRF, path traversal, auth bypass).
```
katana -u https://<ip> -jc -kf all -silent -o urls.txt
ffuf -u https://<ip>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,204,301,302,401,403 -t 40
```

## Validation

1. **Open port** — re-confirm with `nmap -sV` against the single port; a verified banner beats a raw SYN-ACK from a stateful firewall.
2. **Exposure** — capture the actual leaked data (index list, key dump, share listing) with a single read-only request; show the public IP in the request and the sensitive content in the response.
3. **Default creds** — log in once, run one harmless identifying command (`id`, `whoami`, `SELECT version()`, `INFO`), capture output, and stop.
4. **CVE** — prefer a safe detection signature (version match + a benign template hit) over destructive exploitation; if exploitation is required and authorized, demonstrate minimal impact (e.g., read a non-sensitive file) and record exact request/response.
5. **TLS** — attach the `testssl.sh` line proving the weak cipher/cert and, for Heartbleed, the leaked memory snippet with PII redacted.
6. Record the exact port, protocol, product/version, command, and timestamp so the finding is reproducible.

## False Positives

- **Firewall/IPS SYN-ACK on every port** — a host that reports hundreds of "open" ports with no banners is likely a filtering device, not real services; `-verify`/`nmap -sV` will show no service.
- **Shared hosting / CDN / load balancer IP** — the IP fronts many tenants; the default response is not the in-scope app, and a finding on the edge may not belong to the target.
- **Honeypot signatures** — implausible combinations (every DB + RDP + SMB open with stub banners) indicate a decoy.
- **Self-signed cert "errors"** — internal/mgmt hosts legitimately use self-signed certs; only escalate if it enables interception or exposes data.
- **`nuclei` info/low template noise** — version banners and tech-detect hits are leads, not vulnerabilities, until tied to an exploitable condition.
- **Rate-limit/scan artifacts** — ports that flap open/closed under load; re-verify slowly before reporting.

## Chaining & Impact

- Default DB/Redis creds → write primitive (Redis RDB to crontab/SSH key, MSSQL `xp_cmdshell`) → host RCE.
- SNMP `private` write or exposed config → credential/key theft → lateral movement to sibling hosts revealed by ARP/route tables.
- TLS SAN / PTR enumeration → discovery of additional in-scope hosts and internal hostnames → wider footprint.
- Web SSRF on the IP → cloud metadata (`169.254.169.254`) → IAM credentials → cloud control plane (see the SSRF skill).
- Unauth Docker/Kubelet → container escape / host takeover → pivot into the orchestrator and its secrets.
- Single foothold (SSH/RDP via weak creds) → internal port scan from the host → reach previously unroutable RFC1918 services.

## Pro Tips

- Always run a **full `-p -` sweep when scope allows** — the highest-impact findings (mgmt planes, forgotten DBs, debug ports) live on non-standard ports above 1024.
- UDP is where the easy unauthenticated leaks hide (SNMP, DNS, IKE, NetBIOS); budget time for at least the top-50.
- The **TLS certificate is free recon** — SAN entries reveal sibling hostnames and the org, turning one IP into a host inventory.
- If 80/443 returns a bland default page, the real apps are vhosts — brute `Host:`/SNI before concluding "nothing here".
- Pin exploitation to the **exact version string**; a generic CVE template firing on a patched build is the most common false report.
- Keep credential testing tiny and targeted (4 threads, curated small lists) to avoid lockouts and to stay defensible.
- Scan from a stable egress and re-verify flapping ports slowly; transient results waste triage time and erode report credibility.
- Treat the IP scan as a **dispatcher**: its only job is to hand each open port to the right specialist methodology — don't try to exploit everything from the network layer.
