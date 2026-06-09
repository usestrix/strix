---
name: dns_infrastructure
description: DNS infrastructure assessment - zone transfers, subdomain takeover, DNSSEC validation, resolver and cache behavior, and registrar/delegation abuse.
---

# DNS Infrastructure

DNS infrastructure is the authoritative and recursive layer that maps names to addresses and publishes service metadata (MX, TXT, SRV, CAA, NS). The attacker's objective is to harvest internal topology, hijack dangling names, poison or manipulate resolution, and abuse misconfigured authoritative servers or resolvers to break confidentiality, integrity, or availability of everything that depends on a name. A single exposed zone transfer or a forgotten CNAME to a deprovisioned cloud bucket can expose the entire internal estate or yield full subdomain control.

## Attack Surface

**Authoritative servers**
- TCP/UDP 53 on every NS listed in the zone's `NS` records and parent delegation
- AXFR/IXFR (zone transfer) endpoints, often left open to the world or to stale secondary IPs
- Dynamic updates (RFC 2136) on unprotected primaries; NOTIFY spoofing
- Hidden primaries and out-of-rotation secondaries with weaker ACLs

**Recursive resolvers**
- Open resolvers (UDP/TCP 53) usable for cache poisoning and DDoS amplification
- DoH/DoT endpoints (443/853) with their own ACL and validation behavior
- Local stub/forwarder configs and split-horizon views that leak internal-only names

**Delegation and registrar layer**
- Dangling `CNAME`/`NS`/`A` records pointing to deprovisioned cloud resources (subdomain/NS takeover)
- Lame delegations, expired domains, registrar account/email-verification weaknesses
- CAA gaps that let an attacker issue certs after a takeover

**Published metadata**
- TXT (SPF/DKIM/DMARC, verification tokens, internal hostnames), SRV/MX (service map), HINFO/LOC leaks

## Recon & Enumeration

Most ProjectDiscovery and DNS tools are preinstalled in the Kali sandbox. Install any missing ones:
```
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
apt-get install -y dnsutils dnsrecon dnsenum fierce nsec3map  # dig/host/nslookup live in dnsutils
go install -v github.com/haccer/subjack@latest   # subdomain-takeover signatures
pip install dnstwist                              # registrable lookalikes / typosquats
```

Map authoritative servers and delegation:
```
dig +short NS example.com
dig +short SOA example.com
dig +trace example.com            # walk delegation parent->child, spot lame/inconsistent NS
whois example.com | grep -iE 'expir|registrar|name server|status'
```

Attempt zone transfer against every NS (the highest-value quick win):
```
for ns in $(dig +short NS example.com); do
  echo "== $ns =="; dig AXFR example.com @"$ns" +time=5 +tries=1
done
dnsrecon -d example.com -t axfr
fierce --domain example.com        # NS discovery + AXFR + bruteforce
```

Enumerate records and brute hosts:
```
dnsrecon -d example.com -t std,srv,axfr
dnsx -d example.com -w /usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt -a -aaaa -cname -mx -ns -txt -resp -silent -o dnsx.txt
subfinder -d example.com -all -recursive -silent -o subs.txt
dnsx -l subs.txt -a -cname -resp -silent -o resolved.txt   # resolve + capture CNAME chains for takeover triage
```

DNSSEC posture and zone-walking:
```
dig +dnssec +multiline DNSKEY example.com
dig +dnssec SOA example.com | grep -E 'RRSIG|ad;'   # 'ad' flag = validating resolver accepted signatures
delv example.com A +rtrace                          # full chain-of-trust validation with reasons
dig +short +dnssec NSEC3PARAM example.com
nsec3map -o hashes.txt example.com                  # walk NSEC3 zones; nsec (no 3) walks trivially via NSEC chasing
```

Resolver behavior, takeover, and lookalikes:
```
nmap -sU -sV -p53 --script dns-recursion,dns-cache-snoop,dns-nsid,dns-zone-transfer <resolver_ip>
nuclei -l resolved.txt -t dns/ -tags takeover -severity high,critical -j -o dns_nuclei.jsonl
subjack -w subs.txt -t 50 -timeout 10 -ssl -c /root/go/.../subjack/fingerprints.json -v -o takeover.txt
dnstwist --registered example.com   # phishing/typosquat domains already registered
```

## Methodology

1. **Establish delegation truth.** `dig NS` at the child, `dig +trace` from root, and compare against the parent's glue. Note every NS IP, hidden primaries, lame delegations, and NS/glue mismatches — these define the real attack surface.
2. **Hunt zone transfers.** Run AXFR against each NS (TCP 53). A successful transfer dumps the entire zone: internal hosts, naming conventions, infra IPs. Also try IXFR and stale secondary IPs from historical records.
3. **Brute and passive-enumerate names.** Combine `subfinder` (passive) with `dnsx` wordlist resolution. Capture full CNAME chains and the final answer for every host.
4. **Triage dangling records.** For each CNAME/NS/A, check whether the target resource still exists. A CNAME to an unclaimed cloud endpoint (S3, Azure, Heroku, GitHub Pages, Fastly, etc.) returning NXDOMAIN or a "no such bucket/app" page is a candidate takeover.
5. **Assess DNSSEC.** Determine if the zone is signed, whether the chain validates (`delv`), whether DS exists at the parent, and whether weak algorithms (RSA/SHA-1, alg 5/7) or NSEC (vs NSEC3) enable zone-walking.
6. **Probe resolvers.** Identify open recursion, cache-snooping, predictable source ports/TXIDs, and lack of 0x20/DNS-cookie defenses. Check DoH/DoT for the same.
7. **Inspect published metadata.** Parse SPF/DKIM/DMARC for spoofing gaps, find verification TXT records and internal hostnames, map services via SRV/MX.
8. **Validate registrar/CAA layer.** Check domain expiry, registrar-lock status, and whether CAA restricts issuance after a takeover.

## Key Weaknesses / Techniques

**Open zone transfer (AXFR).** The classic full-disclosure bug. Confirm by dumping the zone:
```
dig AXFR internal.example.com @ns1.example.com
```
A non-empty `IN SOA ... IN A ...` listing rather than `Transfer failed` means the entire zone leaked. Capture it for the internal map; do not modify records.

**Subdomain takeover (dangling CNAME).** A name like `legacy.example.com` CNAMEs to `legacy-app.s3.amazonaws.com` that no longer exists. Verify the dangle, then assess claimability:
```
dig +short CNAME legacy.example.com
curl -sSI https://legacy.example.com   # look for "NoSuchBucket", "There isn't a GitHub Pages site here", etc.
```
PoC = registering the orphaned resource (only with explicit authorization and on a scoped non-production name) and serving a harmless marker file, never live malicious content.

**NS takeover / lame delegation.** A delegated subzone points to an NS whose domain or cloud DNS zone is unclaimed. Claiming it yields authority over the entire subzone — far broader than a single CNAME. Confirm with `dig NS sub.example.com` returning servers that NXDOMAIN or that you can register.

**DNSSEC failures.** Unsigned zones permit on-path spoofing/cache poisoning. Broken chains (missing DS at parent, expired RRSIG, key rollover errors) cause SERVFAIL or, worse, silent bypass on non-validating resolvers. NSEC zones allow trivial zone-walking (`dig NSEC` chasing); weak algorithms (alg 5/7, SHA-1) weaken integrity.

**Cache poisoning / resolver manipulation.** Open recursion plus predictable TXID or static source port enables Kaminsky-style poisoning; absent 0x20 encoding and DNS cookies (RFC 7873) lowers off-path difficulty. Confirm recursion and snoop the cache for visited domains:
```
nmap -sU -p53 --script dns-recursion,dns-cache-snoop --script-args 'dns-cache-snoop.mode=timed,dns-cache-snoop.domains={www.bank.com,vpn.example.com}' <resolver_ip>
```

**Amplification / DoS.** Open resolvers answering large records (ANY, DNSKEY, TXT) for spoofed sources are reflectors. Measure the amplification factor (response/query size) read-only; never source-spoof or send sustained traffic.

**Dynamic update abuse.** RFC 2136 primaries without TSIG let an attacker inject/overwrite records:
```
nsupdate -v <<'EOF'
server ns1.example.com
zone example.com
update add evil.example.com 60 A 203.0.113.10
send
EOF
```
A successful update (verify with a fresh `dig`) is integrity compromise of the zone.

**SPF/DMARC gaps.** `+all`/`?all`, overly broad includes, or missing DMARC enable email spoofing of the domain — chains into phishing and password reset abuse.

## Validation

1. **Zone transfer:** show the AXFR output containing real RRs the NS should not expose externally; record which NS IP served it and that it is reachable from outside the trusted secondary set.
2. **Takeover:** prove the target resource is unclaimed (NXDOMAIN/error fingerprint) AND that you (with authorization) claimed it and served a benign proof token at the orphaned name. A dangling record alone is suggestive, not confirmed.
3. **DNSSEC:** use `delv +rtrace` / `dig +dnssec` to show the specific validation state (insecure/bogus/expired RRSIG/missing DS) with the actual chain output.
4. **Open resolver/recursion:** query an external domain you control through the resolver and observe it recursing for a non-cached, third-party name; cache-snoop to demonstrate it answers for arbitrary domains.
5. **Dynamic update:** add a uniquely-named harmless record, confirm it resolves, then remove it. Document exactly which NS accepted the update without TSIG.

## False Positives

- **AXFR refused but partial answer:** `Transfer failed.` or only the SOA returned is not a leak; require a full RR set.
- **Takeover false alarms:** a CNAME to a *live* third-party that simply returns 404 is not claimable. Many cloud providers now block re-registration of released names; verify the resource is actually claimable, not merely 404ing.
- **DNSSEC "bogus" from your own resolver:** local time skew or a stale trust anchor causes false SERVFAIL — validate from a clean resolver before reporting.
- **Recursion that is ACL-scoped:** a resolver recursing for you because your test IP is in an allowlist is not "open." Test from an out-of-scope vantage where authorized.
- **Internal names from split-horizon:** names visible only because you queried an internal view are not external disclosure.
- **Wildcard records:** `*.example.com` resolving makes brute-force tools report thousands of "hosts" that do not exist — detect the wildcard first (`dig randomstring123.example.com`).

## Chaining & Impact

- AXFR / brute enum → internal hostnames and IP ranges → targeted attacks on admin panels, VPN, mail, and staging not meant to be public.
- Subdomain takeover → serve content under a trusted name → cookie theft (parent-domain cookies), OAuth/SSO redirect abuse, CSP bypass, and phishing with a legitimate certificate (issue via the takeover unless CAA blocks it).
- NS takeover → full control of a subzone → mint arbitrary records, intercept mail (MX), and pass ACME DNS-01 challenges to issue wildcard certs.
- Cache poisoning / dynamic update → redirect users and services (login, update servers, package mirrors) → credential capture and supply-chain compromise.
- SPF/DMARC gaps + lookalike domains → high-fidelity phishing → account takeover that feeds the rest of the chain.
- Open resolver → reflection/amplification participation and cache snooping that fingerprints the victim's upstream dependencies.

## Pro Tips

1. Always query *every* NS individually; one stale secondary frequently still allows AXFR while the primaries refuse.
2. Pull historical NS/A records (passive DNS, `whois -h whois.cymru.com`, crt.sh) — decommissioned servers and old delegations are where transfers and takeovers hide.
3. crt.sh and certificate transparency reveal subdomains DNS brute-forcing misses; cross-reference CT names against live resolution to surface dangling records.
4. Detect wildcard DNS before brute-forcing or every tool will drown you in phantom hosts.
5. For takeovers, the error-page fingerprint matters more than NXDOMAIN — keep `subjack`/nuclei takeover templates current; provider strings change.
6. NSEC zones are a free zone enumeration: chase the NSEC chain instead of brute-forcing. NSEC3 needs `nsec3map` plus a wordlist/GPU to reverse hashes.
7. The `ad` flag in a `dig` answer tells you the *resolver* validated DNSSEC; absence of DS at the parent tells you the *zone* is effectively unsigned regardless of its DNSKEYs.
8. Check CAA early — a strict CAA can be the only control stopping a confirmed takeover from escalating to a trusted certificate.
9. Test DoH/DoT separately; ACLs and validation often differ from plain UDP 53 on the same infrastructure.
10. Keep all destructive probes (dynamic update, amplification) read-only or self-cleaning, and confine claimed takeover resources to benign proof tokens.
