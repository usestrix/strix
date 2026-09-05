---
name: ssl-tls-analysis
description: SSL/TLS configuration assessment covering cipher suite enumeration, certificate chain validation, protocol downgrade attacks, and known implementation vulnerabilities
---

# SSL/TLS Configuration Analysis

SSL/TLS misconfigurations remain among the most common network-layer findings. Weak cipher suites, expired certificates, protocol downgrade vulnerabilities, and implementation flaws expose encrypted communications to interception, decryption, and man-in-the-middle attacks.

## Attack Surface

**Scope**
- Any service exposing TLS: HTTPS (443), SMTPS (465/587), IMAPS (993), LDAPS (636), database TLS, custom ports
- Load balancers, reverse proxies, CDN edge nodes (each may have independent TLS configuration)
- Internal services using self-signed or improperly chained certificates

**What to Test**
- Protocol versions supported (SSLv3, TLS 1.0/1.1/1.2/1.3)
- Cipher suite selection and ordering
- Certificate validity, chain completeness, and trust anchoring
- Key exchange strength and forward secrecy
- Known implementation vulnerabilities (BEAST, POODLE, Heartbleed, ROBOT, etc.)
- HSTS, certificate transparency, OCSP stapling configuration

## Key Vulnerabilities

### Protocol Downgrade

**Legacy Protocol Support**
- SSLv3 → POODLE attack (CVE-2014-3566); padding oracle on CBC ciphers
- TLS 1.0 → BEAST attack (CVE-2011-3389); CBC IV predictability
- TLS 1.1 → No known critical attacks but lacks modern security features; deprecated by RFC 8996

**Detection**
```bash
# Check for SSLv3 support
nmap --script ssl-enum-ciphers -p 443 <host> | grep -i "SSLv3"

# Or with openssl
openssl s_client -ssl3 -connect <host>:443 2>&1 | grep -i "alert"
```

### Weak Cipher Suites

**Critical Weaknesses**
- `NULL` ciphers — no encryption at all
- `EXPORT` ciphers — 40/56-bit keys; trivially breakable (FREAK, Logjam)
- `RC4` ciphers — biased keystream; practical plaintext recovery (CVE-2013-2566)
- `DES`/`3DES` — 56/112-bit effective; Sweet32 birthday attack (CVE-2016-2183)
- `CBC` mode without TLS 1.3 — vulnerable to padding oracle attacks in older implementations

**No Forward Secrecy**
- `RSA` key exchange (not `ECDHE`/`DHE`) — compromised server key decrypts all past traffic
- Static `DH` parameters — precomputed logjam tables for common 1024-bit groups

### Certificate Issues

**Chain Problems**
- Expired certificate or intermediate
- Self-signed certificate in production
- Incomplete chain (missing intermediates)
- Wrong hostname (CN/SAN mismatch)
- Revoked certificate (CRL/OCSP)

**Key Weakness**
- RSA key < 2048 bits
- ECDSA key < 256 bits (P-256)
- SHA-1 signed certificates (deprecated since 2017)

### Implementation Vulnerabilities

| Vuln | CVE | Test |
|------|-----|------|
| Heartbleed | CVE-2014-0160 | `nmap --script ssl-heartbleed -p 443 <host>` |
| POODLE | CVE-2014-3566 | Check for SSLv3+CBC support |
| ROBOT | CVE-2017-13099 | `nmap --script ssl-robot -p 443 <host>` (if script available) |
| DROWN | CVE-2016-0800 | Check for SSLv2 support on any server sharing the RSA key |
| CCS Injection | CVE-2014-0224 | `nmap --script ssl-ccs-injection -p 443 <host>` |
| CRIME/BREACH | CVE-2012-4929 | Check TLS compression; `Accept-Encoding: gzip` response analysis |
| Renegotiation | CVE-2009-3555 | `openssl s_client -connect <host>:443` then type `R` |

## Testing Methodology

### 1. Enumerate Supported Protocols and Ciphers

```bash
# Comprehensive nmap scan
nmap -n -Pn --script ssl-enum-ciphers -p 443,8443 <host>

# Quick openssl check for specific protocol
openssl s_client -tls1 -connect <host>:443 < /dev/null 2>&1
openssl s_client -tls1_1 -connect <host>:443 < /dev/null 2>&1
openssl s_client -tls1_2 -connect <host>:443 < /dev/null 2>&1
openssl s_client -tls1_3 -connect <host>:443 < /dev/null 2>&1
```

### 2. Inspect Certificate Chain

```bash
# Full certificate details
openssl s_client -connect <host>:443 -showcerts < /dev/null 2>&1 | openssl x509 -noout -text

# Check specific fields
openssl s_client -connect <host>:443 < /dev/null 2>&1 | openssl x509 -noout \
  -subject -issuer -dates -fingerprint -ext subjectAltName
```

### 3. Test for Known Vulnerabilities

```bash
# Heartbleed
nmap -n -Pn --script ssl-heartbleed -p 443 <host>

# CCS Injection
nmap -n -Pn --script ssl-ccs-injection -p 443 <host>

# Multiple checks in one pass
nmap -n -Pn --script "ssl-*" -p 443 <host>
```

### 4. Check Security Headers

```bash
# HSTS header
curl -sI https://<host> | grep -i strict-transport

# Expected: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

## Validation

1. **Demonstrate the weakness** — Show the specific weak protocol/cipher is negotiable, not just advertised
2. **Prove impact** — For protocol downgrade, show the client can be forced to use the weak protocol; for weak ciphers, confirm the server selects them when offered exclusively
3. **Certificate issues** — Show the exact chain failure (expired date, hostname mismatch, missing intermediate)
4. **Implementation vulns** — Confirm with Nmap NSE scripts or equivalent tool output
5. **Rate accurately** — TLS 1.0 support alone is Medium; combine with CBC ciphers for High; SSLv3 or Heartbleed is Critical

## False Positives

- Server advertises weak ciphers but never selects them (server preference enforced) — verify by offering only the weak cipher
- Certificate expired in alternate SAN but primary domain is valid
- CDN/WAF terminates TLS before reaching origin — the finding applies to the edge, not the origin
- HSTS missing on a non-browser API endpoint — lower severity than a user-facing site
- TLS 1.0 enabled but only for specific legacy clients behind a load balancer policy

## CVSS Context

| Finding | Typical CVSS | Rationale |
|---------|-------------|-----------|
| SSLv3 enabled + CBC ciphers (POODLE) | 7.5 (High) | Network-exploitable padding oracle |
| TLS 1.0 only (no TLS 1.2/1.3) | 5.3 (Medium) | Deprecated protocol, known weaknesses |
| Heartbleed (confirmed) | 9.1 (Critical) | Memory disclosure, key extraction |
| Self-signed cert in production | 5.9 (Medium) | No trust chain; enables MITM |
| Missing HSTS | 4.3 (Medium) | Protocol downgrade on first visit |
| Weak DH parameters (< 2048 bit) | 5.3 (Medium) | Logjam precomputation feasible |
| No forward secrecy (RSA key exchange) | 5.3 (Medium) | Past traffic decryptable if key leaked |

## Pro Tips

1. Always test all TLS-enabled ports, not just 443 — SMTP STARTTLS (587), database TLS, and custom service ports often have weaker configurations
2. Check if the same RSA key is shared across multiple services — one SSLv2 service enables DROWN on all of them
3. For CDN-fronted targets, also test the origin directly if accessible — CDN may mask origin TLS weaknesses
4. Certificate transparency logs (crt.sh) can reveal additional subdomains and cert history
5. Modern TLS 1.3 has no known cipher suite weaknesses — if the server supports only TLS 1.3, focus testing on certificate chain and implementation instead

## Tooling

- **nmap** (preinstalled) — `ssl-enum-ciphers`, `ssl-heartbleed`, `ssl-ccs-injection` NSE scripts
- **openssl** (preinstalled) — Protocol probing, certificate inspection, manual cipher testing
- **nuclei** (preinstalled) — TLS misconfiguration templates: `nuclei -u https://<host> -tags ssl,tls`
