---
name: tls_network_layer
description: TLS and network-layer security testing covering cipher/protocol downgrade, certificate validation bugs, and SNI/ALPN confusion
---

# TLS & Network Layer

This skill covers the transport-layer surface beneath the application — cipher/protocol negotiation, certificate trust, and routing decisions made before any HTTP request is parsed. It's distinct from `tooling/nmap` (port/service discovery) and feeds directly into `http_request_smuggling` (framing confusion carried up from TLS/connection reuse into HTTP parsing).

## Attack Surface

**Negotiation**
- Protocol version (SSLv3/TLS1.0-1.3), cipher suite selection, key exchange (ECDHE vs static RSA), session resumption (session IDs, session tickets, TLS 1.3 PSK)
- ALPN (`h2`, `http/1.1`) — protocol selected during the TLS handshake itself, before any HTTP layer exists

**Certificate Trust**
- Chain validation, hostname verification (CN/SAN matching), revocation checking (OCSP/CRL, frequently not enforced)
- Client certificate authentication (mTLS) — presence check vs identity binding

**Routing**
- SNI-based virtual hosting — which certificate/backend is selected based on the client-declared SNI value
- STARTTLS — protocols that begin in plaintext and upgrade in-band (SMTP, IMAP, FTP, and some custom app protocols)

## Reconnaissance

**Protocol & Cipher Enumeration**
```bash
# on-demand install, not in the sandbox by default
apt-get install -y testssl.sh 2>/dev/null || git clone --depth 1 https://github.com/drwetter/testssl.sh /opt/testssl && /opt/testssl/testssl.sh target:443
```
`testssl.sh` covers protocol versions, cipher suites, known TLS CVEs (Heartbleed, ROBOT, etc.), certificate details, and common misconfigurations in one pass — start here before manual probing.

**Manual Handshake Inspection**
```bash
openssl s_client -connect target:443 -servername target -showcerts        # default negotiation + full chain
openssl s_client -connect target:443 -tls1                                 # force a specific (weak) version
openssl s_client -connect target:443 -cipher 'RC4-MD5'                     # force a specific (weak) cipher
```

## Key Vulnerabilities

### Protocol/Cipher Downgrade

- Confirm whether the server still accepts TLS 1.0/1.1 or SSLv3 alongside 1.2/1.3 — a downgrade-capable MITM position (out of scope to execute against production unless the program explicitly allows active MITM testing, but the *acceptance* of the weak protocol is itself the finding) exposes sessions to known protocol-level attacks (BEAST, POODLE, etc. depending on version)
- Export-grade or NULL/anonymous cipher suites still enabled (`openssl ciphers 'EXPORT'`) — trivially broken key exchange
- Missing forward secrecy — static RSA key exchange instead of (EC)DHE means a compromised private key retroactively decrypts captured traffic

### Certificate Validation Bugs (Client-Side)

This is about **client code under test** (a mobile app, an internal service calling out, a webhook consumer) accepting a certificate it shouldn't — not the server's own cert:
- Hostname verification bypass — client connects successfully to a cert issued for a different CN/SAN than the host it dialed (common in custom HTTP clients, gRPC channels configured with `insecure_skip_verify`/`InsecureSkipVerify`/`rejectUnauthorized: false` left on from debugging)
- Self-signed or expired certificate silently accepted
- Missing pinning where the app claims to pin (extract the pin set from a decompiled mobile client and verify the pin is actually enforced, not just present in code but unreachable/dead)

### STARTTLS Injection / Stripping

For protocols that upgrade in-band (SMTP `STARTTLS`, IMAP `STARTTLS`, or a custom app protocol doing the same pattern): if a MITM position can inject a response *before* the real STARTTLS acknowledgment arrives, or strip the STARTTLS capability advertisement, the client may continue in plaintext believing it's now encrypted, or the plaintext commands buffered before the upgrade may be processed as if authenticated post-upgrade (command injection across the plaintext/TLS boundary — this class of bug hit multiple mail servers historically). Test by observing whether commands issued immediately before `STARTTLS` are re-processed or buffered incorrectly after the upgrade completes.

### SNI-Based Routing Confusion

- Send a handshake with SNI absent, or SNI mismatched from the subsequent `Host` header at the HTTP layer, against infrastructure using SNI to route to different backends (shared load balancers, CDN edge nodes) — a mismatch between TLS-layer routing (SNI) and HTTP-layer routing (`Host` header) can reach an unintended backend/virtual host, functioning as a host-header-confusion variant one layer down:
```bash
openssl s_client -connect target:443 -servername internal-only.target.com
# then send an HTTP request with a different Host header over the established connection
```
- Domain fronting-style behavior — if SNI selects the TLS cert/routing but the HTTP `Host` header selects the actual application backend, and these are validated independently, a mismatch can bypass network-layer access controls that only inspect SNI

### mTLS Client-Certificate Bypass

- Confirm the server validates client-cert *identity* (CN/SAN/issuer chain to an authorized CA), not merely *presence* of some cert — a self-signed cert presented where any-cert-from-trust-store is expected reveals presence-only checking
- Test whether the mTLS-protected endpoint is also reachable via a non-mTLS-enforcing path (different port, different vhost/SNI on the same IP, a load balancer that terminates TLS before the mTLS check and forwards over plaintext to the backend)

### ALPN / Protocol-Confusion Smuggling

- If ALPN negotiates `h2` but a downstream component only speaks HTTP/1.1 (or vice versa), and translation happens at a proxy boundary, this is the TLS-layer root of many HTTP request smuggling setups — confirm what protocol is actually negotiated end-to-end (`openssl s_client -alpn h2 ...`) versus what each hop in the chain assumes, then hand off to `http_request_smuggling` methodology for the framing-desync exploitation itself.

## Testing Methodology

1. **Baseline scan** — `testssl.sh` full run against every distinct TLS endpoint (not just the main vhost — check API subdomains, admin panels, internal services if reachable)
2. **Downgrade check** — explicitly force weak protocol versions/ciphers, confirm server-side rejection
3. **Client validation** — for any client component in scope (mobile app, internal service, webhook consumer), test hostname/chain/pinning enforcement
4. **SNI/Host divergence** — test mismatched SNI vs `Host` header against shared infrastructure
5. **mTLS depth** — if mTLS is present, test identity binding vs presence-only, and search for a non-mTLS path to the same backend
6. **STARTTLS** — for any in-band-upgrade protocol in scope, test command buffering/injection across the plaintext-to-TLS boundary

## Validation

- `testssl.sh`/manual output showing accepted weak protocol/cipher with the exact negotiated parameters
- Client successfully connecting to a certificate that fails proper hostname/chain validation, with the mismatch documented
- SNI/Host divergence reaching an unintended backend, with request/response evidence
- mTLS bypass reaching protected functionality via a non-enforcing path

## False Positives

- Only TLS 1.2+ with forward-secret cipher suites accepted; weak versions/ciphers rejected at handshake
- Client code correctly validates hostname, chain, and enforces pinning where claimed
- SNI and `Host` header cross-validated, mismatches rejected
- mTLS validates full identity chain, no non-enforcing path found

## Tooling

```bash
git clone --depth 1 https://github.com/drwetter/testssl.sh /opt/testssl && /opt/testssl/testssl.sh <target>:443
openssl s_client -connect <target>:443 -servername <sni> [-tls1|-tls1_1|-cipher <suite>|-alpn h2]
```
`openssl`, `curl` (with `--resolve`/`--connect-to` for SNI/Host divergence testing), and `testssl.sh` cover this skill's full methodology without needing a GUI proxy.

## Summary

TLS and routing decisions happen before the application ever sees a request — a downgrade, a validation gap, or an SNI/Host mismatch at this layer can undermine every control built on top of it, including ones that look airtight at the HTTP layer.
