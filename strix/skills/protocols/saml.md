---
name: saml
description: SAML 2.0 SSO security testing covering XML signature wrapping, assertion replay, NameID spoofing, and IdP/SP trust confusion
---

# SAML 2.0

SAML failures compromise the entire federation trust boundary — a single wrapped or forged assertion grants full account takeover across every SP trusting that IdP. Treat the XML document itself as the attack surface: signature scope, parsing order, and canonicalization all diverge between validator and consumer.

## Attack Surface

**Bindings**
- HTTP-Redirect (deflate + base64 in URL, used for AuthnRequest)
- HTTP-POST (base64 in form body, used for Response/assertion)
- HTTP-Artifact (indirect, resolved server-to-server via ArtifactResolve)

**Endpoints**
- SP: `/saml/acs`, `/saml/login`, `/Shibboleth.sso/SAML2/POST`, `/sso/saml`, metadata at `/saml/metadata`
- IdP: `/idp/profile/SAML2/*`, `/adfs/ls`, `/Shibboleth.sso/Metadata`, metadata at `/FederationMetadata/2007-06/FederationMetadata.xml` (ADFS/Entra)

**Document Structure**
- `AuthnRequest` (SP→IdP), `Response` containing one or more `Assertion` elements (IdP→SP)
- `Assertion` → `Subject`/`NameID`, `Conditions` (`NotBefore`/`NotOnOrAfter`, `AudienceRestriction`), `AuthnStatement`, `AttributeStatement`
- `ds:Signature` — may sign the `Response`, the `Assertion`, both, or neither

## Reconnaissance

**Metadata Discovery**
```
GET /saml/metadata
GET /Shibboleth.sso/Metadata
GET /FederationMetadata/2007-06/FederationMetadata.xml
GET /.well-known/saml-configuration
```
Extract: `entityID`, `X509Certificate` (signing cert — save it, needed for forgery once compromised), `SingleSignOnService`/`AssertionConsumerService` URLs, `NameIDFormat`, whether `WantAssertionsSigned`/`AuthnRequestsSigned` is advertised (advertised ≠ enforced — always test).

**Capture a Baseline Flow**
Trigger a real login, intercept the POST-bound `Response` (base64-decode the `SAMLResponse` form field) to get a working assertion to mutate. Keep the original for diffing.

## Key Vulnerabilities

### XML Signature Wrapping (XSW)

The signature validates a referenced node by ID, but the *processing logic* may read a different node than the one validated — inject a spoofed, unsigned copy of the signed element for the processor to consume while the original signed copy still validates.

**XSW1/XSW2** — Clone the signed `Response`/`Assertion`, move the original (still holding the valid signature and `Reference URI`) to become a sibling or child of the clone, insert attacker-controlled `NameID`/attributes into the clone the processor reads:
```xml
<samlp:Response>
  <saml:Assertion ID="evil"><!-- attacker NameID, no signature --></saml:Assertion>
  <saml:Assertion ID="orig" ><!-- original, signature Reference="#orig" still valid --><ds:Signature>...</ds:Signature></saml:Assertion>
</samlp:Response>
```
**XSW3-XSW8** — Variants: wrap inside `Extensions`, duplicate at the `Response` level instead of `Assertion` level, move the signed assertion under a new root sibling, nest the original inside the forged copy. Try all eight against every endpoint — libraries differ in which they resolve to first (DOM traversal order vs `Reference URI` lookup).

Automate variant generation instead of hand-editing each:
```bash
pip install --user samlrequests  # or hand-roll: parse Reference URI, clone node, splice per XSW1-8 layout
```

### Signature Exclusion / Stripping

- Delete `ds:Signature` entirely — some validators fail open if the element is simply absent rather than invalid
- Change `WantAssertionsSigned` expectations: if only the `Response` is checked for a signature but the `Assertion` inside is trusted independently, strip the outer signature and forge the inner assertion (or vice versa)
- Downgrade `SignatureMethod`/`DigestMethod` to a weak or unsupported algorithm and observe whether validation silently skips

### Comment Injection in NameID

```xml
<saml:NameID>admin@company.com<!--x-->.evil.com</saml:NameID>
```
XML parsers may strip the comment for signature canonicalization but string-parsing code downstream (e.g. `NameID.split('@')` or regex extraction) reads the full un-canonicalized string — causes signature validation to pass against `admin@company.com.evil.com` while application logic authenticates as `admin@company.com` or the reverse.

### Assertion Replay

- Capture a valid `Response`, resubmit it after the user's session ends — check whether `NotOnOrAfter`/`InResponseTo` are actually enforced server-side (not just present in the XML)
- `InResponseTo` binding to the original `AuthnRequest` `ID` — omit or reuse an old `ID` to test if the SP tracks outstanding requests at all
- Missing `Conditions/AudienceRestriction` enforcement lets an assertion issued for SP-A be replayed at SP-B under the same IdP

### NameID Spoofing / Format Confusion

- Switch `NameIDFormat` between `emailAddress`, `persistent`, `transient`, `unspecified` — some SPs trust the format without validating IdP actually issued that type consistently
- If IdP allows self-service or federated identity linking, test whether `NameID` can be influenced by attacker-controlled upstream identity attributes before reaching the signed assertion

### XXE via SAML XML Parsing

SAML is XML — the same DOCTYPE/entity-expansion surface as any XML endpoint applies to the decoded `SAMLResponse`/`SAMLRequest` body:
```xml
<?xml version="1.0"?>
<!DOCTYPE saml:Response [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<samlp:Response>...&xxe;...</samlp:Response>
```
Test both directions — SP parsing an IdP-bound `Response`, and IdP parsing an SP-bound `AuthnRequest` if self-registration/SP-initiated metadata upload exists.

### IdP/SP Metadata Confusion

- If the SP trusts multiple IdPs, check whether the signing certificate is validated per-`entityID` or globally — an assertion correctly signed by IdP-A's cert but claiming `Issuer` = IdP-B may be accepted if cert lookup keys off the wrong field
- Multi-tenant SPs: does the SP scope the accepted `entityID`/audience per tenant, or does any registered IdP's valid signature grant access to any tenant?

### Golden SAML

If a signing private key is ever recovered (compromised IdP, leaked cert+key pair, weak key generation) — forge arbitrary assertions for any user, any SP, indefinitely, without touching the IdP again. This is a **post-compromise persistence technique**, not an initial-access test; only pursue if a key is legitimately recovered during the engagement, and stop at proof of forgery for one low-privilege test account — do not mint admin assertions beyond what's needed to prove the primitive.

## Testing Methodology

1. **Capture** a full valid `AuthnRequest` → `Response` round trip; base64-decode both directions
2. **Signature scope** — determine exactly which node(s) `ds:Signature` covers (`Response` only, `Assertion` only, both)
3. **XSW sweep** — generate all 8 wrapping variants against the captured `Response`, replay each to the ACS endpoint
4. **Strip/downgrade** — remove signature, downgrade algorithm, observe fail-open vs fail-closed
5. **Replay** — resubmit after expiry, reuse `InResponseTo`, cross-SP replay under shared IdP
6. **Comment/encoding tricks** — inject XML comments and entity references into `NameID`/attributes
7. **XXE** — DOCTYPE/entity injection in the decoded XML body at both SP and IdP endpoints

## Validation

- Demonstrate a mutated/wrapped assertion is accepted by the SP for a `NameID` the tester does not legitimately control, resulting in authenticated access as that identity
- Show the exact XSW variant number and the diff between signed and processed node
- Prove replay by reusing a captured `Response` outside its original validity window or `InResponseTo` binding
- Full request/response chain: original `AuthnRequest`, captured legitimate `Response`, mutated `Response`, resulting authenticated session

## False Positives

- All 8 XSW variants rejected consistently (validator resolves signed node by ID before any DOM-order lookup)
- `NotOnOrAfter`/`InResponseTo`/`AudienceRestriction` enforced and reject replay/cross-SP reuse
- Signature stripping/downgrade fails closed
- XXE payload returns no entity expansion (external entities disabled, as they should be)

## Tooling

No SAML-specific tool ships in the sandbox by default. Manual XML manipulation via `python3` (`lxml`/`xml.etree`) is the most reliable approach — GUI tools (Burp's SAML Raider) aren't available headless.

```
pip install --user lxml signxml python3-saml   # XML parsing, signature validation, and SP-side test harness
```
Decode/encode the transport envelope by hand:
```bash
# decode HTTP-POST SAMLResponse
python3 -c "import base64,sys; print(base64.b64decode(sys.argv[1]).decode())" "$SAMLRESPONSE"
# re-encode after mutation
python3 -c "import base64,sys; print(base64.b64encode(open(sys.argv[1],'rb').read()).decode())" mutated.xml
# HTTP-Redirect binding additionally deflates before base64 — decompress with zlib.decompressobj(-15)
```

## Summary

SAML security depends entirely on the gap between what a signature covers and what the application logic actually reads. XSW variants, comment injection, and signature stripping all exploit that gap. Any SP that resolves nodes by DOM position rather than the signed `Reference URI` is forgeable.
