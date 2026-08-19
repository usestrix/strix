---
name: saml
description: SAML SSO security testing covering assertion tampering, XML signature wrapping, signature stripping, replay, and audience/recipient validation gaps
---

# SAML

SAML (Security Assertion Markup Language) is the enterprise SSO workhorse: an Identity Provider (IdP) signs an XML assertion about a user and the Service Provider (SP) trusts it to establish a session. The trust boundary is entirely about XML signature verification and attribute validation. If the SP verifies signatures incorrectly, or skips audience/recipient checks, an attacker can mint their own admin assertion. Unlike JWTs, the "signature" is XMLDSIG - with canonicalization, reference resolution, and multiple XML parsers in play - which makes implementation bugs common and subtle.

## Attack Surface

- SP login endpoints that accept `SAMLResponse` (HTTP POST binding) or `SAMLRequest`/`SAMLResponse` in redirect URLs (HTTP Redirect binding)
- IdP discovery and metadata endpoints: `/Shibboleth.sso/Metadata`, `/saml/metadata`, `/metadata`, federation metadata XML
- Assertion contents: `Subject`/`NameID`, `AttributeStatement` (roles, groups, email), `AuthnStatement` (session/loa), `Conditions` (NotBefore/NotOnOrAfter, AudienceRestriction)
- RelayState - often echoed into post-login redirects and a classic open redirect/token-leak vector
- SP-side libraries: Shibboleth, SimpleSAMLphp, Spring Security SAML, OneLogin, python3-saml, `pysaml2`, .NET `Saml2`/Sustainsys, ADFS, Keycloak SP side

## Reconnaissance

1. **Capture a real SAML exchange** - log in via the SP, intercept the POST/redirect with the proxy (agent-browser + caido), and save the `SAMLResponse`
2. **Decode**: POST binding is base64 XML; Redirect binding is base64 + DEFLATE:
   ```
   echo '<base64>' | base64 -d > response.xml
   python3 -c "import zlib,sys; sys.stdout.buffer.write(zlib.decompress(__import__('base64').b64decode(open(0,'rb').read())))" < enc.bin > response.xml
   ```
3. **Verify the signature locally** (`xmlsec1 --verify` or a SAML library) so you know exactly what is signed and what is not
4. **Map the metadata**: endpoints, certificates, NameID formats, and which attributes the SP consumes (roles/email are the high-value ones)
5. **Test the SP's IdP trust** - does it accept assertions from any IdP, or only configured metadata?

## Key Vulnerabilities

### Missing Signature Verification

The SP accepts an unsigned or tampered `SAMLResponse`. Modify `NameID` to another user or add `Role=admin`, re-encode, and replay:

```
<saml:Subject><saml:NameID>admin@target</saml:NameID></saml:Subject>
<saml:Attribute Name="Role"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute>
```

### Signature Stripping

Remove the entire `ds:Signature` element (and references). Some SPs only verify when a signature is present.

### XML Signature Wrapping (XSW)

The verifier resolves a reference to one part of the document while the application logic reads another. Common variants:

- Insert a forged, unsigned `<Assertion>` *before* the signed one; the app reads the first, the verifier checks the signed second
- Wrap the signed assertion inside an unsigned parent (`<Extensions>`, `<Object>`, another `<Assertion>`) and add a forged sibling
- Duplicate the assertion with a new `ID`, place the attacker's copy first
- Keep the signature element but change the reference target/ID so the signed bytes and the consumed bytes diverge

Test systematically with 8-12 XSW variants (prepend, wrap, nested, comment-injected) rather than a single payload.

### Comment Injection / Canonicalization Bugs

XML comments inside signed content can change the document tree after canonicalization in some parsers (libxml2/REXML/Nokogiri differentials). Insert comments into `SignedInfo`-adjacent content and observe whether the SP's view differs from the verifier's.

### Key/Trust Confusion

- SP trusts an attacker-embedded `<ds:KeyInfo>` instead of the configured IdP certificate
- Accepts assertions signed by any certificate in the metadata bundle, including self-signed test certs
- Multiple IdPs configured and the SP does not bind the assertion to the IdP that issued it (IdP confusion)

### Missing Audience / Recipient Checks

- `AudienceRestriction` absent or not validated: an assertion minted for SP-A is accepted at SP-B
- `Recipient` attribute not checked: a response meant for one ACS URL works at another endpoint
- Cross-service token confusion across SPs sharing an IdP

### Replay and Lifetime

- Same `SAMLResponse` accepted repeatedly (no one-time-use/cache of assertion IDs)
- `NotBefore`/`NotOnOrAfter` not enforced, or huge clock skew tolerated
- `SessionNotOnOrAfter`/`AuthnStatement` ignored

### RelayState Abuse

- `RelayState` reflected unvalidated into a redirect -> open redirect (phishing)
- RelayState carrying state/tokens that leak to attacker-controlled URLs

## Advanced Techniques

- **Assertion reuse across SPs**: if the same IdP federates several SPs, test SP-A's assertion at SP-B (audience confusion)
- **NameID confusion**: formats like `emailAddress` vs `persistent`; SPs sometimes map the NameID to the account identifier - switch formats to impersonate
- **Attribute-based authz**: many apps authorize from `Role`/`group` attributes without checking the IdP signed them - tamper and replay
- **Offline crafting**: with the SP's public metadata and a valid signed sample, build custom assertions and test each validation gap in isolation

## Testing Methodology

1. Capture and decode a real response; record what is signed
2. Verify locally; identify unsigned sections and the exact canonicalization
3. Baseline: replay the untouched response - does the SP accept it (replay)?
4. Tamper attributes/NameID and re-encode - accepted (no signature check) or rejected?
5. Strip the signature - accepted?
6. Run XSW variants and comment injections
7. Swap Audience/Recipient/Issuer values; test cross-SP and cross-IdP
8. Test RelayState for open redirect

## Validation

1. Reproduce end-to-end: modified assertion -> SP accepts -> session as the impersonated/privileged user
2. Show the tampered XML and the exact verification gap (signature absent, wrapping variant, audience mismatch accepted)
3. Prove the impact user-visible: an admin role, another user's data, or cross-SP access
4. Keep the proof minimal: NameID switch or a role attribute read, no destructive actions

## False Positives

- Tampered assertion rejected with a signature error - the SP verifies correctly (no finding)
- Replay blocked by assertion-ID cache or short expiry
- Audience/Recipient enforced (cross-SP test fails)
- SP verifies against the configured IdP cert only (embedded KeyInfo ignored)
- RelayState validated against an allowlist (no open redirect)

## Impact

- Full account takeover by minting assertions as any user
- Privilege escalation via tampered role/group attributes
- Cross-SP/tenant access when audience checks fail
- Phishing via RelayState open redirects

## Pro Tips

1. Always verify the original locally first - knowing what is signed tells you which tampering is worth trying
2. XSW is a family, not one payload: run prepend/wrap/nest/duplicate variants in combination with attribute tampering
3. Test replay with the *identical* response before modifying anything
4. Check `Recipient` and `AudienceRestriction` independently - SPs often check one and forget the other
5. Capture multiple assertions (different roles/users) to diff how the SP maps attributes
6. `xmlsec1` and the `python3-saml`/`pysaml2` libraries are the practical workhorses for crafting and verifying; install via apt/pip in the sandbox
7. Combine with `authentication_jwt` when the same IdP also issues JWTs - token confusion across protocols is common

## Summary

SAML security is signature-verification security: capture a real assertion, learn what is signed, then attack the gaps - missing verification, signature stripping, XML signature wrapping, key trust confusion, and missing audience/recipient/lifetime checks. Prove impact with a replayed or tampered assertion that yields an authenticated session.
