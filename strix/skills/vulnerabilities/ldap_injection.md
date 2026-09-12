---
name: ldap-injection
description: LDAP injection testing covering search filter manipulation, authentication bypass, blind boolean extraction, and DN injection against Active Directory and OpenLDAP
---

# LDAP Injection

LDAP injection exploits unsanitized user input concatenated into LDAP search filters, distinguished names (DNs), or directory-modification operations. Unlike SQL, LDAP has no native parameterized-query API in most language bindings, so string concatenation is the default pattern in application code — making this class common wherever an app talks to Active Directory, OpenLDAP, or Novell eDirectory for auth, user lookup, or group resolution. Treat every value interpolated into a filter string (RFC 4515) or a DN as untrusted until proven otherwise.

## Attack Surface

**Directory Services**
- Active Directory (AD) — dominant in enterprise SSO/auth backends
- OpenLDAP, 389 Directory Server, Novell/NetIQ eDirectory
- Cloud-adjacent: AD LDS, AWS Directory Service, Azure AD DS (LDAP interface)

**Integration Paths**
- Native bindings: Java JNDI (`DirContext.search`), PHP `ldap_search`/`ldap_bind`, Python `python-ldap`/`ldap3`, .NET `DirectorySearcher`/`DirectoryEntry`, Node `ldapjs`
- SSO/auth middleware: PAM LDAP modules, Apache `mod_authnz_ldap`, Spring Security LDAP, Keycloak/Okta LDAP federation
- Directory-backed features: employee/user search, group membership checks, address-book lookups, password-reset identity verification

**Input Locations**
- Login username/password fields bound directly into a search-then-bind flow
- Search/filter parameters (`cn=`, `mail=`, `sAMAccountName=`) exposed via "find user" or "find group" APIs
- Attributes echoed into modify/add operations (`ldapmodify`-equivalent calls) — second-order sink
- Base DN or OU selectors driven by user-controlled tenant/org identifiers

## High-Value Targets

- Login forms performing search-then-bind (`(&(uid=INPUT)(objectClass=user))` then bind as the found DN)
- "Forgot password" / account-recovery flows that resolve identity via LDAP search
- User/group directory search and autocomplete endpoints
- SSO bridges and reverse proxies mapping HTTP auth to LDAP bind (Apache/Nginx LDAP modules)
- Self-service profile update or group-join features that write attributes back to the directory (second-order injection)
- Multi-tenant apps where a user-supplied org/tenant ID is concatenated into the base DN

## Detection Channels

### Error-Based

- Malformed filter syntax (unbalanced parens, stray `*`, invalid attribute names) often surfaces raw LDAP error text: `LDAPException`, `javax.naming.NameNotFoundException`, `Invalid DN syntax`, `Bad search filter`
- Distinguish directory implementation from error phrasing (AD vs OpenLDAP error codes differ, e.g. AD `data 52e`/`data 525` in bind failures)

### Boolean-Based Blind

- Compare application behavior (login success/failure, result count, "user found" vs "not found") between a filter forced true and one forced false
- No native `SLEEP()` equivalent in the LDAP protocol itself — blind extraction relies purely on response-shape differentials, not timing

### Result-Count / Content Differential

- Wildcard-widened filters return more entries than intended; count or listing differences confirm filter manipulation reached the query

### Out-of-Band

- Limited natively, but chained impact is possible: if extracted DNs or attributes are later used in SSRF-prone operations (e.g., `memberUrl` dynamic groups referencing external URLs in some directory extensions), pivot through that secondary channel

## Core Payloads

### Authentication Bypass (Search-Then-Bind)

Three distinct mechanisms apply here, each requiring a different precondition. Do not report any of them as a working bypass until the resulting bind actually succeeds without the target account's real credentials — a widened search or a parser error is not proof by itself.

**Unauthenticated ("blank password") bind — try this first**

Per RFC 4513 §5.1.2, a bind with a non-empty DN and a *zero-length* password is defined as an unauthenticated bind, which most directory servers accept and report as success without checking any password. If the app calls `bind(foundDN, suppliedPassword)` without rejecting an empty `suppliedPassword` up front, submitting an empty password authenticates as whatever DN the search step returned — no filter metacharacter needed, and it works even against a fixed, valid `uid`:

```
uid: admin
password: (empty string)
```

**Wildcard value against a search-only auth check**

Some implementations never bind at all — they treat "search returned a result" as authenticated, e.g. `(&(uid=INPUT)(userPassword=INPUT2))` evaluated only via `search()`. Here a wildcard produces a fully valid, balanced filter with no broken syntax:

```
uid: admin
password: *
```
`(&(uid=admin)(userPassword=*))` matches the admin entry as long as it has *any* `userPassword` value set — true almost universally. This defeats only the search-only anti-pattern; confirm which flow you're facing (search-only vs. actual bind) before reporting.

**Operator truncation (parser-dependent — verify before relying on it)**

```
uid: *)(uid=*))(|(uid=*
```
Against `(&(uid=INPUT)(userPassword=INPUT2))` this yields `(&(uid=*)(uid=*))(|(uid=*)(userPassword=x))` — two adjacent top-level filter expressions, not one grouped OR. Whether this changes anything depends entirely on the client library: RFC 4515-strict parsers reject filters with trailing content after a complete expression, while some tolerant implementations parse only the first complete expression and silently discard the rest. Use this as a parser-fingerprinting probe, not an assumed bypass. Even where it does widen the *search* result, the subsequent *bind* still requires that returned DN's real password unless paired with the blank-password technique above.

### Attribute/Wildcard Enumeration

```
cn=admin*        → matches any cn starting with "admin"
mail=*@corp.com  → enumerates every account in the corp.com mail domain
sAMAccountName=*  → returns first entry in scope (AD)
```

### Blind Boolean Extraction

Extract an unknown attribute value (e.g., a service-account password stored in a custom attribute, or a hidden `description` field) character by character:

```
(&(uid=admin)(description=a*))    → true/false via app behavior
(&(uid=admin)(description=b*))
...
(&(uid=admin)(description=ad*))
```
Binary-search the character space per position to minimize requests, exactly as in blind SQLi.

### DN Injection

Base/target DNs use RDN grammar (RFC 4514: comma-separated `attr=value` components), not filter syntax — parentheses and `|` have no special meaning in a DN and just become part of a literal, likely non-matching attribute value. Probe with the DN's actual separator instead:

```
Sales,ou=Executives
```
If the app builds a search base as `"ou=" + input + ",dc=corp,dc=com"`, an unescaped comma in `input` inserts an additional RDN component **ahead of** the fixed suffix — this example yields `ou=Sales,ou=Executives,dc=corp,dc=com`, valid only if that exact nested path exists in the directory. Because the fixed suffix is appended verbatim, comma injection alone cannot remove or replace it; it can only add components in front of it, so impact here is bounded by the existing directory structure.

The high-impact variant needs no injection trick at all: a directory-browser or "search within OU" feature that passes a path parameter straight through as the base DN with **no fixed suffix**. There, any DN the caller supplies becomes the literal search base outright, exposing whatever subtree it points to regardless of intended scope.

## Key Vulnerabilities

### Search Filter Injection (Classic)

- Root cause: `"(&(uid=" + input + ")(objectClass=user))"` string concatenation
- Unbalanced parentheses in `input` change filter grouping, but the effect is parser-dependent: RFC 4515-strict implementations reject a filter with trailing content after a complete expression, while some client libraries parse only the first complete expression and silently discard the rest — establish which behavior applies before treating this as a reliable bypass rather than a fingerprinting probe
- Confirm by sending a value with an unescaped `)` and observing either an error or a behavior change vs. a value with the same `)` percent-encoded

### Authentication Bypass via Search-Then-Bind

- Highest-confidence variant: the app calls `bind(foundDN, suppliedPassword)` without rejecting a zero-length `suppliedPassword` first — RFC 4513's unauthenticated-bind semantics make the bind succeed regardless of the real password (see Core Payloads above)
- Filter-manipulation variant: if the search filter can be widened to change *which entry* is returned, and the app never verifies the returned identity matches the one requested, the attacker still needs that entry's real password to complete the bind on its own — this is an identity-confusion/data-exposure primitive, not a full bypass, unless combined with the blank-password technique
- Distinct from credential brute-force: these manipulate *which entry* is matched or *whether a password is checked at all*, not the password value itself

### Blind Data Extraction

- Any endpoint exposing a true/false or count signal (search UI, autocomplete, "email already registered" checks) can be walked attribute-by-attribute to exfiltrate directory contents an unauthenticated or low-privilege user should never see: internal usernames, email addresses, phone numbers, custom HR/organizational attributes, or group membership

### Second-Order LDAP Injection

- User-controlled data stored elsewhere (a profile field, an imported CSV, a webhook payload) is later read back and concatenated into an LDAP filter or DN during a *different* operation (e.g., a nightly sync job, a "find related users" feature) — payload must survive storage and reappear unescaped downstream

### Blind Injection via Group/ACL Checks

- Applications that gate access with `(&(uid=USER)(memberOf=cn=admins,ou=groups,dc=corp,dc=com))` are worth probing if `USER` is attacker-controlled and unescaped — try the operator-truncation payload from Core Payloads (`admin)(|(objectClass=*`) to test whether the parser discards the trailing `memberOf` clause, but confirm the specific client library's tolerance for trailing content before treating this as a reliable bypass rather than a fingerprinting probe

### DN/RDN Injection in Write Operations

- Where user input builds a target DN for add/modify/delete operations (self-service directory tools, provisioning APIs), an unescaped comma inserts an extra RDN component ahead of any fixed suffix, redirecting the operation to a different — but still nested and existing — entry or OU
- Where no fixed suffix is appended at all, the supplied value becomes the literal target DN outright, with no injection technique required

## Bypass Techniques

**Escaping Gaps**
- Applications frequently escape only `(` `)` `*` `\` per RFC 4515 §3 but miss NUL (`\00`), which historically truncated filter parsing in some implementations
- Inconsistent escaping between the *filter* context and the *DN* context — a value sanitized for one is often unescaped when reused in the other

**Encoding Variants**
- URL-encode injected parentheses/asterisks to slip past naive WAF rules expecting literal `()`
- Double-encoding where the app decodes once before its own escaping routine runs

**Whitespace and Case**
- LDAP attribute names are case-insensitive; mixed-case attribute names (`ObjectClass` vs `objectclass`) can evade filter-name allowlists implemented as case-sensitive string matches

**Alternate Attribute Names (AD)**
- If `sAMAccountName` is filtered/validated, pivot to `userPrincipalName`, `cn`, or `mail` — many AD-backed apps validate only one attribute path while accepting several as equivalent identifiers

## Testing Methodology

1. **Inventory LDAP-backed features** — login, password reset, user/group search, autocomplete, SSO bridge, self-service profile/group tools
2. **Identify search-then-bind patterns** — distinguish "filter builds the bind DN" flows (highest impact) from "filter only returns display data" flows
3. **Probe escaping** — submit `)`, `(`, `*`, `\`, NUL in isolation; compare error text/behavior against a benign baseline
4. **Establish an oracle** — result count, "found"/"not found" messaging, HTTP status, redirect target, or timing-adjacent side effects
5. **Attempt filter-widening bypass** — wildcard and unbalanced-paren payloads against auth and search endpoints
6. **Attempt blind extraction** — if an oracle exists, walk a sensitive attribute character-by-character
7. **Check second-order sinks** — trace stored user input into background sync jobs, admin directory-search tools, or reporting features
8. **Confirm DN-context injection separately from filter-context injection** — the same payload class behaves differently depending on which syntax it lands in

## Validation

1. Demonstrate a filter-shape change: identical request differing only in the injected metacharacter produces a different result set or bind outcome
2. For auth bypass, show successful authentication as an account the tester does not control the credentials for
3. For blind extraction, retrieve a value not otherwise visible and independently confirm it (e.g., via an admin-visible directory browser) to rule out coincidence
4. Provide the exact filter string reconstructed from the vulnerable concatenation logic (from source, if white-box) alongside the request/response pair
5. Rule out that the differential is caused by input-length limits, unrelated validation errors, or rate limiting rather than filter semantics

## False Positives

- Input passed through a parameterized/escaping LDAP API (e.g., `ldap3`'s `escape_filter_chars`, JNDI's `DirContext` with proper `Rdn.escapeValue`) before concatenation
- Generic "invalid characters" validation errors that reject the payload before it reaches the directory call at all
- Directory servers configured with strict schema validation that reject malformed filters outright with no behavioral difference exploitable
- Search results that differ only due to normal pagination/sorting, not filter-scope change

## Impact

- Authentication bypass into arbitrary or privileged directory-backed accounts
- Enumeration and exfiltration of internal directory data: usernames, emails, phone numbers, org structure, group membership
- Authorization bypass where access control is enforced via `memberOf`/group-filter checks
- Lateral movement inside the target's identity infrastructure (Active Directory findings often chain into broader AD attack paths beyond the web app's scope)
- Unauthorized directory writes (attribute tampering, group membership changes) where write operations are reachable

## Pro Tips

1. Prioritize search-then-bind login flows — they carry the highest impact (full auth bypass) and are the most common vulnerable pattern
2. Test the same input in both filter context and DN context separately; escaping is frequently inconsistent between the two
3. Active Directory tolerates more filter malformation than OpenLDAP in some client libraries — fingerprint the backend early via error phrasing to calibrate payloads
4. When wildcard/operator-truncation payloads fail, fall back to attribute-name aliasing (`sAMAccountName` vs `userPrincipalName` vs `mail`) before concluding the sink is unreachable
5. Autocomplete and "check availability" endpoints are underexplored oracles for blind extraction — they leak boolean signal without looking like a security-relevant feature
6. Always check whether extracted DNs or attributes get reused in a second directory operation — second-order injection is common in provisioning/sync tooling
7. Document the exact vulnerable concatenation (from source when available); defenses must escape correctly per RFC 4515, not merely blocklist a handful of characters

## Summary

LDAP injection is eliminated the same way SQL injection is: never build filters or DNs via string concatenation. Use library-provided escaping (`escape_filter_chars`/`Rdn.escapeValue`) or parameterized filter builders on every value entering a search filter, a DN component, or a modify operation, and verify the identity returned by a search actually matches the identity requested before binding as it.
