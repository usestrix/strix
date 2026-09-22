---
name: ldap
description: LDAP injection and directory-bind authentication testing for any application backed by an LDAP/LDAPS directory
---

# LDAP

This skill covers the **protocol surface** any application exposes when it authenticates or queries against LDAP — login forms doing a directory bind, search filters built from user input, attribute-based access checks. It is distinct from `active_directory` (that skill covers AD as the directory *service itself* — Kerberos, domain trust, lateral movement once you have network reach to a DC). Here the target is a web/app-layer client of LDAP, reachable without any domain foothold.

## Attack Surface

**Application Integration Points**
- Login forms performing an LDAP bind with user-supplied credentials (`simple bind` against `uid=<input>,ou=users,dc=...`)
- Search forms building LDAP filters from user input (directory lookups, "find employee" features, group membership checks)
- Attribute-based authorization (`memberOf` checks, custom attribute flags read post-bind and trusted for role decisions)

**Protocol Basics**
- Filter syntax: `(attribute=value)`, boolean composition `(&(...)(...))`, `(|(...)(...))`, negation `(!(...))`
- Special characters requiring escaping: `* ( ) \ NUL` — RFC 4515
- Anonymous bind (no credentials), unauthenticated bind (username, empty password — distinct from anonymous, some servers treat this differently), simple bind, SASL

## Reconnaissance

**Service Identification**
- Default ports: 389 (LDAP), 636 (LDAPS), 3268/3269 (Global Catalog, AD-specific)
- `ldapsearch` against the base DN with no credentials to test anonymous access:
```bash
ldapsearch -x -H ldap://target -b "" -s base "(objectclass=*)" namingContexts
```

**Anonymous/Unauthenticated Bind Testing**
```bash
ldapsearch -x -H ldap://target -b "dc=example,dc=com" "(objectclass=*)"        # anonymous bind
ldapsearch -x -H ldap://target -D "cn=someuser,dc=example,dc=com" -w "" -b "dc=example,dc=com" "(objectclass=*)"  # unauthenticated bind, empty password
```
Many LDAP servers accept a bind with a valid DN and an *empty* password as a successful anonymous-equivalent bind per the LDAP spec — this is a distinct, often-missed misconfiguration from true anonymous bind and needs its own test.

## Key Vulnerabilities

### LDAP Filter Injection

If user input is concatenated directly into a filter without escaping `* ( ) \`, an attacker controls the filter's boolean logic.

**Authentication Bypass via Filter Injection**

If the app builds a bind DN or a pre-bind search filter from input like:
```
(&(uid=USERNAME)(userPassword=PASSWORD))
```
injecting into `USERNAME`:
```
admin)(&(1=1
```
produces:
```
(&(uid=admin)(&(1=1)(userPassword=PASSWORD))
```
collapsing the password check depending on parenthesis balance and server tolerance — always test several parenthesis-balancing variants, since a broken filter usually errors rather than bypasses, but exact syntax varies by how the app assembles the string:
```
*)(uid=*))(|(uid=*
admin)(|(1=1
*)(|(objectclass=*
```

**Search Filter Injection (Data Exposure)**

For any search feature (employee directory, "find user"), inject to widen the search beyond intended scope:
```
INPUT: * 
FILTER BECOMES: (name=*)   -- returns every entry instead of exact match
```
```
INPUT: *)(uid=*
FILTER BECOMES: (&(name=*)(uid=*))(...)   -- may expose attributes from every entry
```

### Blind LDAP Injection

When results aren't reflected directly (e.g. filter only affects a boolean allow/deny, or an error page is generic), extract data via boolean or timing inference — same methodology as blind SQLi, applied to filter logic:
```
(&(uid=admin)(userPassword=a*))    -- true/false on whether password starts with 'a'
(&(uid=admin)(userPassword=ab*))   -- narrow further
```
Iterate character-by-character against any attribute the app conditionally reveals (existence of a user, password prefix if the app is naive enough to filter on it, custom attribute values gating a feature).

### Bind-Based Authentication Bypass

- **Wildcard in bind DN construction** — if the app builds `uid=<input>,ou=users,dc=...` and passes it directly as the bind DN (not via a search-then-bind pattern), test DN injection: `admin,ou=users,dc=example,dc=com` variants, or attempt to bind against a different OU entirely by injecting DN components
- **Empty password / unauthenticated bind acceptance** — submit a valid-looking username with an empty password field; per LDAP spec this can succeed as an unauthenticated bind and some application code treats *any* successful bind call as "login succeeded" without checking that a password was actually supplied
- **Null byte / attribute injection in bind flow** — test null bytes and filter metacharacters in the username field specifically at the bind step, not just search steps, since some apps sanitize search inputs but not the credential passed straight to the bind call

### StartTLS Downgrade

If the app is configured to use StartTLS over plaintext port 389 rather than native LDAPS (636), test whether a downgrade/stripping of the StartTLS negotiation forces the connection to continue in plaintext — exposing bind credentials on the wire. Confirm with a packet capture whether credentials are visible if StartTLS can be prevented from establishing.

### Attribute Enumeration & Information Disclosure

Once any bind succeeds (anonymous, unauthenticated, or valid low-priv), enumerate the full attribute schema exposed:
```bash
ldapsearch -x -H ldap://target -b "dc=example,dc=com" "(objectclass=person)" "*" "+"   # + requests operational attributes too
```
Look for sensitive attributes readable by low-privilege/anonymous binds: `userPassword` (sometimes stored reversibly or even in plaintext on misconfigured servers), `memberOf`, internal employee IDs, phone/SSN-style custom attributes.

## Testing Methodology

1. **Anonymous/unauthenticated bind sweep** — test both true anonymous and empty-password-unauthenticated bind against the base DN
2. **Map the app's filter construction** — determine which fields feed directly into LDAP filters or bind DNs by testing single `*` and `)` characters and observing errors/behavior changes
3. **Auth bypass injection** — target the login flow specifically with filter-balancing payloads
4. **Search injection** — widen any directory-search feature's result set via wildcard/filter injection
5. **Blind extraction** — if no direct reflection, build a boolean-based extraction loop against a target attribute
6. **Attribute dump** — once any bind succeeds, enumerate the full schema for oversensitive exposed attributes
7. **Transport** — verify StartTLS actually establishes before credentials are sent, or confirm LDAPS is enforced

## Validation

- Successful authentication bypass demonstrated with the exact injected username/filter value and resulting session
- Search injection returning entries/attributes outside the intended query scope, with before/after result comparison
- Extracted attribute value via blind boolean inference, with the character-by-character request sequence documented
- Full request: raw filter/bind DN sent, LDAP server response, and resulting application behavior

## False Positives

- Special characters (`* ( ) \`) properly escaped before filter/DN construction (test confirms literal string matching rather than filter logic change)
- Bind requires non-empty password; unauthenticated bind explicitly rejected
- Anonymous bind disabled at the directory server level
- Search results scoped correctly regardless of wildcard/metacharacter input

## Tooling

`ldapsearch` (OpenLDAP client tools) is not installed by default in the sandbox (same as the AD/Kerberos tooling — the image ships only web-focused tools). Install it first:
```bash
apt-get install -y ldap-utils
```
For scripted blind extraction or filter-fuzzing beyond what `ldapsearch` one-liners cover, use Python's `ldap3`:
```bash
pip install --user ldap3
```

## Summary

LDAP injection follows the same logic as SQL injection — untrusted input reaching filter/DN construction without escaping breaks out of the intended query structure. The distinguishing risk is that a successful bind (even an accidental unauthenticated one) often *is* the authentication decision itself, making bind-flow injection directly equivalent to an auth bypass rather than just a data leak.
