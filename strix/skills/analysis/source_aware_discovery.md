---
name: source_aware_discovery
description: Enumeration discipline for reading code — which locations to keep as separate candidates, which safe siblings prove nothing, and the per-family sweeps that are routinely missed
---

# Source-Aware Discovery

Reading code for bugs fails in two directions. You collapse many real
instances into one candidate and under-report, or you stop at the loudest
issue in a file and never sweep the family around it.

This skill is about *what to enumerate*, not how to exploit it — the
vulnerability-class skills cover exploitation. Discovery decides
plausibility and preserves evidence; severity comes later.

## Instance Discipline

**One root cause is not one candidate.** If a dangerous helper has six
call sites and four are independently reachable, that is four candidates
— not one "the helper is unsafe" note. Each needs its own source, its own
closest control, and its own line. A reader has to be able to fix them
individually.

**Do not collapse distinct proof tuples that share a route.** Command
execution, SSRF, path/file write, parser abuse, template execution, and
authorization bypass on the same endpoint are separate findings when the
sink, the broken control, or the impact differ. Sharing a URL is not
sharing a bug.

**Keep the wrapper and the shared helper both visible.** When the path
crosses from an entrypoint into a shared sink or control, record both:
the wrapper proves reachability, the helper is where the fix goes. Losing
either one makes the finding unactionable.

**A safe sibling is a negative control for itself and nothing else.** A
correctly-parameterized query three lines above a concatenated one proves
the developer knew better, not that the concatenated one is safe.

**Label your locations.** Mark each as entrypoint, root control, sink, or
concrete implementation. Multi-location findings that don't say which
line is which force the reader to re-derive your analysis.

## Where the Real Control Lives

The most common discovery error is anchoring on the dramatic sink and
missing the reusable broken control behind it.

- When a resolver, allowlist, denylist, class filter, or guard is the
  thing that's wrong, that line is the candidate. The transport that
  reaches it proves reachability — it doesn't replace it.
- When the same filter or resolver is **duplicated** across core, server,
  client, plugin, or import packages, each copy is its own candidate.
  Fixing one leaves the others live.
- In a concrete strategy / handler / converter / operation subclass, read
  the specialized helper, not just the top-level `handle` / `apply` /
  `perform` override. If the subclass splits, filters, canonicalizes, or
  rebuilds attacker input before delegating to a shared evaluator, the
  subclass line is the root control.
- Branch-specific transforms — append, wildcard, fallback, copy/move
  `from`, default-value, type-resolution — routinely bypass or narrow the
  shared validator. Keep the branch predicate as its own location. A
  finding on the shared helper does not close them.

## Family Sweeps

When you find one instance of these, sweep the whole family before
closing it out.

**Deserialization / object construction.** Enumerate every registered
codec, deserializer, converter, and container handler — array,
collection, map, bean, enum, throwable, generic object. A top-level
parser-config finding does not close a concrete codec that recursively
re-invokes parsing or type resolution on attacker data.

**XML / parsers.** Enumerate parser factories, readers, converters,
validators, transformers, and unmarshal entrypoints independently.
Hardening that is best-effort does not suppress anything: a
secure-processing flag alone, a `setFeature` call whose failure is
swallowed or logged, or a safe default factory all leave
caller-supplied factories and converter paths open.

**Object models for untrusted formats.** Sweep the primitive and
container helpers that traverse or convert attacker-controlled documents
— `to*Array`, `get*`, numeric conversion, `parse*`, iterators, size
accessors, unchecked casts, allocation loops. Missing type, size, shape,
recursion, or numeric guards here cause type confusion, unbounded
traversal, and resource exhaustion. These sweeps create candidate rows,
not automatic findings — promote one only when malformed input plausibly
reaches it and the missing guard has a concrete security effect.

**Archive extraction and import/restore.** Keep four things visible per
operation: the member name, the destination join, the containment check,
and the extract/write call. A later copy step, manifest gate, or UUID
check does not close it if the write already happened. "The stdlib
normalizes paths" is not containment evidence — the code must show
per-entry containment *before* the write, including symlink, hardlink,
and recursive-copy paths. The write does not need to escape the app root
to matter: overwriting config, a peer tenant's directory, or a shared
imported subtree is still file impact.

**Path-sensitive filesystem operations.** Enumerate each exported
operation separately — restore, import, export, backup, copy, move,
download, open, key/config fetch. For each, keep the decode, join,
normalize, canonicalize, strip-prefix, extension-check, and
destination-selection lines candidate-visible.

**Static-file and resource serving.** The candidate is the line that
decides whether an attacker-chosen path is allowed: the allowlist, the
matcher, the canonicalization, the URL decode, the resource selection. Do
not substitute a safer sibling handler for the vulnerable legacy one.

**Outbound requests.** For URL importers, webhook and callback clients,
preview/render fetchers, `downloadFrom`-style helpers, and
redirect-following clients: enumerate each attacker-controlled
destination and its closest allow/deny/redirect control. Do not drop the
row because the fetch is an intended feature, because the filter is
operator-configured or empty by default, or because it only runs
pre-request.

**Command and action runners.** Enumerate every attacker-controllable
argument type and execution mode before you call command injection
covered. Type-safety maps, unsafe-type denylists, template substitution,
shell wrapping, direct-exec branches, and API-side argument ingestion are
each separate controls. A denylist covering three types says nothing
about the no-op typecheck branches that still render into a shell string.
Frontend widget constraints are not controls at all.

**Query APIs (SQL, NoSQL, LDAP, XPath, and friends).** Do not suppress
because the endpoint is already user-facing, because it's an insert
rather than a read, or because a later business check appears to limit
the effect. If attacker input reaches query syntax or selector operators,
carry it forward and record the later check as counterevidence.

**Structured patch / edit APIs.** For JSON Patch, document edits, and
config mutations, enumerate the request-selected operations — add,
remove, replace, move, copy, test. Operation-specific path transforms,
array-append handling, and wildcard selection stay candidate-visible when
they feed a shared evaluator or binder.

**Authentication state machines.** The candidate is the line that
installs or reuses a principal, credential, token, issuer, or protocol
state *after* a transition — pre-auth to authenticated, TLS upgrade,
redirect, assertion consumption, IdP handoff. Missing rebind or
reauthentication at that seam authenticates the wrong identity.

**SSO / SAML / federation.** Keep response and assertion validators
distinct from generic claims authorizers and from service-method
authorization; they fail differently. Include the lines doing assertion
selection, list indexing, DOM access, node cloning, signed-object lookup,
subject confirmation, recipient, audience, destination, ACS URL, and
issuer binding — each decides *which* assertion is trusted.

The signature failure to watch for: a validation loop or a
`foundValid`-style flag, followed by a **separate** fixed-index,
first-element, clone, re-serialization, or return path. Treat that later
selection line as the broken control until you have proven the validated
object and the consumed object are byte-identical and equally bound. This
is the validated-vs-consumed mismatch, and it is invisible if you only
read the validator.

**Realms and authenticators.** Enumerate the concrete implementations —
LDAP, Kerberos, PAM, SAML, OAuth/OIDC, custom realms — before promoting a
generic HTTP auth finding. In multi-step or TLS-upgraded binds, keep the
bind/rebind and credential-installation line visible.

**Self-service update routes.** Include the guard that compares the
requested object against the persisted one. Missing checks on
security-sensitive scalars and collection aliases let a user change their
own identity, roles, group membership, tenancy, or account-recovery
properties.

**Protocol utility code.** In protocol-heavy repositories, read the
version, capability, feature, and negotiation helpers even when the
obvious candidates are REST and admin routes. Look for `Version`,
`versionCompare`, `Capability`, `Feature`, `Negotiation`, and the
comparator methods around them — downgrade and confusion bugs live there,
and nobody looks.

**Public webhook / status / callback endpoints.** Enumerate these
independently from nearby credential bugs whenever they read protected
objects, trigger jobs, or mutate protected state.

## Cross-Boundary Inputs

In frameworks and libraries, stored client, tenant, application, IdP,
exception, and imported-configuration values are attacker-controlled when
they are later rendered, evaluated, parsed, or used for authorization —
provided there is a plausible runtime path from some boundary. Do not
suppress just because the writer lives outside this repository. That
requires evidence the value is trusted-only in normal deployments, not an
assumption.

Similarly, do not suppress a high-impact candidate because the API is
deprecated, opt-in, or documented as dangerous. Record that as a
precondition and keep the candidate — shipped code with a bypassable
control is shipped code.

## The Finding Bar

Worth opening a candidate: authorization bypass, confused deputy, SSRF,
path traversal, injection with a real sink, cross-tenant exposure,
sensitive state change without enforcement, sandbox or trust-boundary
escape.

Not worth it: "this could use more validation" with no path, style and
maintainability complaints, and cosmetic variants of a candidate you
already opened.

Keep reading until no distinct plausible candidate remains — then record
what you swept with `record_coverage`, including the families that came
back clean.
