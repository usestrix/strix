---
name: infrastructure-lifecycle
description: Discovery and security analysis of abandoned or ownership-drifted infrastructure trusted by software, firmware, DNS, mail, update systems, packages, scripts, telemetry, and deployed agents
---

# Infrastructure Lifecycle Trust

Use this skill when a product, application, device, image, or organization continues to trust an external name or provider resource whose ownership can expire, be deleted, be reassigned, or move outside the intended organization.

This is broader than subdomain takeover. The vulnerable asset may make outbound requests to a retired update bucket, load JavaScript from an abandoned domain, send mail to an expired MX domain, query a reassigned WHOIS/RDAP server, install from a missing package namespace, or beacon to an embedded telemetry/control endpoint. The security property is continuity of ownership across the full lifetime of every trust consumer.

## Trust-Consumer Graph

Model each dependency:

```text
consumer/version/deployment
  -> embedded logical name or URL
  -> DNS/provider/package resolution chain
  -> current owner/controller
  -> content/protocol accepted
  -> privilege and trigger in the consumer
```

Record separately:

- where the reference is stored: source, binary, firmware, image layer, config, database, IaC, documentation, update metadata
- deployed versions and whether the consumer still runs
- endpoint type, resolution chain, TLS/signature/authentication requirements, and fallback order
- current registration/provider ownership and historical ownership
- request trigger, frequency, payload/data sent, and response/content interpretation
- consumer privilege: browser origin, installer/root, CI runner, mail receiver, parser, agent, or telemetry process
- decommission owner, renewal/update process, and monitoring coverage

A domain or bucket being available is only half the finding. Show that a live in-scope consumer still trusts it and what that consumer would accept.

## Control and Claimability Levels

Do not collapse these into one claim:

| Level | Evidence |
|---|---|
| Indicator | NXDOMAIN, expired registration, provider tombstone, missing package/resource |
| Authoritative availability | Registrar/provider/package authority confirms the exact name/resource can be acquired or bound |
| Acquisition/control | Authorized tester controls the registrable domain, resource, namespace, or provider binding |
| Protocol identity | Required DNS, custom-host binding, TLS certificate, authentication, or protocol handshake succeeds |
| Consumer acceptance | A live in-scope consumer contacts the controlled endpoint and accepts the relevant response semantics |

Record the highest proven level for every consumer. Before acquisition or provider binding, determine whether control can immediately receive existing third-party traffic and apply the Passive Sensor and Sinkhole plan below.

## High-Value Dependency Classes

### Update and Code Distribution

- firmware/software update URLs, manifests, package indexes, installers, drivers, VM/container images
- CDN/object-storage buckets serving binaries, scripts, templates, rules, signatures, or configuration
- browser JavaScript/CSS imports and desktop/mobile auto-update channels
- bootstrap, CI, devcontainer, build, and installation scripts
- model/agent skill, plugin, prompt, MCP server, and tool-definition update channels

Record signature, hash, certificate, pinning, version/rollback, and content-type enforcement. TLS alone authenticates the current domain controller, not continuity with the original publisher.

### Naming and Package Resolution

- missing public/private package names, scoped package versus executable alias, plugin/module/template namespaces
- `PATH`, autoload, search path, registry, cache, mirror, and remote fallback order
- provider-generated hostnames or globally unique resource names released on deletion
- legacy aliases retained in manifests, lockfiles, scripts, or installed products

Do not register or publish candidate names merely to test them without explicit authorization and a containment plan. Prove the consumer's resolution behavior first.

Registry "missing" responses are not interchangeable with "claimable".
Similarity, reservation, security-hold, dispute, and unpublish rules can block
a name that returns `404`; verify ownership and registry policy separately.
Load `npx_confusion` when the consumer first treats a missing executable as an
npm package spec. Model other ecosystems independently rather than assuming
npm's resolution order applies to them.

### Mail and Identity

- expired organizational, supplier, recovery, notification, or former employee domains
- MX targets and catch-all aliases that remain in applications, address books, SSO, password recovery, certificates, or vendor accounts
- OAuth redirect/logout URIs, SAML endpoints, webhook callbacks, CORS/CSP allowlists, and trusted-origin lists tied to retired hosts
- domain-based tenant verification and support/administrative identity flows

Differentiate ability to receive a tester-created message from interception of real correspondence. Do not access unrelated mail or use received secrets/credentials.

### Telemetry, Control, and Protocol Infrastructure

- crash reporting, analytics, licensing, activation, NTP/DNS, support, and health-check endpoints
- hardcoded agent/controller, webshell/C2, webhook, exfiltration, or callback domains embedded in deployed systems
- hardcoded retired WHOIS/RDAP endpoints, certificate validation services, keyservers, mirrors, proxies, and service-discovery dependencies
- local/remote management domains in appliances, mobile apps, extensions, and container images

Treat unexpected inbound traffic as potentially sensitive. Passive receipt does not authorize interaction, command issuance, credential use, or expansion beyond the approved sensor purpose.

## Discovery

### Source, Image, and Firmware Corpus

Extract hostnames, URLs, email domains, bucket names, package names, registry endpoints, and certificate subjects from:

- source and history, lockfiles, CI/IaC, release assets, SBOMs
- container/VM layers including deleted-file history
- firmware rootfs, strings/resources, scripts, configs, examples, and updater logic
- JavaScript/mobile/desktop bundles, extensions, templates, and documentation
- logs and network captures from controlled normal operation

Use staged extraction rather than relying on one broad regex:

```bash
# URLs and email addresses
rg -n -i 'https?://|wss?://|s3[.-]|blob\.core\.|[A-Z0-9._%+-]+@[A-Z0-9.-]+' extracted/

# Then query format-aware config keys, DNS/MX data, certificate metadata,
# package manifests, and binary strings for bare hostnames/namespaces.
```

Review bare-hostname candidates for prose, source-map, test, and generated-data false positives. Deduplicate content-addressed layers and repeated vendor boilerplate so prevalence is not inflated. Preserve the source file, artifact hash, version, and surrounding semantic context for every candidate.

### Ownership and Resolution History

- Resolve A/AAAA/CNAME/NS/MX/TXT/CAA and retain complete chains.
- Check current registrar/provider resource state through authoritative sources, including custom-domain binding and reservation rules.
- Use historical DNS, CT, WHOIS/RDAP, package metadata, source history, and release timelines to establish ownership drift.
- Identify wildcard/catch-all responses, parked domains, provider tombstones, and reused cloud IPs that mimic availability.
- Compare vulnerable/current builds to learn whether the reference was removed, replaced, or cryptographically hardened. Record CAA, DNSSEC/DANE where relevant, certificate issuance/custom-host requirements, pinning, embedded trust stores, and independent content signatures.

Do not rely on an HTTP `404`, NXDOMAIN, or “NoSuchBucket” alone. Providers reserve names, enforce ownership verification, or return identical errors for owned/private resources.

### Live Consumer Confirmation

Within scope, observe a controlled consumer through:

- offline code/dataflow from trigger to request and response consumer
- DNS/HTTP proxy logs in a lab
- packet capture or process/network tracing during a normal test operation
- a tester-owned canary endpoint configured through a supported setting
- already-authorized sensor/sinkhole telemetry

Record request method/protocol, SNI/Host, headers, authentication, body data classification, retry cadence, TLS verification, and how the response is parsed or executed.

## Security Analysis

Ask in order:

1. Can ownership/control actually transfer to an unrelated party?
2. Does an in-scope deployed consumer still resolve or contact it?
3. What authenticity/integrity checks survive endpoint takeover?
4. What response fields/content/protocol messages can the controller influence?
5. Under what identity and privilege does the consumer process them?
6. Is the trigger automatic, scheduled, administrative, user-driven, or update-only?
7. What population and versions remain affected?
8. What claimability level is proven, and is acquisition necessary for the remaining questions?
9. Could acquisition receive out-of-scope traffic or data?
10. Does this name serve several distinct consumers that require separate semantics and impact analysis?

High-impact patterns include:

- unsigned or weakly verified update/package content processed with system/administrator privilege
- JavaScript loaded under a trusted web origin or CSP allowlist
- mail/recovery/identity messages delivered to a re-registered domain
- secrets or device metadata automatically sent to a reassigned endpoint
- trusted control/telemetry responses parsed as commands, config, templates, or executable content
- CA/domain verification, service discovery, or protocol logic depending on mutable external ownership

## Passive Sensor and Sinkhole Handling

Operating a domain or provider resource that receives real third-party traffic is a separate data-handling activity, not ordinary proof-of-concept hosting. Before enabling it, define:

- written authorization and legal/privacy owner
- accepted protocols and non-interaction policy
- collection minimization, encryption, access control, retention, deletion, and redaction
- handling for credentials, personal data, malware, or out-of-scope victims
- notification/escalation and provider/registrar coordination
- prohibition on commands, authentication attempts, payload delivery, or use of received secrets

Prefer aggregate metadata or a unique tester-controlled canary. Do not deliberately expose a genuinely vulnerable product to collect wild exploitation without separate deployment authorization and containment review.

## Relationship to Other Skills

- Load `subdomain_takeover` for dangling DNS records or custom-domain provider bindings. Ordinary expiration/re-registration of a registrable domain, MX identity, or embedded software endpoint remains in this skill.
- Load `source_aware_sast` for targeted source/dataflow confirmation; string presence does not prove current ownership or live consumption.
- Load `agentic_system_security` only when the endpoint supplies or controls AI skills, plugins, MCP/model adapters, tool definitions, or effective agent authority.
- Load `semantic_confusion` only when a security decision and privileged consumer use different endpoint/package/alias representations or resolution results. Pure temporal ownership drift does not require it.

## Validation Deliverable

Include:

1. exact consumer artifact/version/deployment and reference location
2. full DNS/provider/package resolution and current ownership evidence
3. historical ownership/decommission timeline
4. live or source-confirmed request trigger and accepted response semantics
5. TLS/signature/hash/authentication behavior
6. consumer privilege, affected population, and configuration prerequisites
7. controlled ownership/canary evidence where authorized
8. highest claimability level and confidence in live-consumer/prevalence evidence
9. sensor/data-handling authorization when acquisition could receive existing traffic
10. separate impact analysis for each mail, identity, update, telemetry, code, or control consumer
11. remediation across both the endpoint and every retained consumer

## Common False Positives

- NXDOMAIN/provider tombstone with a name that cannot be registered or bound.
- A hardcoded URL present only in dead code, examples, tests, or an undeployed version.
- Live requests go to a vendor-controlled wildcard/catch-all despite an apparently missing specific resource.
- Update content is independently signed and the reassigned endpoint cannot produce an accepted artifact; this usually blocks forged-code impact, but metadata exposure, update suppression, unsigned manifest fields, and rollback/version behavior still require analysis.
- Expired domain appears in documentation but is absent from authentication, mail, software, and deployed configuration.
- A package name is unregistered but the consumer is pinned to a private registry with no public fallback, the scope is routed by `.npmrc`, or the command is already satisfied by a locally installed binary.
- The name is unregistered but registry policy, reservation, dispute, or unpublish state prevents the contested registration.
- Inbound sensor traffic cannot be attributed to an in-scope consumer/version.

## Remediation

- Remove or replace references in every supported and still-deployed version.
- Retain defensive ownership of externally embedded domains/resource names for the consumer's realistic lifetime.
- Sign update/config/package content with independently managed, rotatable keys and enforce rollback/version policy.
- Eliminate implicit public fallback; pin registries, publishers, hashes, and plugin identities.
- Inventory domain/MX/provider/package dependencies in decommission workflows and continuous monitoring.
- Revoke old credentials/tokens, rotate trust, and provide a migration/kill-switch path for stranded clients.
- Monitor DNS, CT, registrar, provider binding, package namespace, and live outbound traffic for ownership drift.

## Summary

External names are long-lived security dependencies. Track every consumer to its current controller, prove that deployed software still trusts the endpoint, analyze the authenticity checks and processing privilege, and manage ownership for as long as any supported or abandoned client can call home.
