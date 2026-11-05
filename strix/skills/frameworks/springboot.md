---
name: springboot
description: Security testing playbook for deployed or source-available Spring Boot services, including Spring MVC/WebFlux, Spring Security, REST controllers, Actuator, Spring Data REST, Jackson serialization, SpEL, outbound clients, and session management. Use when Spring Boot runtime or configuration is confirmed; first identify the MVC/WebFlux mode, active security chains, method-security wiring, management exposure, profiles, and resolved dependency versions. Covers authentication, authorization, CSRF/CORS, Actuator exposure, path matching, DTO over-binding, validation, deserialization, SSRF, session controls, and Spring-specific configuration flaws.
---

# Spring Boot

Security testing for Spring Boot REST applications, from source code or a running deployment. Confirm MVC vs WebFlux first: filter chains and method-security wiring differ.

## Attack Surface

**Core Components**
- `@RestController`, `@PreAuthorize`/`@Secured`, `SecurityFilterChain` (WebFlux: `SecurityWebFilterChain`)
- Actuator, H2 console, devtools, Spring Data REST

**Data Handling**
- `@Valid`/`@Validated`, `@RequestBody`, `@InitBinder`, Jackson, SpEL, Thymeleaf view names
- `HttpSession`, `JSESSIONID`/`SESSION`, Spring Session

**Configuration**
- `application.properties`/`.yml` profiles, `management.*`, `server.error.*`, dependency versions

## High-Value Targets

- `/actuator/heapdump`, `/env`, `/beans`, and `/mappings` (every route, verb, and media type)
- `/h2-console` outside a development profile; the Spring Data REST root
- Alternate controllers and jobs reusing services checked only at the HTTP layer
- Remoting endpoints, `@JsonTypeInfo` DTOs, remember-me, and logout

## Reconnaissance

**Discovery**
- Try `/actuator`, `/actuator/mappings`, `/v3/api-docs`, and `/h2-console` with `GET`/`HEAD`; never invoke write-capable Actuator operations
- Resolve the context path and management port before reading 404s

**Static discovery**
- Resolve versions from `pom.xml`/`build.gradle`; a source marker does not prove a feature is active in the deployed build
- Read every filter chain bean (`securityMatcher` order, `requestMatchers`, `csrf`, `rememberMe`)

## Key Vulnerabilities

### Spring Security

**Actuator & Console Exposure**
- Only a minimal endpoint set is exposed by default; a wider set means `management.endpoints.web.exposure.include` was changed
- `/env` values may be masked by default (varies by release): compare the real response; `/heapdump` can still expose credentials
- `spring.h2.console.enabled=true` outside development exposes an SQL console

**Authentication & CSRF**
- Default configuration: HTTP Basic and form login for `user`, with a password generated at startup and written to the log
- `NoOpPasswordEncoder` and `{noop}` store passwords without hashing; `InMemoryUserDetailsManager` alone does not imply weak credentials: inspect the configured passwords and encoder. For JWT check issuer, audience, and algorithms
- `csrf.disable()` or a broad `ignoringRequestMatchers` weakens the default: replay POST, PUT, and DELETE with a session cookie and no token

### REST Controllers

**Verbs, Errors & CORS**
- A bare `@RequestMapping` accepts every verb; with `spring.mvc.hiddenmethod.filter.enabled`, a POST carrying `_method` is handled as that verb
- `include-stacktrace` defaults to `never`, but `on_param` serves traces on `?trace=true`
- Spring MVC rejects a literal `allowedOrigins("*")` with credentials, but `allowedOriginPatterns("*")` can reflect any origin: send a foreign `Origin` and look for it echoed with `Access-Control-Allow-Credentials: true`

**DTO Over-Binding**
- Binding a JPA `@Entity` as `@RequestBody` exposes every writable setter: compare with `@JsonIgnore` and `@JsonProperty(access = READ_ONLY)`

Vulnerable patterns:
```java
@PutMapping("/users/{id}")
public User update(@PathVariable Long id, @RequestBody User user) { return repository.save(user); }
```
Test: `PUT /api/users/{id}` with `{"role":"ADMIN"}` as a regular user, then read the record back.

**Spring Data REST & Outbound Requests**
- `spring-boot-starter-data-rest` exports every public repository, write verbs included, and security placed only on controllers does not cover it: test writes as a low-privilege principal
- User-controlled URLs reaching `RestTemplate`/`WebClient`: test loopback and internal ranges

### Input Validation

**Cascade & Skipped Validation**
- Nested objects need `@Valid` on the field, and a plain `@Valid` does not validate a `Collection` or `Map` body; `BindingResult` after a validated argument suppresses rejection, so read the handler body

**Expression Language Injection**
- Trace whether attacker-controlled text is parsed and evaluated as an expression through `SpelExpressionParser`, SpEL in `@Value`/`@Query`, or Thymeleaf template or view-name construction. Values supplied through `StandardEvaluationContext` or bound to a fixed expression are not automatically evaluated as code
- A violation message built from input can reach Hibernate Validator's Expression Language; interpolation of custom messages is disabled by default in current releases

Vulnerable patterns:
```java
context.buildConstraintViolationWithTemplate("Invalid value: " + value).addConstraintViolation();
```
Test: `${7*7}` and `#{7*7}` in the field; `49` in the response confirms evaluation.

### Serialization and Deserialization

**Remoting & Session Store**
- `HttpInvokerServiceExporter`, `RmiServiceExporter`, or any reachable `ObjectInputStream` sink
- Spring Session with Redis or JDBC uses JDK serialization unless a JSON serializer is set: a store an attacker can write to becomes a sink

**Jackson Polymorphism**
- Identify the Jackson major version first: polymorphic-typing defaults differ
- Review `@JsonTypeInfo(use = Id.CLASS)`, `activateDefaultTyping()`, and `PolymorphicTypeValidator`, then trace an attacker-controlled type ID to a DTO

Vulnerable patterns:
```java
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS) private Object payload;
```
Test: send a type id (`{"payload":{"@class":"<class name>"}}`) outside the intended subtypes and compare an allowed and a disallowed class.

### Authorization

**URL vs Method Security**
- Method security is not enabled by the starter: look for `@EnableMethodSecurity`
- A request outside every `securityMatcher` chain gets no Spring Security filtering
- `@PreAuthorize` works through proxies: private methods, non-proxied beans, and self-invocation are unprotected

**Rule Ordering & Path Matching**
- The first matching `requestMatchers` wins: an early `permitAll()` or a broad `/**` overrides later rules
- `hasRole("ADMIN")` checks `ROLE_ADMIN`; a mismatch with the token's authorities leaves a rule that never matches
- Matchers and the MVC dispatcher have historically disagreed on normalization: test trailing slashes, `;` path parameters, `%2F`, case, and `%0a` against `RegexRequestMatcher`

### Session Management

**Fixation & Creation**
- Compare the session ID before and after login and test whether the old cookie still works

**Remember-Me, Cookies & Logout**
- `maximumSessions()` is unlimited by default: log in twice and check whether the oldest session is evicted
- `TokenBasedRememberMeServices` derives its cookie from a shared `key`, `PersistentTokenBasedRememberMeServices` does not: review the `key`
- Inspect `cookie.secure`, `.http-only`, and `.same-site`; log out and replay a request

## Bypass Techniques

- JSON ↔ XML ↔ form-urlencoded to reach alternate converters and validators
- Path normalization, `;` parameters, `%0a`, and `_method` against filter-chain matchers
- Self-invocation around security and validation proxies

## Testing Methodology

1. **Map** — resolve versions, profile, MVC vs WebFlux, management paths, and reachable routes
2. **Spring Security** — match routes to ordered chains and method security; test authentication, CSRF, and Actuator
3. **REST controllers** — compare verb, media type, binding, error, and CORS behavior; enumerate Spring Data REST exports
4. **Validation and serialization** — trace constraints, groups, sinks, and type binding with malformed and nested inputs
5. **Authorization and sessions** — unauthenticated, two-user, and cross-tenant comparisons; fixation, cookies, remember-me, logout
6. **Dependencies** — check resolved versions against advisories (a match is a lead, not proof), then prove impact at the executing endpoint

## Validation Requirements

- Exposure and authorization: identities or alternate paths compared for the same action or object; a 200 alone is insufficient
- CSRF: demonstrate an attacker's page causing a state change with the victim's credentials and without a valid token. CORS: demonstrate an attacker's page reading a sensitive response with the victim's credentials; reflected `Origin` headers alone are a lead, not proof
- Over-binding and expression injection: a privileged field accepted with the resulting state change, or a deterministic oracle (`${7*7}` returning `49`) and the evaluating sink
- Deserialization and outbound requests: untrusted input reaching the sink or the resolved host reached (bounded callback where feasible)
- Sessions: pre/post-login identifiers, old-cookie validity, or post-logout replay
- Redact cookies, tokens, and secrets from all evidence

## False Positives

- An Actuator 401/403 for tested identities says nothing about other roles, routes, or management ports
- CSRF exclusions on bearer-only APIs without ambient authentication
- A path variant with no handler; a 404 is not an authorization bypass
- `@JsonTypeInfo` or Jackson on the classpath without attacker-controlled type IDs or a reachable sink
- An advisory-matching version whose configuration prerequisites are absent

## Impact

- Disclosure of configuration, credentials, or memory through Actuator or the H2 console
- Unauthorized access through filter-chain, method-security, or path-matching gaps
- Privilege escalation and data tampering through over-bound entities
- Remote code execution through deserialization or expression injection

## Pro Tips

1. Start from `/actuator/mappings` when reachable: it inventories every route
2. A route outside every `securityMatcher` chain has no Spring Security at all
3. `permitAll()` does not by itself bypass `@PreAuthorize`: look for missing annotations or proxy-bypassing calls

## Tooling

The sandbox ships `semgrep`, `ripgrep`, `httpx`, `trivy`, `interactsh-client`, and Caido. Use static review first and confirm each lead over HTTP or OAST.

- **semgrep** (preinstalled) — `semgrep scan --config p/java --metrics=off --quiet .`; the ruleset is fetched on first use, so it returns nothing without network access
- **ripgrep** (preinstalled) — `rg -n 'csrf\.disable|@PreAuthorize|HttpInvokerServiceExporter|activateDefaultTyping|JsonTypeInfo'`
- **httpx** (preinstalled) — `httpx -l hosts.txt -path /actuator/env,/actuator/heapdump,/v3/api-docs -mc 200,401,403`
- **Caido** (preinstalled) — replay requests under two principals for authorization and session tests
- **interactsh-client** (preinstalled) — OAST confirmation for Remoting, Jackson, SSRF, and expression-injection sinks
- **trivy** (preinstalled) — `trivy fs --scanners vuln .` on `pom.xml` or `gradle.lockfile`; it downloads its database on first run and needs network access

## Summary

Spring Boot's defaults help, but filter-chain ordering, method-security wiring, over-bound entities, skipped validation, polymorphic deserialization, and session configuration still introduce frequent gaps. Resolve the deployed stack first and prove impact at the executing endpoint.
