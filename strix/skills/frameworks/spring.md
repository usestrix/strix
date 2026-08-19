---
name: spring
description: Security testing playbook for Spring/Spring Boot applications covering actuator exposure, SpEL injection, Spring4Shell, JDBC deserialization, and heapdump secrets
---

# Spring / Spring Boot

Spring Boot is the default for Java microservices, and its superpower - auto-configuration - ships a pile of management endpoints (`/actuator/*`) that are often left exposed. Beyond that, Spring's data binding (which made Spring4Shell possible), SpEL evaluation, and Java deserialization chains make it one of the highest-value Java targets: an exposed actuator, a heapdump, or a `@RequestParam` reaching an expression evaluator can end the assessment.

## Attack Surface

- Actuator endpoints: `/actuator`, `/actuator/env`, `/actuator/heapdump`, `/actuator/beans`, `/actuator/mappings`, `/actuator/configprops`, `/actuator/health`, `/actuator/info`, `/actuator/loggers`, `/actuator/threaddump`, `/actuator/scheduledtasks`, `/actuator/jolokia`, `/actuator/gateway/routes`, `/actuator/refresh`, `/actuator/restart`, `/actuator/shutdown` (older: `/env`, `/dump`, `/trace`, `/mappings`, `/beans`, `/configprops`, `/metrics`)
- Data binding: `@RequestParam`/`@ModelAttribute`/`@RequestBody` into POJOs and nested objects (Spring4Shell class)
- Expression evaluation: SpEL in `@Value`/`#{...}`, `SpelExpressionParser`, Spring EL in security annotations, template engines (Thymeleaf with SpEL)
- Deserialization: Java native serialization, XStream, Jackson polymorphic typing, H2 console, JDBC `rowSet`/`datasource` URLs
- Swagger/OpenAPI exposure, H2 console (`/h2-console`), Jolokia JMX, Spring Cloud Gateway routes
- Whitelabel error pages leaking exception classes and paths
- Spring Security misconfiguration: `permitAll` on actuators, method-security gaps, JWT/JWKS handling, CORS

## Reconnaissance

1. **Probe actuator endpoints** with a wordlist of the paths above; status 200 vs 404 vs 401/403 tells you exposure vs protection
2. **Fingerprint**: `X-Application-Context`, whitelabel error page, `Spring` in headers, actuator JSON shapes, `Server: Apache Tomcat`
3. **Download `/actuator/heapdump`** if present - it contains env secrets, tokens, and connection strings (analyze below)
4. **Read `/actuator/env`** for plaintext secrets (database passwords, API keys, `SECRETS`) and config sources
5. **Read `/actuator/mappings`** for the complete route inventory - it is the app's own API spec
6. **Source-aware**: grep for `SpelExpressionParser`, `@Value("${...}")`, `Runtime.exec`, `ObjectInputStream`, `readObject`, `@RequestParam` binding into domain objects, `actuator` config in `application.yml`

## Key Vulnerabilities

### Exposed Actuators

- `/actuator/env` leaks secrets and lets you see every `application.properties`/env override
- `/actuator/heapdump` leaks the live JVM heap: passwords, tokens, keys (analyze below)
- `/actuator/mappings` reveals every controller route and method
- `/actuator/beans`/`/configprops` reveal internal beans and configuration values
- `/actuator/jolokia` can expose JMX MBeans (older CVEs enabled RCE via `Logback`/`reloadByURL`)
- `/actuator/gateway/routes` on Spring Cloud Gateway -> route inventory and, with write access, SpEL injection (CVE-2022-22947)
- `/actuator/restart`/`/shutdown` -> availability impact

### Spring4Shell (CVE-2022-22965)

Unauthenticated RCE via data binding on JDK 9+ + Tomcat WAR deployments (Spring < 5.2.20/5.3.18):

```
POST /?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20...&...=... HTTP/1.1
Content-Type: application/x-www-form-urlencoded
```

The chain sets the Tomcat `AccessLogValve` `pattern`/`suffix`/`directory`/`prefix` via nested binding to write a JSP webshell. Version-gate before testing (affected: Spring Framework 5.3.0-5.3.17, 5.2.0-5.2.19, older, on JDK 9+ and WAR packaging). Also probe the simpler data-binding sanity check first (`?class.module.classLoader.URLs[0]=...` behavior) to avoid noisy payload spraying.

### SpEL Injection

User input reaching `SpelExpressionParser` or Spring EL (`#{...}`) evaluates as expressions:

```
T(java.lang.Runtime).getRuntime().exec('id')
new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).useDelimiter("\\A").next()
```

Also check `@RequestParam` values interpolated into SpEL in Thymeleaf (`${...}` + `#{...}`) and Spring Cloud Gateway route predicates/filters.

### Java Deserialization

- Native `ObjectInputStream` on request bodies/cookies -> ysoserial gadget chains (CommonsCollections, Spring, Groovy)
- Jackson with `default typing` enabled -> polymorphic deserialization RCE
- XStream/`@XStreamImplicit` -> CVE-2017-9805 class
- H2 console (`/h2-console`) with `CREATE ALIAS` + `javax.naming.InitialContext` -> JNDI/RCE when reachable
- JDBC URL injection: attacker-controlled `jdbc:...` URLs (H2, Derby, PostgreSQL) can execute code on connect

### Mass Assignment via Data Binding

Spring binds request params to object graphs by convention:

```
POST /api/user?role=admin&active=true HTTP/1.1
```

If the handler binds `@ModelAttribute User` without whitelisting, undeclared fields (role, balance, tenant) bind directly. Spring4Shell is the extreme form of the same mechanism. See `mass_assignment`.

### Whitelabel / Error Information Disclosure

Default error pages leak exception class names, file paths, and sometimes bean/message details. They also fingerprint exact Spring/Tomcat versions for CVE matching.

### Spring Security Gaps

- Actuators on `permitAll`, or behind a proxy that strips the auth header
- Method security (`@PreAuthorize`) missing on controller methods (BFLA)
- JWT with `none`/weak algorithms, or JWKS URL SSRF (see `authentication_jwt`, `ssrf`)
- CORS reflect + credentials (see `cors_misconfiguration`)

## Advanced Techniques

- **Heapdump analysis**: download `/actuator/heapdump`, then:
  ```
  strings heapdump | grep -iE 'password|secret|token|apikey|jdbc'
  # or Eclipse MAT / jhat for object-level extraction
  ```
  Prefer `strings` + targeted greps for speed; MAT for structured extraction of `char[]` secrets
- **Jolokia/Logback**: with write access to `/actuator/jolokia`, `reloadByURL` can pull a malicious logback config (historical RCE path; version-gate)
- **Gateway SpEL**: Spring Cloud Gateway < 3.1.1/3.0.7 - `POST /actuator/gateway/routes/{id}` with a SpEL filter -> RCE (CVE-2022-22947); check actuator write methods before assuming read-only
- **`/actuator/env` write (POST)**: on some configs, POSTing `{ "name": "x", "value": "y" }` sets env props (e.g., `spring.cloud.bootstrap.location` to a remote config) -> property manipulation
- **Log4Shell context**: Spring Boot apps commonly run Log4j2 - test `${jndi:...}` interpolation on user-controlled log fields only on confirmed vulnerable versions (CVE-2021-44228); prefer OAST evidence

## Testing Methodology

1. Probe the actuator surface and version-fingerprint
2. Pull `/actuator/env`, `/actuator/heapdump`, `/actuator/mappings` when exposed; extract secrets and routes
3. Test data binding: mass assignment fields, then Spring4Shell preconditions (JDK 9+/WAR/version) before the full chain
4. Fuzz SpEL/expression sinks with benign evaluation probes (`T(java.lang.Math).random()`)
5. Check deserialization endpoints with safe gadget probes or version evidence
6. Audit Spring Security method coverage against the mappings inventory
7. Validate every finding with exact request/response pairs and version evidence

## Validation

1. Actuator: show real secrets/routes/beans from the exposed endpoint with minimal disclosure (redact long-lived creds in the report)
2. SpEL: evaluate a benign expression and show the result in the response
3. Mass assignment: persist an undeclared field with a two-account/baseline diff
4. Heapdump: show a concrete secret string found and its source
5. CVE paths: version-gate, then minimal marker proof

## False Positives

- Actuator returns 401/403 or is stripped by the proxy - not exposed
- `/actuator` root lists nothing but individual endpoints 404 (no management exposure)
- SpEL in a template that evaluates server-side but never reflects or affects anything
- Data binding rejects undeclared fields (no persistence change)
- Heapdump present but empty/no secrets extractable (still an information-disclosure finding at low severity)
- Whitelabel page leaks a generic message but no actionable version/path data

## Impact

- RCE via Spring4Shell, SpEL, deserialization, or Jolokia/gateway paths
- Credential theft from env/heapdump leaks, then lateral movement
- Full route/API inventory disclosure via mappings
- Privilege escalation via data-binding mass assignment

## Pro Tips

1. `/actuator/heapdump` + `strings` is the fastest secrets find in Java land - grab it before anything else
2. `/actuator/mappings` is free API documentation; use it to drive authz testing
3. Version-check Spring4Shell carefully (JDK 9+, WAR, Tomcat) before spending a cycle on it
4. Test data binding on every `@ModelAttribute`/POJO handler - it is the modern mass-assignment class
5. Pair with `insecure_deserialization`, `mass_assignment`, `authentication_jwt`, and `ssrf` skills

## Summary

Spring Boot assessments start at the actuator surface (env/heapdump/mappings), then move to data binding, SpEL, deserialization, and Spring Security gaps. Pull the inventory and secrets first, version-gate the famous CVEs, and validate with concrete evidence.
