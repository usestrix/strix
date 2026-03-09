---
name: nestjs
description: Security testing playbook for NestJS applications covering guards, pipes, decorators, module boundaries, and multi-transport auth
---

# NestJS

Security testing for NestJS applications. Focus on guard gaps across decorator stacks, validation pipe bypasses, module boundary leaks, and inconsistent auth enforcement across HTTP, WebSocket, and microservice transports.

## Attack Surface

**Decorator Pipeline**
- Guards: `@UseGuards`, `CanActivate`, execution context (HTTP/WS/RPC), `Reflector` metadata
- Pipes: `ValidationPipe` (whitelist, transform, forbidNonWhitelisted), `ParseIntPipe`, custom pipes
- Interceptors: response mapping, caching, logging, timeout — can modify request/response flow
- Filters: exception filters that may leak information
- Metadata: `@SetMetadata`, `@Public()`, `@Roles()`, `@Permissions()`

**Module System**
- `@Module` boundaries, provider scoping (DEFAULT/REQUEST/TRANSIENT)
- Dynamic modules: `forRoot`/`forRootAsync`, global modules
- DI container: provider overrides, custom providers

**Controllers & Transports**
- REST: `@Controller`, versioning (URI/Header/MediaType)
- GraphQL: `@Resolver`, playground/sandbox exposure
- WebSocket: `@WebSocketGateway`, gateway guards, room authorization
- Microservices: TCP, Redis, NATS, MQTT, gRPC, Kafka — often lack HTTP-level auth

**Data Layer**
- TypeORM: repositories, QueryBuilder, raw queries, relations
- Prisma: `$queryRaw`, `$queryRawUnsafe`
- Mongoose: operator injection, `$where`, `$regex`

**Auth & Config**
- `@nestjs/passport` strategies, `@nestjs/jwt`, session-based auth
- `@nestjs/config`, ConfigService, `.env` files
- `@nestjs/throttler`, rate limiting with `@SkipThrottle`

**API Documentation**
- `@nestjs/swagger`: OpenAPI exposure, DTO schemas, auth schemes

## High-Value Targets

- Swagger/OpenAPI endpoints in production (`/api`, `/api-docs`, `/api-json`, `/swagger`)
- Auth endpoints: login, register, token refresh, password reset, OAuth callbacks
- Admin controllers decorated with `@Roles('admin')` — test with user-level tokens
- File upload endpoints using `FileInterceptor`/`FilesInterceptor`
- WebSocket gateways sharing business logic with HTTP controllers
- Microservice handlers (`@MessagePattern`, `@EventPattern`) — often unguarded
- CRUD generators (`@nestjsx/crud`) with auto-generated endpoints
- Background jobs and scheduled tasks (`@nestjs/schedule`)
- Health/metrics endpoints (`@nestjs/terminus`, `/health`, `/metrics`)
- GraphQL playground/sandbox in production (`/graphql`)

## Reconnaissance

**Swagger Discovery**
```
GET /api
GET /api-docs
GET /api-json
GET /swagger
GET /docs
GET /v1/api-docs
GET /api/v2/docs
```

Extract: paths, parameter schemas, DTOs, auth schemes, example values. Swagger may reveal internal endpoints, deprecated routes, and admin-only paths not visible in the UI.

**Guard Mapping**

For each controller and method, identify:
- Global guards (applied in `main.ts` or app module)
- Controller-level guards (`@UseGuards` on the class)
- Method-level guards (`@UseGuards` on individual handlers)
- `@Public()` or `@SkipThrottle()` decorators that bypass protection

## Key Vulnerabilities

### Guard Bypass

**Decorator Stack Gaps**
- Guards execute: global → controller → method. A method missing `@UseGuards` when siblings have it is the #1 finding.
- `@Public()` metadata causing global `AuthGuard` to skip enforcement — check if applied too broadly.
- New methods added to existing controllers without inheriting the expected guard.

**ExecutionContext Switching**
- Guards handling only HTTP context (`getRequest()`) may fail silently on WebSocket or RPC, returning `true` by default.
- Test same business logic through alternate transports to find context-specific bypasses.

**Reflector Mismatches**
- Guard reads `SetMetadata('roles', [...])` but decorator sets `'role'` (singular) — guard sees no metadata, defaults to allow.
- `applyDecorators()` compositions accidentally overriding stricter guards with permissive ones.

### Validation Pipe Exploits

**Whitelist Bypass**
- `whitelist: true` without `forbidNonWhitelisted: true`: extra properties silently stripped but may have been processed by earlier middleware/interceptors.
- Missing `@Type(() => ChildDto)` on nested objects: `@ValidateNested()` without `@Type` means nested payload is never validated.
- Array elements: `@IsArray()` doesn't validate elements without `@ValidateNested({ each: true })` and `@Type`.

**Type Coercion**
- `transform: true` enables implicit coercion: strings → numbers, `"true"` → `true`, `"null"` → `null`.
- Exploit truthiness assumptions in business logic downstream.

**Conditional Validation**
- `@ValidateIf()` and validation groups creating paths where fields skip validation entirely.

**Missing Parse Pipes**
- `@Param('id')` without `ParseIntPipe`/`ParseUUIDPipe` — string values reach ORM queries directly.

### Auth & Passport

**JWT Strategy**
- Check `ignoreExpiration` is false, `algorithms` is pinned (no `none` or HS/RS confusion)
- Weak `secretOrKey` values
- Cross-service token reuse when audience/issuer not enforced

**Passport Strategy Issues**
- `validate()` return value becomes `req.user` — if it returns full DB record, sensitive fields leak downstream
- Multiple strategies (JWT + session): one may bypass restrictions of the other
- Custom guards returning `true` for unauthenticated as "optional auth"

**Timing Attacks**
- Plain string comparison instead of bcrypt/argon2 in local strategy

### Serialization Leaks

**Missing ClassSerializerInterceptor**
- If not applied globally, `@Exclude()` fields (passwords, internal IDs) returned in responses.
- `@Expose()` with groups: admin-only fields exposed when groups not enforced per-request.

**Circular Relations**
- Eager-loaded TypeORM/Prisma relations exposing entire object graph without careful serialization.

### Interceptor Abuse

**Cache Poisoning**
- `CacheInterceptor` without user/tenant identity in cache key — responses from one user served to another.
- Test: authenticated request, then unauthenticated request returning cached data.

**Response Mapping**
- Transformation interceptors may leak internal entity fields if mapping is incomplete.

### Module Boundary Leaks

**Global Module Exposure**
- `@Global()` modules expose all providers to every module without explicit imports.
- Sensitive services (admin operations, internal APIs) accessible from untrusted modules.

**Config Leaks**
- `forRoot`/`forRootAsync` configuration secrets accessible via `ConfigService` injection in any module.

**Scope Issues**
- Request-scoped providers (`Scope.REQUEST`) incorrectly scoped as DEFAULT (singleton) — request context leaks across concurrent requests.

### WebSocket Gateway

- HTTP guards don't automatically apply to WebSocket gateways — `@UseGuards` must be explicit.
- Authentication deferred from `handleConnection` to message handlers allows unauthenticated message sending.
- Room/namespace authorization: users joining rooms they shouldn't access.
- `@SubscribeMessage()` handlers relying on connection-level auth instead of per-message validation.

### Microservice Transport

- `@MessagePattern`/`@EventPattern` handlers often lack guards (considered "internal").
- If transport (Redis, NATS, Kafka) is network-accessible, messages can be injected bypassing all HTTP security.
- `ValidationPipe` may only be configured for HTTP — microservice payloads skip validation.

### ORM Injection

**TypeORM**
- `QueryBuilder` and `.query()` with template literal interpolation → SQL injection.
- Relations: API allowing specification of which relations to load via query params.

**Mongoose**
- Query operator injection: `{ password: { $gt: "" } }` via unsanitized request body.
- `$where` and `$regex` operators from user input.

**Prisma**
- `$queryRaw`/`$executeRaw` with string interpolation (but not tagged template).
- `$queryRawUnsafe` usage.

### Rate Limiting

- `@SkipThrottle()` on sensitive endpoints (login, password reset, OTP).
- In-memory throttler storage: resets on restart, doesn't work across instances.
- Behind proxy without `trust proxy`: all requests share same IP, or header spoofable.

### CRUD Generators

- Auto-generated CRUD endpoints may not inherit manual guard configurations.
- Bulk operations (`createMany`, `updateMany`) bypassing per-entity authorization.
- Query parameter injection in CRUD libraries: `filter`, `sort`, `join`, `select` exposing unauthorized data.

## Bypass Techniques

- `@Public()` / skip-metadata applied via composed decorators at method level causing global guards to skip via `Reflector` metadata checks
- Route param pollution: `/users/123?id=456` — which `id` wins in guards vs handlers?
- Version routing: v1 of endpoint may still be registered without the guard added to v2
- `X-HTTP-Method-Override` or `_method` processed by Express before guards
- Content-type switching: `application/x-www-form-urlencoded` instead of JSON to bypass JSON-specific validation
- Exception filter differences: guard throwing results in generic error that leaks route existence info

## Testing Methodology

1. **Enumerate** — Fetch Swagger/OpenAPI, map all controllers, resolvers, and gateways
2. **Guard audit** — Map decorator stack per method: which guards, pipes, interceptors are applied at each level
3. **Matrix testing** — Test each endpoint across: unauth/user/admin × HTTP/WS/microservice
4. **Validation probing** — Send extra fields, wrong types, nested objects, arrays to find pipe gaps
5. **Transport parity** — Same operation via HTTP, WebSocket, and microservice transport
6. **Module boundaries** — Check if providers from one module are accessible without proper imports
7. **Serialization check** — Compare raw entity fields with API response fields

## Validation Requirements

- Guard bypass: request to guarded endpoint succeeding without auth, showing guard chain break point
- Validation bypass: payload with extra/malformed fields affecting business logic
- Cross-transport inconsistency: same action authorized via HTTP but exploitable via WebSocket/microservice
- Module boundary leak: accessing provider or data across unauthorized module boundaries
- Serialization leak: response containing excluded fields (passwords, internal metadata)
- IDOR: side-by-side requests from different users showing unauthorized data access
- ORM injection: raw query with user-controlled input returning unauthorized data, or error-based evidence of query structure
- Cache poisoning: response from unauthenticated or different-user request matching a prior authenticated user's cached response
