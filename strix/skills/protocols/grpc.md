---
name: grpc
description: gRPC security testing covering server reflection, grpcurl workflows, authz gaps, protobuf field abuse, and gateway confusion
---

# gRPC

gRPC is an HTTP/2-based RPC framework with Protocol Buffers (protobuf) as the default wire format. Binary payloads and port-based services make it easy to overlook next to HTTP APIs, but the security model is the same: authentication, authorization, and input validation must hold per method. The best news for testers is server reflection - many production servers expose their full service inventory to anyone who asks.

## Attack Surface

- gRPC servers on non-standard ports (commonly 50051, 9090, 443, 8443) and behind load balancers/ingresses
- Services split into public and internal methods on the same server (admin/health/debug mixed with user APIs)
- gRPC-Web and REST/gateway translations that front the same backend (envoy gRPC-Web, grpc-gateway, Cloud Endpoints)
- Health checks (`grpc.health.v1.Health/Check`), reflection (`grpc.reflection.v1alpha.ServerReflection` / `v1`), and debug endpoints
- TLS vs plaintext (`-plaintext`), mTLS gaps, and authorization metadata (bearer tokens, API keys, custom headers)

## Reconnaissance

1. **Find gRPC endpoints** - port scan (`naabu`) for common ports, HTTP/2 prior-knowledge probes, mobile/JS bundle mining for `.proto` files or service names, and TLS ALPN (`h2`) detection
2. **Try reflection first**:
   ```
   grpcurl -plaintext host:port list
   grpcurl -plaintext host:port describe pkg.Service
   grpcurl -plaintext host:port describe pkg.Service.Method
   ```
   If reflection is disabled, errors differ (`unknown service` vs `method not implemented`) - that is still useful fingerprinting
3. **Get the protos** - source code, mobile binaries (extract `.proto`/descriptors), gRPC-Web JS bundles (protobuf messages are discoverable from compiled JS), or `grpcurl describe` output when reflection works
4. **Check health and metadata**: `grpcurl -plaintext host:port list` usually reveals `grpc.health.v1.Health`; call `Check` with no auth
5. **Map authentication** - which methods require metadata (tokens) and which answer unauthenticated; compare against the client's real calls captured via proxy (agent-browser/caido can see HTTP/2)

## Key Vulnerabilities

### Reflection Exposure

Server reflection leaks the complete service/method inventory and field schemas to unauthenticated callers. It is information disclosure that turns black-box testing into white-box:

```
grpcurl -plaintext host:port list
grpcurl -plaintext host:port describe admin.AdminService
```

### Missing Authentication / Authorization

- Methods invoked without credentials succeed (`grpcurl -plaintext host:port pkg.Service.SensitiveMethod` with empty metadata)
- Interceptors validate at the service level but individual methods skip their own checks (BFLA: user calls admin methods with a user token)
- Health/reflection/debug methods exposed on internet-facing ports

### Protobuf Field Abuse

- Unknown/enum fields: send out-of-range enum values, negative numbers, huge strings, or duplicate fields - parsers differ on strictness
- Type confusion: `oneof` fields can be switched to another type; JSON transcoding can coerce types (`"price":"1e3"`)
- Injection in string fields: SQL/NoSQL injection, command injection, path traversal, XXE - the values reach the same sinks as HTTP parameters
- IDs and offsets for pagination/export methods -> IDOR/BOLA

### Large Message / DoS

- Unbounded message size or streaming: send multi-GB messages or endless client streams to exhaust memory
- `grpc.MaxCallRecvMsgSize` defaults cap at 4 MiB server-side, but proxies and custom configs may not
- Nested `google.protobuf.Any`/recursive messages that blow up deserialization depth

### Gateway / Protocol Confusion

- gRPC-Web or REST gateway translates requests differently: path-parameter smuggling (`/v1/users/{id}` vs `%2F`), header-to-metadata confusion (`authorization` vs `x-api-key`), or query-param injection into message fields
- Load balancers terminating HTTP/2 and re-framing to HTTP/1.1 can split or merge messages (request smuggling analogues)

## Advanced Techniques

- **Authz matrix**: collect tokens for N roles and run the full method x role matrix; methods often forget role checks after adding a new service
- **Replay**: capture a valid request with credentials and replay later - does the server enforce freshness/idempotency?
- **Timing enumeration**: valid vs invalid object IDs often differ in latency or error wording (`not found` vs `permission denied`)
- **Error-message mining**: invoke with malformed payloads; rich error details (`google.rpc.Status` details) leak stack traces, types, and internal state
- **Bidi streaming abuse**: interleave messages to hit TOCTOU/race conditions in stateful methods
- **mTLS/proxy gaps**: check whether internal-only services are reachable through an exposed gateway with default credentials

## Testing Methodology

1. Discover the endpoint and service inventory (reflection first, protos second)
2. Pull field schemas for every method (`describe`)
3. Baseline each method with a well-formed empty/minimal payload; record auth requirements and error shape
4. Run the authz matrix (no token, user, admin, expired, wrong audience)
5. Fuzz field values: injection payloads, type confusion, huge/lengthy values, unknown fields
6. Test streaming and message-size limits
7. Check gateway/transcoding paths for translation bugs

## Validation

1. Show a concrete request/response pair for each finding (`grpcurl -d '{...}' -H 'authorization: ...' host:port pkg.Service.Method`)
2. For authz gaps: identical method, two different tokens (or none), unauthorized success
3. For injection: reproduce against the underlying data store with evidence from the app response
4. Keep payloads minimal and non-destructive; prefer read-only proofs

## False Positives

- Reflection lists services but every method enforces auth (`permission denied` without token) - exposure is still low-severity info disclosure
- `unknown service` from a different protocol on the port (not gRPC at all)
- "Unauthenticated" calls that actually use a default/ambient credential baked into the client config
- Health/reflection endpoints on internal-only interfaces that are not reachable from the tested network

## Impact

- Full API inventory disclosure via reflection
- Account takeover and data access via missing per-method authorization
- RCE/data loss via injection in unvalidated message fields
- Availability impact via message/stream size abuse

## Pro Tips

1. Try `grpcurl -plaintext host:port list` before anything else - reflection is often left enabled in production
2. `grpcurl -plaintext host:port describe pkg.Service` prints field names, types, and labels - treat it as an API spec
3. Install when needed: `go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest`
4. Use `-d @` with a JSON file for complex payloads; `-H 'authorization: Bearer ...'` for auth
5. For TLS endpoints use `-servername`/`-insecure` carefully; check ALPN with `openssl s_client -alpn h2`
6. Test every method with empty input - default/zero values frequently reach different code paths than valid input
7. Combine with `api_spec_testing` when a REST gateway fronts the same backend; translation bugs live in the mapping layer

## Summary

gRPC services are HTTP APIs wearing a binary costume: enumerate with reflection, map per-method authz, abuse field validation, and test the gateway. Start with `grpcurl list`/`describe`, build a role x method matrix, and validate findings with exact request/response pairs.
