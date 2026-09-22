---
name: grpc
description: gRPC security testing covering reflection-based enumeration, metadata/interceptor auth bypass, and protobuf field abuse
---

# gRPC

gRPC hides its attack surface behind compiled protobuf schemas and HTTP/2 framing — most web scanners never see it. Reflection, when enabled, turns an opaque binary protocol into a fully enumerable API; when disabled, schema recovery becomes the first real obstacle.

## Attack Surface

**Transport**
- HTTP/2 required (h2c cleartext or TLS) — Content-Type `application/grpc`, `application/grpc+proto`, `application/grpc+json`
- gRPC-Web (browser-compatible variant, proxied through Envoy/nginx to backend gRPC) — Content-Type `application/grpc-web`, `application/grpc-web-text`
- Bidirectional/server/client streaming RPCs, not just unary

**Auth Surface**
- Per-call metadata (gRPC's header equivalent) — `authorization`, custom auth metadata keys, often validated in an interceptor separate from business logic
- mTLS at the transport layer, independent of any application-level auth
- Interceptor chains — auth interceptor may not apply uniformly to every registered service/method

**Schema**
- `.proto` service/message definitions compiled into the binary — not shipped to clients unless reflection is enabled or files are bundled client-side (mobile APK, web bundle referencing `.proto`/generated stubs)

## Reconnaissance

**Reflection Enumeration**

If server reflection (`grpc.reflection.v1alpha.ServerReflection`) is enabled — common in dev/staging, sometimes left on in prod:
```bash
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest   # on-demand install, sandbox has go
grpcurl -plaintext target:50051 list                             # list services
grpcurl -plaintext target:50051 list <package.Service>            # list methods
grpcurl -plaintext target:50051 describe <package.Service.Method> # full message schema
grpcurl -plaintext -d '{"id":"1"}' target:50051 <package.Service/Method>
```
For TLS targets drop `-plaintext` and add `-insecure` if the cert isn't trusted (note the finding regardless — accepting `-insecure` in testing doesn't mean production clients should).

**Schema Recovery Without Reflection**
- Pull `.proto`/generated stub files from mobile APK (`jadx`, search for `*.proto` or generated `*Grpc.java`/`*_pb2.py`), from web bundles (`protobuf.js` generated code, `grpc-web` client stubs), or from public API docs/GitHub
- If only a compiled binary client exists, extract method names and field numbers from generated stub source (protoc-generated code preserves field tags even when minified)
- Brute-force method names against a known service using common CRUD verb patterns (`Get`, `List`, `Create`, `Update`, `Delete` + noun) once at least one method is known to confirm the service path prefix

**gRPC-Web Proxy Identification**
- Check for an Envoy/nginx-grpc-web bridge in front of the real gRPC service — the bridge often applies its own (possibly weaker) auth/rate-limit policy before forwarding, and errors/timing can reveal whether the check happens at bridge or backend

## Key Vulnerabilities

### Reflection Left Enabled in Production

Reflection exposes the entire method/message inventory to an unauthenticated caller, including internal/admin-only services never intended for the public client. Treat every reflected method as a target, especially ones absent from public API docs — those are the ones nobody expects to be probed.

### Metadata/Interceptor Auth Bypass

- Call methods directly via `grpcurl` bypassing any auth logic embedded in the official client SDK rather than the server interceptor — if auth is only enforced client-side (common mistake carried over from REST thinking), every method is open
- Test each method individually for interceptor coverage — a global interceptor registered after specific services were already registered, or a per-service interceptor missed during a later service addition, leaves gaps
- Omit metadata entirely, send empty/malformed `authorization` metadata, and diff the response — `UNAUTHENTICATED` vs `PERMISSION_DENIED` vs actual data distinguishes "no check" from "check present but bypassable"
- Streaming RPCs: auth may only be validated on stream setup, not re-validated per message — test whether a long-lived stream keeps working after the underlying token/session is revoked

### Protobuf Field-Level Abuse

Without the full `.proto`, fields can still be probed by tag number since protobuf wire format is just `(field_number, wire_type, value)` tuples:
```bash
grpcurl -plaintext -d '{"1":"value","2":123}' target:50051 pkg.Service/Method  # field-number JSON mapping
```
- **Mass assignment** — send extra/undocumented field numbers (increment from known ones) to probe for hidden fields the server accepts but the official client never sets (role flags, internal IDs, debug toggles)
- **Type confusion** — send a field with the wrong wire type (varint where a length-delimited string is expected) and observe parser behavior; some implementations silently coerce or crash rather than reject
- **IDOR via message fields** — same as REST/GraphQL IDOR but the object reference lives in a protobuf field; enumerate by incrementing/guessing ID fields across unary calls

### HTTP/2 Downgrade & Framing Abuse

- h2c smuggling: if a reverse proxy in front of gRPC also serves HTTP/1.1 traffic, test HTTP/1.1-to-h2c upgrade request smuggling to reach the backend directly, bypassing proxy-level auth/WAF
- Stream multiplexing abuse — HTTP/2 allows many concurrent streams per connection; some rate limits are per-connection rather than per-stream, letting a single connection multiplex past intended limits (flag as throttle-by-default, this shades into DoS)

### TLS/mTLS Misconfiguration

- Server accepts plaintext (h2c) despite intending TLS-only — check whether the plaintext port is reachable directly, bypassing an mTLS-enforcing load balancer in front of the TLS port
- mTLS client-cert validation checks presence but not CN/SAN binding to an authorized identity — any valid cert from the CA authenticates as any identity

## Testing Methodology

1. **Enumerate** — reflection if available; otherwise recover schema from client artifacts (APK/web bundle/docs)
2. **Auth matrix** — call every method with no metadata, invalid metadata, and a low-privilege valid token; diff status codes and payloads
3. **Field sweep** — for each message, probe adjacent/undocumented field numbers for mass-assignment and hidden functionality
4. **IDOR pass** — for methods taking an ID/reference field, swap to foreign-owned IDs under a low-privilege account
5. **Streaming** — verify auth is re-checked during long-lived streams, not just at handshake
6. **Transport** — confirm h2c is actually disabled where TLS-only is intended; test proxy/backend auth parity

## Validation

- Reflection response listing internal/admin services not present in public documentation
- Direct `grpcurl` call to a protected method succeeding with missing/invalid metadata where the official client would have blocked the same call
- Undocumented field number accepted and observably changing server state or returned data (role, price, ownership)
- Full request: exact `grpcurl`/raw HTTP2 invocation, metadata sent, and response demonstrating unauthorized data or action

## False Positives

- Reflection disabled and confirmed via `list` returning `Unimplemented`
- Every method rejects missing/malformed metadata with `UNAUTHENTICATED` consistently, including streaming
- Undocumented field numbers rejected or ignored (protobuf's default "unknown fields are dropped" behavior, correctly not wired to any handler)
- h2c connection refused when TLS-only is intended

## Tooling

```bash
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest   # CLI enumeration/invocation
go install github.com/fullstorydev/grpcui/cmd/grpcui@latest     # web UI over a gRPC target, useful for manual field exploration
```
`grpcurl` covers reflection, unary/streaming calls, and TLS/mTLS/h2c testing from the command line — sufficient for the full methodology above without a GUI proxy.

## Summary

gRPC's opacity is its weakest point once reflection or schema recovery breaks it open: every method becomes directly callable outside the official client's guardrails. Auth and field-level checks that assume "the client only sends what it's supposed to" collapse the moment `grpcurl` is talking to the server directly.
