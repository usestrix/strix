---
name: websocket
description: WebSocket and real-time protocol security testing covering upgrade auth, CSWSH, message injection, and channel authorization
---

# WebSocket

Security testing for WebSocket and real-time channels. Focus on the HTTP upgrade
boundary, browser-origin trust, stateful authorization after connection, and
message injection over an established channel.

## Attack Surface

**Upgrade Endpoints**
- Paths that return `101 Switching Protocols`
- API routes accepting `Upgrade: websocket`
- SockJS, Socket.IO, Phoenix Channels, ActionCable, SignalR, GraphQL subscriptions
- Environment-specific paths such as `/ws`, `/socket`, `/realtime`, `/events`

**Handshake Headers**
- `Upgrade: websocket`
- `Connection: Upgrade`
- `Sec-WebSocket-Key`
- `Sec-WebSocket-Version`
- `Sec-WebSocket-Protocol`
- `Origin`
- Cookies, bearer tokens, API keys, and signed query parameters

**Message Types**
- JSON commands and events
- RPC envelopes with method/action fields
- Channel subscribe/unsubscribe messages
- Binary frames and compressed payloads
- Heartbeat, ping, reconnect, and resume messages

## Reconnaissance

**Endpoint Discovery**
```
GET /ws
GET /socket
GET /socket.io/?EIO=4&transport=websocket
GET /realtime
GET /graphql
```

Inspect client bundles for `new WebSocket(...)`, Socket.IO initializers,
GraphQL subscription links, reconnect URLs, and hardcoded channel names.
Capture the initial HTTP request and record which authentication material is
sent in cookies, headers, subprotocols, or query strings.

**Handshake Baseline**
```
GET /ws HTTP/1.1
Host: target.example
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Sec-WebSocket-Protocol: chat, graphql-transport-ws
Origin: https://target.example
Cookie: session=...
```

Compare accepted and rejected handshakes across authenticated, logged-out,
expired, low-privilege, and cross-origin browser contexts. A valid handshake
does not prove authorization is enforced for later messages.

## Key Vulnerabilities

### Handshake Auth Bypass

Test handshake auth bypass by removing or mutating each credential source:
- No cookie and no bearer token
- Expired, revoked, or low-privilege token
- Token moved between header, query parameter, and `Sec-WebSocket-Protocol`
- Duplicate credential locations with conflicting identities
- Missing CSRF token when the web app uses cookie authentication

Flag any unauthenticated upgrade paths that still return `101 Switching
Protocols` or let the client subscribe to protected channels after connection.

### Cross-Site WebSocket Hijacking

CSWSH occurs when a cookie-authenticated WebSocket trusts ambient browser
cookies and fails to validate `Origin`. Test with hostile origins:
```
Origin: https://attacker.example
Origin: null
Origin: http://target.example
```

The server should reject untrusted origins before accepting the upgrade. If the
upgrade succeeds, attempt reads and writes that depend on the victim's session.

### Message Injection

After a connection is established, perform message injection against every
client-observed command shape:
```json
{"type":"subscribe","channel":"admin"}
{"type":"update","userId":"FOREIGN_USER_ID","role":"admin"}
{"action":"delete","resourceId":"FOREIGN_RESOURCE_ID"}
```

Probe for mass assignment, command confusion, unexpected event types, duplicate
JSON keys, nested object overrides, and parser differences between client-side
validation and server-side dispatch.

### Channel Authorization

Authorization must be checked at subscription time and at message handling time,
not only during the handshake.
- Subscribe to another user's room, organization, tenant, or document
- Reuse channel names from browser logs with a lower-privilege account
- Replay a valid subscribe message after changing the session or token
- Send writes to a channel after losing access in another browser session

Look for cross-tenant data leakage, stale membership checks, and server-side
broadcasts that trust client-supplied channel identifiers.

### Replay And Session Fixation

Capture messages from a valid client and replay them:
- On a fresh connection for the same user
- From a different user with the same tenant role
- From a different tenant
- After logout, password change, or token revocation

Resume tokens, connection IDs, and last-event IDs should be scoped to the
current principal and expire when the session does.

### Protocol Confusion

Validate `Sec-WebSocket-Protocol` handling:
- Unsupported subprotocols are rejected
- Downgrade to a less protected subprotocol is impossible
- Authentication embedded in subprotocol values is parsed strictly
- GraphQL subscription protocols still enforce per-operation authorization

For Socket.IO or SockJS, test both polling and WebSocket transports. A secure
WebSocket path can still be bypassed through a fallback transport.

### Rate Limits And Resource Exhaustion

Exercise per-connection and per-principal limits:
- Rapid connect/disconnect loops
- Many subscriptions on one socket
- Oversized text and binary frames
- High-frequency heartbeat or publish messages
- Compression bombs when per-message deflate is enabled

Confirm the server closes abusive connections and keeps limits consistent across
reconnects and transport fallbacks.

## Validation Checklist

- Unauthenticated upgrades are rejected before the socket is established
- Cookie-authenticated sockets validate `Origin` to prevent CSWSH
- `Upgrade: websocket` and `Sec-WebSocket-*` headers cannot bypass routing auth
- Every subscribe, publish, and RPC message rechecks principal authorization
- Message injection attempts fail with explicit authorization or validation errors
- Cross-user and cross-tenant channel names cannot be guessed or replayed
- Revoked sessions lose access on new messages or reconnect
- Logs capture rejected handshakes and denied message actions without secrets

## Reporting Guidance

Report the exact upgrade URL, handshake headers, authenticated principal, frame
payload, expected authorization boundary, observed server response, and impact.
For CSWSH, include the hostile `Origin` and whether browser cookies were sent.
For message injection, include the minimal frame that crosses the authorization
boundary and the server event or data it produced.
