---
name: websocket
description: WebSocket security testing covering cross-site hijacking, per-frame authorization, and subprotocol/handshake abuse
---

# WebSocket

WebSocket has no same-origin policy equivalent, no CSRF token convention, and no per-message authorization model to inherit from REST — every gap that HTTP's ecosystem quietly closed has to be re-verified by hand. Treat the handshake as one auth check and every subsequent frame as a separate, unauthenticated-until-proven-otherwise request.

## Attack Surface

**Handshake**
- `GET` with `Upgrade: websocket`, `Sec-WebSocket-Key`, `Origin` header (browser-set, not attacker-controllable, but server validation of it is optional and frequently skipped)
- Auth carried in: cookies (ambient, sent automatically by the browser — the CSWSH risk), query-string tokens, or a first-message auth frame post-connect
- Subprotocol negotiation (`Sec-WebSocket-Protocol`) — server may trust a client-declared subprotocol to select a parsing/auth mode

**Message Layer**
- Text or binary frames, no built-in structure — application defines its own message schema (often JSON with an `action`/`type` field acting as a mini-RPC router)
- No per-message CSRF-equivalent protection by default; whatever auth exists is whatever the app explicitly re-checks per message

## Reconnaissance

**Discovery**
- Look for `wss://`/`ws://` URLs in JS bundles, `new WebSocket(...)` calls, or `Upgrade: websocket` responses when replaying discovered endpoints with the upgrade headers added
- Identify the message protocol by capturing a live session: note the `action`/`type`/`event` field convention and required fields per action

**Baseline Capture**
```bash
# on-demand install if not present
pip install --user websocat 2>/dev/null || (curl -L https://github.com/vi/websocat/releases/latest/download/websocat.x86_64-unknown-linux-musl -o /usr/local/bin/websocat && chmod +x /usr/local/bin/websocat)
websocat wss://target/ws -H "Cookie: session=..." -H "Origin: https://target"
```
Capture the full handshake response headers and the first few application-level messages (many apps send an auth-ack or initial state dump on connect — useful for confirming session binding).

## Key Vulnerabilities

### Cross-Site WebSocket Hijacking (CSWSH)

WebSocket connections are exempt from same-origin policy and CORS preflight — a page on `evil.com` can open `new WebSocket('wss://victim.com/ws')` and the browser will send the victim's cookies automatically, exactly like a classic CSRF but for a persistent bidirectional channel.

**Test**
1. Connect to the target WS endpoint from a page/script under a different `Origin`, with only the victim's session cookie attached (no other auth material)
2. If the handshake succeeds and the server streams authenticated data or accepts authenticated actions, `Origin` validation is missing or trusts too broad a pattern
```bash
websocat wss://target/ws -H "Origin: https://evil.com" -H "Cookie: session=<victim_session>"
```
- Check for permissive `Origin` matching: substring match (`*.target.com` matching `target.com.evil.com`), regex anchoring bugs, or `null` origin acceptance (sandboxed iframes, some browser edge cases)
- If cookie-based and `SameSite=Lax/Strict` is set correctly, CSWSH may already be mitigated at the browser level for cross-site framing — verify the actual cookie attributes rather than assuming

### Missing Re-Authentication Per Message

Handshake-only auth means the connection, once established, is treated as permanently authenticated for its lifetime — test whether:
- A session/token revoked mid-connection still allows the open socket to keep issuing privileged actions
- Privilege changes (role downgrade, account suspension) mid-session are not reflected until reconnect
- The server never re-validates `action`-level authorization per message, relying entirely on "you got through the handshake"

### Message-Based IDOR / Injection

Every distinct `action`/`type` value is effectively its own endpoint — enumerate them from client JS and test each independently:
```json
{"action":"get_order","order_id":"OTHER_USERS_ID"}
{"action":"subscribe","channel":"user:OTHER_USER_ID:notifications"}
```
- Channel/room subscription without ownership validation — subscribing to another user's or tenant's event channel by guessing/incrementing an identifier
- Standard injection classes (SQLi, NoSQLi, command injection, SSTI) apply identically inside WS message payloads — they're just JSON/text bodies delivered over a different transport, and are less likely to have been tested since most scanners only speak HTTP request/response

### Subprotocol Negotiation Abuse

If the server selects parsing/auth behavior based on client-declared `Sec-WebSocket-Protocol`, test declaring an unexpected or legacy subprotocol value to see if it routes to a less-validated code path (common when a service evolved multiple protocol versions and kept old handlers reachable for backward compatibility).

### Denial of Service via Frame Flooding

Rapid frame sends or oversized frames can exhaust server-side per-connection buffers or CPU (especially with per-message compression enabled — `permessage-deflate` decompression bombs). **This is a throttle-by-default test per engagement DoS rules** — confirm the behavior exists with a small burst, note it, and do not scale up against production infrastructure without explicit program allowance.

## Testing Methodology

1. **Capture baseline** — full handshake and several authenticated message exchanges
2. **CSWSH** — reconnect with cross-origin `Origin` header, cookie-only auth, confirm whether the server streams data
3. **Enumerate actions** — pull every `action`/`type` value from client JS, test each with foreign-owned IDs
4. **Revocation check** — revoke the session/token server-side mid-connection, confirm whether the open socket still functions
5. **Subprotocol probe** — declare alternate subprotocol values, observe behavior differences
6. **Injection sweep** — apply standard injection payloads to each message field, same as REST/GraphQL testing

## Validation

- Successful cross-origin connection with victim cookies returning authenticated data or accepting authenticated actions (CSWSH)
- A message action returning or modifying another user's data (message-level IDOR)
- Continued privileged action success after the underlying session was revoked (stale-auth bypass)
- Full capture: handshake headers, exact message JSON sent, and response demonstrating the unauthorized outcome

## False Positives

- `Origin` strictly validated against an exact allowlist, `null` origin rejected
- Server re-validates auth/authorization on every message, not just at handshake
- Session revocation immediately terminates or degrades the open connection
- Standard injection payloads properly sanitized/parameterized in message handlers

## Tooling

```bash
# websocat — the primary manual WS client for raw frame control
curl -L https://github.com/vi/websocat/releases/latest/download/websocat.x86_64-unknown-linux-musl -o /usr/local/bin/websocat && chmod +x /usr/local/bin/websocat
websocat wss://target/ws -H "Origin: https://evil.com" -H "Cookie: session=..."
```
For proxying through an interception layer to fuzz messages interactively, `mitmproxy` (already reasonable to `pipx install mitmproxy` on demand) supports WebSocket interception and message editing in its default flow view.

## Summary

WebSocket's lack of a same-origin equivalent and its handshake-only auth model mean every connection needs an explicit `Origin` check and every message needs its own authorization check — assume neither exists until proven, and enumerate the message-level action surface exactly as you would REST endpoints or GraphQL fields.
