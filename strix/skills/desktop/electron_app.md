---
name: electron_app
description: Electron desktop app testing — unpack ASAR, assess nodeIntegration/contextIsolation, IPC, preload bridges, and custom protocol handlers.
---

# Electron Desktop App

An Electron app ships a full Chromium renderer plus a Node.js main process bundled with the application's JavaScript, usually packed into an `app.asar` archive inside the installer. The attacker's objective is to turn renderer-controlled input (untrusted web content, deep links, loaded files, IPC messages) into Node.js execution in the main or a privileged renderer process, then into local command execution, file read/write, secret theft, or persistence. The whole client is shippable to disk, so source, config, and embedded secrets are recoverable — treat the binary as readable source.

## Attack Surface

**Bundled code & config**
- `app.asar` (and `app.asar.unpacked/`) — full application JS, HTML, templates
- `package.json` main entry, `electronVersion`, fuses, build config (electron-builder/forge)
- Embedded API keys, signing tokens, update URLs, hardcoded creds

**Renderer trust boundary**
- `BrowserWindow` `webPreferences`: `nodeIntegration`, `contextIsolation`, `sandbox`, `webSecurity`, `allowRunningInsecureContent`, `enableRemoteModule`
- Preload scripts and the `contextBridge` API exposed to web content
- `<webview>`/`<iframe>` tags loading remote or attacker-influenced origins
- `window.open`, `webContents.setWindowOpenHandler`, `will-navigate` handling

**IPC**
- `ipcMain.handle`/`ipcMain.on` channels and what arguments they trust
- `ipcRenderer.invoke`/`send` wrappers leaked through the bridge
- Sender validation (does the handler check `event.senderFrame`/origin?)

**External input vectors**
- Custom protocol handlers (`app.setAsDefaultProtocolClient`, `protocol.registerFileProtocol`) and `deeplink://` / `myapp://` URIs
- Files opened by the app (project files, config import, drag-and-drop)
- Auto-update channel (electron-updater feed URL, signature checks)
- Remote content loaded into windows/webviews

## Recon & Enumeration

Locate and unpack the archive. `asar` runs via `npx` (Node is in the sandbox):
```bash
# find the packaged archive in an installed app / extracted installer
find / -name "app.asar" 2>/dev/null
# unpack
npx -y @electron/asar extract app.asar app_src
npx -y @electron/asar list app.asar | head
# unpacked native modules sit alongside
ls -R app.asar.unpacked 2>/dev/null
```
Determine Electron version and fuse config (drives which CVEs and hardening apply):
```bash
grep -aoiE 'electron[/ ]?v?[0-9]+\.[0-9]+\.[0-9]+' app_src/package.json
# inspect fuses (RunAsNode, EnableNodeCliInspect, EnableNodeOptions, OnlyLoadAppFromAsar, ...)
npx -y @electron/fuses read --app /path/to/App.app   # or the unpacked binary
```
Map the dangerous config and sinks with grep / Semgrep:
```bash
cd app_src
grep -rniE 'nodeIntegration|contextIsolation|sandbox|webSecurity|allowRunningInsecureContent|enableRemoteModule' .
grep -rniE 'ipcMain\.(handle|on)|ipcRenderer\.(invoke|send)|contextBridge\.exposeInMainWorld' .
grep -rniE 'setAsDefaultProtocolClient|registerFileProtocol|registerStringProtocol|setWindowOpenHandler|will-navigate|new-window' .
grep -rniE 'child_process|exec\(|execSync|spawn|eval\(|new Function|loadURL|loadFile|shell\.openExternal|shell\.openPath' .
semgrep --config p/electronjs --config p/javascript . 2>/dev/null
```
Recover secrets and dependency CVEs:
```bash
trufflehog filesystem app_src --only-verified
gitleaks detect --source app_src --no-git -v
# bundled node_modules vulns
trivy fs --scanners vuln app_src 2>/dev/null
# or, if a lockfile survives
( cd app_src && npm audit --omit=dev ) 2>/dev/null
```
If the app exposes a local HTTP/WebSocket service or an update feed, enumerate it:
```bash
ss -ltnp        # local listeners the app opened (devtools 9222, IPC ws, license server)
nmap -sT -p 9222,17000-17100 127.0.0.1
httpx -u http://127.0.0.1:<port> -title -tech-detect
nuclei -u http://127.0.0.1:<port> -tags electron,exposure,debug -s critical,high -silent
```
For binary-only or obfuscated bundles, fall back to `strings app.asar | grep -iE 'http|api|secret|token'` and `binwalk` on the installer (`apt-get install -y binwalk`).

## Methodology

1. **Acquire and unpack.** Extract `app.asar` + `app.asar.unpacked`, read `package.json` to find the main entry point and Electron version.
2. **Read the fuses.** RunAsNode/EnableNodeOptions/EnableNodeCliInspect left on means `ELECTRON_RUN_AS_NODE` or `--inspect` turns the signed binary into an arbitrary Node interpreter — note for chaining.
3. **Inventory windows.** For every `new BrowserWindow(...)` / `<webview>`, record `webPreferences` and what URL/file it loads. Flag any window with `nodeIntegration:true` or `contextIsolation:false` that ever loads remote or attacker-influenced content.
4. **Map the bridge.** Read all `contextBridge.exposeInMainWorld` calls; treat every exposed function as renderer-reachable. Trace each to its `ipcRenderer.invoke`/`send` and the matching `ipcMain` handler.
5. **Audit IPC handlers.** For each handler, check argument validation and sender checks. Look for handlers that pass args to `child_process`, `fs`, `shell.*`, `eval`, dynamic `require`, or SQL.
6. **Trace external input.** Follow protocol-handler args, opened-file contents, and deep-link parameters into the renderer/main; check for DOM XSS sinks and command/path construction.
7. **Reach a Node primitive.** Establish whether renderer-side script (XSS or loaded remote content) can reach Node — directly (nodeIntegration) or indirectly (an over-broad bridge/IPC method).
8. **Build a PoC and assess impact.** Demonstrate a benign command run, a file read outside the app dir, or secret retrieval, then document the full chain.

## Key Weaknesses / Techniques

**nodeIntegration on untrusted content** — if a window has `nodeIntegration:true` (and old default `contextIsolation:false`) and renders content you can influence (remote page, markdown preview, injected DOM), `require` is reachable. Validate with a contained payload in an injectable field/page:
```html
<img src=x onerror="window.top.require('child_process').execSync('id > /tmp/poc_e.txt')">
```

**contextIsolation disabled** — even without `nodeIntegration`, a disabled `contextIsolation` lets renderer script reach preload internals and prototype-pollute the bridge. Assess by checking whether `require`/`process`/`global` are reachable from `window`.

**Over-permissive contextBridge / IPC** — the safe config is `nodeIntegration:false`, `contextIsolation:true`, `sandbox:true`, but a bridge that exposes a generic primitive defeats it. Hunt for exposed `invoke('exec', cmd)`, `readFile(path)`, `openExternal(url)`, or `ipcRenderer` passed through verbatim. From a renderer console / injected script:
```js
// enumerate what the bridge leaks
Object.keys(window).filter(k => typeof window[k] === 'object')
window.electronAPI && Object.keys(window.electronAPI)
// abuse an over-broad file/exec method
await window.electronAPI.runCommand('id')           // command sink
await window.electronAPI.readFile('/etc/passwd')    // arbitrary read sink
```

**Missing IPC sender validation** — `ipcMain.handle('run', (e,c)=>exec(c))` with no `event.senderFrame` origin check is callable by any frame, including a hostile iframe/webview. Confirm the handler does not verify the sender's URL/frame.

**Command/path injection in handlers** — args concatenated into `exec`/`spawn` or `path.join` without sanitization. Test with `;id`, `$(id)`, `` `id` ``, and `../../../../etc/passwd` style traversal through the IPC method.

**shell.openExternal / openPath with attacker URLs** — `openExternal` on an unvalidated string allows `file:`, `smb:`, or app-specific schemes that launch local programs; on Windows historically reaches arbitrary executables. Verify the app validates the scheme against an allowlist.

**Custom protocol handler abuse** — `myapp://` deep links are parsed and routed; if a parameter feeds navigation, IPC, or a command, a malicious link delivered via browser/email is remote-triggerable. Map the handler then craft a link, e.g. `myapp://open?file=../../sensitive` or one that drives a privileged IPC call.

**Insecure window/navigation handling** — no `setWindowOpenHandler` deny and no `will-navigate` guard lets loaded content navigate the main window to attacker origins, re-acquiring any leftover Node privileges. `webSecurity:false` or `allowRunningInsecureContent:true` compounds this.

**Insecure auto-update** — an `electron-updater` feed over HTTP, or one without signature verification, allows update-channel takeover and code execution. Check the feed URL scheme and whether `verifySignature`/code-signing is enforced.

**Exposed remote debugging** — a window or build started with `--remote-debugging-port` (or `--inspect`) exposes a DevTools/CDP endpoint on `127.0.0.1:9222` allowing `Runtime.evaluate` in the privileged context.

**Known CVEs** — old Electron carries renderer-to-main escapes (e.g. `nodeIntegrationInSubFrames`, ASAR integrity bypasses, `shell.openExternal` argument-injection CVEs). Cross-reference the detected version.

## Validation

- Reproduce the chain end to end: untrusted input source → reachable Node primitive → observable effect. A real finding has a concrete entry point, not just a risky config line.
- Use a benign, contained PoC: write a marker file (`id > /tmp/poc_e.txt`) or read a known non-secret file, and capture the output. Prefer effects you can clean up.
- For IPC/bridge issues, drive the call from a renderer context that an attacker actually controls (injected DOM, loaded remote page, hostile iframe) — not from your own injected `<script>` in a trusted local page that wouldn't exist in the real flow.
- For protocol handlers, trigger via the OS URL dispatcher (`xdg-open 'myapp://...'`) to prove the link is remotely deliverable, not just internally callable.
- Confirm `webPreferences` at runtime, not only in source — build flags or runtime overrides can differ.

## False Positives

- `nodeIntegration:true` on a window that only ever loads trusted, bundled local HTML with no injection sink and no remote/loaded content — no untrusted input reaches it.
- A `contextBridge` that exposes only narrow, validated functions (fixed channel names, type-checked args, no arbitrary path/command) — exposure alone is not a vuln.
- Secrets that are public client config (analytics keys, OAuth public client IDs) rather than server-side credentials.
- `child_process`/`exec` used only with hardcoded, non-attacker-influenced arguments.
- `npm audit`/`trivy` CVEs in transitive dev or unused modules not present at runtime — confirm the vulnerable path is actually reachable.
- DevTools open in a dev build; verify against the shipped production build.

## Chaining & Impact

- Renderer XSS (or loaded remote content) + `nodeIntegration`/leaky bridge → `child_process` → local code execution as the user.
- Over-broad IPC file read → exfiltrate `~/.ssh`, browser cookies, tokens stored in app data → account/host compromise.
- Deep-link/protocol handler → privileged IPC call → command execution, all triggerable from a web page or email (drive-by on a desktop target).
- Left-on `RunAsNode`/`EnableNodeOptions` fuse → use the signed, trusted binary as a Node interpreter (`ELECTRON_RUN_AS_NODE=1 ./App -e '...'`) for execution and AV/allowlist evasion / persistence.
- Insecure auto-update feed → push a malicious update → persistent RCE across the install base.
- Exposed CDP/`--inspect` port → `Runtime.evaluate` in main process → full Node capabilities without any in-app bug.

## Pro Tips

- Always read the fuses, not just `webPreferences`. A perfectly hardened renderer is moot if `RunAsNode`/`EnableNodeCliInspect` is enabled.
- `contextIsolation:true` is only effective with a correctly written preload; a preload that stuffs raw `ipcRenderer` or Node objects onto `window` silently reintroduces the bridge — read the preload, don't trust the flag.
- Distinguish "can be called" from "attacker can reach it": a dangerous IPC handler matters only if some untrusted frame/content can invoke it. Map the actual reachability path.
- Deminify with a beautifier (`npx prettier`/`js-beautify`) before auditing bundled `main.js`; webpack output hides handler logic.
- Check `app.asar.unpacked` and any native `.node` addons — sensitive logic is often pushed out of the archive and is easier to inspect.
- `event.senderFrame.url` checks are the modern fix for IPC; their absence in a handler that hits a dangerous sink is a strong lead.
- Test deep links by actually registering/triggering them through the OS so you prove remote deliverability, the difference between a theoretical and a reportable finding.
- The shipped binary is the source of truth — config in source can be overridden at build time, so verify the live process where possible.
