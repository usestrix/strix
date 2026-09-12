---
name: electron-desktop-apps
description: Test Electron desktop applications across renderer, preload, IPC, main-process, navigation, custom-protocol, storage, permission, and update trust boundaries; use for packaged Electron apps, ASAR review, web-to-native capability analysis, and Electron-specific exploit chains
---

# Electron Desktop Applications

Use this skill for Electron applications. Other webview desktop frameworks may share the high-level web-to-native trust question, but their bridge, sandbox, update, and process APIs differ; do not apply Electron-specific conclusions to NW.js, CEF, Tauri, or Wails without mapping that framework separately.

Pair this skill with `browser_security` for browser state and navigation, `xss` for renderer injection, `argument_injection` for native subprocess launches, and `insecure_deserialization` or `rce` for a main-process sink.

## Architecture and Authority Map

Inventory each security principal and the capabilities crossing between them:

```text
origin + document + frame
  -> renderer JavaScript
  -> preload isolated world
  -> contextBridge API
  -> IPC channel
  -> sender/argument/identity checks
  -> main process or utility process
  -> filesystem, process, credential, media, network, update, or OS action
```

Record:

- Electron, Chromium, Node, and application versions
- packaging form, `app.asar`, unpacked resources, entry point, and fuses
- every `BrowserWindow`, `WebContentsView`, `<webview>`, session/partition, and child window
- `webPreferences`: `preload`, `nodeIntegration`, `contextIsolation`, `sandbox`, `webSecurity`, `allowRunningInsecureContent`, experimental features, and subframe/worker integration
- every preload export and every `ipcMain.handle`/`ipcMain.on` consumer
- origins/documents/frames that can reach each exported API
- custom protocols, deep links, navigation helpers, permissions, downloads, storage, and update channels

Do not infer authority from a setting or channel name alone. Follow one request from renderer input to the main-process side effect and record each authorization decision.

## Package and Source Reconnaissance

Extract the application bundle with a reviewed, version-pinned ASAR implementation or inspect an already unpacked `resources/app` tree. Locate `package.json#main`, preload paths, build metadata, Electron version, native modules, and update configuration.

Search for:

```text
BrowserWindow  WebContentsView  webviewTag  webPreferences
preload  contextBridge.exposeInMainWorld  ipcRenderer
ipcMain.handle  ipcMain.on  webContents.ipc
will-navigate  will-frame-navigate  will-redirect
setWindowOpenHandler  loadURL  loadFile  openExternal
setPermissionRequestHandler  registerSchemesAsPrivileged
setAsDefaultProtocolClient  open-url  second-instance
autoUpdater  electron-updater
```

Treat decompiled or bundled JavaScript as a hypothesis when source maps, minification, generated IPC bindings, or runtime feature flags can change the installed behavior.

## Preload and Context-Bridge Analysis

A preload script has privileged Electron/Node access even when `nodeIntegration` is disabled. With context isolation, it can still expose selected functions and values into the page's main world.

Classify every export:

- narrow operation with fixed channel and validated arguments
- caller-selected channel or event name
- direct exposure of `ipcRenderer`, Node/Electron modules, filesystem/process objects, or mutable privileged objects
- callback/event registration that leaks the raw IPC event or privileged objects
- secret/session/storage access
- operation whose authorization exists only in renderer JavaScript

A generic `send(channel, ...)` or `invoke(channel, ...)` bridge expands the renderer's candidate capability set, but the registered handler list is not the ACL. For each handler, inspect:

- `event.senderFrame` URL/origin and frame identity validation
- expected `webContents`, window, session/partition, and application state
- user/tenant authorization and request provenance
- argument schema, paths, URLs, command options, and object deserialization
- result exposure and event subscriptions

An IPC handler's existence does not prove an untrusted frame can invoke it successfully.

## Navigation and Window Boundaries

Web preferences belong to a `webContents`; navigation does not automatically turn a privileged window into an ordinary browser tab. A configured preload can run for newly loaded documents and expose its bridge to content that was never intended to receive it.

Map all navigation causes:

- user- or page-initiated main-frame navigation (`will-navigate`)
- subframe navigation (`will-frame-navigate`)
- server redirects (`will-redirect`)
- new windows and popups (`setWindowOpenHandler`)
- application calls to `loadURL`, `loadFile`, history APIs, or routing helpers
- custom-protocol redirects and external-link handlers

`will-navigate` does not cover every programmatic navigation, so the event's presence is not complete enforcement.

Parse candidate URLs with `URL` and compare explicit protocol, origin/host, port, and path rules. Do not use string-prefix checks such as `startsWith("https://trusted.example")`. Apply the same canonical policy to initial loads, redirects, frames, popups, programmatic loads, and externally opened URLs.

Before calling `shell.openExternal`, validate the scheme and complete destination expected by the feature. Treat `file:`, custom schemes, handler-specific arguments, credentials in URLs, and ambiguous encodings as separate cases.

## Node, Isolation, and Sandbox Settings

- `nodeIntegration: true` in a renderer that can execute untrusted script directly exposes Node capability and commonly turns renderer injection into native code execution.
- `contextIsolation: false` weakens the boundary between page and preload worlds but is not, by itself, proof of native code execution.
- `sandbox: false` removes Chromium process isolation; determine which preload or renderer capabilities become reachable rather than reporting the flag alone.
- `webSecurity: false`, `allowRunningInsecureContent`, permissive experimental features, and unsafe `<webview>` preferences change separate browser boundaries and must be traced to an exploit path.
- `nodeIntegrationInSubFrames` and preload injection into frames require frame-by-frame sender and origin analysis.

Record Electron-version defaults. A missing explicit setting can mean different behavior on different major releases.

## Custom Protocols and Deep Links

Treat OS-delivered URLs and second-instance command lines as attacker-controlled inputs:

```text
OS handler / browser / document
  -> custom scheme or argv
  -> URL/argument parsing
  -> application router
  -> renderer navigation or native operation
```

Test authority and parser boundaries for host/path normalization, duplicate parameters, encoding depth, file paths, option injection, and cross-profile/account routing. Confirm which application instance and user session receives the event.

For custom application protocols, record whether the scheme is registered as secure, standard, CORS-enabled, stream-capable, or privileged, and how that affects origin and storage behavior.

## Permissions, Storage, and Secrets

Map session permission handlers for media, notifications, geolocation, clipboard, display capture, USB/HID/serial, filesystem access, and external protocols. Verify decisions use the requesting frame/origin and cannot be inherited from a more trusted window.

Inventory secrets and capability-bearing state reachable from renderer or preload code:

- tokens, cookies, session identifiers, recovery material, and encryption keys
- IndexedDB, local/session storage, cookies, cache, filesystem databases, and keychain wrappers
- local service ports, named pipes, Unix sockets, and authentication material

At-rest encryption does not protect data when the renderer can retrieve the key or ask a privileged bridge to decrypt it.

## Updates and Native Extensions

Trace the update pipeline as an executable supply chain:

- feed URL and channel selection
- TLS identity, redirects, proxy behavior, and metadata parsing
- artifact signature and publisher verification
- version/rollback policy and staged update state
- native modules, helper binaries, installers, and post-update hooks

An attacker-controlled feed is not automatically native code execution if independent artifact signatures are mandatory. Conversely, HTTPS does not compensate for missing artifact authenticity or unsafe rollback behavior.

## Validation

- Record the exact installed build, Electron version, preferences, preload, handler, and current document/frame origin.
- Demonstrate the complete path from attacker-controlled input or renderer state to the main-process operation.
- Capture sender-validation and argument-validation outcomes, not only successful IPC transport.
- Re-test after cross-origin navigation, redirect, frame creation, window creation, and session/profile changes.
- Separate renderer script execution, bridge access, accepted IPC, privileged data access, filesystem/process control, and native code execution.

## False Positives

- A preload or handler exists but the tested document/frame cannot reach it.
- A channel is registered but rejects the sender, identity, state, or arguments.
- `contextIsolation` or sandboxing is disabled without a reachable privileged API.
- Navigation is blocked on user links but still possible through application code, or vice versa.
- A remote page has no preload export, Node integration, IPC route, or privileged permission.
- An update feed is mutable but every artifact and version transition is independently authenticated.
- A secret-looking value is scoped to synthetic/test data or cannot authorize any downstream action.

## Remediation

- Load local application UI and isolate remote content in an unprivileged `WebContentsView` or external browser.
- Keep Node integration disabled, context isolation enabled, and renderer sandboxing enabled.
- Expose narrow preload APIs with fixed operations and strict schemas.
- Validate every IPC sender frame, application identity, authorization context, and argument in the main process.
- Parse and allowlist navigation destinations consistently across every navigation path.
- Restrict permissions per session and requesting origin.
- Keep credentials and encryption keys outside renderer reach.
- Authenticate update metadata and artifacts, enforce rollback policy, and pin publishers.

## Summary

Electron security depends on which document and frame can reach which native capability. Map navigation, preload exports, IPC sender checks, permissions, storage, protocols, and updates as one authority graph, then validate the entire path to the privileged operation.
