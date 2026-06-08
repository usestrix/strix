---
name: ios-ipa
description: iOS IPA security testing - binary decryption and analysis, Info.plist/ATS review, insecure storage, Keychain misuse, hardcoded secrets, URL scheme abuse, WKWebView issues, and jailbreak/cert-pinning bypass
---

# iOS IPA Security Testing

An iOS IPA is a ZIP archive whose `Payload/<App>.app` bundle contains a Mach-O executable, the `Info.plist`, bundled frameworks, and resources. App Store binaries ship encrypted under FairPlay (the `LC_ENCRYPTION_INFO` load command), so static analysis of real-world apps starts by dumping the decrypted Mach-O from a jailbroken device. The recurring weaknesses are client-side trust decisions (App Transport Security exceptions, custom cert validation, pinning), secrets stored in NSUserDefaults/plists/Keychain with the wrong protection class, secrets compiled into the binary, and IPC surface exposed through custom URL schemes and universal links. Static review (class-dump, otool, nm, a disassembler) maps the binary; dynamic instrumentation (Frida, objection) hooks the running process to defeat pinning and jailbreak detection. Binary decryption, Keychain dumping, runtime hooking, and on-device storage inspection require a jailbroken physical device (the iOS Simulator runs unencrypted x86_64/arm64 binaries and lacks the real Keychain and Data Protection semantics, so it is not a substitute for these steps).

## Attack Surface

**Scope**
- `Payload/<App>.app/<App>` Mach-O executable (encrypted on App Store builds, decrypted on disk at runtime)
- `Info.plist` - URL schemes, `NSAppTransportSecurity`, associated-domains entitlement, declared capabilities
- Embedded frameworks (`Frameworks/*.framework`), `*.dylib`, and bundled resources/assets
- On-device storage: app sandbox `Library/Preferences/*.plist` (NSUserDefaults), `Documents`, `Library/Application Support`, Core Data stores, the shared Keychain
- Compiled strings, certificates, and pinned public keys in the Mach-O `__cstring`/`__const` sections
- IPC: custom URL schemes (`scheme://`), universal links (`applinks:`), document/share extensions, pasteboard

**Entry Points**
- Custom URL schemes and universal links reachable from Safari, another app, or a QR code
- App extensions (share, action, today) receiving attacker-influenced items
- WKWebView content loading attacker-controlled or cleartext URLs
- Files synced to iCloud/iTunes backup (items without `NSFileProtection`/`ThisDeviceOnly` Keychain attributes leave the device)
- Pasteboard and inter-app data passed via `openURL`

**Entitlements and identity**
- `Info.plist` `CFBundleURLTypes` (claimed schemes - any app can also claim a scheme, so callers are untrusted)
- `com.apple.developer.associated-domains` for universal links; absence or a bad `apple-app-site-association` lets the scheme be hijacked
- Code signing / provisioning profile (`embedded.mobileprovision`), entitlements (`codesign -d --entitlements`)
- Keychain access groups and `kSecAttrAccessible` protection class chosen per item

## Key Vulnerabilities

### Binary Encryption and Decryption

- App Store binaries carry `LC_ENCRYPTION_INFO`/`LC_ENCRYPTION_INFO_64` with `cryptid 1`; static tools see only ciphertext until dumped
- A decrypted dump exposes Objective-C class/method metadata, Swift symbols, and embedded strings/secrets

**Test:**
```
unzip -o target.ipa -d target_extract
otool -l "target_extract/Payload/Target.app/Target" | grep -A4 LC_ENCRYPTION_INFO
# cryptid 1 => encrypted; dump the decrypted Mach-O from a jailbroken device
frida-ios-dump -H <device-ip> -u mobile -P alpine com.target.app
# or, on-device, use the dumpdecrypted dylib / objection memory dump
objection -g com.target.app explore -s "ios bundles list_bundles"
```

### Binary Analysis and Symbol Recovery

- Objective-C selectors and class layout recoverable with `class-dump`; reveals private APIs, debug methods, and logic
- `nm`/`otool`/`strings` expose imported symbols, linked frameworks, and embedded constants; Hopper/Ghidra for control flow

**Test:**
```
class-dump -H "target_extract/Payload/Target.app/Target" -o headers/
otool -ov "target_extract/Payload/Target.app/Target" | grep -iE 'pin|trust|jailbreak|debug|secret'
nm -u "target_extract/Payload/Target.app/Target"            # undefined (imported) symbols
otool -L "target_extract/Payload/Target.app/Target"          # linked frameworks/dylibs
strings -a "target_extract/Payload/Target.app/Target" | grep -iE 'https?://|api[_-]?key|password|token'
```

### Info.plist and App Transport Security

- `NSAllowsArbitraryLoads = true` globally disables ATS; per-domain `NSExceptionAllowsInsecureHTTPLoads`/`NSExceptionMinimumTLSVersion` weaken specific hosts
- Cleartext HTTP to backend domains; downgraded TLS versions; forward-secrecy exceptions

**Test:**
```
plutil -p "target_extract/Payload/Target.app/Info.plist" | grep -A15 NSAppTransportSecurity
plutil -convert xml1 -o - "target_extract/Payload/Target.app/Info.plist" | grep -iE 'ArbitraryLoads|InsecureHTTPLoads|MinimumTLSVersion'
codesign -d --entitlements :- "target_extract/Payload/Target.app/Target"
```

### Insecure Local Storage

- Secrets/tokens/PII in NSUserDefaults (`Library/Preferences/<bundleid>.plist`) in cleartext
- Sensitive data in unencrypted Core Data / SQLite stores or plists under `Documents`/`Library`
- Files written without `NSFileProtectionComplete`, readable from a backup or with the device unlocked-once

**Test:**
```
# on a jailbroken device (sandbox path resolved via objection/frida)
objection -g com.target.app explore -s "env"   # prints the app's Documents/Library paths
objection -g com.target.app explore -s "ios nsuserdefaults get"
objection -g com.target.app explore -s "ios plist cat /var/mobile/Containers/Data/Application/<UUID>/Library/Preferences/com.target.app.plist"
# pull and inspect a Core Data / SQLite store
sqlite3 store.sqlite .tables
```

### Keychain Misuse

- Items stored with `kSecAttrAccessibleAlways`/`AfterFirstUnlock` instead of `WhenUnlockedThisDeviceOnly` - included in backups and/or readable while locked
- Missing `ThisDeviceOnly` lets credentials migrate to a restored/cloned device; access groups shared too broadly across apps

**Test:**
```
objection -g com.target.app explore -s "ios keychain dump"
# inspect the protection class chosen per item
frida -U -f com.target.app -l ios-keychain-dump.js
# look for the requested accessibility constant in the binary
strings -a "target_extract/Payload/Target.app/Target" | grep -iE 'kSecAttrAccessible'
```

### Hardcoded Secrets and API Keys

- API keys, cloud credentials, encryption keys, and private endpoints compiled into `__cstring`/`__const` or bundled config plists
- Pinned public keys and backend secrets reused server-side

**Test:**
```
strings -a "target_extract/Payload/Target.app/Target" | grep -inE '(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|sk_live_[0-9A-Za-z]+|-----BEGIN)'
grep -rinE 'api[_-]?key|secret|password|token' "target_extract/Payload/Target.app/" --include='*.plist'
# full static + secret scan
curl -s -F 'file=@target.ipa' -H "Authorization: $MOBSF_KEY" http://127.0.0.1:8000/api/v1/upload
```

### URL Scheme and Universal Link Abuse

- Handlers in `application(_:open:options:)` / `scene(_:openURLContexts:)` trusting URL parameters for auth, redirects, or object ids (see idor, ssrf, mass_assignment)
- Custom schemes are first-come, claimable by any app - never treat the caller as trusted
- Universal links without a valid `apple-app-site-association` (or missing associated-domains entitlement) fall back to a hijackable scheme

**Test:**
```
plutil -p "target_extract/Payload/Target.app/Info.plist" | grep -A6 CFBundleURLTypes
# trigger a scheme handler (Simulator or device)
xcrun simctl openurl booted 'targetapp://reset?token=attacker&next=https://evil'
frida-trace -U -f com.target.app -m '-[* application:openURL:options:]' -m '-[* *:openURLContexts:]'
curl -s https://target.com/.well-known/apple-app-site-association
```

### WKWebView Vulnerabilities

- `WKWebView` loading attacker-influenced or cleartext URLs; deprecated `UIWebView` (no process isolation) still present
- `WKScriptMessageHandler` bridges (`window.webkit.messageHandlers.<name>.postMessage`) trusting JS-supplied data into native actions
- `allowFileAccessFromFileURLs`/`allowUniversalAccessFromFileURLs` (via `setValue:forKey:` on the config) enabling `file://` sandbox reads from loaded content (see xss for the in-WebView payload)

**Test:**
```
class-dump -H "target_extract/Payload/Target.app/Target" -o headers/ && grep -rnE 'WKWebView|UIWebView|messageHandlers|allowFileAccess|loadRequest|loadHTMLString' headers/
otool -ov "target_extract/Payload/Target.app/Target" | grep -iE 'addScriptMessageHandler|allowUniversalAccessFromFileURLs'
frida-trace -U -f com.target.app -m '-[WKWebView loadRequest:]' -m '-[* userContentController:didReceiveScriptMessage:]'
```

### Jailbreak Detection and Cert-Pinning Bypass

- Jailbreak checks (file existence of `/Applications/Cydia.app`, `/bin/bash`, `fork()` success, scheme `cydia://`) are client-side and hookable
- Pinning via `NSURLSession` `didReceiveChallenge`, TrustKit, AFNetworking `AFSecurityPolicy`, or Alamofire `ServerTrustManager` - all bypassable on a jailbroken device
- These are device-trust controls: they stop network attackers, not an attacker who controls the jailbroken device

**Test:**
```
# bypass jailbreak detection + pinning at runtime (jailbroken device)
objection -g com.target.app explore -s "ios jailbreak disable"
objection -g com.target.app explore -s "ios sslpinning disable"
frida -U -f com.target.app -l frida-ios-pinning-bypass.js
# system-wide TLS interception alternative
# install SSL Kill Switch 2 (.deb via Cydia/Sileo) then route traffic through a proxy
otool -ov "target_extract/Payload/Target.app/Target" | grep -iE 'evaluateServerTrust|SecTrustEvaluate|AFSecurityPolicy|TrustKit'
```

### Insufficient Binary Protections

- No PIE (`MH_PIE` flag absent) defeats ASLR; missing stack canaries (`__stack_chk_guard`/`___stack_chk_fail` not linked); ARC disabled (manual retain/release, use-after-free risk)
- Absence of these does not by itself grant access but lowers the bar for memory-corruption exploitation

**Test:**
```
otool -hv "target_extract/Payload/Target.app/Target" | grep -i PIE          # expect PIE flag
otool -Iv "target_extract/Payload/Target.app/Target" | grep -E 'stack_chk_guard|stack_chk_fail'   # stack canaries
otool -Iv "target_extract/Payload/Target.app/Target" | grep -E 'objc_release|objc_retainAutorelease'  # ARC indicators
nm "target_extract/Payload/Target.app/Target" | grep -E '___stack_chk_fail|_objc_autoreleasePoolPush'
```

## Bypass Techniques

**Jailbreak-detection bypass**
- objection `ios jailbreak disable` or a Frida hook on the detection method; for stubborn checks, hook `fileExistsAtPath:`, `canOpenURL:`, and `fork`/`stat` to lie about the environment

**Pinning bypass**
- objection/Frida hook of the trust-evaluation callback, or SSL Kill Switch 2 to disable system-wide trust evaluation, then proxy the traffic

**Repackaging on jailbroken devices**
- Patch and resign with a developer cert + `ldid`/`codesign`, or inject a Frida gadget dylib (`optool`/`insert_dylib`) into the Mach-O to instrument without a jailbreak (requires resigning under your own provisioning profile)

**Scheme/link hijack**
- Register a competing app declaring the victim's custom URL scheme; iOS resolution between apps claiming the same scheme is undefined, enabling interception of scheme-borne data

## Testing Methodology

1. **Extract** - `unzip` the IPA, locate `Payload/<App>.app`, read `Info.plist` and entitlements (`codesign -d --entitlements`)
2. **Check encryption** - `otool -l ... | grep LC_ENCRYPTION_INFO`; if `cryptid 1`, dump the decrypted Mach-O from a jailbroken device with frida-ios-dump
3. **Baseline scan** - run the IPA through MobSF for ATS, plist, binary-protection, and secret findings in one pass
4. **Static binary analysis** - `class-dump` for the class/method map, `otool -ov`/`nm`/`strings` for symbols and constants, Hopper/Ghidra for logic; hunt pinning, jailbreak, and secret code paths
5. **Config review** - parse `Info.plist` for URL schemes, ATS exceptions, and associated domains; validate the `apple-app-site-association`
6. **Storage review** - on a jailbroken device, dump NSUserDefaults, plists, Core Data/SQLite, and the Keychain; check protection classes and backup inclusion
7. **IPC abuse** - enumerate and trigger custom schemes/universal links; trace `openURL`/`scene` handlers; exercise WKWebView message handlers
8. **Runtime instrumentation** - attach Frida/objection (jailbroken device) to bypass jailbreak detection and pinning, then proxy decrypted traffic
9. **Binary hardening** - confirm PIE, stack canaries, and ARC; note gaps as exploitation-enablers, not standalone findings

## Validation

1. For binary findings, work from a confirmed decrypted dump (`cryptid 0` after dumping) - static results on an encrypted binary are meaningless
2. For insecure storage/Keychain, extract the concrete secret and show its protection class is weaker than required (e.g. present in an unencrypted backup or readable while locked)
3. For hardcoded secrets, demonstrate the key authenticating to its service; exclude public identifiers and restricted client keys
4. For pinning/jailbreak bypass, capture a decrypted request/response through the proxy after the bypass - the plaintext traffic is the proof
5. For URL schemes/universal links, demonstrate the downstream effect (idor read, ssrf, session manipulation) reached via the link, not merely that the app opens
6. For binary protections, report missing PIE/canary/ARC only as a hardening gap with the exploitation context, never as an exploited vulnerability on its own

## False Positives

- Static analysis of an encrypted App Store binary (`cryptid 1`) - `class-dump`/`strings` yield garbage; results are invalid until decrypted
- Pinning/jailbreak "bypass" that only works on a jailbroken device - that is the expected device-trust model, not a server-side flaw
- Hardcoded "secrets" that are public identifiers (third-party SDK app ids, restricted client keys, OAuth client ids)
- ATS exceptions scoped to `localhost` or a vendor's documented media domain that genuinely cannot serve TLS
- Keychain items intentionally `AfterFirstUnlock` for legitimate background access (e.g. push-token refresh) where no secret is exposed
- Missing PIE/canaries on a binary with no reachable memory-corruption sink - a hardening note, not a vulnerability

## Impact

- Account takeover and privilege escalation via URL-scheme/universal-link injection into auth flows
- Theft of credentials, tokens, and PII from NSUserDefaults, plists, Core Data, or weakly protected Keychain items (including via backups)
- Backend compromise from hardcoded API keys, cloud credentials, or encryption keys recovered from the binary
- Code execution / native-action abuse through a WKWebView script-message bridge
- Network MITM and traffic decryption where ATS is disabled or pinning is the only protection
- Exposure of private APIs, business logic, and debug functionality from a decrypted binary's recovered symbols
- Easier memory-corruption exploitation where PIE, canaries, or ARC are absent

## Pro Tips

1. Always check `LC_ENCRYPTION_INFO` first - analyzing an encrypted App Store binary wastes time; dump it decrypted before class-dump/strings
2. The iOS Simulator runs unencrypted binaries but has no real Keychain, Data Protection, or jailbreak semantics - use a jailbroken device for storage, Keychain, pinning, and detection work
3. `class-dump` plus `frida-trace -m '-[Class method:]'` is the fastest loop: map methods statically, then watch the interesting ones live
4. URL schemes are claimable by any app - the calling app is never trustworthy; treat every scheme parameter as attacker-controlled input
5. Universal links need both the associated-domains entitlement and a reachable `apple-app-site-association`; a missing/invalid AASA silently degrades to the hijackable custom scheme
6. Run objection's `ios sslpinning disable` and `ios jailbreak disable` before launching the target flow, not after - both checks fire early in startup
7. Keychain `kSecAttrAccessible*` without `ThisDeviceOnly` means the secret leaves the device in a backup - grep the binary for the constant and confirm at runtime
8. SSL Kill Switch 2 disables trust evaluation system-wide when per-app Frida hooks are flaky against custom pinning stacks
9. For non-jailbroken instrumentation, inject a Frida gadget dylib with `optool`/`insert_dylib` and resign under your own provisioning profile

## Summary

iOS findings chain from the binary and config outward: a decrypted Mach-O reveals logic, pinning/jailbreak code, and compiled secrets; the `Info.plist` exposes URL schemes and ATS gaps; insecure storage and weak Keychain protection classes supply credentials; and a trusting scheme handler or WKWebView bridge turns external input into account takeover or native-action abuse. Static tools (class-dump, otool, nm, MobSF) map the surface, but the real-world workflow begins with decrypting the binary on a jailbroken device and ends with Frida/objection defeating the client-side controls - pinning and jailbreak detection - that were the app's only protection. Validate every finding with the concrete effect: extracted secret, decrypted request, or privileged action reached through the IPC surface.
