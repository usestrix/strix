---
name: mobile_apk_ipa_static
description: Static-only Android APK / iOS IPA analysis — decompilation, secret/manifest/export enumeration, and pinning detection for headless sandboxes with no device or emulator
---

# Mobile APK / IPA — Static Analysis Only

**Scope limit, stated up front:** the default Strix sandbox is a headless Kali container with no Android emulator, no iOS simulator, and no physical device — there is nowhere to run Frida, `adb`, or any dynamic instrumentation. This skill covers what a static decompile-and-grep pass can prove: hardcoded secrets, exported-component exposure, manifest/plist misconfiguration, and pinning presence. It cannot prove runtime behavior (auth bypass in a running app, actual network traffic, IPC exploitation in practice) — flag those as "requires dynamic testing on a device/emulator, out of scope for this sandbox" rather than guessing at runtime behavior from static code alone.

## Attack Surface

**Android (APK)**
- `AndroidManifest.xml` — exported components, permissions, deep links, backup/debug flags
- Decompiled Java/Kotlin (via jadx) and raw smali (via apktool) — hardcoded secrets, crypto misuse, WebView config
- `res/xml/network_security_config.xml` — cert pinning and cleartext-traffic policy
- `assets/`, `res/raw/` — bundled config files, keys, embedded certs

**iOS (IPA)**
- `Info.plist` — ATS (App Transport Security) exceptions, URL schemes, permission usage strings
- `Payload/<App>.app/` binary + `embedded.mobileprovision` — entitlements, provisioning
- Bundled `.plist`/`.json`/`.js` config files — API endpoints, keys

## Setup

```
# Android
sudo apt-get install -y apktool
curl -L -o jadx.zip https://github.com/skylot/jadx/releases/latest/download/jadx-<ver>.zip && unzip jadx.zip -d jadx
# or: pipx install droidasc   # if available — fast headless APK/DEX decompile + xref search, prefer for large APKs

# iOS — no special tool needed, IPA is a zip
mkdir ipa_extracted && unzip target.ipa -d ipa_extracted
```

```
jadx -d out_java <target>.apk           # full Java decompile
apktool d <target>.apk -o out_smali     # manifest + smali + resources
```

## Recon

**Manifest / plist extraction**
```
apktool d <target>.apk -o out && cat out/AndroidManifest.xml
# or without apktool: aapt dump badging <target>.apk / aapt dump xmltree <target>.apk AndroidManifest.xml
plutil -convert xml1 -o - ipa_extracted/Payload/*.app/Info.plist   # if plutil available; else python biplist/plistlib
python3 -c "import plistlib,sys; print(plistlib.load(open(sys.argv[1],'rb')))" ipa_extracted/Payload/*.app/Info.plist
```

**Package/app identity**
```
aapt dump badging <target>.apk | grep -E "package:|application-label|sdkVersion|targetSdkVersion"
```

## Key Vulnerabilities

### Hardcoded Secrets

Grep the decompiled tree broadly first, then narrow — false-positive rate is high, confirm each hit is a real credential and not a UI string or test fixture:

```
grep -rniE "api[_-]?key|secret|password|token|bearer|aws_access_key_id|AIza[0-9A-Za-z_-]{35}" out_java/ out_smali/ ipa_extracted/
grep -rn "eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*" out_java/           # JWTs
grep -rn "https\?://" out_java/ | grep -viE "schemas.android.com|w3.org|xmlpull" # embedded internal endpoints
find . -name "google-services.json" -o -name "GoogleService-Info.plist"         # Firebase config
```

Cross-reference any found API base URL against known internal/staging hostnames — an internal endpoint hardcoded in a shipped app is itself often a finding (attack-surface disclosure) even before any key is tested.

### Exported Component Exposure (Android)

Any `activity`/`service`/`receiver`/`provider` in the manifest with `android:exported="true"`, OR with an `<intent-filter>` but no explicit `android:exported` on Android 12+ (implicit-export rules changed — check `targetSdkVersion` to know which rule applies), is reachable by **any other app on the device** without holding a permission, unless gated by `android:permission`.

```
grep -B2 -A15 "<activity\|<service\|<receiver\|<provider" out/AndroidManifest.xml | grep -B15 'exported="true"'
```

For each exported component, check what it does with `getIntent().getExtras()` / `onStartCommand` input in the decompiled Java — an exported activity that deserializes an extra into a sensitive operation (e.g. loads a URL into a WebView, executes a deep-link-supplied command) is a real finding even statically, since the *reachability* (any app can send it an intent) is provable without a device — only the runtime trigger needs one.

**Content providers** deserve extra attention: an exported `ContentProvider` with no `readPermission`/`writePermission` and a SQL-building `query()`/`update()` method is a static-provable SQL-injection-adjacent surface.

### Deep Links / Custom URI Schemes

```
grep -A5 "android:scheme" out/AndroidManifest.xml
grep -rn "CFBundleURLSchemes" -A5 ipa_extracted/Payload/*.app/Info.plist
```
Trace each scheme's handling activity/view controller in the decompiled code for unsafe use of the incoming URI (loaded directly into a WebView, used to build a file path, used to bypass auth by carrying a token parameter that isn't re-validated server-side).

### Certificate Pinning (presence check only — cannot test bypass without a device)

```
find . -name "network_security_config.xml" -exec cat {} \;
grep -rn "CertificatePinner\|X509TrustManager\|checkServerTrusted" out_java/    # OkHttp / custom TrustManager
grep -rn "NSAppTransportSecurity\|NSExceptionDomains\|NSAllowsArbitraryLoads" ipa_extracted/Payload/*.app/Info.plist
```
Report pinning **presence/absence and configuration** (e.g. `NSAllowsArbitraryLoads=true` disables ATS entirely; a `<domain-config cleartextTrafficPermitted="true">` block whitelists plaintext HTTP for named hosts) — do not claim to have bypassed pinning, since that requires runtime instrumentation this sandbox cannot do.

### Debuggable / Backup Flags (Android)

```
grep -E 'android:debuggable="true"|android:allowBackup="true"' out/AndroidManifest.xml
```
`debuggable="true"` in a release build lets any locally-installed tool attach a debugger to the app process; `allowBackup="true"` with no `android:fullBackupContent` restriction lets `adb backup` extract app data on a device with USB debugging enabled — both statically provable from the manifest alone.

### WebView Misconfiguration

```
grep -rn "setJavaScriptEnabled(true)\|addJavascriptInterface\|setAllowFileAccess(true)\|setAllowUniversalAccessFromFileURLs(true)" out_java/
```
`addJavascriptInterface` exposing a Java object to a WebView that loads any attacker-influenceable URL (including one reachable via a deep link traced above) is a classic static-provable RCE-adjacent chain — trace the WebView's `loadUrl` source back to the exported/deep-link entry point.

## Testing Methodology

1. Extract with jadx (Java-readable) and apktool (manifest + resources) in parallel for Android; unzip for IPA
2. Pull manifest/plist first — it's the fastest source of exported-surface and ATS/pinning findings
3. Grep for secrets broadly, then manually confirm each hit is live/real (not a test key, not a public SDK identifier)
4. Enumerate exported components, trace each one's intent-handling code for unsafe input use
5. Check WebView config and trace `loadUrl` sources back to any attacker-reachable entry point (deep link, exported activity, IPC)
6. Explicitly note anything that needs dynamic verification (device/emulator + Frida) as out of scope rather than asserting it works

## Validation

1. For secrets: show the exact file/line and, where safe and in scope, a redacted proof the credential is live (e.g. a 401→200 status change) — never fully exfiltrate downstream data with it
2. For exported components: show the manifest entry plus the exact code path the intent reaches, and state precisely what an unprivileged co-installed app could trigger
3. For WebView/deep-link chains: show the full source-to-sink trace in the decompiled code
4. Label every finding clearly as **static-confirmed** vs **requires dynamic verification** — don't blur the two

## False Positives

- `exported="true"` on a component gated by a `signature`-level `android:permission` shared only with sibling apps from the same vendor
- Hardcoded string matching a secret pattern that is actually a public SDK/analytics identifier (e.g. a Firebase `apiKey`, which is not a secret by Google's own design — verify against Firebase's documented model before flagging)
- `addJavascriptInterface` present but the WebView only ever loads a hardcoded first-party URL, never attacker-influenceable input
- Deep-link scheme present but the target activity is not exported and requires an explicit component name only the app itself can supply

## Impact

- Direct credential/key compromise from embedded secrets
- Local privilege escalation / data exposure via exported components on-device
- MITM exposure where ATS/pinning is absent or explicitly disabled
- RCE-adjacent WebView-to-JS-bridge chains reachable via deep link

## Pro Tips

1. `droidasc` (if installed) is faster than full jadx decompilation for targeted class/method lookups on large APKs — use it for search, jadx for reading full context
2. Diff two versions of the same app (old vs new APK) when available — newly added exported components or removed pinning are high-signal
3. For dynamic follow-up (Frida instrumentation, live traffic interception, runtime auth-bypass testing), use the operator's separate mobile pentest tooling against an actual device/emulator — this skill only covers the static half

## Tooling

- **jadx** — Java/Kotlin decompilation, the primary read tool
- **apktool** — manifest + resource + smali extraction, needed for `AndroidManifest.xml` in readable form
- **aapt** (Android SDK build-tools, if available) — fast manifest/badging dump without full decompilation
- **unzip / plutil / plistlib** — IPA and plist extraction, no special tool required beyond stdlib

## Summary

A headless sandbox can fully prove static findings — hardcoded secrets, exported-component reachability, manifest/ATS misconfiguration, WebView-to-bridge source/sink chains — but cannot execute or instrument the app. Extract with jadx/apktool, start from the manifest/plist, and be explicit about what still needs a real device.
