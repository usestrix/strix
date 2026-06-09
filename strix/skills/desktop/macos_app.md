---
name: macos_app
description: Security testing playbook for macOS .app/.pkg/.dmg bundles covering code signing, entitlements, hardened runtime, IPC, and Mach-O analysis
---

# macOS Application

A macOS application ships as a `.app` bundle (or wrapped in `.dmg`/`.pkg`) containing a Mach-O executable, an `Info.plist`, embedded frameworks, `XPC` services, and a code signature. The attacker objective is local privilege escalation, code injection into a signed/entitled process, sandbox/TCC escape, and abuse of insecure update or IPC channels to run code with another user's or root's privileges. This sandbox is Linux/Kali, so Apple-native tooling (`codesign`, `otool`, `spctl`, `lipo`, `plutil`) is unavailable — perform static unpacking and Mach-O parsing with the cross-platform tools below, and reserve native commands for an on-host macOS verification step where the engagement allows it.

## Attack Surface

**Bundle layout** (`Target.app/Contents/`)
- `MacOS/<exe>` main Mach-O; `Frameworks/` embedded dylibs/frameworks; `Resources/`; `Info.plist`
- `_CodeSignature/CodeResources`, embedded `Code Signing Requirements`, provisioning profile
- `XPCServices/*.xpc`, `Library/LaunchServices/*` privileged helpers, `Library/LoginItems`

**Trust & policy**
- Code signature validity, signer identity, Designated Requirement (DR), notarization ticket
- Hardened Runtime flag and runtime exception entitlements (`allow-dyld-environment-variables`, `disable-library-validation`, `allow-unsigned-executable-memory`)
- Entitlements: `com.apple.security.app-sandbox`, `get-task-allow`, TCC grants, keychain access groups

**IPC / privileged surfaces**
- Mach services (`NSXPCConnection`, `xpc_connection_create_mach_service`), distributed notifications
- `SMJobBless`/`SMAppService` LaunchDaemon helpers running as root
- Custom URL schemes (`CFBundleURLTypes`), document/UTI handlers, AppleScript/`NSUserScriptTask`
- Auto-update channels (Sparkle, custom), bundled CLI tools, `setuid` binaries

## Recon & Enumeration

Acquire and unpack the artifact (handles `.dmg`/`.pkg`/`.app` from Linux):

```bash
# DMG (HFS+/APFS) extraction without macOS
sudo apt-get install -y dmg2img p7zip-full xar-utils cpio
dmg2img Target.dmg Target.img && 7z x Target.img -oTarget_extracted
# Flat .pkg = xar archive of payload cpio.gz
xar -xf Target.pkg -C pkg_out && (cd pkg_out && for p in $(find . -name Payload); do cat "$p" | gunzip -dc | cpio -id; done)
# .app is just a directory tree
find Target.app -type f | sort
```

Parse Mach-O, signatures, entitlements, and load commands without `otool`:

```bash
pip install macholib lief
# Architectures, load commands, dylibs, rpaths
python3 - <<'PY'
import lief; b=lief.MachO.parse("Target.app/Contents/MacOS/Target")
for m in b:
    print("arch",m.header.cpu_type)
    print("rpaths",[c.path for c in m.commands if c.command==lief.MachO.LOAD_COMMAND_TYPES.RPATH])
    print("dylibs",[d.name for d in m.libraries])
    print("hardened/flags",m.header.flags)
    cs=m.code_signature; print("has_codesig", cs is not None)
PY
# Entitlements live in the embedded __TEXT.__entitlements blob / code-sign superblob
strings -a Target.app/Contents/MacOS/Target | grep -iE 'com.apple.security|get-task-allow|disable-library-validation|allow-dyld'
r2 -qc 'iE; ic~entitlement; i~signature' Target.app/Contents/MacOS/Target 2>/dev/null
```

Plist, secrets, and supply-chain scans (install asset-specific tooling):

```bash
# Plists may be binary — convert with a portable parser
python3 -c 'import plistlib,sys;print(plistlib.load(open(sys.argv[1],"rb")))' Target.app/Contents/Info.plist
# Secrets / hardcoded creds across the bundle
curl -sL https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_linux_amd64.tar.gz | tar xz -C /usr/local/bin trufflehog
trufflehog filesystem Target.app --results=verified,unknown
GO111MODULE=on go install github.com/gitleaks/gitleaks/v8@latest && gitleaks dir Target.app -v
# SAST on bundled scripts (sh, py, JXA, Electron JS)
pip install semgrep && semgrep --config auto Target.app
# SBOM + CVE on embedded frameworks/dylibs
syft Target.app -o cyclonedx-json=sbom.json && grype sbom:sbom.json
trivy fs --scanners vuln,secret,misconfig Target.app
```

On-host macOS verification (run only on an authorized macOS box):

```bash
codesign -dvvv --entitlements :- Target.app          # signer, DR, entitlements
codesign --verify --deep --strict --verbose=4 Target.app
spctl -a -vvv -t exec Target.app                     # Gatekeeper/notarization
otool -L Target.app/Contents/MacOS/Target; otool -l ... | grep -A2 LC_RPATH
```

## Methodology

1. **Acquire & verify provenance**: unpack the `.dmg`/`.pkg`, record SHA-256, identify the signer Team ID and whether the package is notarized. Compare against the vendor's published identity.
2. **Map the bundle**: enumerate the main Mach-O, embedded frameworks, XPC services, helper tools, login items, and any bundled scripts or interpreters (Electron/Python/JXA).
3. **Dump entitlements & runtime flags**: extract the entitlements blob and Mach-O header flags; flag hardened-runtime exceptions (`disable-library-validation`, `allow-dyld-environment-variables`, `get-task-allow`) and broad TCC grants.
4. **Assess signature integrity**: check whether resources are sealed, whether nested code is signed, and whether the Designated Requirement pins the Team ID (weak DR = forgeable identity).
5. **Analyze dynamic loading**: resolve `@rpath`/`@executable_path`/`@loader_path` search order and confirm whether Library Validation is enforced (the prerequisite for dylib hijacking/injection).
6. **Enumerate IPC**: list Mach service names, XPC listeners, and privileged helpers; check connection authorization (audit token / DR validation vs. PID-based checks).
7. **Test the update channel**: capture the updater's network traffic; verify HTTPS, signature/EdDSA verification of the downloaded payload, and appcast integrity.
8. **Validate, chain, report**: build a minimal PoC for each confirmed weakness; chain into privilege escalation or TCC/sandbox escape; document signer, entitlements, and exact reproduction.

## Key Weaknesses / Techniques

**Dylib hijacking / injection (no Library Validation)** — If `disable-library-validation` is set or the binary is unsigned, a writable `@rpath`/`@loader_path` directory lets you drop a malicious dylib that loads into the trusted process.
```bash
# Resolve search order, then find a load path that is writable / missing on disk
python3 -c 'import lief;b=lief.MachO.parse("Target.app/Contents/MacOS/Target")[0];print([c.path for c in b.commands if "RPATH" in str(c.command)])'
# A hijack dylib needs a constructor; build/sign on macOS, place in the first writable rpath dir
# __attribute__((constructor)) static void run(){ system("id > /tmp/poc"); }
```

**DYLD environment injection** — With `com.apple.security.cs.allow-dyld-environment-variables` (and no hardened runtime), `DYLD_INSERT_LIBRARIES` forces an arbitrary dylib into the process:
```bash
DYLD_INSERT_LIBRARIES=/tmp/poc.dylib /Applications/Target.app/Contents/MacOS/Target
```

**Insecure privileged helper (SMJobBless/SMAppService)** — A root LaunchDaemon that authorizes clients by PID or bundle path (not the audit token + DR) lets an unprivileged process invoke its privileged XPC methods. Inspect the helper's `SMAuthorizedClients` requirement and its connection handler; absence of `[connection setCodeSigningRequirement:]` / `xpc_connection_set_peer_code_signing_requirement` is the bug.

**Weak Designated Requirement / unsealed resources** — If the DR does not pin Team ID + identifier, a re-signed forgery satisfies it. If `Resources/` scripts or frameworks are not sealed in `CodeResources`, you can swap content post-signing without invalidating the signature in practice.

**Custom URL scheme / document handler abuse** — A registered scheme that maps untrusted input to a privileged action (file open, command, deeplink to internal API) enables drive-by invocation:
```bash
# Inspect CFBundleURLTypes / CFBundleDocumentTypes, then trigger from a webpage: location='target://...'
python3 -c 'import plistlib;d=plistlib.load(open("Target.app/Contents/Info.plist","rb"));print(d.get("CFBundleURLTypes"),d.get("CFBundleDocumentTypes"))'
```

**Insecure auto-update** — Plaintext HTTP appcast, missing EdDSA/DSA signature check, or downgrade-able feed (classic CVE-2016-9892 Sparkle class). Confirm the feed URL scheme and whether the downloaded archive is signature-verified before execution.

**TCC / sandbox over-grant** — Broad entitlements (`com.apple.security.automation.apple-events`, full-disk-equivalent temporary exceptions, `com.apple.security.cs.allow-jit`) widen blast radius. Map each entitlement to the capability it unlocks.

**Hardcoded secrets / embedded creds** — API keys, signing material, or backend tokens in `Resources/`, plists, or the Mach-O `__cstring` section (catch via trufflehog/gitleaks above).

## Validation

1. **Signature claim**: on macOS, `codesign --verify --deep --strict` must fail after your modification (or the unmodified app must fail to confirm tampering acceptance). On Linux, show the sealed-resource hash in `CodeResources` does not cover the file you swapped.
2. **Injection**: run the target with your PoC dylib and show out-of-band evidence the code executed inside the trusted process (e.g., a file written as the app's user, or a beacon to `interactsh-client` from the app's context — not your shell's).
3. **Privileged helper**: from an unprivileged process, invoke the helper's XPC method and demonstrate a root-owned side effect (`ls -l /tmp/poc` shows `root`), with the client doing nothing privileged itself.
4. **Update**: intercept the feed (mitmproxy), serve a benign re-packaged update, and show it installs/launches without a signature rejection.
5. Capture exact entitlements, Team ID, load command paths, and a minimal reproduction script for every finding.

## False Positives

- `disable-library-validation` present but the bundle is still fully sandboxed and has no writable rpath directory — not exploitable in isolation.
- `get-task-allow` true only in a **debug/development** build that never ships; verify it is absent from the release/notarized artifact.
- Unsigned helper that is only reachable by root anyway (no privilege boundary crossed).
- "Secrets" that are public client identifiers (OAuth public client IDs, Sentry DSNs) — not credentials.
- Grype/Trivy CVEs on a statically-linked or patched fork where the vulnerable code path is not built in — confirm the symbol/version actually present.
- HTTP appcast that nonetheless EdDSA-verifies the payload before execution — transport is cosmetic, integrity holds.
- Custom URL scheme that only routes to inert UI navigation with no privileged sink.

## Chaining & Impact

- Dylib hijack into an app holding **Full Disk Access** or Automation TCC grants → read protected files / drive other apps → TCC bypass without a prompt.
- Writable rpath + auto-launched login item → persistence that re-injects on every login.
- Unauthenticated privileged helper → arbitrary command execution as **root** → full local privilege escalation.
- Insecure update + MITM (rogue Wi-Fi/ARP) → remote code execution at install privilege, often root.
- Forgeable DR + unsealed resources → trojanized "trusted" app that passes Gatekeeper on the victim's first run.
- Hardcoded backend token → pivot from local app to cloud/API compromise.

## Pro Tips

1. The entitlements that matter most for injection are `disable-library-validation`, `allow-dyld-environment-variables`, and `allow-unsigned-executable-memory` — grep for them first; their presence reorders your whole attack plan.
2. PID-based XPC authorization is always a bug: PIDs are reusable/forgeable. Real checks use the audit token plus a code-signing requirement — confirm which one the handler uses.
3. `@loader_path` and `@executable_path` differ from `@rpath`; resolve them relative to the *loading* binary, not the main executable, or you will chase a non-writable directory.
4. Binary plists fail `cat`/`grep` — always normalize with `plistlib`/`plutil -convert xml1` before reading; many "no entitlements" conclusions are just unconverted binary blobs.
5. Notarization proves Apple scanned it, not that it is safe or that *your* tampered copy is trusted — re-verify the signature after every modification.
6. Electron and Python apps hide the real logic in `app.asar` / `__pycache__`/`site-packages` inside `Resources/` — unpack `asar` and decompile `.pyc`; that is where secrets and IPC handlers usually live.
7. Helper tools in `Library/LaunchServices` and the `SMAuthorizedClients`/`SMPrivilegedExecutables` plist keys reveal the trust relationship between app and helper — read both ends before testing the channel.
8. Reserve `codesign`/`spctl`/`otool` for an authorized macOS verification pass; do the heavy static unpacking and triage on this Linux sandbox with `lief`/`r2`/`xar`/`dmg2img` to keep iteration fast.
