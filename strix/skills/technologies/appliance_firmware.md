---
name: appliance-firmware
description: Security analysis of appliances and firmware through artifact provenance, safe extraction, root filesystem and runtime mapping, listener and trust-boundary inventory, patch comparison, managed/native code triage, hardware constraints, and isolated device validation
---

# Appliance and Firmware Analysis

Use this skill for VPNs, firewalls, storage/backup systems, management appliances, embedded products, virtual appliances, and other packaged systems where security behavior is split across firmware, web-server configuration, native daemons, scripts, managed services, generated state, and hardware-specific runtime details.

Appliance research is architecture research. The public web UI is only one entry point; auxiliary listeners, localhost APIs, sidecars, support agents, update services, telemetry jobs, package installers, and product-native administration features often carry equal or greater authority.

## Build and Artifact Matrix

Record before comparing anything:

| Dimension | Examples |
|---|---|
| Product | model/SKU, physical/virtual/cloud image, edition/license |
| Software | marketing version, build/revision, branch, hotfix, package set |
| Platform | architecture, endian, kernel, libc, bootloader, filesystem |
| Install state | factory image, upgraded system, migrated config, retained files |
| Configuration | feature flags, listeners, authentication mode, HA/cluster role |
| Artifact source | vendor download, updater, installed disk, backup, marketplace |
| Update form | full image, delta package, component hotfix, rollback bundle |
| Authenticity | signature/encryption state, certificate/key ID, manifest/base-version requirement |

Hash original artifacts and preserve acquisition metadata. A neighboring version from a different SKU, edition, architecture, or installation lineage can produce a convincing but irrelevant diff.

## Safe Extraction

Treat firmware and every embedded archive/filesystem as hostile input. Extract as an unprivileged user into a fresh writable quota-limited output directory with no network, bounded recursion/processes, and read-only input.

### unblob

[unblob](https://github.com/onekey-sec/unblob) provides recursive extraction plus structured metadata for many firmware/container/filesystem formats. Prefer a reviewed container image digest:

```bash
appliance_out="$(mktemp -d)"
docker run --rm --network none \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --user "$(id -u):$(id -g)" --pids-limit 256 --memory 4g --cpus 2 \
  --tmpfs /tmp:rw,noexec,nosuid,size=512m \
  -v /path/to/input:/data/input:ro \
  -v "$appliance_out":/data/output \
  ghcr.io/onekey-sec/unblob@sha256:<reviewed-digest> \
  -e /data/output -d 6 -p 2 --report /data/output/unblob.json \
  /data/input/firmware.bin
```

Create the output directory first and ensure it is writable by the chosen UID/GID; otherwise the host may create a root-owned mount point. Never extract over an existing analysis tree. Inspect symlinks, device nodes, archive paths, decompression ratios, and output size before interacting with the tree.

### diffoscope

Use [diffoscope](https://diffoscope.org/) for a recursive format-aware first comparison of vulnerable/fixed directories, packages, images, JARs, and executables:

```bash
diffoscope --html diffoscope.html vulnerable-root/ fixed-root/
```

Run it in an isolated reviewed container when processing hostile artifacts because it invokes many external format helpers. Use the first report to narrow files/config/packages rather than repeatedly expanding the entire image.

Use the unblob report and packaged filesystem metadata for ownership, mode, xattr, capability, and device-node claims; a host extraction run under your own UID can intentionally remap them. Do not mount an untrusted extracted filesystem or `chroot` into it on the analyst host.

## Filesystem and Boot Architecture

Inventory:

- partition table, bootloader, kernel, initramfs, SquashFS/UBIFS/ext filesystems
- init system, service definitions, inetd/socket activation, rc scripts, supervisors, and watchdogs
- read-only base image versus writable overlay, tmpfs, bind mounts, containers/chroots, and persistent data partitions
- factory defaults, first-boot generation, upgrade/migration scripts, rollback slots, and retained legacy files
- environment files, credentials, certificates, secrets, licenses, databases, sessions, caches, and backup/restore formats
- cron/timers, log rotation, telemetry, diagnostics, update checks, package deployment, support bundles, and cleanup tasks
- ownership, group membership, capabilities, setuid/setgid, ACLs, sudo/doas rules, device access, and IPC permissions

Static extracted files may not match runtime. Boot-time scripts can patch files, mount overlays, generate configs, copy certificates, activate routes, or replace binaries. Capture live filesystem/mount/process state when an apparently relevant change is absent from the disk image.

## Update and Installed-State Reconstruction

Before trusting a package or image diff, reconstruct how the device installs it:

- verify signature and manifest order, trust anchors, and whether integrity/authenticity checks cover the whole payload or only a wrapper
- distinguish full image, delta update, component hotfix, and required base version
- identify target partition, boot slot, rollback path, and anti-rollback/version checks
- review pre/post-install hooks, migrations, symlink changes, permission/capability changes, and retained/generated state
- map overlay, bind-mount, and generated-file precedence over the extracted rootfs
- test fresh install versus upgraded and partially rolled-back states
- reconcile package contents with hashes/build IDs from the actual running process and live filesystem

Record package-manager databases, shipped SBOM/manifests, bundled library copies, loader path, and `RPATH`/`RUNPATH` so you can distinguish a vulnerable library on disk from the library the running process actually maps.

## Listener and Service Map

Build a table for every network and local endpoint:

```text
address/port/socket | transport/TLS | process | config/init source
route/message type | authentication | authorization | privilege | feature/default
```

Include:

- HTTP(S) UI/API, CGI/FastCGI, WebSocket, SOAP, SAML/OIDC, upload/download
- SSH/SFTP, VPN/IKE, message queues, databases, backup/storage protocols
- proprietary TLS/RPC, cluster/HA, device-manager, agent, and telemetry ports
- loopback/Unix sockets, localhost APIs, sidecars, containers, and debug/support agents
- outbound update/download endpoints and trusted remote control planes

For outbound updater, telemetry, licensing, or control-plane names, record authoritative DNS/ownership, TLS identity and pinning, proxy/fallback behavior, request data, failure behavior, manifest integrity, payload integrity, rollback/version policy, and whether the external domain, bucket, package, or provider resource can expire or be reassigned.

Map edge configuration to code: reverse-proxy rules, rewrites, location blocks, authentication modules, trusted client-IP headers, TLS client certificates, and backend socket selection. A handler can be patched while a new edge rule merely hides it—or vice versa.

## Trust and Authorization Boundaries

Trace:

```text
external listener -> proxy/config -> router/dispatcher -> authentication
                  -> parser -> privileged operation -> OS/service identity
```

Test conceptual boundaries such as:

- public versus management interface
- external versus localhost/sidecar trust
- managed device versus manager/controller trust
- cluster peer, certificate, flag, or registration state
- web user versus OS/service/database authentication
- direct route versus internal redirect/component dispatch
- fresh install versus upgraded/retained installation state
- optional feature disabled versus installed-but-reachable handler

Successful TCP/TLS/WebSocket negotiation proves transport reachability, not authenticated identity or authorization. Determine the actual privileged result and which server-side flag/session/role enabled it.

## Code and Configuration Triage

### Scripts and Configuration

- Trace Apache/nginx/lighttpd rules, CGI mappings, environment variables, and shell/Perl/Python/PHP scripts.
- Search command construction beyond obvious shell metacharacters: arithmetic expansion, config files, response files, argument injection, newline/control characters, and third-party CLI parsing.
- Inspect support/debug functions, backup/restore, package install, log/telemetry processors, custom tags/templates, and native admin command runners.
- Compare configuration and init/upgrade changes alongside application code.

### Java/JVM and .NET

- Use [Vineflower](https://github.com/Vineflower/vineflower) for Java class/JAR reconstruction and `javap -c` to confirm ambiguous bytecode.
- Use official [ILSpy/ilspycmd](https://github.com/icsharpcode/ILSpy) for .NET assemblies and inspect IL/metadata when reconstructed C# is ambiguous.
- Do not build or run decompiler output, target assemblies/classes, bundled build scripts, or embedded resources in their associated target runtimes/viewers.
- Diff class/resource inventories before decompiled text to separate compiler/obfuscator noise from semantic changes.

### Native Binaries

- Use official [Ghidra](https://github.com/NationalSecurityAgency/ghidra) for strings/imports/xrefs/decompilation and reproducible headless projects.
- Use [BinDiff](https://github.com/google/bindiff) after manifest/package triage isolates the relevant native binaries, and keep the disassembler/BinExport version pair compatible across both sides.
- Confirm changed length, auth, command, parser, and file-handling conditions in assembly/runtime; decompiler types and similarity scores are hypotheses.
- Record architecture-specific calling convention, endian, alignment, libc, allocator, and mitigations.

Load `memory_corruption` for bounds/lifetime/disclosure findings and exploitability analysis. Load `protocol_reverse_engineering` for custom/stateful message formats.

## Version and Patch Analysis

Compare more than one adjacent pair when possible:

```text
older unaffected/unknown -> vulnerable -> first fixed -> current
```

- Build changed-file/package/config manifests first.
- Identify the security invariant introduced by the patch.
- Review every caller/sibling handler using the patched helper/parser.
- Check branch backports and inconsistent fixes across SKUs/architectures.
- Re-test the old structural condition on the fixed build and nearby routes.
- Inspect boot/runtime overlays and upgrade scripts if static diff shows no meaningful change.
- Distinguish one CVE from one code path; advisories may bundle several bugs or fix only the most exposed route.

Pair with `advisory_to_poc` for evidence classification, public-PoC decomposition, vulnerable/fixed controls, and detector handoff.

## Hardware, Virtualization, and Emulation

Record what the test environment omits:

- hardware security module/TPM/secure element and device-bound keys
- NIC/accelerator/driver behavior, DMA, endian/alignment, and kernel modules
- boot chain, secure boot, verified partitions, recovery mode, watchdog, and HA peer
- model-specific memory, allocator pressure, process limits, and service configuration
- virtual appliance differences from physical products

Full-system emulation can help recover routes and protocol behavior but often changes drivers, timing, entropy, memory layout, certificates, hardware identity, and mitigations. Treat emulation results as a separate platform and reproduce security-relevant behavior on the actual supported model when the claim depends on those properties.

Do not disable ASLR, canaries, signature checks, or other mitigations without labeling the resulting demonstration as lab-only and nonrepresentative of default exploitability.

## Physical-Lab Prerequisites

Have a recovery path before live-device work:

- console, serial, hypervisor, snapshot, or other known-good rollback method
- exact in-scope image/build and a way to reapply it
- isolated management network and controlled outbound connectivity
- process or watchdog visibility and a safe way to capture one request at a time

## Runtime Observation

Within an authorized lab, collect:

- process tree, executable/build ID, argv, cwd, users/groups/capabilities, open ports/sockets/files, mounts, namespaces/containers
- service logs, audit logs, core files, watchdog/restart events, and packet captures
- loaded mappings/libraries, relevant Unix sockets/file descriptors, and config source while sending one known request
- filesystem/process events while sending one known request
- boot/upgrade output and live configuration generated from templates/databases

Prefer observation that explains a static hypothesis. Do not install intrusive agents or attach a debugger to production equipment.

## Capability and Chain Mapping

Treat findings as product-context primitives:

- file read → configs, sessions, credentials, tokens, keys, topology
- SSRF/request → loopback APIs, sidecars, metadata, package agents
- file write → web roots, plugins, templates, restore packages, jobs, telemetry inputs
- auth bypass → support/admin command runners, package deployment, native operations
- parser disclosure → session/token/pointer material
- low-privilege identity → built-in management tools and trusted peer relationships

Inventory native product consumers before importing a generic exploit gadget. An appliance's normal backup, restore, diagnostic, package, scripting, or cluster function is frequently the shortest bridge between primitives.

## Deliverable

Include:

1. artifact provenance/hashes and complete SKU/version/platform/config matrix
2. extraction method and filesystem/boot/runtime architecture
3. listener/service/auth/trust-boundary map
4. changed-file/config/package manifest and relevant code path
5. external route/protocol through privileged operation and OS identity
6. hardware/emulation/mitigation constraints
7. vulnerable/fixed/negative-control behavior
8. adjacent handlers/branches/install states reviewed
9. tool versions, generated artifacts, and unresolved assumptions

## Common Errors

- Diffing different SKUs/architectures and attributing packaging noise to a security fix.
- Assuming extracted rootfs equals live state despite overlays, generation, or boot-time patches.
- Mapping only the web UI and missing auxiliary/custom/local listeners.
- Treating a hidden route as removed or a blocked route as a patched sink.
- Assuming fresh-install behavior covers upgraded systems with retained files/configuration.
- Calling a service pre-auth because a connection succeeds before a privileged operation is attempted.
- Treating emulator-only behavior or disabled mitigations as representative of a shipping device.
- Running an analyzed binary, extension, build script, or firmware helper on the analyst host.

## Summary

Appliances are integrated systems, not single applications. Preserve artifact lineage, extract safely, map boot/runtime state and every listener, trace edge configuration into code and privileged native features, compare fixes across branches and install states, and keep hardware/platform constraints attached to every finding.
