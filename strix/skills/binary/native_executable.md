---
name: native-executable
description: Native binary security testing across ELF / PE / Mach-O - triage, protection enumeration, memory-corruption and command-injection bugs, fuzzing, and exploitability classification
---

# Native Executable Security Testing

Compiled executables and shared libraries expose a binary-level attack surface that source-level review misses: memory-corruption bugs (stack/heap overflows, use-after-free, integer overflows), unsafe library calls (`system`, `strcpy`, `sprintf`), hardcoded secrets baked into `.rodata`, and outdated statically-linked dependencies carrying known CVEs. The same triage workflow applies to ELF (Linux), PE (Windows), and Mach-O (macOS) - only the tool flags differ. Mitigations (NX, ASLR/PIE, RELRO, stack canaries, FORTIFY) decide whether a memory bug is a crash or a shell, so enumerating them is the load-bearing first step. The goal is to find untrusted input reaching an unsafe sink, drive a controlled crash through it, and classify whether that crash yields instruction-pointer control or an information leak. For RCE on services that shell out, see rce; for command injection patterns, see command_injection.

## Attack Surface

**Scope**
- ELF executables and shared objects (`.so`), Linux setuid/setgid binaries, systemd-spawned services
- PE executables and DLLs (`.exe`, `.dll`), Windows services, scheduled tasks
- Mach-O binaries and dylibs, macOS LaunchDaemons, codesigned apps
- Statically and dynamically linked third-party libraries (zlib, OpenSSL, libpng, sqlite) and their bundled versions
- Network-facing parsers: protocol daemons, file-format parsers, RPC/IPC endpoints

**Entry Points**
- Command-line arguments and environment variables consumed by setuid binaries
- File inputs: config files, media/document parsers, archive extractors, firmware blobs
- Network sockets: listening services, client handlers, deserialization endpoints
- IPC: Unix sockets, named pipes, D-Bus, shared memory, Windows LPC/ALPC
- Locally-writable paths the binary trusts (temp files, world-writable configs, `LD_PRELOAD`/`DYLD_INSERT_LIBRARIES` search paths)

**Identity and privilege context**
- setuid-root / setgid binaries (`find / -perm -4000 -type f`) run attacker input with elevated privilege
- Windows services running as `SYSTEM`, scheduled tasks, and DLLs loaded by privileged processes (DLL search-order hijack)
- macOS binaries with `setuid`, entitlements, or installed as root LaunchDaemons
- Capabilities on Linux (`getcap -r / 2>/dev/null`) - `cap_setuid`, `cap_dac_override` widen impact even without the setuid bit

## Key Vulnerabilities

### Triage and Embedded Secrets

First identify the format, architecture, linkage, and any credentials or sensitive paths compiled into the binary before touching disassembly.

**Test:**
```
file ./target && rabin2 -I ./target
strings -n 8 -t x ./target | grep -iE 'pass(word)?|secret|api[_-]?key|token|BEGIN .*PRIVATE KEY|https?://|/tmp/|aws_'
nm -D ./target 2>/dev/null; readelf -d ./target | grep NEEDED
objdump -T ./target.dll 2>/dev/null; rabin2 -z ./target   # PE/Mach-O imports + ASCII/UTF-16 strings
```

### Dependency CVEs

Bundled or statically-linked libraries ship the vulnerabilities of their frozen version. Extract version banners from `.rodata` and map them to known CVEs.

**Test:**
```
strings ./target | grep -iE 'openssl|zlib|libpng|sqlite|curl|libxml2|log4j' | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?'
rabin2 -z ./target | grep -iE 'OpenSSL [0-9]|zlib version'
syft ./target -o table        # SBOM, then grype sbom:./sbom.json for CVE matching
```

### Stack Buffer Overflow

Unbounded copies (`strcpy`, `strcat`, `gets`, `sprintf`, `scanf("%s")`, `memcpy` with attacker-controlled length) into fixed stack buffers overwrite the saved return address.

**Test:**
```
rabin2 -i ./target | grep -iE 'strcpy|strcat|gets|sprintf|scanf|memcpy'
# cyclic pattern to find exact offset to saved RIP/EIP
python3 -c "from pwn import *; print(cyclic(200).decode())" | ./target
gdb -q -ex 'run < <(python3 -c "from pwn import *; sys.stdout.buffer.write(cyclic(200))")' -ex 'bt' ./target
# after crash in pwndbg/GEF: cyclic -l $rsp  (or the faulting address) -> offset
```

### Format String

User input passed directly as the format argument (`printf(user)`, `fprintf(fp, user)`, `syslog(pri, user)`) leaks stack memory with `%p`/`%x` and writes arbitrary memory with `%n`.

**Test:**
```
rabin2 -i ./target | grep -iE 'printf|fprintf|snprintf|syslog|err|warn'
./target "$(python3 -c 'print("%p."*20)')"          # leak: non-literal output proves the bug
./target "$(python3 -c 'print("AAAA" + "%x."*10)')"  # 41414141 in output = controlled stack read
# pwntools FmtStr automates the %n write-what-where once offset is known
```

### Use-After-Free / Double-Free

A pointer dereferenced or freed after its object was already freed. Detect with ASan or Valgrind; confirm the dangling access path in the disassembler.

**Test:**
```
clang -fsanitize=address -g src.c -o target_asan && ./target_asan < crashing_input
valgrind --leak-check=full --track-origins=yes ./target < crashing_input
# ASan report: "heap-use-after-free" / "double-free" with alloc + free + use stacks
gdb -q -ex 'run' ./target   # then in pwndbg: 'vis_heap_chunks' to inspect tcache/fastbin reuse
```

### Heap Overflow

Out-of-bounds write past a heap allocation corrupts adjacent chunk metadata or object pointers (vtables, function pointers).

**Test:**
```
clang -fsanitize=address -g src.c -o target_asan && ./target_asan < oversized_input
# ASan: "heap-buffer-overflow ... WRITE of size N"; note redzone offset
gdb -q ./target   # pwndbg: 'heap', 'bins', 'vis_heap_chunks' to see corrupted chunk headers
ltrace -e 'malloc+free+realloc' ./target < input   # correlate sizes with attacker control
```

### Integer Overflow to Undersized Allocation

An attacker-controlled size multiplied/added before `malloc` wraps, allocating a tiny buffer that a later copy overflows. Look for `malloc(count * size)` and `len + header` without overflow checks.

**Test:**
```
rabin2 -i ./target | grep -iE 'malloc|calloc|realloc|alloca'
# in Ghidra/radare2 decompiler, audit allocation sites for unchecked arithmetic on input-derived len
clang -fsanitize=integer,address -g src.c -o target_san && ./target_san < input  # UBSan flags the wrap
# supply len near 2^32 / 2^64 boundary (e.g. 0xffffffff) so size*elem wraps to a small value
```

### Command Injection via system()/exec

Binaries that build shell command strings from input and pass them to `system`, `popen`, or `execl("/bin/sh","-c",...)` allow injection via `;`, `|`, `$()`, backticks.

**Test:**
```
rabin2 -i ./target | grep -iE 'system|popen|execl|execve|ShellExecute|CreateProcess|WinExec'
# in disassembly, find the format string concatenated before the system() call
./target "input; id"        # or "$(id)" / "`id`" / "input|id"
strace -f -e trace=execve ./target "input; id"   # confirms /bin/sh -c with injected command
```

### Insecure Temp Files / Path Issues

Predictable temp names (`/tmp/app.XXXX`, PID-based), `tmpnam`/`mktemp`-then-open races (TOCTOU), or relative/attacker-writable paths enable symlink attacks and library hijacking.

**Test:**
```
rabin2 -i ./target | grep -iE 'tmpnam|tmpfile|mktemp|mkstemp|fopen|access|open|getenv'
strace -f -e trace=open,openat,access,readlink ./target 2>&1 | grep -E '/tmp/|\.\./|access'
# symlink race: pre-create /tmp/<predicted_name> -> /etc/passwd, run, check follow
ltrace -e 'getenv' ./target   # LD_PRELOAD / PATH / config-path env trust on setuid binary
```

### Hardcoded Credentials / Keys

Embedded passwords, API keys, private keys, or backdoor comparisons compiled into the binary. Static literals live in `.rodata`; comparison logic reveals the expected value.

**Test:**
```
rabin2 -z ./target | grep -iE 'pass|key|secret|token|admin|BEGIN .*KEY'
# locate the string xref, then read the comparison in the decompiler
r2 -q -c 'izz~password; axt @ <str_addr>' ./target
# Ghidra headless cross-reference for a string-equality check against the literal
analyzeHeadless /tmp/proj proj -import ./target -postScript ResolveX86orX64LinuxSyscallsScript.java
```

## Bypass Techniques

**ASLR / PIE leaks** - A single leaked runtime address (libc symbol via format string, GOT entry, stack/heap pointer) defeats randomization for the whole module. Compute the base by subtracting the symbol's static offset, then derive every gadget/function address relative to it. PIE binaries need a leak of their own `.text` base before ROP into the binary itself.

**ret2libc / ROP** - With NX/DEP on, the stack is non-executable, so reuse existing code. Overwrite the saved return address to chain `system("/bin/sh")` (ret2libc) or stitch gadgets ending in `ret` into a ROP chain. Build chains with `ROPgadget --binary ./target`, `ropper -f ./target --search "pop rdi"`, or pwntools `ROP(elf)`; resolve libc layout from a leak plus the matching libc (`libc-database`).

**GOT / PLT overwrite** - With Partial RELRO (or no RELRO) the GOT is writable. A write primitive (format-string `%n`, arbitrary-write bug) can point a frequently-called PLT-resolved entry (e.g. `free`, `printf`) at `system` or a one-gadget. Confirm GOT writability and entry addresses with `objdump -R ./target` / `readelf -r ./target`.

**Partial RELRO abuse** - Partial RELRO leaves the GOT writable and lazy binding active, so GOT overwrites work; Full RELRO maps the GOT read-only and resolves all symbols at load, closing that path and pushing toward `__malloc_hook`/`__free_hook` (glibc < 2.34), `_dl_runtime_resolve` abuse, or stack pivots. Check the exact level with `checksec` before choosing a strategy.

## Testing Methodology

1. **Triage** - `file` / `rabin2 -I` for format, arch, bits, endianness, linkage (static vs dynamic), and stripped status; pull `strings`, imports (`nm -D`, `objdump -T`), and `NEEDED` libraries
2. **Enumerate protections** - run `checksec --file=./target` (pwntools `checksec` or the checksec.sh script) and `rabin2 -I` to read NX, PIE/ASLR, RELRO level, canary, and FORTIFY; record the system ASLR setting (`cat /proc/sys/kernel/randomize_va_space`)
3. **Reverse key functions** - load into Ghidra (`analyzeHeadless` for batch), radare2/rizin (`aaa`, `pdf`), or IDA; locate input handlers, parsers, and dangerous-sink callers
4. **Identify untrusted input** - trace argv, env, file reads, and socket recv to the unsafe sinks found in triage (`strcpy`, `system`, `malloc(len*..)`, `printf(user)`)
5. **Fuzz** - harness the input path with AFL++ (`afl-fuzz -i seeds -o out -- ./target @@`) or libFuzzer (`clang -fsanitize=fuzzer,address`); seed with valid samples and compile with ASan for crash visibility
6. **Reproduce the crash** - replay the crashing input under gdb+pwndbg/GEF; capture the faulting instruction, register state, and backtrace
7. **Classify exploitability** - determine whether the crash gives saved-return-address/RIP control, a controlled write (`%n`, heap metadata), or only a non-controllable read; map against enabled mitigations to judge real-world severity (use `exploitable`/`!exploitable` heuristics as a starting signal, not proof)

## Validation

1. Show the exact offset to the saved return address with a cyclic pattern (`cyclic`/`pattern_create`) and prove `$rip`/`$eip` (or `$pc`) equals the controlled value (e.g. `0x6161616161616166`) - no shellcode, no payload that runs anything
2. For info leaks, dump the leaked bytes (libc pointer, canary, stack address) and show they match a real runtime address, demonstrating ASLR defeat without further exploitation
3. For format strings, show `%p`/`%x` returning live stack data and identify the controllable parameter index - stop before the `%n` write
4. Capture the sanitizer report (ASan/UBSan/Valgrind) with allocation, free, and faulting stacks as ground truth for UAF/overflow classification
5. Demonstrate command injection with a benign, observable command (`id`, `whoami`, or an OAST DNS lookup) - never a destructive or persistence payload
6. Provide the minimal reproducing input (smallest crashing file/arg) plus the precise crash location, not a weaponized exploit

## False Positives

- A crash (SIGSEGV) with no register or memory control - a NULL-pointer deref or read-only fault is a stability bug, not an exploitable primitive
- `system`/`popen` present in imports but only ever called with fully static, non-input strings
- "Dangerous" functions (`strcpy`, `sprintf`) used with provably-bounded sizes or length-checked inputs
- `strings` hits on key-like patterns that are public certificates, test fixtures, or library constants rather than live secrets
- Stack canary "missing" reported on a function with no stack buffers - the compiler legitimately omits the canary there
- Sanitizer reports from instrumented test harnesses that exercise paths unreachable from real untrusted input

## Impact

- Remote or local code execution when a memory-corruption bug yields instruction-pointer control on a network-facing or setuid binary
- Local privilege escalation via setuid-root, capability-bearing, or SYSTEM-context binaries
- Information disclosure of memory contents (canaries, pointers, adjacent secrets) enabling further exploitation
- Command execution as the binary's user through `system`/`exec` injection
- Credential and key compromise from hardcoded secrets recoverable by anyone with the binary
- Supply-chain exposure when bundled libraries carry unpatched CVEs that the host application inherits

## Pro Tips

1. Run `checksec` before anything else - Full RELRO + PIE + canary + NX changes the entire exploitation strategy and tells you which bug classes are even worth chasing
2. Disable ASLR for local triage (`setarch -R ./target` or `echo 0 > /proc/sys/kernel/randomize_va_space`) to get stable addresses while reproducing, then re-enable to assess the real bug
3. A leak is worth more than a write early on - one libc/`.text` address unlocks ROP, ret2libc, and GOT targeting against an otherwise-randomized process
4. Stripped binaries: let radare2/Ghidra auto-name, then pivot off import calls and string xrefs - the `system`/`strcpy`/`recv` callers are your map
5. Always compile or run with ASan/UBSan when source is available - it turns silent corruption into a precise diagnostic and slashes fuzzing triage time
6. Seed AFL++ with real valid inputs and enable `cmplog`/dictionaries for format-aware targets; minimize crashes with `afl-tmin` before debugging
7. `one_gadget` against the target's libc often collapses a GOT/`__free_hook` overwrite into a single-address `execve("/bin/sh")` - check constraints before relying on it
8. On Windows, check for DLL search-order and unquoted-service-path hijacks (`sc qc <svc>`, missing-DLL probes under Process Monitor) - often easier than memory corruption
9. Match the exact libc (`libc-database` via leaked symbol offsets) before computing addresses; an off-by-one libc version silently breaks every gadget offset

## Summary

Native-binary findings chain from triage to control: file/format identification and protection enumeration scope what is exploitable, disassembly locates where untrusted input meets an unsafe sink, fuzzing turns that path into a reproducible crash, and debugger analysis classifies the crash as RIP control, a controlled write, or an info leak. Mitigations are the hinge - a stack overflow under Full RELRO + PIE + canary may need a leak plus a ROP chain, while the same bug on a no-canary, no-PIE binary is direct return-address control. Validate by proving the primitive (offset to saved return, leaked address, controllable `%p`) with benign observables, never a weaponized payload, and weight severity by the binary's privilege and network exposure.
