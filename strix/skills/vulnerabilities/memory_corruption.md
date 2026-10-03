---
name: memory-corruption
description: Native memory-safety analysis for stack and heap overflows, out-of-bounds access, uninitialized memory, use-after-free, integer and signedness errors, format strings, crash triage, exploitability constraints, and controlled lab validation
---

# Memory Corruption

Use this skill for authorized analysis of native parsers, network services, firmware daemons, libraries, and mixed web/native components where attacker-controlled bytes may violate memory safety.

Separate three questions throughout the work:

1. **Bug existence:** does an input cause an invalid read, write, lifetime violation, or disclosure?
2. **Primitive quality:** what bytes, address, length, timing, or object state can the attacker control or observe?
3. **Exploitability:** can that primitive bypass the target architecture, mitigations, allocator, protocol, and restart constraints?

A crash, connection close, watchdog restart, or sanitizer report proves neither instruction-pointer control nor RCE.

## Lab Boundary

Malformed-input and crash work is denial-of-service testing. Run it only against an explicitly authorized, restartable lab target with console/process visibility, health checks, rate ceilings, and a recovery procedure. Do not fuzz production services or automatically replay crash cases.

Analyze hostile binaries, cores, packet captures, and corpora inside an isolated environment. Do not execute an unknown sample merely because a debugger or decompiler imported it.

## Vulnerability Classes

### Bounds and Length Errors

- fixed destination with attacker-controlled copy/format length
- allocation based on one length and copy based on another
- off-by-one termination or delimiter handling
- nested length fields and cumulative-size overflow
- stack/heap out-of-bounds read or write
- negative length converted to unsigned, truncation between integer widths, or multiplication/addition overflow
- encoded/decoded/compressed size disagreement

### Initialization and Termination

- uninitialized stack/heap data returned in a response
- reused object/buffer retaining data from another request or tenant
- missing NUL termination followed by string length/format operations
- partial structure initialization with stale flags, pointers, or lengths
- padding, union, or serialization bytes copied beyond initialized fields

### Lifetime and Object Confusion

- use-after-free, double free, stale callback, iterator invalidation
- type/object confusion after parsing, casting, or virtual dispatch
- reference-count races and cross-thread ownership errors
- reallocation invalidating stored pointers
- constructor/destructor/finalizer behavior reached in an unexpected state

### Format and Variadic Errors

- attacker-controlled format string
- type/width mismatch in variadic arguments
- destination-size assumptions around `sprintf`-family calls
- logging/error paths that process attacker bytes after a partial parse

## Build the Input-to-Memory Model

Record:

```text
transport field -> parser type/width -> normalized value -> allocation
                -> copy/read/format operation -> object/buffer -> later use
```

For each relevant field, capture:

- wire offset/path, endian, encoding, signedness, and declared versus actual size
- validation order and parser state required to reach the operation
- allocation expression and destination capacity
- copy/read/write expression and implicit casts
- terminator/padding/alignment behavior
- attacker-controlled byte alphabet and precision
- thread, connection, session, heap, and restart lifetime

Trace both source-to-sink and sink-to-source. Start from changed bounds checks or crash instructions when available, but reconstruct the minimum valid protocol state that reaches them.

## Source-Available Workflow

### Compiler Instrumentation

Build a lab-only target or minimal harness with the compiler's maintained sanitizers when source permits:

```bash
clang -g -O1 -fno-omit-frame-pointer \
  -fsanitize=address,undefined \
  harness.c parser.c -o parser-harness
```

- Keep the harness local and networkless; call the narrow parser/API directly.
- Preserve the exact compiler, flags, architecture, allocator, and dependencies.
- AddressSanitizer changes layout and timing. Reproduce important behavior on a representative unsanitized build under a debugger before drawing exploitability conclusions.
- UndefinedBehaviorSanitizer may report conditions that do not produce the deployed security impact; trace each report to attacker control and later use. It does not replace explicit arithmetic and cast review.
- For ordinary uninitialized-value hypotheses, use a separate MemorySanitizer build such as `-fsanitize=memory -fsanitize-memory-track-origins=2`; it requires an instrumented dependency set and is not interchangeable with ASan.
- For race-dependent ownership or refcount paths, use a separate ThreadSanitizer build only when concurrency is in scope; do not imply the sanitizer families compose cleanly into one representative build.
- Add regression cases for the minimized triggering input and neighboring non-triggering controls.

### Static Review

Search around input parsing for:

- `memcpy`, `memmove`, `strcpy`, `strcat`, `sprintf`, `snprintf`, `scanf` families
- manual cursor/end-pointer arithmetic and nested TLV/XML/string parsers
- `malloc/calloc/realloc/new` size arithmetic
- signed/unsigned conversions and narrowing casts
- length values stored in smaller fields or reused across decoded representations
- error cleanup, ownership transfer, callbacks, and asynchronous lifetime
- custom allocators, pools, slabs, ring buffers, and request-buffer reuse

Do not report a dangerous function name without proving attacker control, reachable state, capacity mismatch, and the actual deployed implementation.

## Binary-Only Workflow

1. Identify architecture, endian, ABI, OS/libc, compiler clues, and stripped/symbol state.
2. Record NX/DEP, ASLR/PIE, stack canaries, RELRO, CFI/PAC/CET, allocator hardening, seccomp/sandbox, privilege, and restart behavior.
3. Anchor on imports, strings, message IDs, error paths, new checks, crash PC, or advisory-relevant constants.
4. Trace length/copy/allocation dataflow in decompiler and assembly.
5. Record the deployed binary identity: build ID or hash, interpreter or loader, loaded modules/base addresses, allocator, and whether the runtime executable came from base image, overlay, bind mount, or update staging.
6. Reproduce under a debugger or emulator only when its environment matches the relevant parser and allocator behavior.
7. Compare vulnerable and fixed functions; describe the restored invariant and inspect sibling callers.

Use official [Ghidra](https://github.com/NationalSecurityAgency/ghidra) for cross-architecture static analysis and [BinDiff](https://github.com/google/bindiff) for function-level version comparison after package/file diffs narrow the target. Similarity scores and decompiled C are triage aids, not proof; confirm critical conditions in assembly and runtime evidence.

## Crash and Disclosure Triage

Preserve one known-good transcript and then minimize while keeping the framing, checksums, parser state, and negotiation required to reach the vulnerable operation. Identify the first invalid access, not only the eventual crash site. Use a distinctive non-executable pattern to measure overwrite offset or disclosure position, classify whether the observed effect is read, write, non-control-data, pointer/object, or control-state influence, and then repeat the same case on a representative unsanitized build plus fixed and negative controls.

For each case, record:

- exact minimized input and protocol transcript
- deterministic frequency and required heap/session preparation
- signal/exception, PC, faulting instruction bytes/disassembly, fault address, access type/size, registers, stack, loaded mappings/build IDs, and relevant object memory
- process versus worker crash, watchdog/restart, and external symptom
- corrupted object provenance and last known-valid parser state
- vulnerable/fixed/unaffected build behavior
- whether the same case under debugger/sanitizer changes outcome

Deduplicate by root cause, not only crash address. One overwrite may crash at many later consumers; one parser family may contain multiple distinct missing checks.

For disclosures, classify the returned bytes:

- predictable padding or constant data
- same-request content
- cross-request/tenant secrets
- heap/stack pointers useful against ASLR
- session tokens, keys, credentials, or application data

Derive detectors from response structure or a constant non-secret marker rather than collecting sensitive memory.

## Primitive Analysis

### Write Primitive

- location: fixed, relative, attacker-derived, heap-neighbor, object field, return/control data
- width and count: single byte/bit, bounded span, arbitrary length, repeated writes
- value control: exact, restricted alphabet, additive, terminator, pointer-derived
- timing/state: before validation, after free, race-dependent, heap-shape-dependent
- repeatability under default allocator and mitigations

### Read/Leak Primitive

- offset and length control
- termination rules and response encoding
- ability to repeat/advance across memory
- cross-request process reuse
- pointer or secret classification
- noise, truncation, and crash threshold

### Control-Flow/Object Primitive

- overwritten callback, vtable, length, non-control-data flag, pointer, credential/session reference, allocator metadata, saved return state, or interpreter structure
- required heap grooming/object placement
- available modules/gadgets and address disclosure
- thread/process privilege and sandbox boundary after control
- whether the attacker can only corrupt a field, or can also choose the dereference target and value later consumed

Document what remains constrained. “Arbitrary write” should not be used for a relative, partial, alphabet-limited, or race-only overwrite.

## Exploitability Matrix

| Dimension | Record |
|---|---|
| Reachability | listener, authentication, feature/config, valid prior state |
| Platform | architecture, endian, ABI, firmware model/SKU |
| Input | transport, maximum size, forbidden bytes, encoding/transforms |
| Primitive | read/write/control precision, repeatability, heap dependence |
| Mitigations | ASLR/PIE, NX, canary, RELRO, CFI/PAC/CET, allocator, sandbox |
| Process | privilege, chroot/container, worker isolation, watchdog/restart |
| Information | version fingerprint, pointer/module/heap leak availability |
| Reliability | attempts, races, connection/session persistence, crash side effects |

Rate exploitability separately from bug severity. A strong memory disclosure can enable a later control-flow bug; a large overflow may remain crash-only under the deployed constraints.

## Protocol and Patch Pairing

- Load `protocol_reverse_engineering` when valid negotiation/state is required before the vulnerable field.
- Load `advisory_to_poc` for vulnerable/fixed artifact matrices and patch-invariant review.
- Load `appliance_firmware` for rootfs, listener, runtime overlay, architecture, and device lifecycle mapping.
- Model transformation boundaries explicitly when the memory length or type changes across transport, parser, decoder, or native FFI layers.

## Validation Deliverable

Include:

1. exact vulnerable/fixed build, platform, configuration, and artifact hashes
2. minimized input plus complete protocol/parser prerequisites
3. source, IR/bytecode, or assembly trace from attacker field to invalid access, with the exact crashing process/build identity
4. debugger/sanitizer/core evidence and non-triggering control
5. primitive precision and constraints
6. mitigation, architecture, allocator, process, and restart analysis
7. bug-existence and exploitability conclusions stated separately
8. adjacent callers/parser family reviewed

## False Positives

- Connection close caused by protocol rejection, idle timeout, rate limit, or load balancer behavior.
- Process restart inferred from one failed request without process/console evidence.
- Sanitizer finding unreachable in the deployed feature, route, architecture, or configuration.
- Out-of-bounds read that returns only deterministic in-buffer padding, described as sensitive disclosure.
- Crash-only overwrite called RCE without a controlled data/control primitive and mitigation analysis.
- Decompiler type or buffer size accepted as ground truth without assembly/runtime confirmation.
- Lab build with mitigations disabled presented as representative of production.

## Summary

Memory-corruption research is constraint analysis. Trace exact bytes through length, allocation, copy, object lifetime, and later use; establish the read/write/control primitive; then evaluate architecture, mitigations, allocator, protocol, and process context independently from the mere existence of a crash.
