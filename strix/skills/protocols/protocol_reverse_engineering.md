---
name: protocol-reverse-engineering
description: Authorized analysis of undocumented, proprietary, binary, or stateful network protocols using passive captures, client/server artifacts, explicit state machines, bounded lab harnesses, and semantic vulnerable-versus-fixed validation
---

# Protocol Reverse Engineering

Use this skill when an exposed service cannot be tested correctly as isolated HTTP-like requests: custom RPC, binary framing, TLS-wrapped management protocols, message queues, VPN negotiation, in-band control records, or any protocol whose authentication and parsing depend on prior state.

The objective is a reviewable protocol model and controlled evidence that proves or disproves a security property. A socket connection, completed TLS handshake, `200`, or parser crash does not prove authentication, authorization, or code execution.

## Authorization and Safety Boundary

- Work from supplied artifacts, offline captures, or an isolated lab target unless active testing is explicitly authorized.
- Prefer offline parsing. Captures may contain credentials, session material, personal data, or private topology; minimize, encrypt, redact, and expire them.
- Never replay production credentials or captured authentication material.
- Put active harnesses in a network namespace or isolated VLAN with an explicit destination allowlist, low rate, bounded retries, and one mutation at a time.
- Do not broadcast, scan unrelated addresses, or start mutation/fuzz loops by default.
- Treat a malformed-packet crash as a denial-of-service test. Perform it only in a restartable lab and never infer RCE from it.

## Build the Protocol Model

Record each layer separately:

| Layer | Questions |
|---|---|
| Transport | TCP, UDP, HTTP tunnel, queue, Unix socket, reconnect behavior? |
| Security | TLS/mTLS, certificate role, message MAC/signature, encryption boundary? |
| Framing | magic, version, type, flags, length, checksum, terminator, nesting? |
| State | negotiation, challenge, authentication, session, command, teardown? |
| Identity | where is peer/user/device identity introduced and verified? |
| Authorization | which state or role permits each operation? |
| Data model | integers, strings, TLV, XML/JSON, compression, serialization? |
| Responses | acknowledgements, errors, correlation IDs, timing, connection close? |

Maintain a message-field ledger:

```text
offset/path | size/type | endian/encoding | producer | consumer | validation | state | confidence
```

Label every statement as observed, inferred, or experimentally confirmed. Unknown bytes remain unknown; do not name them after a single sample.

## Workflow

### 1. Collect Passive Evidence

Use, in order of preference:

- official protocol or integration documentation
- offline captures of a legitimate client/server exchange
- client binaries, SDKs, schemas, constants, error strings, and debug logs
- server handlers, dispatch tables, configuration, and certificate logic
- vulnerable/fixed captures or binaries from the same branch

Use two supplied or explicitly authorized successful sessions and controlled variations when available. Otherwise record the evidence gap; do not obtain or replay production credentials merely to complete the model. Compare message boundaries, counters, nonces, lengths, identity fields, and state-dependent responses. Keep the original capture immutable and hash it.

Use [TShark](https://www.wireshark.org/docs/man-pages/tshark.html) for reproducible offline extraction:

```bash
tshark -r session.pcapng -q -z conv,tcp
tshark -r session.pcapng -Y 'tcp.stream == 0' -T fields \
  -e frame.number -e tcp.seq -e tcp.len -e tcp.payload
```

Prefer `-r` over live capture. Do not run Wireshark/TShark as root, capture unrelated production traffic, or assume dissector output is safe or correct; use a patched build in an isolated environment for hostile captures.

### 2. Reconstruct Framing Before Meaning

- Reassemble streams before assigning message boundaries; TCP packets are not application messages.
- Test length hypotheses against multiple messages and both directions.
- Identify byte order, signedness, alignment, padding, compression, and checksums.
- Separate outer transport/tunnel framing from the inner application message.
- For nested formats, model each parser boundary independently.
- Reject impossible lengths before allocation, recursion, decompression, or slicing.

When the layout stabilizes, encode it in a declarative grammar such as [Kaitai Struct](https://kaitai.io/). Add `valid` constraints and strict size/count limits; generated parsers can still allocate or recurse dangerously on hostile lengths. Keep compiler/runtime versions aligned and regression-test the grammar on positive, truncated, oversized, and unknown-type samples.

### 3. Recover the State Machine

Write transitions explicitly:

```text
DISCONNECTED -> TRANSPORT -> NEGOTIATED -> PEER_VERIFIED
             -> USER_AUTHENTICATED -> AUTHORIZED -> OPERATION
```

For every transition, record:

- initiating message and required prior state
- server-side check and identity source
- success, denial, and malformed responses
- state stored across messages or reconnects
- timeout/replay/counter behavior
- whether an alternate message type reaches the same handler

Distinguish transport establishment, peer verification, user authentication, session creation, role authorization, and successful privileged action. Prove the specific boundary relevant to the security claim.

### 4. Trace Fields to Decisions and Sinks

From binaries or source, anchor on message IDs, error strings, constants, certificate handling, dispatcher tables, and changed functions. Trace attacker-controlled fields through:

- length arithmetic, allocation, copy, termination, and integer conversion
- parser state, tag nesting, recursion, and unknown-field behavior
- identity selection, trust flags, signature/certificate verification, and session lookup
- shell/process calls, filesystem paths, deserialization, reflection, or product-native admin operations

Decompiler output is a hypothesis. Confirm important conditions in assembly, bytecode, runtime logs, or controlled packet results.

### 5. Build a Bounded Active Harness

Only craft packets after valid framing and state are understood. [Scapy](https://scapy.readthedocs.io/en/stable/) is appropriate for packet layers and stateful automata:

```bash
python -m pip install 'scapy==<reviewed-version>'
```

Start with a local responder or replay parser, not the appliance. Preserve a known-good transcript, mutate one semantic field, recompute dependent lengths/checksums, and compare the response. The harness must enforce:

- exact destination/port allowlist
- one target and one mutation by default
- rate, packet count, response size, timeout, and retry ceilings
- no broadcast/multicast and no automatic crash retry
- artifact logging without credentials or secret payloads
- cleanup and target health check after each risky case

Raw sockets may require privilege; isolate socket creation and drop privileges afterward where possible.

### 6. Design Semantic Experiments

Prefer experiments that answer one question:

- Does an invalid identity or signature reach the authorized state?
- Does a declared length govern copying, parsing, or only framing?
- Do duplicate/unknown fields change the selected handler?
- Does patched behavior add validation, change state, or block an outer route?
- Does a response prove the operation, or merely that dispatch began?

Use vulnerable, fixed, and malformed-negative controls. Repeat enough to separate deterministic semantics from loss, retransmission, process restart, load balancing, and timeout noise.

## Safe Oracles

Prefer, from least to most invasive:

1. distinctive protocol/version field
2. deterministic denial-versus-accept response
3. synthetic-account no-op or non-secret lab read
4. unique constant callback through explicitly authorized, preferably self-hosted OAST
5. inert canary write with cleanup
6. process execution only under separate explicit authorization when no lower-harm oracle can establish the required impact

A connection close is normally an ambiguous result. If crash validation is unavoidable, combine lab-only process logs, restart evidence, and a non-triggering control; report bug existence separately from exploitability.

When the starting point is an advisory, fixed build, patch, or public PoC, pair this skill with `advisory_to_poc` for evidence classification, artifact comparison, and partial-fix review.

## Patch and Version Differentials

- Compare message/state behavior across the closest vulnerable and fixed builds of the same branch.
- Derive a fingerprint from the restored invariant, not only from banners.
- Check configuration, certificate role, feature enablement, architecture, and deployment mode.
- Treat protocol differences as version evidence unless they directly prove vulnerable behavior.
- When one handler is patched, enumerate sibling message types, alternate transports, and pre-auth dispatch paths using the same parser or decision.

## Validation Deliverable

Include:

1. target versions, platform, configuration, and artifact/capture hashes
2. layered protocol diagram and message-field ledger
3. explicit state machine and identity/authentication/authorization boundaries
4. source/binary trace for the relevant field and decision
5. bounded harness with rate/destination safeguards
6. vulnerable, fixed, and negative-control results
7. minimum safe oracle and any side effects/cleanup
8. unresolved fields, assumptions, and confidence levels
9. bug-existence versus exploitability assessment
