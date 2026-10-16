---
name: cyberchef
description: Multi-layer payload deobfuscation, cryptographic decoding, heuristic recipe detection (magic), and entropy analysis via CyberChef MCP.
---

# CyberChef MCP Tooling Playbook

Official resources:
- https://github.com/gchq/CyberChef
- https://github.com/noor202401938-netizen/cyber-chef-mcp
- https://gchq.github.io/CyberChef/
- https://modelcontextprotocol.io

CyberChef MCP provides 33 core data transformation, cryptographic, compression (Gunzip, Gzip, Zlib, Raw Deflate), and forensic operations with zero external dependencies. Connected via the Model Context Protocol (MCP) server `cyberchef`, it enables Strix agents to autonomously analyze, deobfuscate, unpack, and verify encoded exploit payloads, authorization tokens, and obfuscated attack vectors with deterministic sub-millisecond execution.

## MCP Discovery & Dispatch Workflow

In Strix, agents interact with external MCP servers through the standard generic-dispatch tools:
1. **Discover Connection**: Call `list_mcps()` to verify that the `cyberchef` connection is active.
2. **Search Tools**: Call `search_mcp_tools(connection="cyberchef", query="magic")` to locate matching tool names.
3. **Inspect Schema**: Call `get_mcp_tool_schema(connection="cyberchef", tool="cyberchef_magic")` to review argument parameters.
4. **Dispatch Call**: Call `call_mcp(connection="cyberchef", tool="<tool_name>", arguments={...})` to execute the operation.

## High-Signal CyberChef Tools

When connected to `cyberchef`, the following tools are available on the connection:

- `cyberchef_magic`: Run heuristic detection across known encodings, ciphers, and hash formats. Returns recommended deobfuscation recipes and confidence scores.
- `cyberchef_bake`: Execute sequential operation chains (e.g. `[{"op": "From Base64"}, {"op": "URL Decode"}]`).
- `cyberchef_from_base64`: Decode standard or URL-safe Base64 strings.
- `cyberchef_to_base64`: Encode plaintext into Base64 / URL-safe Base64.
- `cyberchef_from_hex`: Convert hexadecimal sequences to text (supports `None`, `Space`, `0x`, `Comma` delimiters).
- `cyberchef_url_decode`: Decode single or multi-round percent-encoded parameters.
- `cyberchef_rot13`: Rotate characters by offset (default 13, Caesar cipher support).
- `cyberchef_xor`: Decrypt or apply bitwise XOR with secret key.
- `cyberchef_jwt_decode`: Parse and inspect header, claims, alg, and signatures of JSON Web Tokens.
- `cyberchef_entropy`: Calculate Shannon entropy to distinguish plaintext, compressed data, and encrypted or packed payloads.
- `cyberchef_defang_url`: Defang malicious or suspicious indicators (`hxxps://target[.]com`) for safe reporting.
- `cyberchef_extract_entities`: Extract URLs, IP addresses, and email addresses from raw logs or memory strings.

## Agent-Safe Baseline for Automation

### 1. Heuristic First (`cyberchef_magic`)
Always run `cyberchef_magic` via `call_mcp` on unknown high-entropy or encoded strings before guessing transformations:
```json
{
  "tool": "call_mcp",
  "arguments": {
    "connection": "cyberchef",
    "tool": "cyberchef_magic",
    "arguments": {
      "input": "ZXlKaGJHY2lPaUpTVXpVbkxh..."
    }
  }
}
```

### 2. Sequential Multi-Layer Deobfuscation (`cyberchef_bake`)
For payloads with layered obfuscation (e.g. Hex inside Base64 inside URL-encoded query params):
```json
{
  "tool": "call_mcp",
  "arguments": {
    "connection": "cyberchef",
    "tool": "cyberchef_bake",
    "arguments": {
      "input": "%34%38%36%35%36%63%36%63%36%66",
      "recipe": [
        { "op": "URL Decode" },
        { "op": "From Hex", "args": ["None"] }
      ]
    }
  }
}
```

### 3. Entropy Assessment & Raw-Byte Workflow
When evaluating whether a payload or parameter is encrypted, packed shellcode, or benign text, evaluate Shannon entropy through `call_mcp`.

Depending on whether you are assessing an encoded representation directly or require true 8-bit raw-byte entropy, use one of the two workflows below:

#### Workflow A: Direct Representation-Calibrated Entropy (`cyberchef_entropy`)
Pass the encoded string (Hex or Base64) directly to `cyberchef_entropy` without prior decoding:
```json
{
  "tool": "call_mcp",
  "arguments": {
    "connection": "cyberchef",
    "tool": "cyberchef_entropy",
    "arguments": {
      "input": "01a2fe89cb994821a0d8e4..."
    }
  }
}
```
`cyberchef_entropy` automatically detects the representation alphabet and returns `shannonEntropy`, `bitsPerChar`, `maxForAlphabet`, and `normalizedRatio` (saturation).

> [!IMPORTANT]
> **Calibrate entropy thresholds by input encoding representation:**
> Shannon entropy measures bits of information per character. The theoretical maximum is strictly bounded by the alphabet size ($\log_2(N)$):
> - **Hex Strings (16 characters, max 4.0 bits/char)**:
>   - *Plain text / formatted Hex*: ~2.5 – 3.2
>   - *High-entropy ciphertext / encrypted payload*: **3.8 – 4.0** (Cannot exceed 4.0!)
>   - *Warning*: Do not misclassify hex ciphertext scoring ~3.9 as low-entropy content.
> - **Base64 Strings (64 characters, max 6.0 bits/char)**:
>   - *Plain text Base64*: ~3.8 – 4.5
>   - *High-entropy ciphertext / packed data*: **5.7 – 6.0** (Cannot exceed 6.0!)
> - **Normalized Saturation Rule**: If `normalizedRatio >= 0.85` (or `verdict == "encrypted_or_compressed"`), the payload is near-maximal entropy for its alphabet, indicating encryption, CSPRNG keys, or compressed data.

#### Workflow B: Atomic Raw-Byte Entropy via `cyberchef_bake` (Recommended for Raw Binary Streams)
To evaluate true 8-bit Shannon entropy (max 8.0 bits/byte) on an encoded payload (Base64 or Hex), execute the decode operation and entropy analysis **atomically** in a single `cyberchef_bake` recipe:
```json
{
  "tool": "call_mcp",
  "arguments": {
    "connection": "cyberchef",
    "tool": "cyberchef_bake",
    "arguments": {
      "input": "rLYFVVXj/6ydut5XjZodQFTcIX3qdGy5lS4CBmdY...",
      "recipe": [
        { "op": "From Base64" },
        { "op": "Entropy" }
      ]
    }
  }
}
```
For Hex-encoded payloads:
```json
{
  "tool": "call_mcp",
  "arguments": {
    "connection": "cyberchef",
    "tool": "cyberchef_bake",
    "arguments": {
      "input": "4a8f1b9c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b...",
      "recipe": [
        { "op": "From Hex", "args": ["None"] },
        { "op": "Entropy" }
      ]
    }
  }
}
```
This in-engine pipeline keeps raw decoded byte buffers in memory without serializing non-UTF-8 bytes across the JSON-RPC boundary. The returned entropy report uses the 8-bit raw alphabet (`maxForAlphabet: 8`):
- **Raw Binary / Decoded Byte Streams (256 values, max 8.0 bits/byte)**:
  - *Plain text / uncompressed source code*: < 4.5 bits/byte
  - *Compressed archives / packed code / encrypted shellcode*: > 7.2 bits/byte

> [!CAUTION]
> **Do NOT attempt multi-turn raw byte passing across `call_mcp`:**
> `call_mcp` transports inputs and outputs over JSON-RPC strings. Arbitrary 8-bit binary bytes (such as non-printable ciphertext or compressed streams) cannot be safely represented or transported across JSON-RPC without corruption (mojibake, Unicode replacement characters `\uFFFD`, or truncation). Never call `cyberchef_from_base64` or `cyberchef_from_hex` and then attempt to pass the resulting string to `cyberchef_entropy` in a second `call_mcp` call. Always use `cyberchef_bake` to chain decoding and entropy atomically, or evaluate representation-calibrated entropy directly on the encoded string via `cyberchef_entropy`.

## Common Security Analysis Patterns

### Pattern 1: Nested WAF Bypass / Obfuscated Injection Vector
When target web applications accept encoded input in parameters or cookies:
1. Extract candidate parameter from HTTP request or response.
2. Call `call_mcp(connection="cyberchef", tool="cyberchef_magic", arguments={"input": candidate})` to determine layers.
3. Call `call_mcp(connection="cyberchef", tool="cyberchef_bake", arguments={"input": candidate, "recipe": [...]})` with the suggested pipeline to recover the plaintext injection string.
4. Verify whether the underlying query contains unsanitized SQLi (`UNION SELECT`), XSS, or SSRF vectors.

### Pattern 2: JWT Security Inspection
When encountering `Authorization: Bearer <token>` or session tokens:
1. Call `call_mcp(connection="cyberchef", tool="cyberchef_jwt_decode", arguments={"token": token})`.
2. Inspect the header: check for `alg: "none"`, `alg: "HS256"` with potential asymmetric public key confusion, or empty signatures.
3. Inspect claims: verify expiry timestamps (`exp`), issuer (`iss`), role/privilege elevations, and user identities.

### Pattern 3: XOR Obfuscation Recovery
When inspecting hardcoded binary strings, PowerShell scripts, or obfuscated malware droppers:
1. Identify probable key length or common plaintext prefix (e.g., `MZ`, `http`, `function`).
2. Run `call_mcp(connection="cyberchef", tool="cyberchef_xor", arguments={"input": data, "key": candidate_key})` iterating candidate keys to extract underlying C2 endpoints or script payloads.

### Pattern 4: Encrypted / Compressed Payload & Entropy Classification
When verifying whether an unknown string parameter is ciphertext, packed shellcode, or a high-entropy secret token:
1. **Calibrated check**: Call `call_mcp(connection="cyberchef", tool="cyberchef_entropy", arguments={"input": candidate})`. Inspect `normalizedRatio` and `verdict`. If `normalizedRatio >= 0.85`, it is probable ciphertext or compressed data.
2. **Raw-byte verification**: If strict 8-bit thresholds (> 7.2 bits/byte) are required, run `call_mcp(connection="cyberchef", tool="cyberchef_bake", arguments={"input": candidate, "recipe": [{"op": "From Base64"}, {"op": "Entropy"}]})` (or `From Hex`).

## Critical Correctness Rules

- **Use `call_mcp` Dispatch**: Never attempt to call CyberChef tools directly as top-level agent tools. Always dispatch through `call_mcp(connection="cyberchef", tool="...", arguments={...})`.
- **Atomic Raw-Byte Entropy Execution**: Never attempt to pass decoded raw binary bytes between separate `call_mcp` calls. JSON-RPC cannot transport arbitrary non-printable bytes without corruption. When evaluating raw byte entropy for Base64 or Hex payloads, always chain `From Base64`/`From Hex` and `Entropy` atomically in a single `cyberchef_bake` recipe.
- **Do Not Guess Encodings**: If a string contains `=, %, 0x` or unexpected symbols, run `cyberchef_magic` first rather than blindly applying base64 or URL decoding.
- **Preserve Raw Inputs**: Keep the original obfuscated string in agent memory/notes alongside the decoded output for accurate proof-of-concept (PoC) reporting.
- **Fail-Safe Fallback**: If an operation fails during `cyberchef_bake`, isolate the failing recipe step and execute individual tools (`cyberchef_from_base64`, `cyberchef_url_decode`) sequentially via `call_mcp`.
- **Safe Defanging**: Always run `cyberchef_defang_url` via `call_mcp` on confirmed malicious or C2 URLs before writing final markdown reports.

## Failure Recovery

- If `cyberchef_from_base64` throws a padding error, retry with `urlSafe: true` or inspect whether characters are URL percent-encoded first.
- If `cyberchef_from_hex` produces unprintable characters, check if the input is big-endian or uses custom delimiters (`0x`, `Space`, `,`).
- If `call_mcp` returns an unknown tool error, call `search_mcp_tools(connection="cyberchef", query="...")` to discover the exact tool names registered by the server.

If uncertain, query web_search with:
`site:gchq.github.io/CyberChef cyberchef <operation_name>`
