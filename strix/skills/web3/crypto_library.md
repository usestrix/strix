---
name: crypto_library
description: Authorized review of cryptographic libraries — primitives, randomness, constant-time guarantees, and key handling.
---

# Cryptographic Library

A cryptographic library is the code that other software trusts to keep secrets: it implements ciphers, hashes, MACs, signatures, key exchange, RNGs, and key/serialization plumbing (PEM/DER, JWK, keystores). Because callers cannot easily tell whether the math is correct, a subtle defect — a non-constant-time comparison, a reused nonce, a predictable RNG, a skipped signature check — silently destroys the guarantee while every test still passes. The attacker's objective is to find the gap between what the API promises and what the implementation actually does, then turn it into key recovery, forgery, decryption, or authentication bypass.

## Attack Surface

**Public API**
- Encrypt/decrypt, sign/verify, MAC, KDF, key generation, key import/export
- AEAD wrappers, hybrid encryption, password hashing, token (JWT/PASETO/COSE) helpers
- "Easy"/"box" convenience APIs that hide nonce, IV, or padding handling from callers

**Primitive implementations**
- Block/stream ciphers, GCM/CCM/Poly1305, ECDSA/EdDSA/RSA, ECDH/X25519, hashes/XOFs
- Bignum/field arithmetic, modular inversion, point multiplication (scalar handling)

**Trust boundaries**
- Parsers for ASN.1/DER, PEM, X.509, JWK, PKCS#8/#12 — pre-key-validation attacker input
- Randomness source (OS CSPRNG, userspace PRNG, seeding, fork/VM-clone safety)
- FFI/bindings to native code; build flags that toggle hardening or assembly paths
- Side channels: timing, cache, branch, error-message and padding oracles, power (out of scope but noted)

## Recon & Enumeration

Treat the library as source-first. Most high-impact bugs are read off the code, not fuzzed out.

```bash
# Inventory the codebase, languages, and crypto deps
syft dir:./target -o table                 # SBOM of bundled crypto deps
grep -rIn -E "(MD5|SHA1|DES|RC4|ECB|PKCS1v15|Random\(|math/rand|ssl3|TLS1\.0)" target/

# Known-CVE / outdated-primitive scan against the dependency tree
grype dir:./target -o table
trivy fs --scanners vuln,secret target/

# Hardcoded keys, test vectors left as defaults, leaked private keys
trufflehog filesystem target/ --results=verified,unknown
gitleaks detect --source target/ --no-banner

# Semgrep crypto rulepacks (constant-time, weak rng, static IV, etc.)
semgrep --config p/r2c-security-audit --config p/crypto target/
semgrep --config p/insecure-transport target/

# If a Solidity/EVM crypto lib (precompiles, BLS, ecrecover wrappers):
pipx install slither-analyzer && slither . --detect weak-prng,suicidal,unchecked-lowlevel
pipx install mythril && myth analyze contracts/*.sol

# Compiled / native artifact: confirm hardening and assembly path actually shipped
binwalk -e libcrypto.so
checksec --file=libcrypto.so          # NX/RELRO/stack canary
nm -D libcrypto.so | grep -iE "memcmp|rand|ct_"
```

For a network-exposed service that wraps the library (KMS, signing oracle, token service):

```bash
naabu -host api.target.tld -top-ports 1000 -silent | httpx -silent -title -tech-detect
nuclei -u https://api.target.tld -tags jwt,ssl,exposure -s critical,high -silent -j -o crypto_svc.jsonl
jwt_tool <token> -M pb                  # probe alg confusion / weak secrets on issued tokens
katana -u https://api.target.tld -jc | ffuf -w - -u FUZZ   # map signing/decrypt/verify endpoints
```

## Methodology

1. **Map the promise.** Read the public API and docs. For each function note the security claim (confidential? authenticated? deterministic? constant-time?) and the secret it touches. These claims are your test oracles.
2. **Trace every secret.** Follow keys/nonces/IVs/seeds from generation through use to zeroization. Flag any value that is logged, copied without wipe, or exported in cleartext.
3. **Audit the RNG.** Identify the entropy source for keys, nonces, salts, and blinding. Verify it is the OS CSPRNG, properly seeded, and reseeded across `fork()`/snapshot.
4. **Check primitive parameters.** Nonce/IV uniqueness, GCM nonce length (96-bit), CTR counter reuse, RSA padding (OAEP vs PKCS#1v1.5), curve/point validation, key-size minimums.
5. **Hunt non-constant-time paths.** Tag comparisons, table lookups, and branches that depend on secret bytes (HMAC/tag compare, padding check, scalar bits, PIN/secret equality).
6. **Stress the parsers.** Feed malformed DER/PEM/JWK/X.509 to the import path before any key check runs; look for confusion, panics, or downgrade.
7. **Probe verification logic.** Confirm sign/verify and MAC actually reject tampered input; look for skipped checks, truncated tags, `alg:none`, and type confusion.
8. **Reproduce with vectors.** Build a minimal harness using official test vectors (NIST CAVP, Wycheproof) to prove correct vs. broken behavior deterministically.
9. **Escalate.** Convert each defect into the strongest concrete impact (forgery, key recovery, plaintext recovery) with a self-contained PoC.

## Key Weaknesses / Techniques

**Non-constant-time comparison (tag/MAC/secret).** A `==`, `memcmp`, or short-circuit string compare on a secret leaks position of the first mismatch via timing.
```bash
grep -rIn -E "memcmp\(|== *(mac|tag|sig|hmac|digest)|String\.equals|secrets\.compare_digest" target/
```
Validate timing dependence by measuring response time across many trials per guessed byte; correct code uses a branch-free `ct_compare`/`crypto.timingSafeEqual`/`hmac.compare_digest`.

**Nonce / IV reuse.** GCM/ChaCha20-Poly1305 nonce reuse under one key leaks the auth key (forgery) and XORs plaintexts. CTR/CBC static IV breaks confidentiality.
```bash
grep -rIn -E "iv *= *(b?\"|\[0|new byte\[)|nonce *= *0|static.*[Ii][Vv]" target/
```
Verify by encrypting two messages and checking the emitted nonce; identical nonce on distinct calls under the same key is a finding.

**Weak / predictable randomness.** Keys or nonces from `math/rand`, `java.util.Random`, `rand()`, time-seeded PRNGs, or unseeded userspace generators are recoverable.
```bash
grep -rIn -E "math/rand|java\.util\.Random|Math\.random|srand\(|new Random\(" target/
```
PoC: collect several outputs, recover internal state / seed, predict the next key or nonce.

**Padding / error oracles.** PKCS#1v1.5 (Bleichenbacher), CBC-PAD (Vaudenay), and AEAD that distinguishes "bad pad" from "bad MAC" enable adaptive decryption/forgery.
- Distinguishable error or timing between padding failure and MAC failure → oracle. Replay ciphertexts with flipped bytes and diff responses/latency.

**Signature verification flaws.**
- JWT `alg:none` or RS256→HS256 confusion (public key used as HMAC secret): `jwt_tool <tok> -X a` and `-X k -pk public.pem`.
- ECDSA: missing low-`s` check (malleability), accepting `r=0`/`s=0`, or non-deterministic nonce with biased bits → lattice key recovery.
- RSA: ignoring trailing bytes after the hash in PKCS#1v1.5 (BERserk/e=3 forgery); verify the parser is strict.

**Missing key/point validation.** No curve membership check enables invalid-curve attacks; small-subgroup/order checks missing on ECDH; RSA with tiny `e` or unverified CRT params.

**Key lifecycle defects.** Keys logged, serialized to disk unencrypted, kept in GC'd immutable strings (no wipe), exported via a debug endpoint, or default/test keys shipped.
```bash
grep -rIn -E "log.*key|print.*(priv|secret)|toString\(\).*key|BEGIN (RSA |EC )?PRIVATE" target/
trufflehog filesystem target/ --results=verified,unknown
```

**Downgrade / algorithm negotiation.** Library honors attacker-chosen weak cipher/hash, or falls back to MD5/SHA-1/DES/RC4/export ciphers.

## Validation

1. **Build a deterministic harness.** Pull Project Wycheproof and NIST CAVP vectors; run the library against them. A vector the library accepts-but-should-reject (or vice versa) is a confirmed, reproducible bug — far stronger than a heuristic match.
2. **Demonstrate the concrete primitive break:**
   - Constant-time: a statistically significant timing gradient correlated with secret bytes (report trial count and the recovered byte).
   - Nonce reuse: two ciphertexts with identical nonce under one key, plus the XOR/forgery they enable.
   - Weak RNG: predict the next key/nonce from prior outputs.
   - Signature: a forged token/signature the verifier accepts (e.g., a JWT minted via alg confusion that authenticates as another user in a test account).
3. **Self-contained PoC.** Provide a small script + exact inputs/outputs so a maintainer can reproduce without your environment.
4. **Bound the blast radius.** State which keys, sessions, or messages are affected and under what attacker position (chosen-ciphertext, network, co-resident).

## False Positives

- A flagged `memcmp` on **public** data (ciphertext, public key, non-secret length) — only secret-dependent comparisons matter.
- MD5/SHA-1 used for non-security purposes (checksums, cache keys, ETags, dedup) — confirm it is not authenticating or signing.
- "Static IV" that is actually a per-message random value assigned just before use, or a deterministic nonce scheme (SIV/AES-GCM-SIV) designed for reuse resistance.
- `math/rand` used for jitter, backoff, or test fixtures rather than key/nonce/salt material.
- ECB/PKCS#1v1.5 present only in legacy/compat code paths that are unreachable from the public API or gated off by default.
- Timing differences swamped by network noise or GC pauses — without controlled measurement it is not a finding.
- Semgrep/grype hits on a vendored dependency that is never built or linked into the shipped artifact (confirm with `syft`/`nm`).

## Chaining & Impact

- Non-constant-time tag compare → remote MAC forgery → authenticated-channel bypass or session token forgery.
- Predictable RNG → recover signing/session key → impersonate any user, mint valid tokens, decrypt past traffic (no forward secrecy).
- Nonce reuse in AEAD → recover Poly1305/GHASH key → forge arbitrary authenticated ciphertexts → tamper with encrypted commands.
- Padding oracle on a decryption endpoint → full plaintext recovery of stored secrets / session cookies without ever touching the key.
- ECDSA nonce bias across many signatures → lattice attack → private key recovery → total compromise (code signing, TLS, blockchain wallet drain).
- alg-confusion / `alg:none` in the JWT helper → forge admin tokens → full authn bypass of every service trusting the issuer.
- Unencrypted key export / key in logs → direct private-key theft → decrypt everything and sign as the victim indefinitely.

## Pro Tips

1. The bug is usually in the *glue*, not the cipher core — nonce management, parser, error handling, and the convenience API are where guarantees leak.
2. Always run Wycheproof: it encodes the exact edge cases (point at infinity, `s=0`, oversized DER, special curve points) that hand-written tests miss.
3. Constant-time claims are about the **binary**, not the source — compilers and `-O2` reintroduce branches. Inspect the emitted assembly or use `dudect`/`ctgrind` rather than trusting comments.
4. Check `fork()`/snapshot/VM-clone behavior of the RNG; cloud auto-scaling and container forking are a real-world source of duplicated nonces.
5. For signing oracles, deterministic nonces (RFC 6979/EdDSA) eliminate a whole bug class — flag any ECDSA path that does not use them.
6. Error messages and HTTP status/timing are oracles even when the crypto is "correct" — uniform failure handling is part of the security claim.
7. Don't trust version strings: a patched-version dependency can still be misused by the wrapper (e.g., GCM with a 64-bit truncated tag). Test behavior, not metadata.
8. When you find one weak default, sweep for siblings — the same author who shipped a static IV often shipped a hardcoded salt and a `math/rand` keygen nearby.
