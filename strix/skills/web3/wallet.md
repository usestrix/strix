---
name: wallet
description: Assess crypto wallet key storage, signing flows, and transaction-approval UX across browser extensions, mobile apps, and embedded/MPC backends.
---

# Wallet (Identifier)

A wallet is the identifier and trust boundary that maps a private key (or MPC key share) to on-chain identity and signing authority. The asset spans browser-extension wallets, mobile wallets, hardware-backed and embedded wallets, and custodial/MPC backends. The attacker's objective is to extract or exercise signing authority without the owner's intent: recover seeds/keys from storage, coerce a signature through a deceptive approval flow, or abuse a signed message/transaction to drain funds or take over the account that gates an app's auth. Treat any path that yields a valid signature over attacker-chosen data as equivalent to key compromise.

## Attack Surface

**Key material at rest**
- Browser extension: `chrome.storage.local`, IndexedDB, LevelDB vaults, `localStorage` (encrypted keyring blobs)
- Mobile: Keychain (iOS) / Keystore (Android), SharedPreferences, SQLite, app sandbox files, cloud/iCloud/Android backups
- Embedded/MPC: server-held key shares, KMS/HSM wrappers, recovery share escrow, social-recovery guardians

**Signing entry points**
- `eth_sign`, `personal_sign`, `eth_signTypedData_v4` (EIP-712), `eth_sendTransaction`, `wallet_sendCalls` (EIP-5792)
- WalletConnect (v2) session proposals and `wc:` pairing URIs / deep links
- dApp connector: `window.ethereum` / EIP-1193 provider, `wallet_addEthereumChain`, `wallet_switchEthereumChain`
- "Sign-In with Ethereum" (EIP-4361 / SIWE) auth messages
- Solana `signMessage` / `signTransaction` / `signAllTransactions`

**Approval / consent UX**
- Transaction confirmation screens, spend-limit (ERC-20 `approve` / `Permit` / `Permit2`) prompts
- Network/chain switch prompts, account-disclosure prompts
- Deep links and intent handlers that pre-fill or auto-confirm

**Backend / API**
- Wallet-as-a-service signing APIs, gas sponsorship / paymaster (ERC-4337) endpoints
- RPC providers and bundler endpoints, broadcast/relayer services

## Recon & Enumeration

Most relevant tools are in the sandbox. Asset-specific tooling install commands noted inline.

```bash
# --- Map the dApp / wallet web surface ---
subfinder -d target.tld -all -silent | httpx -silent -title -tech-detect -o hosts.txt
katana -u https://app.target.tld -jc -kf all -d 5 -o urls.txt        # crawl + JS for provider calls
nuclei -l hosts.txt -as -s critical,high -rl 50 -c 20 -bs 20 -timeout 10 -j -o nuclei.jsonl

# --- Hunt for leaked keys / seeds / RPC secrets (the highest-value bug) ---
trufflehog filesystem ./build --only-verified --json > tf.json
trufflehog git https://github.com/org/wallet-app --only-verified
gitleaks dir ./ -v --report-path gitleaks.json
# Regexes worth grepping JS bundles / source / configs:
#   BIP-39 mnemonic (12/24 words), 0x[0-9a-f]{64} priv keys, "INFURA_KEY", "ALCHEMY", "PRIVATE_KEY="

# --- Browser-extension static analysis ---
# Pull the .crx, unzip, then audit manifest + storage handling
unzip wallet.crx -d ext/ ; jq . ext/manifest.json     # check permissions, host_permissions, CSP
semgrep --config p/javascript --config p/secrets ext/  # weak crypto, postMessage, eval, dynamic import
grep -rnE 'eth_sign|personal_sign|signTypedData|chrome.storage|localStorage' ext/

# --- Mobile (APK / IPA) static analysis ---
# apktool d app.apk ; or use jadx for decompiled Java/Kotlin
pip install apkleaks ; apkleaks -f app.apk            # URIs, secrets, endpoints
grep -rnE 'getSharedPreferences|MODE_WORLD|allowBackup|android:debuggable' app/
# Confirm Keystore usage vs plaintext: look for SharedPreferences writing seed/key strings

# --- Smart-contract / approval target analysis (if a contract gates the wallet's funds) ---
pip install slither-analyzer mythril
slither 0xTokenOrVault --etherscan-apikey $KEY        # or slither ./contracts
myth analyze contracts/Vault.sol --execution-timeout 120

# --- WalletConnect / RPC endpoint probing ---
naabu -host rpc.target.tld -p 80,443,8545,8546 -silent
httpx -u https://rpc.target.tld:8545 -json -method POST \
  -body '{"jsonrpc":"2.0","method":"eth_accounts","id":1}'   # unauth account exposure?

# --- OAST for blind callbacks from any URL/metadata the wallet fetches ---
interactsh-client -v                                  # token-list / NFT-metadata SSRF oracle
```

## Methodology

1. **Define the boundary.** Identify each component holding or exercising signing authority: extension keyring, mobile keystore, embedded/MPC backend, hardware bridge. Each is tested separately.
2. **Hunt key material first.** Run trufflehog/gitleaks over repos, build artifacts, and JS bundles; inspect extension storage and mobile preferences for plaintext or weakly-encrypted seeds/keys. A leaked key ends the engagement on that account.
3. **Audit the at-rest crypto.** Determine the vault KDF and parameters (scrypt/PBKDF2 iterations, salt uniqueness, AES-GCM vs ECB). Weak KDF + exfiltrable blob = offline brute-force.
4. **Map signing methods.** Enumerate every RPC method the provider exposes to a dApp. Flag legacy `eth_sign` (blind signing of arbitrary 32-byte hashes) and any auto-approve path.
5. **Probe the approval UX.** Build a hostile dApp that requests signatures and watch what the confirmation screen actually shows: is the spender, amount, chain, and decoded calldata accurate and unspoofable?
6. **Test SIWE / signed-message auth.** Capture the SIWE message; check domain binding, nonce, expiry, and chainId. A reusable or domain-agnostic signature is account takeover.
7. **Test allowance flows.** Look for unlimited `approve`, blind `Permit`/`Permit2`, and `setApprovalForAll` requests obscured in the UX.
8. **Assess the backend signer.** For WaaS/MPC, test authn/authz on signing APIs, replay, IDOR across user keys, and gas-sponsorship abuse.
9. **Validate with a PoC** that produces a real (testnet) signature or storage extraction, then document chaining and impact.

## Key Weaknesses / Techniques

**Plaintext or weakly-encrypted key storage.** Seed/private key written to `localStorage`, SharedPreferences, or an SQLite row in clear, or encrypted with a low-iteration KDF.
```bash
# Pull extension vault and inspect KDF strength
strings ext_storage/leveldb/*.ldb | grep -iE 'salt|cipher|kdf|iterations|"data"'
# If the encrypted blob is exfiltrable and KDF is weak, mount an offline guess against the unlock password.
```

**Blind signing via `eth_sign`.** `eth_sign` signs an opaque hash; an attacker presents a hash that is actually `keccak256(rlp(transaction))`, turning a "sign this message" prompt into an authorized transfer.
```js
// Hostile dApp request — the user sees only a hex blob, not a transfer
ethereum.request({ method: 'eth_sign', params: [userAddr, '0x' + dangerousTxHash] })
```
Finding: wallet allows `eth_sign` without a hard warning / decoded preview.

**EIP-712 typed-data spoofing.** `signTypedData_v4` payloads (`Permit`, `Permit2`, Seaport orders) are human-unreadable; the approval screen may not decode `spender`, `value`, or `deadline`, so an off-chain signature authorizes a later drain.
```json
{"types":{"Permit":[{"name":"owner","type":"address"},{"name":"spender","type":"address"},
{"name":"value","type":"uint256"},{"name":"nonce","type":"uint256"},{"name":"deadline","type":"uint256"}]},
"domain":{"name":"USDC","chainId":1,"verifyingContract":"0xA0b8..."},
"message":{"spender":"0xATTACKER","value":"115792089237316195423570985008687907853269984665640564039457584007913129639935"}}
```

**Unlimited / hidden allowances.** `approve(spender, uint256max)` or `setApprovalForAll(operator,true)` requested under a benign label. Verify the prompt surfaces spender identity and the actual amount.

**SIWE / signed-auth flaws.** Missing domain binding, static/absent nonce, no expiry, or chainId not enforced → a signature captured on a phishing domain (or replayed) authenticates the victim elsewhere.
```bash
# Replay a captured SIWE signature against the auth endpoint
httpx -u https://app.target.tld/api/siwe/verify -method POST \
  -body '{"message":"<captured-siwe-message>","signature":"0x<captured-sig>"}'
```

**Malicious chain/network injection.** `wallet_addEthereumChain` adding a chain whose RPC is attacker-controlled, or a spoofed chainId that makes the user sign for a different network than displayed.

**Backend signer authz / replay.** WaaS or MPC signing API that lacks per-request authn, allows IDOR across `userId`/`keyId`, or accepts replayed signing requests.
```bash
# Swap the owner identifier and see if you can sign for another user's key
httpx -u https://api.target.tld/v1/wallets/<victimId>/sign -method POST \
  -H 'Authorization: Bearer <attackerToken>' -body '{"payload":"0x<txhash>"}'
```

**Clipboard / deep-link hijack.** Mobile wallets that auto-fill recipient from clipboard, or `wc:`/custom-scheme deep links that pre-populate or auto-confirm a transaction.

**Token-list / NFT-metadata SSRF & XSS.** Wallet fetches remote token logos / NFT JSON; unvalidated URLs hit internal services (use the interactsh oracle) or render HTML/SVG that executes script in the wallet UI context.

## Validation

- **Key extraction:** Demonstrate recovery of the seed/private key from an exfiltrated artifact (storage blob, backup, repo), or recompute the address from the recovered key to prove it matches the target wallet. Show the offline KDF crack only against your own test password.
- **Signature coercion:** On a testnet, run the hostile dApp end-to-end and capture a valid signature/transaction the wallet produced over attacker-chosen data; verify with `ecrecover` that the signer == target address.
- **SIWE replay:** Show the captured signature authenticating a session you did not legitimately establish (new cookie/JWT issued).
- **Backend signer:** Produce a signature for a key/user other than the authenticated principal, or replay a prior signing request successfully.
- Always prove signer recovery (`ecrecover` / `personal_recover`) so a finding is not just "a prompt looked odd."

## False Positives

- Encrypted vault that is only decryptable with the user's password and uses a strong KDF (high-iteration scrypt/PBKDF2, unique salt) — exfiltrating the blob alone is not key compromise.
- Hardware-wallet or secure-enclave-bound keys where the host never sees the private key; a "leaked" handle is not the key.
- `eth_sign` blocked or hard-gated behind an explicit risk acknowledgment.
- SIWE signatures that are correctly domain-bound, nonced, and time-limited — capturing one does not yield reuse.
- OAST callbacks whose source IP is the tester/browser, not the wallet backend (client-side fetch, not server SSRF).
- Testnet-only signing demos that cannot affect mainnet keys or funds.
- Allowance prompts that fully and accurately decode spender + amount and let the user edit the limit.

## Chaining & Impact

- Leaked seed/private key → full key compromise → drain all assets across every chain that key controls.
- Exfiltrable vault + weak KDF → offline password crack → key recovery → drain.
- Blind `eth_sign` / spoofed EIP-712 `Permit` → off-chain signature → later on-chain `transferFrom` drains tokens without a second prompt.
- Hidden `setApprovalForAll` → operator drains an entire NFT collection.
- SIWE replay / weak nonce → account takeover of the dApp the wallet authenticates, then in-app fund movement or admin actions.
- Backend signer IDOR/replay → sign for arbitrary users → mass drain of a custodial/MPC fleet.
- Token-list SSRF → cloud metadata creds → control-plane access to the wallet provider's infrastructure.

## Pro Tips

1. The cheapest critical is a leaked key — run trufflehog/gitleaks across repos, CI logs, and minified bundles before anything dynamic.
2. Off-chain signatures (`Permit`, `Permit2`, Seaport) are more dangerous than transactions: they cost no gas, leave no on-chain trace until executed, and approval UX rarely decodes them. Prioritize them.
3. Always run `ecrecover` on any signature you obtain — a recovered address matching the target is unambiguous proof and removes UX subjectivity.
4. Diff what the approval screen *shows* against what is actually signed; the gap between displayed intent and signed bytes is where most real wallet bugs live.
5. For extensions, the storage layer (LevelDB/IndexedDB) is the prize — `chrome.storage.local` survives across sessions and is readable by any code with the extension's origin.
6. On mobile, check `android:allowBackup` and iCloud Keychain sync; a seed that syncs to a backup is reachable without rooting the device.
7. Test `wallet_addEthereumChain` with an attacker RPC — a wallet that trusts the dApp-supplied chainId/RPC can be made to display one network while signing for another.
8. For MPC/WaaS, the key never leaves the backend, so pivot from "extract the key" to "make the backend sign" — authz, IDOR, and replay on the signing API are the real targets.
