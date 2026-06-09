---
name: dlt
description: Assessing permissioned distributed-ledger platforms — consensus, membership/identity, and the smart-contract execution layer.
---

# DLT (Permissioned Distributed Ledger)

A DLT identifier points at a permissioned ledger deployment — Hyperledger Fabric, R3 Corda, Quorum/GoQuorum, Hyperledger Besu (IBFT/QBFT), or ConsenSys-style consortium chains — where a known set of organizations run nodes, an MSP/CA controls who may transact, and ordering/consensus is BFT or crash-tolerant rather than open proof-of-work. Unlike a public chain, trust is concentrated in identity infrastructure and node operators. The attacker's objective is to subvert one of three layers: **consensus/ordering** (forge or reorder blocks, halt the network), **membership/identity** (mint or steal a valid identity, escalate org roles), or the **contract layer** (chaincode/CorDapp/smart-contract logic that moves assets or exposes private data). Compromising any one frequently yields read access to "private" ledger state or the ability to commit fraudulent transactions that all nodes accept as canonical.

## Attack Surface

**Node & peer RPC/APIs**
- Fabric: peer (`7051` gossip/endorsement), orderer (`7050`), CA (`7054`), operations/metrics (`9443`, `9444`)
- Besu/Quorum: JSON-RPC HTTP `8545`, WS `8546`, GraphQL `8547`, P2P/devp2p `30303`, Raft `50400`, privacy manager Tessera/Orion (`9101`, `9081`)
- Corda: P2P AMQP `10002`, RPC `10003`, node shell SSH, network-map and doorman HTTP services

**Identity / membership**
- Fabric CA enrollment/registration REST (`/enroll`, `/register`, `/reenroll`, `/revoke`), MSP cert stores, `connection.json` / wallet files
- Corda doorman/CSR signing endpoints, network parameters file
- TLS client certs, admincerts, and signing keys often shipped in repos or container images

**Contract / app layer**
- Fabric chaincode (Go/Node/Java) invoked via gateway SDK; CC2CC calls; private data collections (PDC)
- Quorum/Besu EVM contracts (often Solidity) plus `eth_*`/`priv_*` privacy methods
- CorDapp flows, contract `verify()` constraints, oracle services
- Off-chain gateways, REST wrappers, explorer UIs (Hyperledger Explorer, Blockscout, Cakeshop)

**Operational glue**
- CouchDB state DB (Fabric, `5984`), LevelDB; Kafka/Raft for ordering
- Config management: genesis block, `configtx.yaml`, channel config, network parameters
- CI/CD that signs and packages chaincode

## Recon & Enumeration

```bash
# Port + service sweep across consortium hosts (in scope)
naabu -host <node> -p 7050,7051,7054,8545,8546,8547,9443,10002,10003,30303,5984,50400 -o ports.txt
nmap -sV -sC -p- --open <node> -oA dlt_node

# Web/API surface of explorers, REST gateways, CA
httpx -l hosts.txt -ports 7054,8545,8547,9443,5984,8080,3000 -title -tech-detect -status-code -o http.txt
nuclei -l http.txt -tags exposure,misconfig,blockchain,ethereum -s critical,high,medium -j -o nuclei.jsonl

# EVM JSON-RPC fingerprint + method exposure (Quorum/Besu)
curl -s -X POST http://<node>:8545 -H 'content-type:application/json' \
  -d '{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}'
for m in admin_peers admin_nodeInfo txpool_content debug_traceTransaction \
         personal_listAccounts miner_start eth_accounts net_version clique_getSigners \
         istanbul_getValidators priv_getPrivateTransaction; do
  curl -s -X POST http://<node>:8545 -H 'content-type:application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"$m\",\"params\":[],\"id\":1}"; echo " <= $m"
done

# Fabric CA: probe enrollment surface + cert info
curl -sk https://<ca>:7054/cainfo | jq .
curl -sk https://<ca>:7054/api/v1/cainfo | jq .

# CouchDB state DB exposure (Fabric)
curl -s http://<node>:5984/_all_dbs
curl -s http://<node>:5984/_utils/   # Fauxton UI

# Operations/metrics + health (often unauthenticated)
curl -s http://<node>:9443/metrics | head; curl -s http://<node>:9443/healthz

# Directory/asset discovery on gateways and explorers
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://<gw>/FUZZ -mc 200,401,403
katana -u http://<explorer> -d 3 -jc -o explorer_endpoints.txt

# Secrets in any pulled artifacts (repos, images, wallets, connection profiles)
trufflehog filesystem ./artifacts --only-verified
gitleaks detect -s ./repo -v
grep -rEl 'BEGIN (EC |RSA )?PRIVATE KEY|adminCerts|signcerts|"private_key"' ./artifacts

# Container image audit (node/CA/chaincode images)
trivy image <registry>/fabric-peer:<tag>
syft <registry>/quorum:<tag> -o table   # if asset-specific SBOM needed: install via curl -sSfL https://get.anchore.io/syft | sh

# Smart-contract / chaincode static analysis
# Solidity (Quorum/Besu): pip install slither-analyzer; pip install mythril (or docker)
slither contracts/ --json slither.json
myth analyze contracts/Vault.sol
# Go/Node/Java chaincode + CorDapps:
semgrep --config p/owasp-top-ten --config p/secrets chaincode/
```

Asset-specific tooling worth installing: `slither`/`mythril` for EVM contracts, `web3.py`/`ethereum-input-decoder` for RPC interaction, the Fabric `peer`/`fabric-ca-client` binaries for channel and identity probing, `corda-tools` shell, `jwt_tool` for any gateway JWTs, and `interactsh-client` for blind callbacks from oracle/webhook flows.

## Methodology

1. **Map the topology.** Identify ledger flavor (Fabric vs Quorum/Besu vs Corda) from ports, `web3_clientVersion`, CA banners, and any explorer. Enumerate orgs, peers, orderers/validators, and the consensus type (Raft/Kafka, IBFT/QBFT/Clique, BFT-SMaRt, Notary).
2. **Inventory exposed control planes.** For each node, determine which admin/privileged RPC namespaces (`admin_`, `personal_`, `miner_`, `debug_`, `txpool_`, `clique_`/`istanbul_`, `priv_`) or operations endpoints answer without auth. These are the highest-value misconfigs.
3. **Probe membership/identity.** Test whether the CA/doorman will enroll or register an identity with weak/default bootstrap credentials, whether CSRs are signed without approval, and whether wallet/MSP material leaked into images, repos, or backups.
4. **Assess channel/network config.** Pull channel config (`configtxlator`) or network parameters; review endorsement policies, admin policies, ACLs, and which orgs can sign config updates. A single-org admin policy is a takeover primitive.
5. **Audit the contract layer.** Statically analyze chaincode/CorDapp/Solidity for access-control gaps, missing endorsement enforcement, integer/decimal handling, phantom reads in PDC, and unchecked external calls. Then dynamically invoke from a low-privilege identity.
6. **Test private-data confidentiality.** Verify that "private" collections, `priv_` transactions (Tessera/Orion), and Corda need-to-know flows actually withhold data from non-party nodes.
7. **Assess consensus resilience.** Without disrupting production, reason about validator-set governance, quorum thresholds, and whether one compromised org/validator can halt ordering or, in Raft/Clique, gain disproportionate control.
8. **Chain and prove impact.** Convert a leaked identity or open RPC into a committed fraudulent transaction, an unauthorized state read, or a documented denial-of-service path — then stop at a benign PoC.

## Key Weaknesses / Techniques

- **Unauthenticated/over-exposed admin RPC.** `personal_*` and `miner_*`, or `clique_propose`/`istanbul_propose` reachable without auth lets an attacker unlock accounts, send transactions, or vote validators in/out. Validate:
  ```bash
  curl -s -X POST http://<node>:8545 -H 'content-type:application/json' \
    -d '{"jsonrpc":"2.0","method":"clique_getSigners","params":["latest"],"id":1}'
  # If clique_propose/istanbul_propose is open, a malicious org can add itself as a validator.
  ```
- **`debug_`/`txpool_` information disclosure.** `debug_traceTransaction`, `debug_storageRangeAt`, and `txpool_content` leak pending private transactions, storage slots, and counterparties — breaking the confidentiality that justified using a permissioned chain.
- **Weak CA bootstrap / open enrollment.** Default `admin:adminpw` on Fabric CA, or a doorman that auto-signs CSRs, lets you mint a fully valid org identity:
  ```bash
  fabric-ca-client enroll -u https://admin:adminpw@<ca>:7054 --tls.certfiles ca.pem
  fabric-ca-client register --id.name rogue --id.secret pw --id.type client
  ```
- **Leaked MSP/wallet/keys.** `signcerts`, `keystore` private keys, `connection.json`, or `*.id` wallet files committed to repos or baked into images grant the holder that identity's full transaction rights. Hunt with `trufflehog`/`gitleaks` and inspect container layers.
- **Permissive endorsement / admin policies.** Endorsement policy `OR('Org1.member')` or channel admin policy satisfiable by one org means a single compromised peer can endorse and commit arbitrary state, or rewrite channel config (ACLs, MSPs).
- **Chaincode/contract access-control gaps.** Missing caller checks (`cid.GetID()` / `GetMSPID()` not enforced; Solidity functions lacking `onlyRole`/`require(msg.sender==…)`) allow privilege escalation or unauthorized asset transfer. Flagged by `slither`'s `arbitrary-send`, `unprotected-upgrade`, `tx-origin`, and missing-modifier detectors.
- **Private-data leakage.** PDC defined without proper `memberOnlyRead`/`memberOnlyWrite`, or `priv_` transactions where the payload is reconstructable via `debug_` or an over-broad Tessera peer list.
- **CouchDB rich-query injection / exposure.** Selector queries built from unsanitized input (`getQueryResult`) allow phantom reads and unindexed selector abuse; an open CouchDB port exposes raw world state and admin Fauxton.
- **Replay / nonce & chainID handling.** Pre-EIP-155 Quorum configs or contracts without nonce binding allow cross-chain or in-chain transaction replay.
- **Consensus governance flaws.** Clique/IBFT validator addition by simple majority of a small set, or Raft leader concentration on one operator, makes a single-org compromise a network-control event.

## Validation

- Confirm an exposed RPC is *actionable*, not just present: read a non-public datum (e.g., `debug_storageRangeAt` returning a private slot, or `txpool_content` showing a counterparty) and capture the raw JSON response.
- For identity flaws, enroll a benign test identity and use it to **read** ledger state you should not see, or submit a clearly-labeled no-op/test-namespace transaction that nodes accept — never touch production asset balances.
- For chaincode/contract bugs, write a minimal PoC invocation from a low-privilege identity that triggers the unauthorized path on a test channel/contract; record the resulting state delta and the endorsing peers.
- For private-data leakage, demonstrate that a node *not* in the collection/party set can reconstruct the data, with the request and response side by side.
- Capture validator set, channel/network config hash, block height, and tx ID for every finding so it is reproducible and time-anchored.

## False Positives

- Admin RPC methods that respond but are bound to localhost only, or gated behind mTLS the tester is actually presenting — reachability from the in-scope network must be proven.
- `eth_accounts`/`personal_listAccounts` returning empty is informational, not a key-exposure finding.
- CA enrollment that succeeds with credentials *you were provisioned* — that is intended, not a break.
- `slither`/`mythril` reentrancy or `tx.origin` hits on view-only or owner-gated functions, or on contracts not actually deployed on the in-scope network.
- "Exposed" CouchDB/metrics ports that are inside an isolated overlay network unreachable from any attacker-controlled position.
- Pending transactions visible in `txpool_content` that are already public by design (e.g., non-private value transfers on a fully-shared channel).

## Chaining & Impact

- Leaked/minted identity → submit endorsed transaction satisfying a weak endorsement policy → **fraudulent asset transfer or state forgery** accepted by all peers.
- Open CA/doorman → mint org-admin identity → push a channel/network config update (add MSP, relax ACLs) → **persistent consortium-level control**.
- `debug_`/`priv_`/Tessera exposure → reconstruct private transactions → **confidentiality breach** of supposedly need-to-know data, plus counterparty intelligence.
- `clique_propose`/`istanbul_propose` access → vote in a controlled validator → reach quorum influence → **block-production control or selective censorship**.
- Chaincode RCE/SSRF (chaincode calling external services with attacker input) → pivot from the contract sandbox to the peer host or internal network; combine with leaked TLS certs for lateral movement.
- Ordering-service DoS (overwhelm Raft leader / exploit a panic in chaincode) → **ledger halt**, denying all member transactions.

## Pro Tips

- Fingerprint flavor first; the entire playbook forks on Fabric vs EVM-permissioned vs Corda. `web3_clientVersion` + CA banner + port shape settle it in seconds.
- The richest findings are usually *operational*, not cryptographic: an open `debug_`/`personal_` namespace or a leaked `keystore` beats hunting for a BFT break.
- Always pull and diff channel/network config — endorsement and admin policies are where "permissioned" silently becomes "single-org-controlled."
- Treat private-data collections and `priv_` transactions as suspect by default; vendors frequently leak the payload through trace/debug methods or an over-broad privacy-peer list.
- Decode raw transactions before reporting impact — an "unauthorized write" that the contract would have reverted is noise; confirm the state delta committed.
- For consensus claims, reason from the validator/quorum *governance* model (who can add/remove signers) rather than attempting live disruption against production.
- Keep all PoC transactions in a dedicated test namespace/channel with obviously benign payloads, and record block height + tx ID so the operator can verify and roll back.
