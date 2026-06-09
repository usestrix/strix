---
name: cross_chain_bridge
description: Assessing cross-chain bridges — message verification, replay protection, and custody logic across source/destination chains and relayers.
---

# Bridge / Cross-chain

A cross-chain bridge moves value or messages between chains by locking/burning on a source chain and minting/releasing on a destination chain. Trust is split across on-chain contracts (vault/escrow, mint gateway, message verifier), an off-chain relayer/validator/oracle set, and a message format that both sides must agree on. The attacker's objective is to make the destination chain accept a withdrawal or mint that the source chain never authorized — by forging a message, replaying a valid one, or breaking the custody invariant `minted == locked`. Bridges hold pooled custody, so a single accepted forgery often drains the entire vault.

## Attack Surface

**On-chain (per chain)**
- Source: `deposit`/`lock`/`burn`/`sendMessage` entry points; emitted event is the canonical message.
- Destination: `withdraw`/`mint`/`executeMessage`/`receiveMessage`; verifies a proof or quorum signature, then pays out.
- Verifier internals: Merkle/MPT proof checker, light-client header store, threshold-signature (ECDSA/BLS) check, guardian/validator set registry.
- Privileged surface: `setValidatorSet`, `pause`/`unpause`, fee/limit setters, upgrade proxy admin, owner/multisig.

**Off-chain**
- Relayer/validator/oracle REST and RPC endpoints; signing service; quorum aggregation API.
- Indexers and message-status APIs (`/message/:hash`, `/proof/:id`) that expose nonces, signatures, and pending withdrawals.

**The message itself**
- Encoded tuple: `(srcChainId, dstChainId, nonce, sender, recipient, token, amount, payload)`. Every field is an injection point if not bound into the signed/proven digest.

## Recon & Enumeration

Pull and review the verified source first; on-chain logic is the real attack surface.
```
# Contract source + ABI from explorer (Etherscan-family). Repeat per chain.
curl -s "https://api.etherscan.io/api?module=contract&action=getsourcecode&address=$BRIDGE&apikey=$KEY" -o src.json
# Identify proxy + implementation
cast implementation $BRIDGE --rpc-url $RPC          # foundry; EIP-1967 slot read
cast storage $BRIDGE 0x360894...bbc  --rpc-url $RPC # admin slot
```
Static analysis on the Solidity (install if absent):
```
pipx install slither-analyzer mythril
slither . --print human-summary --print modifiers
slither . --detect arbitrary-send,reentrancy-eth,unchecked-lowlevel,unprotected-upgrade
myth analyze contracts/Bridge.sol --solv 0.8.20 -t 3
semgrep --config p/smart-contracts --config p/solidity .
```
Map the off-chain relayer/API fleet:
```
subfinder -d bridge.example -all -silent | httpx -silent -title -tech-detect -json -o hosts.json
naabu -host relayer.bridge.example -top-ports 1000 -silent | httpx -silent
katana -u https://relayer.bridge.example -jc -d 3 -o endpoints.txt
ffuf -u https://relayer.bridge.example/FUZZ -w api-words.txt -mc 200,401,403
nuclei -l hosts.txt -as -s critical,high -rl 50 -c 20 -j -o nuclei.jsonl
```
Hunt for leaked validator/relayer keys and config (a bridge's nightmare):
```
trufflehog filesystem ./bridge-repo --only-verified
gitleaks detect -s ./bridge-repo -v
# Scan relayer container images for embedded keys / known CVEs
trivy image bridgeorg/relayer:latest
```
Query live on-chain state to learn the verifier model:
```
cast call $BRIDGE "validators()(address[])" --rpc-url $RPC
cast call $BRIDGE "threshold()(uint256)" --rpc-url $RPC
cast call $BRIDGE "processedNonces(uint256)(bool)" 42 --rpc-url $RPC
cast logs --address $BRIDGE "MessageSent(uint256,bytes32,bytes)" --rpc-url $RPC
```

## Methodology

1. Enumerate both legs. Identify the source emit and destination accept functions, and the exact verification path between them (proof, light client, or quorum signatures).
2. Reconstruct the canonical message format and the digest that is actually signed/proven. Diff it against the fields the destination uses to pay out — any field used for payout but absent from the digest is forgeable.
3. Map replay-protection state: where nonces/message hashes are recorded as consumed, the scope of that record (per-chain? global? per-token?), and the order of the consume-vs-pay operations.
4. Verify custody accounting: confirm `mint`/`release` is gated by a corresponding lock/burn and that supply on the destination cannot exceed collateral on the source.
5. Inspect the validator/guardian set: how it is rotated, who can rotate it, default/zero-address handling, and quorum math.
6. Probe the off-chain relayer/signer for input validation, auth, and key exposure that lets you obtain a valid signature over an attacker-chosen message.
7. Test privileged and upgrade paths for missing access control.
8. Build a PoC on a fork before touching anything live.

## Key Weaknesses / Techniques

**Forged / unverified messages.** Destination accepts a message whose proof or signature does not actually bind all payout fields. Classic: signature recovered over `keccak256(amount, recipient)` but payout also reads `token` and `srcChainId` from calldata. Re-encode with a different token/recipient and the same signature still verifies. Validate by recovering the signer from the on-chain digest and comparing to the fields used downstream.
```
# Recompute what the contract hashes vs what it spends:
cast keccak $(cast abi-encode "f(uint256,address,uint256)" 1 $RECIP 1000)
cast call $BRIDGE "recover(bytes32,bytes)(address)" $DIGEST $SIG --rpc-url $RPC
```
**Missing / weak replay protection.** Nonce or message hash not marked consumed, marked after payout (reentrancy window), or scoped too narrowly so the same message replays on a sibling chain. Test by submitting an already-processed withdrawal twice on a fork.
```
cast send $BRIDGE "executeMessage(bytes,bytes)" $MSG $PROOF --rpc-url $FORK
cast send $BRIDGE "executeMessage(bytes,bytes)" $MSG $PROOF --rpc-url $FORK  # second must revert
```
**Cross-domain / chain-id confusion.** `dstChainId` not checked, so a message destined for chain B is accepted on chain C; or the same verifier contract deployed on multiple chains shares a nonce space, enabling cross-chain replay.
**Custody invariant break.** Mint path callable without a matching lock, or burn/lock can be reverted/re-entered after the destination already minted, yielding `minted > locked`. Look for missing reentrancy guards on `lock`→external-call→state-update sequences (`slither --detect reentrancy-eth`).
**Merkle / MPT proof flaws.** Second-preimage on unbalanced trees, missing leaf/internal-node domain separation, accepting a proof of an intermediate node as a leaf, or not binding the proof to the correct state/receipt root. Construct a forged proof against a captured root and submit it.
**Light-client / header forgery.** Insufficient validator-signature checks on submitted headers, accepting headers without finality, or epoch/validator-set transition gaps. Submit a self-signed header with an attacker-controlled validator set.
**Validator-set takeover.** `updateValidatorSet` missing access control, accepting an empty set (threshold then trivially met), or signature malleability/duplicate-signer counting that inflates quorum.
**Off-chain signer abuse.** Relayer signs whatever message its API is handed without verifying source-chain inclusion, or SSRF/SQLi in the indexer leaks pending signatures. (See ssrf / sqlmap skills for the web legs.)

## Validation

1. Fork the destination chain at current head: `anvil --fork-url $RPC --fork-block-number latest`.
2. Reproduce the exact forged/replayed call against the fork and show value leaving the vault to an attacker-controlled address.
3. For forgery, demonstrate the destination accepts a message that no source-chain `lock`/`burn` event backs — prove the absence of the corresponding source event.
4. For replay, show a second `execute`/`withdraw` of one valid message succeeds (or document the precise nonce/hash state that fails to update).
5. Quantify drainable amount: vault balance reachable per forged message and per block.
6. Capture the full PoC (Foundry test or script) and the on-chain tx trace (`cast run $TX --rpc-url $FORK`) so the finding is reproducible without your environment.

## False Positives

- Signature/proof verifies but a separate, correct check (chain-id, nonce, recipient binding) blocks payout — read the whole `require` chain before claiming forgery.
- Replay "succeeds" on a fork only because you reset state between calls; re-run against persistent fork state.
- Privileged function looks open but is behind a timelock/multisig you don't control — note as governance risk, not direct exploit.
- "Missing" event on source is actually emitted under a different signature/contract — confirm with full log search across the bridge's contracts.
- Testnet/mock verifier (e.g. `acceptAll` stub) in a non-production deployment.
- OAST/relayer callback whose source IP is your own client, not the bridge backend.

## Chaining & Impact

- Forged message or broken custody invariant → mint/withdraw without backing → full vault drain across pooled tokens.
- Leaked validator key (trufflehog/gitleaks) → produce a valid quorum signature → forge any message at will.
- Validator-set takeover → permanent control of all future withdrawals.
- SSRF/SQLi on the indexer → harvest pending signatures/nonces → assemble replay or front-run legitimate withdrawals.
- Unprotected upgrade/proxy admin → replace verifier with an `acceptAll` implementation → drain at leisure.
- Wrapped-asset depeg: an over-mint propagates insolvency to every DEX pool and lending market holding the bridged token.

## Pro Tips

- Read the digest, not the docstring. The only thing that matters is which bytes the on-chain verifier hashes and recovers over; everything outside that tuple is attacker-controlled.
- Bridges are symmetric — audit both directions; the lock side and the mint side are often written by different people with different assumptions.
- Check operation ordering: consume-nonce-then-pay vs pay-then-consume is the difference between safe and reentrant.
- The same contract on N chains usually means one nonce space; test cross-chain replay explicitly.
- Validator-set rotation and epoch boundaries are where light clients break — focus on the transition logic, not steady state.
- Count signatures by unique recovered address, not by array length; duplicate-signer and `ecrecover` zero-address returns are common quorum bypasses.
- Always reproduce on a forked mainnet with real state before reporting; bridge logic is too stateful to reason about statically alone.
- Favor read-only confirmation (event absence, recovered signer, supply vs collateral) over live exploitation when assessing production custody.
