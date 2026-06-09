---
name: token_contract
description: Auditing on-chain NFT/token contracts for mint, transfer, approval, and access-control flaws that drain funds or seize ownership.
---

# NFT / Token Contract

The asset is a deployed smart contract identified by an on-chain address (ERC-20, ERC-721, ERC-1155, or a custom variant), usually fronted by a dApp, an indexer/API, and a public RPC. The attacker objective is direct economic impact: mint unauthorized supply, move or burn other holders' assets, drain the treasury/escrow, hijack ownership/admin roles, or break the proxy so future upgrades are attacker-controlled. Audit mint/transfer/approval logic and access control first — that is where almost all real loss originates.

## Attack Surface

**On-chain (the contract itself)**
- Public/external state-changing functions: `mint`, `mintTo`, `safeMint`, `transferFrom`, `safeTransferFrom`, `approve`, `setApprovalForAll`, `burn`, `withdraw`, `claim`, `redeem`.
- Privileged functions guarded by `onlyOwner`/role modifiers: `setBaseURI`, `setPrice`, `setMintActive`, `withdrawFunds`, `grantRole`, `upgradeTo`, `pause/unpause`.
- Proxy machinery: EIP-1967 implementation/admin slots, `initialize()` initializers, `delegatecall` targets, beacon contracts.
- Value flows: `payable` mint, refund logic, royalty/`receiver` payouts, fee-on-transfer hooks, ERC-777/1155 `tokensReceived` callbacks.
- Economic dependencies: price oracle reads, `block.timestamp`/`block.number` gates, on-chain randomness for trait/reveal.

**Off-chain (the surrounding system)**
- dApp frontend, mint allowlist API, signature/voucher minting endpoints, metadata server (`tokenURI` → IPFS/HTTP).
- Indexer/subgraph and read APIs that can be poisoned or desynced.
- Deployer keys, multisig signers, and CI/CD that holds private keys.

## Recon & Enumeration

Install the EVM tooling (not in base Kali):
```
pipx install slither-analyzer mythril
pipx install crytic-compile
curl -L https://foundry.paradigm.xyz | bash && foundryup   # cast/forge/anvil
npm i -g @openzeppelin/upgrades-core   # storage-layout / upgrade safety
```

Identify and pull the target. With a verified contract, fetch the source:
```
export ETHERSCAN_API_KEY=...; export RPC=https://eth-mainnet.g.alchemy.com/v2/KEY
cast etherscan-source -d ./src 0xCONTRACT --chain mainnet
cast code 0xCONTRACT --rpc-url $RPC | head -c 64   # non-empty == deployed
```

Resolve standard, owner, and proxy via on-chain reads:
```
cast call 0xCONTRACT "supportsInterface(bytes4)(bool)" 0x80ac58cd --rpc-url $RPC   # ERC-721
cast call 0xCONTRACT "supportsInterface(bytes4)(bool)" 0xd9b67a26 --rpc-url $RPC   # ERC-1155
cast call 0xCONTRACT "owner()(address)" --rpc-url $RPC
cast storage 0xCONTRACT 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc --rpc-url $RPC  # EIP-1967 impl slot
cast storage 0xCONTRACT 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103 --rpc-url $RPC  # EIP-1967 admin slot
```
If only bytecode is available, decompile and recover selectors:
```
cast 4byte-decode <calldata>            # known-selector lookup
cast disassemble 0xCONTRACT --rpc-url $RPC | grep -i PUSH4   # candidate selectors
# panoramix / heimdall-rs for full decompilation when unverified
```

Static analysis on the recovered source:
```
slither ./src --checklist --json slither.json
slither ./src --print human-summary
slither ./src --print function-summary   # lists modifiers/visibility per function
myth analyze ./src/Token.sol --solv 0.8.20 -o jsonv2   # symbolic exec, slower
semgrep --config p/smart-contracts ./src
```

Off-chain surface (dApp, mint API, metadata) with the standard web kit:
```
subfinder -d mint.target.tld -silent | httpx -silent -tech-detect -json -o web.jsonl
katana -u https://mint.target.tld -jc -d 3 -o urls.txt        # find /api signature endpoints
ffuf -u https://api.target.tld/FUZZ -w api-wordlist.txt -mc 200,401,403
nuclei -l web.txt -as -s critical,high -rl 50 -c 20 -j -o nuclei.jsonl
trufflehog filesystem ./repo --only-verified   # leaked deployer/signer keys in the repo
gitleaks detect -s ./repo --redact
```

## Methodology

1. **Pin the target.** Confirm address, chain, standard (ERC-20/721/1155), and whether it is a proxy. Map implementation vs admin. Verify the source matches the deployed bytecode (`cast code` keccak vs compiled runtime).
2. **Map authority.** Enumerate every state-changing function and its guard. Build a table: function → modifier → who can call it. Flag any privileged action reachable without `onlyOwner`/role/`require(msg.sender == ...)`.
3. **Audit mint logic.** Check supply cap enforcement, per-wallet limits, price/`msg.value` validation, allowlist/signature verification, and whether `_mint`/`_safeMint` is callable by anyone.
4. **Audit transfer/approval.** Verify `transferFrom` checks `isApprovedOrOwner`, that `approve`/`setApprovalForAll` cannot be set on behalf of others, and that custom hooks/overrides did not remove the ownership check.
5. **Trace value flow.** Follow ETH/token in (mint, deposit) and out (withdraw, royalty, refund). Look for reentrancy, unchecked external calls, and arbitrary `to`/`receiver`.
6. **Check proxy/upgrade safety.** Open `initialize`, storage layout collisions, `delegatecall` to attacker-controllable targets, unprotected `upgradeTo`, and self-destruct in the implementation.
7. **Validate off-chain.** Test the signature minting endpoint for replay, missing nonce/chainId, and forgeable vouchers; test metadata for mutability and access control.
8. **Reproduce on a fork.** Use `anvil --fork-url $RPC` to execute the exploit against real state with zero mainnet impact, then quantify loss.

## Key Weaknesses / Techniques

**Unprotected mint / privileged function (broken access control).** The most common real bug: `mint`/`setBaseURI`/`withdraw` missing `onlyOwner`, or a public `_mint` wrapper. Confirm the modifier is absent in `function-summary`, then call directly on a fork:
```
cast send 0xCONTRACT "mint(address,uint256)" $ME 1000000 --rpc-url http://127.0.0.1:8545 --private-key $PK
cast call 0xCONTRACT "balanceOf(address)(uint256)" $ME --rpc-url http://127.0.0.1:8545
```

**Uninitialized / re-callable initializer.** Behind a proxy, if `initialize()` lacks the `initializer` modifier or the implementation was never initialized, anyone can become owner:
```
cast send 0xCONTRACT "initialize(address)" $ME --rpc-url http://127.0.0.1:8545 --private-key $PK
cast call 0xCONTRACT "owner()(address)" --rpc-url http://127.0.0.1:8545   # expect $ME
```

**Missing approval check in transfer.** A custom `transferFrom` override that drops `_isApprovedOrOwner` lets anyone move arbitrary tokens:
```
cast send 0xCONTRACT "transferFrom(address,address,uint256)" $VICTIM $ME 42 --rpc-url http://127.0.0.1:8545 --private-key $PK
```

**Reentrancy in mint/withdraw.** `_safeMint` invokes `onERC721Received`, and ERC-1155/777 hooks call back before state finalizes. If supply/limit accounting or `withdraw` updates state after the external call, loop it. PoC: deploy an attacker contract whose `onERC721Received` re-enters `mint` to exceed the per-wallet cap.

**Signature voucher flaws (off-chain mint).** Allowlist mints signed by a backend: test for (a) no nonce → replay the same signature N times; (b) missing `chainId`/contract address in the signed digest → cross-chain/cross-contract replay; (c) `ecrecover` not checking `v=0` and zero-address return; (d) signer key recoverable from leaked env. Replay:
```
cast send 0xCONTRACT "mintWithSig(uint256,bytes)" 1 0xSIG --rpc-url $FORK --private-key $PK   # repeat
```

**Integer/accounting and fee-on-transfer.** Pre-0.8 unchecked math, or `unchecked{}` blocks; deflationary tokens where received amount < sent amount breaks internal balance math and enables drains in vaults/escrows.

**Weak randomness for traits/reveal.** `keccak256(block.timestamp, block.difficulty, msg.sender)` is predictable — a contract can mint, inspect the rolled trait in the same tx, and `revert` if undesirable to grind rares.

**Price/oracle manipulation.** Mint price or collateral valued via a spot AMM read is flash-loan manipulable; verify a TWAP or off-chain oracle is used.

**Royalty / arbitrary `to` withdraw.** `withdraw(address to)` or settable `royaltyReceiver` callable by non-admin redirects funds.

Re-run `slither ./src --detect arbitrary-send-eth,reentrancy-eth,unprotected-upgrade,suicidal,uninitialized-state,incorrect-modifier` to corroborate each class.

## Validation

- **Fork, don't touch mainnet.** Run everything against `anvil --fork-url $RPC --fork-block-number N`. Use `cast rpc anvil_impersonateAccount $VICTIM` and `anvil_setBalance` to set up state; never submit the exploit to the live chain.
- **Quantify the loss.** Capture before/after `balanceOf`, `totalSupply`, or contract ETH balance and report the exact delta (e.g. minted 1,000,000 unauthorized tokens, or drained X ETH).
- **Minimal reproducer.** Ship a `forge test --fork-url $RPC` test (`vm.prank`, `vm.expectRevert` absent) that asserts the unauthorized state change. A passing PoC test is the proof, not a Slither line.
- **For off-chain bugs**, show the replayed signature producing a second mint, or the leaked key signing a valid voucher.

## False Positives

- Slither/Mythril "reentrancy" on functions that follow checks-effects-interactions or carry `nonReentrant` — read the code, don't report the lint.
- Privileged functions that *are* meant to be owner-only and *are* guarded — power held by a known multisig/timelock is centralization risk, not an exploitable bug, unless the key is compromised.
- "Uninitialized state variable" findings for constants set in the constructor, or proxies already initialized (check the `_initialized` slot via `cast storage`).
- Predictable randomness on a testnet/already-revealed collection where no value depends on the roll.
- `tx.origin` warnings where it is used for logging only, not auth.
- Findings only reachable by the deployer/owner with no privilege boundary crossed.

## Chaining & Impact

- Uninitialized proxy → become owner → `upgradeTo(maliciousImpl)` → arbitrary `delegatecall`/self-destruct → total contract takeover and fund drain.
- Unprotected mint → inflate supply → dump on the AMM pool → drain the paired ETH/stablecoin liquidity.
- Missing approval check → sweep an entire collection's high-value tokens to attacker wallet → list/sell before holders react.
- Leaked deployer key (trufflehog/gitleaks) → call `withdraw`/`grantRole`/`upgradeTo` directly, skipping every on-chain guard.
- Signature replay → unlimited "allowlist" mints → bypass supply cap and economic model.
- Reentrancy in `withdraw` → drain the escrow/treasury balance in one transaction.

## Pro Tips

- Diff the contract against the canonical OpenZeppelin implementation it claims to extend; the bug is almost always in the *override* that removed a check, not in OZ.
- A proxy's `owner()` lives in the implementation's storage but executes via the proxy — always interact through the proxy address, and read the EIP-1967 slots, not a guessed slot 0.
- `slither ./src --print function-summary` gives the fastest authority map: scan the "modifiers" column for state-changing functions with an empty cell.
- Verify deployed bytecode equals the verified source before trusting Etherscan; metadata/CBOR tails differ but the runtime should match.
- For unverified targets, recover selectors with `cast disassemble | grep PUSH4` and brute them against the 4byte directory before reaching for a full decompiler.
- Always fork at a specific block (`--fork-block-number`) so the PoC is deterministic and reviewable.
- Check the metadata `tokenURI`: a mutable HTTP base lets the operator rug the art; an IPFS CID is immutable — note the difference for risk rating.
- When testing the off-chain mint API, include `chainId` and the contract address in your forged digest and confirm `ecrecover` rejects it — many backends sign only the wallet+amount.
