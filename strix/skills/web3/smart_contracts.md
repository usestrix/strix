---
name: smart-contracts
description: EVM/Solidity smart-contract auditing - reentrancy, overflow, access control, delegatecall proxies, oracle manipulation, signature replay, MEV, DoS, and bad randomness with slither/mythril/foundry/echidna
---

# EVM Smart Contract Auditing

Smart contracts are immutable, value-holding programs whose bugs cannot be patched and whose state is publicly readable and adversarially mutable. A single missing modifier, an unchecked external call, or a manipulable price source converts directly into irreversible loss of funds because there is no rollback and every actor can simulate, front-run, and replay transactions. EVM execution is deterministic and atomic per transaction, which both enables flash-loan-funded single-block attacks and means a thrown revert undoes all state — the audit job is to find the path where state mutates before a guard fires or where a guard never fires at all. Like classic memory-safety RCE, the root cause is usually control flow reaching a powerful primitive (`call`, `delegatecall`, `selfdestruct`, arbitrary transfer) before the program proves the caller is authorized; see the rce skill for the conceptual parallel.

## Attack Surface

**Scope**
- Solidity / Vyper source when verified; raw EVM bytecode when not
- Deployed contract state (storage slots, balances) readable via `eth_getStorageAt` and `eth_call`
- Proxy patterns: Transparent (EIP-1967), UUPS, Beacon, Diamond (EIP-2535), and naive delegatecall proxies
- External dependencies: price oracles, DEX pools, ERC-20/721/1155 tokens, bridges, governance
- The mempool itself (pending transactions are public and reorderable)

**Entry Points**
- Public/external functions with `payable` or value-moving logic
- `fallback()` / `receive()` and any `delegatecall` target
- `initialize()` on upgradeable contracts (replaces the constructor)
- Callback hooks: ERC-777 `tokensReceived`, ERC-721 `onERC721Received`, ERC-1155 `onERC1155Received`, Uniswap `uniswapV2Call`
- Oracle/keeper functions and signature-gated functions (`ecrecover`-based meta-tx, permit)

**Identity and authorization**
- `msg.sender` is the immediate caller; `tx.origin` is the EOA that started the tx (never use for auth)
- Roles via OpenZeppelin `Ownable` / `AccessControl`, custom `onlyOwner` modifiers, or multisig owners
- Signature-based auth via `ecrecover` (EIP-712 typed data, EIP-2612 permit) — bypassable if nonce/domain/chainId checks are missing
- Proxy admin vs implementation logic split — admin functions must be unreachable through the proxy's user path

## Key Vulnerabilities

### Reentrancy (single-function, cross-function, read-only)

State updated *after* an external call lets the callee re-enter before balances settle. Single-function reentrancy re-enters the same withdraw; cross-function reentrancy re-enters a *different* function that shares the now-stale state; read-only reentrancy abuses a `view` getter (e.g. a pool's price) that returns mid-transaction inconsistent state to a third-party integrator. The fix is checks-effects-interactions or a `nonReentrant` guard — but guards do not protect read-only reentrancy in *external* view consumers.

**Test:**
```
slither . --detect reentrancy-eth,reentrancy-no-eth,reentrancy-benign,reentrancy-events
# Foundry PoC (test/Reentrancy.t.sol): attacker re-enters withdraw before the balance zeroes
cat > test/Reentrancy.t.sol <<'SOL'
pragma solidity ^0.8.20; import "forge-std/Test.sol";
interface IVault { function deposit() external payable; function withdraw() external; }
contract Attacker { IVault v; constructor(address _v){ v=IVault(_v); }
  function go() external payable { v.deposit{value:msg.value}(); v.withdraw(); }
  receive() external payable { if (address(v).balance >= 1 ether) v.withdraw(); } }
SOL
forge test -vvv   # PASS when attacker balance ends > deposit
```

### Integer Overflow / Underflow (pre-0.8 + unchecked blocks)

Solidity <0.8.0 wraps silently: `0 - 1` becomes `2**256-1`, letting an attacker mint or underflow a balance. Since 0.8.0 arithmetic reverts on over/underflow, but `unchecked { ... }` blocks restore wrapping for gas savings — and that is exactly where the regression hides. Also check explicit `SafeMath` removal, type downcasts (`uint256 -> uint128`), and multiplication-before-division ordering.

**Test:**
```
slither . --detect divide-before-multiply
# Detect unchecked blocks and pragma
grep -rn "unchecked" src/ contracts/
grep -rn "pragma solidity" src/ contracts/    # any ^0.7 / <0.8 is SafeMath-dependent
# Symbolic check for arithmetic
myth analyze contracts/Token.sol --solv 0.7.6 -t 3
# Foundry fuzz: assert no wraparound in accounting
forge test --match-test testFuzz_NoOverflow --fuzz-runs 100000 -vvv
```

### Access Control (missing modifiers, unprotected init, tx.origin auth)

State-changing functions without `onlyOwner`/role checks, `initialize()` callable by anyone, ownership-transfer functions with no guard, and authentication keyed on `tx.origin` (phishable via an intermediate contract). Self-destruct or upgrade functions reachable by an arbitrary caller are immediate criticals.

**Test:**
```
slither . --detect suicidal,arbitrary-send-eth,unprotected-upgrade,tx-origin
# Find state-mutating externals with no modifier
slither . --print function-summary | grep -i "external\|public"
# Confirm initialize is open
cast call $C "owner()(address)" --rpc-url $RPC
cast send $C "initialize(address)" $ATTACKER --rpc-url $RPC --private-key $PK   # should revert if guarded
# tx.origin auth grep
grep -rn "tx.origin" src/ contracts/
```

### Delegatecall + Proxy Storage Collisions

`delegatecall` runs target code against the caller's storage and `msg.sender`/`msg.value` context. If the proxy and implementation lay out storage differently, a write to "implementation slot 0" clobbers the proxy's `owner`. EIP-1967 fixes this with pseudo-random admin/implementation slots; naive proxies that put `address implementation` in slot 0 collide with the logic contract's slot 0. Arbitrary `delegatecall` to a user-supplied address is full takeover.

**Test:**
```
slither . --detect controlled-delegatecall,delegatecall-loop
# Read EIP-1967 implementation + admin slots from a deployed proxy
cast storage $PROXY 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc --rpc-url $RPC  # impl
cast storage $PROXY 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103 --rpc-url $RPC  # admin
# Compare proxy vs implementation storage layout
forge inspect src/Proxy.sol:Proxy storageLayout
forge inspect src/Logic.sol:Logic storageLayout
```

### Uninitialized Proxy / Implementation

UUPS/Transparent implementations left uninitialized let an attacker call `initialize()` on the *implementation* contract directly, become its owner, and (for UUPS) call `upgradeToAndCall` with a contract that `selfdestruct`s the implementation — bricking every proxy that delegates to it (the Parity multisig class of bug). Implementations must call `_disableInitializers()` in their constructor.

**Test:**
```
slither . --detect unprotected-upgrade
# Is the implementation itself initialized?
IMPL=$(cast storage $PROXY 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc --rpc-url $RPC)
cast call ${IMPL:26} "owner()(address)" --rpc-url $RPC   # 0x0 => claimable
cast send ${IMPL:26} "initialize(address)" $ATTACKER --rpc-url $RPC --private-key $PK
# Confirm constructor disables initializers
grep -rn "_disableInitializers" src/ contracts/
```

### Unchecked Low-Level Call Return Values

`addr.call(...)`, `.send()`, and ERC-20 `transfer`/`transferFrom` on non-reverting tokens (USDT, BNB-era tokens) return `false`/nothing instead of reverting. Code that ignores the boolean believes a failed transfer succeeded, mis-accounting balances. Use OpenZeppelin `SafeERC20` and always check `(bool ok, ) = ...; require(ok);`.

**Test:**
```
slither . --detect unchecked-lowlevel,unchecked-send,unchecked-transfer
grep -rnE "\.call\{?|\.send\(|\.transfer\(" src/ contracts/
forge test --match-test testTransferFalse -vvv
```

### Price-Oracle Manipulation via Flash Loans

Contracts that read spot price from a single DEX pool (`getReserves`, `balanceOf`/`totalSupply` of an LP) can be skewed within one transaction by a flash loan that imbalances the pool, then exploited (over-borrow, mint, liquidate), then unwound. Spot AMM price is not an oracle. Defenses: Chainlink/TWAP feeds, `latestRoundData` staleness/round checks.

**Test:**
```
slither . --detect tautology   # plus manual review of any getReserves()/balanceOf-based pricing
grep -rnE "getReserves|getAmountsOut|balanceOf\(address\(this\)\)" src/ contracts/
# Foundry mainnet fork: borrow flash loan, swap to skew, call victim, repay
forge test --fork-url $MAINNET_RPC --match-test testOracleManipulation -vvv
grep -rn "latestRoundData\|updatedAt\|answeredInRound" src/ contracts/
```

### Signature Replay / Missing Nonce / Malleability

`ecrecover` signatures reused across functions, chains, or contracts when the signed payload omits a nonce, `address(this)`, or `chainId`/EIP-712 domain separator. ECDSA is malleable — `(r, s)` and `(r, -s mod n)` both verify, so signature-as-key dedup fails unless `s` is constrained to the lower half. `ecrecover` returns `address(0)` for invalid sigs, which must be rejected.

**Test:**
```
slither . --detect missing-zero-check
grep -rn "ecrecover" src/ contracts/         # verify nonce + chainId + low-s + zero-address check
# Sign a claim digest, then submit the same signature twice; second must revert if nonce-protected
SIG=$(cast wallet sign --private-key $PK $(cast keccak "claim:100"))
cast send $C "claim(uint256,bytes)" 100 $SIG --rpc-url $RPC --private-key $PK
cast send $C "claim(uint256,bytes)" 100 $SIG --rpc-url $RPC --private-key $PK   # replay drains again
```

### Front-Running & MEV / Sandwich

Pending txs are public; a profitable swap or claim can be front-run, back-run, or sandwiched by reordering with higher gas/priority fees. Missing `minAmountOut`/`deadline` slippage params, commit-reveal-free auctions, and on-chain randomness-as-secret are all exploitable. Approvals and `claim()` of known reward amounts are classic targets.

**Test:**
```
# Inspect mempool for victim tx and craft front/back-run
cast rpc txpool_content --rpc-url $RPC | jq '.pending'
grep -rnE "amountOutMin|minOut|deadline|block.timestamp" src/ contracts/
# Simulate sandwich on a fork: front-run swap, victim swap, back-run swap
forge test --fork-url $MAINNET_RPC --match-test testSandwich -vvv
```

### Denial of Service (gas, unbounded loops)

Loops over caller-growable arrays (push to a `recipients[]` then iterate to pay) can be made to exceed the block gas limit, permanently bricking the function. Pull-over-push payment, a single transfer to a contract that reverts in `receive()` blocking a batch, and external calls inside loops are the patterns. `selfdestruct`-forced balance changes break strict `address(this).balance ==` invariants.

**Test:**
```
slither . --detect calls-loop,costly-loop,msg-value-loop
grep -rnE "for *\(.*length|while *\(" src/ contracts/   # unbounded iteration
# Echidna invariant: contract never reaches a permanently-stuck state
echidna . --contract VaultEchidna --config echidna.yaml
# Foundry gas check: grow the array and assert the loop still fits the block
forge test --match-test testGasGriefing --gas-report -vvv
```

### Bad Randomness

`block.timestamp`, `blockhash`, `block.prevrandao`/`block.difficulty`, and `block.number` are validator-influenceable or known in-transaction, so any lottery/NFT-mint/game that derives a "secret" from them is predictable or grindable by a contract that reverts on unfavorable outcomes. Use Chainlink VRF or commit-reveal.

**Test:**
```
grep -rnE "block.timestamp|blockhash|block.difficulty|block.prevrandao|block.number" src/ contracts/
slither . --detect weak-prng
# Foundry: an attacker contract that computes the same "random" value in the same block and only enters on a win
forge test --match-test testPredictRandom -vvv
```

## Bypass Techniques

**Reentrancy guard gaps**
- `nonReentrant` on `withdraw` but not on a sibling function reading the same balance enables cross-function reentrancy
- Read-only reentrancy bypasses *all* guards on the victim — the flaw is in the external consumer trusting a mid-tx `view`

**Access-control phishing**
- `tx.origin == owner` checks are defeated by tricking the owner into calling an attacker contract that then calls the target

**Token-behavior assumptions**
- Fee-on-transfer and rebasing tokens break `amountReceived == amountSent`; deflationary tokens under-credit deposits
- ERC-777 hooks re-enter ERC-20-shaped logic that never expected a callback

**Proxy confusion**
- Function selector clash between proxy admin functions and implementation functions (Transparent proxy mitigates; naive proxies do not)

## Testing Methodology

1. **Acquire the code** - pull verified source via Etherscan API; if unverified, decompile bytecode and reconstruct storage layout
2. **Map the surface** - `slither . --print human-summary,function-summary,inheritance` for entry points, modifiers, and externals
3. **Static pass** - run full Slither detector set; triage criticals (reentrancy, suicidal, arbitrary-send, controlled-delegatecall)
4. **Symbolic pass** - `myth analyze` on hot contracts for overflow, assertion violations, unprotected functions
5. **Model invariants** - encode "total supply == sum of balances", "no free mint", "owner unchanged" and fuzz with Echidna/Foundry
6. **Fork & PoC** - on a mainnet fork, write a Foundry test that funds an attacker (flash loan if needed) and proves value extraction
7. **Check oracles & deps** - trace every external price/state read; confirm TWAP/Chainlink staleness guards
8. **Inspect live state** - read proxy slots, owner, paused flags, and implementation initialization status on-chain via `cast`
9. **Mempool & MEV** - assess slippage/deadline params and reorder-ability of profitable actions

## Validation

1. Prove exploitation on a forked node (`--fork-url`) where attacker balance increases — never broadcast to mainnet
2. Show the exact storage slot or balance delta before/after with `cast storage` / `cast balance` snapshots
3. For access control, demonstrate a non-owner address successfully calling a guarded function in a fork or local deploy
4. For oracle manipulation, show the manipulated price the victim read versus the true market price in the same block
5. Capture the full PoC transaction trace (`forge test -vvvv`) so the call sequence and revert points are unambiguous
6. Keep PoCs read-or-fork only against production; do not send state-changing txs to live contracts

## False Positives

- `reentrancy-benign` / `reentrancy-events` from Slither where the only post-call effect is an event emission (no fund risk)
- `unchecked` blocks that are provably bounded (loop index already range-checked, hash of fixed-size input)
- `tx.origin` used only for analytics/logging, not authorization
- `arbitrary-send` flagged on a function that is in fact `onlyOwner` through a custom modifier Slither did not resolve
- Spot-price reads that are sanity-bounded against a TWAP or have a max-deviation circuit breaker
- "Uninitialized" implementation that calls `_disableInitializers()` in its constructor

## Impact

- Irreversible theft of all contract-held funds (reentrancy, access control, oracle manipulation)
- Permanent loss of upgradeability or self-destruction of the implementation (uninitialized UUPS)
- Unauthorized minting / supply inflation collapsing token value (overflow, missing access control)
- Protocol insolvency from manipulated collateral pricing and bad-debt liquidations
- Permanently bricked functions (gas-DoS) freezing user funds with no recovery
- MEV extraction: users systematically pay a hidden tax to sandwichers

## Pro Tips

1. Always test on a mainnet fork (`forge test --fork-url`) before claiming an oracle/flash-loan finding — local toy pools hide real liquidity constraints
2. Slither first, Mythril second; Slither's `--print function-summary` is the fastest map of who-can-call-what
3. Read the EIP-1967 slots directly (`cast storage`) rather than trusting `implementation()` getters that may lie or be absent
4. Cross-function reentrancy is missed by single-function guards and by reviewers staring at one function — diff the state each function reads vs writes
5. Read-only reentrancy lives in the *integrator*, not the pool; audit how downstream contracts consume `getReserves`/`get_virtual_price` mid-tx
6. Constrain `ecrecover` to lower-half `s` and reject `address(0)` — malleability and zero-address recovery are routinely forgotten
7. For DoS, the killer pattern is an external call (token transfer, ETH send) inside a loop the attacker can grow or stall
8. `block.prevrandao` is not a secret — it is known during execution and weakly biasable by the proposer; treat any RNG without VRF/commit-reveal as broken
9. Fee-on-transfer tokens silently break deposit accounting; always diff `balanceBefore`/`balanceAfter` rather than trusting the transfer amount

## Summary

Smart-contract findings chain from a single broken assumption into total loss because execution is atomic and irreversible: a missing modifier or unprotected `initialize` yields ownership, ownership yields `upgradeToAndCall` or `selfdestruct`, and a manipulable price source plus a flash loan yields a fully-funded single-block drain that unwinds before anyone can react. Start by mapping every value-moving external and the guard that should precede it, prove the gap on a fork with a Foundry PoC that increases attacker balance, and validate non-destructively by reading state deltas rather than broadcasting to production.
