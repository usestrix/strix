---
name: solidity_evm_smart_contracts
description: Solidity/EVM smart-contract auditing methodology — Foundry/Slither/Echidna workflow, mainnet-fork PoCs, function-family mapping, and weird-ERC20 checklist
---

# Solidity / EVM Smart Contracts

A Solidity repo is a source-code target like any other — treat it with the same white-box rigor as a Django or FastAPI codebase, not a black-box web app. The difference is that every bug class here moves money directly, and every "finding" must be a runnable Foundry test that moves a real balance, not a description of a pattern. If you cannot write a passing exploit test, you do not have a finding yet.

## Attack Surface

**What you're looking at**
- A Foundry (`foundry.toml`, `src/`, `test/`), Hardhat (`hardhat.config.*`), or raw `.sol` file set
- Upgradeable proxies (`Proxy.sol`, `UUPSUpgradeable`, `TransparentUpgradeableProxy`) vs immutable contracts
- External dependencies: OpenZeppelin, Solmate, Uniswap/Aave/Compound interfaces — check exact pinned versions, not just import names
- Every function that moves value: `transfer`/`transferFrom`/`mint`/`burn`/`withdraw`/`deposit`/`redeem`/`liquidate`/`swap`/`claim`

**What matters most**
- Anything reachable by an unprivileged `msg.sender` that changes a balance, share, or price variable
- Anything that trusts an external contract's return value or callback without validating it
- Anything computed with division before multiplication, or that reads price/state from a single source

## Setup

The sandbox has no Solidity tooling by default — install what the target needs:

```
curl -L https://foundry.paradigm.xyz | bash && foundryup   # forge, cast, anvil, chisel
pipx install slither-analyzer                                # static analyzer
pip install crytic-compile                                   # compile shim slither/echidna need
# Echidna/Medusa are prebuilt binaries, not pip/apt packages — fetch the release for the repo's needs:
#   https://github.com/crytic/echidna/releases  /  https://github.com/crytic/medusa/releases
```

```
cd <target-repo> && forge build            # confirms the project actually compiles first
forge install                               # pull missing lib/ dependencies if build fails on imports
```

If `forge build` fails on a missing remapping, check `remappings.txt` / `foundry.toml` `remappings` before assuming the code is broken — mismatched `lib/` paths are the most common false start.

## Recon: Build the Function-Family Matrix

Before touching a scanner, read the code like an auditor, not a grep script:

1. **List every state variable that represents value** — balances, shares, prices, reserves, debt, collateral ratios.
2. **For each one, list every function that writes it** — this is the "writer matrix". A bug is far more often "writer #3 forgot the check writers #1 and #2 have" than a novel exploit.
3. **List every external call** (`.call`, `.delegatecall`, low-level or interface calls to non-`view` functions) and note whether state is written before or after it (reentrancy surface) and whether the return value is checked.
4. **Write down the invariants in plain English** before reading `test/` — e.g. "total shares minted must equal sum of user shares", "collateral value must exceed debt value at all times a position is open". Then check whether any function can violate one without reverting.

```
grep -rn "function " src/ | grep -viE "view|pure" | grep -E "external|public"   # state-changing surface
grep -rn "\.call(\|\.call{value\|delegatecall\|staticcall" src/                 # low-level call sites
grep -rn "onlyOwner\|onlyRole\|require(msg.sender" src/                         # access-control gates — note what's NOT gated
```

## Static Analysis

```
slither . --print human-summary                 # inheritance, external calls, state var summary
slither .                                        # full detector run
slither . --detect reentrancy-eth,reentrancy-no-eth,unprotected-upgrade,arbitrary-send-eth,tx-origin
```

Slither's default output has real false positives (especially reentrancy on functions already using a nonReentrant modifier it doesn't recognize, or view-only "reentrancy" with no state impact) — every hit needs manual confirmation against the writer matrix, not a copy-paste into a report.

## Fuzzing / Invariant Testing

Property-based fuzzing catches what pattern-matching misses — feed it the invariants from recon:

```
# Echidna: property-mode (test_*.sol asserting invariants) or assertion-mode
echidna . --contract InvariantTest --test-mode assertion
# Medusa: config-driven, better for large/complex protocols
medusa fuzz --config medusa.json
```

If the repo has no existing invariant test harness, write a minimal one before fuzzing blind — a fuzzer with no invariants just finds reverts, not exploits. A useful default: assert `sum(userShares) == totalShares` and `token.balanceOf(vault) >= totalAssetsOwed` after every fuzzed call sequence.

Hand-writing that harness from scratch is what actually burns time in a real audit — check for a `chimera`-based scaffold (Recon's harness-builder pattern, https://getrecon.xyz) first; it generates the Echidna/Medusa property-test skeleton and handler contracts from the target's ABI, so you're editing invariants instead of writing boilerplate.

## Mainnet-Fork PoCs

The strongest possible finding is a Foundry test that forks real mainnet state and drains real (forked) funds — this removes any "but our deployed config is different" objection from triage:

```
anvil --fork-url $RPC_URL --fork-block-number <N>   # pin the block for reproducibility
forge test --fork-url $RPC_URL --match-test test_exploit -vvvv
```

You need a real RPC endpoint (Alchemy/Infura/a public endpoint for the target chain, or the target's own testnet/devnet if that's what's in scope) reachable from the sandbox. **If the sandbox's network policy blocks outbound RPC calls, say so explicitly and ask the operator for a reachable endpoint or a local anvil snapshot — do not silently fall back to an untested local-only PoC and call it proof against the live protocol.**

```solidity
// forge test skeleton for a fork exploit
function test_exploit() public {
    vm.createSelectFork(vm.envString("RPC_URL"), BLOCK_NUMBER);
    uint256 before = victim.balanceOf(address(vault));
    attacker.exploit();
    assertGt(attacker.profit(), 0, "exploit did not extract value");
    assertLt(victim.balanceOf(address(vault)), before, "vault balance did not drop");
}
```

## Weird-ERC20 Checklist

Any contract that accepts an arbitrary/user-supplied token address must survive all of these — check each one against the writer matrix, don't assume standard behavior:

- **Fee-on-transfer** — `transferFrom(a, b, amount)` delivers less than `amount`; code that credits `amount` instead of the measured balance delta will over-credit.
- **Rebasing** — balance changes without a transfer (stETH-style); cached balances go stale.
- **No return value / non-standard return** — USDT-style tokens that don't return `bool`; raw `IERC20(token).transfer(...)` without `SafeERC20` reverts or silently misreads success.
- **Reentrant tokens** — ERC-777/ERC-1363 hooks (`tokensReceived`, `transferAndCall`) let the token itself reenter the caller.
- **Blocklist-capable tokens** (USDC-style) — a `transfer` can revert unilaterally, breaking loops that assume all transfers in a batch succeed.
- **Zero-decimals / high-decimals** — hardcoded `1e18` scaling breaks on tokens with different decimals.
- **Approve race / non-zero-to-non-zero approve revert** — some tokens (old USDT) revert on `approve` when the current allowance is non-zero.

## Key Vulnerability Classes

See `smart_contract_vulnerabilities` for the full catalog (reentrancy, access control, oracle manipulation, share-math/inflation, delegatecall storage collision, signature replay, flash-loan composability, gas griefing) with PoC patterns for each.

## Testing Methodology

1. `forge build` — confirm the project compiles before anything else
2. Build the writer matrix and invariant list by reading, not scanning
3. `slither .` — triage every hit against the writer matrix, discard false positives
4. Write/extend an invariant test harness, run echidna/medusa against it
5. For anything that looks real, escalate to a mainnet-fork Foundry test that moves a measurable balance
6. Run the weird-ERC20 checklist against any function accepting an external token address

## Validation

1. A passing `forge test` that demonstrably increases attacker balance or decreases victim balance — assert on `balanceOf`/share deltas, not just "the call succeeded"
2. State the exact function, line, and violated invariant
3. If fork-based, include the RPC endpoint (redacted key), block number, and full `-vvvv` trace
4. Show the fix would close it: re-run the same test against a patched version if one exists

## False Positives

- Slither reentrancy hit on a function already protected by `nonReentrant` via a modifier Slither didn't trace through inheritance
- "Unprotected" function that is in fact only callable by another contract via `onlyDelegateCall` or an internal-only visibility Slither misread
- Integer overflow flagged in code compiled with Solidity ≥0.8.0 (checked arithmetic by default) outside an `unchecked` block
- Oracle "manipulation" against a price source that already uses a TWAP/Chainlink with staleness checks — verify the actual read path, not just that an oracle exists

## Impact

- Direct fund drain from vaults/pools/vesting contracts
- Permanent protocol insolvency via share-price manipulation
- Governance takeover via flash-loan-funded voting power
- Unauthorized minting/upgrade via proxy storage collision

## Pro Tips

1. Read `test/` before writing exploits — existing tests reveal the team's own understanding of invariants, and gaps in test coverage are gaps in their threat model
2. `forge test -vvvv` traces every call/storage write — use it to confirm exactly where an invariant breaks, not just that a test reverted
3. Check `git log`/CHANGELOG for prior audit reports or "fix" commits — a partially-fixed bug pattern often has a sibling function that got missed
4. Always confirm the actual deployed bytecode matches the repo (`cast code <address>` vs local `forge build` output) before treating a mainnet-fork PoC as conclusive

## Tooling

- **Foundry** (`forge`/`cast`/`anvil`) — build, test, and fork-test; the primary tool for everything here
- **Slither** — fast static triage, always run first, never trust unverified
- **Echidna** / **Medusa** — property/invariant fuzzing once you have real invariants to assert
- **cast** — direct RPC calls for on-chain recon: `cast call`, `cast storage`, `cast 4byte` for unknown selectors

## Summary

Smart-contract auditing is source-aware white-box testing with an unusually unforgiving bug bar: every finding must be a runnable test that moves value. Build the function-family/writer matrix first, triage Slither against it, fuzz the invariants you derived from reading the code, and escalate anything real to a mainnet-fork Foundry PoC.
