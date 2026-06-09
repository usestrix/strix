---
name: oracle_integration
description: Assessing on-chain oracle integrations for price-feed manipulation, staleness, and source-trust failures.
---

# Oracle Integration

An oracle integration is the code path by which a smart contract imports off-chain or cross-contract data — most commonly an asset price — and acts on it (mint, borrow, liquidate, settle, rebase). The attacker's objective is to make the consuming contract accept a value that does not reflect honest market reality: a spot price snapshot bent by a flash loan, a frozen feed that the contract still trusts, a reference the attacker can write to, or a decimals/sign mismatch that turns a sane number into a catastrophic one. Because the oracle is the contract's source of truth about value, a single bad read frequently converts directly into drained collateral.

## Attack Surface

**Read sites (where the contract pulls a value)**
- Chainlink-style aggregators: `latestRoundData()`, `latestAnswer()`, `decimals()`, `description()`
- DEX-derived prices: Uniswap V2 `getReserves()`, V3 `slot0()` (instant tick), V3 `observe()` (TWAP)
- LP / vault share prices: `getVirtualPrice()`, `pricePerShare()`, `convertToAssets()`, `totalSupply()`/`balanceOf` ratios
- Custom keeper/pusher contracts and signed-price endpoints (Pyth `updatePriceFeeds`, Redstone calldata-injected prices)
- Cross-chain bridges / L2 sequencer uptime feeds

**What is exposed / influenceable**
- The numerator: spot reserves, slot0 tick, share ratios — all mutable inside one transaction via swaps/deposits
- The trust boundary: which address is allowed to push prices, who owns the aggregator/proxy, upgradeable proxies behind the feed
- The freshness contract: `updatedAt`, `answeredInRound`, heartbeat assumptions, deviation thresholds
- The math glue: `decimals()` scaling, signed `int256` answers, division order, fixed-point rounding

## Recon & Enumeration

Most work is source/bytecode review plus a forked-chain harness. Install the EVM tooling:

```bash
pip install slither-analyzer mythril            # static analysis + symbolic
curl -L https://foundry.paradigm.xyz | bash && foundryup   # forge/cast/anvil
npm i -g @openzeppelin/contracts                # reference interfaces for diffing
```

Pull and inventory the target contracts (verified source where available):

```bash
# fetch verified source by address from an explorer (Etherscan-compatible)
cast etherscan-source --chain <chain> -d ./src <CONTRACT_ADDR>
# enumerate every oracle touchpoint
grep -rniE 'latestRoundData|latestAnswer|getReserves|slot0|observe|getVirtualPrice|pricePerShare|convertToAssets|getPrice' ./src
```

Static and secret sweeps:

```bash
slither ./src --print human-summary
slither ./src --detect unused-return,divide-before-multiply,incorrect-equality
semgrep --config p/smart-contracts ./src
trufflehog filesystem ./src --only-verified     # leaked keeper/deployer keys
gitleaks dir ./src
```

Live feed enumeration with `cast` against a fork or archive RPC:

```bash
anvil --fork-url $RPC_URL --fork-block-number <N> &   # deterministic harness
cast call <FEED> "latestRoundData()(uint80,int256,uint256,uint256,uint80)" --rpc-url $RPC_URL
cast call <FEED> "decimals()(uint8)" --rpc-url $RPC_URL
cast call <FEED> "aggregator()(address)" --rpc-url $RPC_URL   # proxy -> underlying
cast call <FEED> "owner()(address)" --rpc-url $RPC_URL        # who controls the source
```

For DEX-sourced prices, read the pool the contract trusts and confirm whether it is the canonical, deep pool or a thin one:

```bash
cast call <PAIR> "getReserves()(uint112,uint112,uint32)" --rpc-url $RPC_URL
cast call <V3POOL> "slot0()(uint160,int24,uint16,uint16,uint16,uint8,bool)" --rpc-url $RPC_URL
cast call <V3POOL> "liquidity()(uint128)" --rpc-url $RPC_URL   # thin pool = cheap to move
```

## Methodology

1. **Map every price read.** From the grep above, list each call site and trace the returned value to the action it gates (LTV, mint amount, liquidation trigger, settlement payout). Note the units and decimals expected at each hop.
2. **Classify each source.** Push oracle (Chainlink/Pyth), spot DEX (`getReserves`/`slot0`), TWAP (`observe`), or derived share price. Spot and derived are manipulable within a transaction; push oracles shift the trust to the publisher and freshness checks.
3. **Audit the trust boundary.** Resolve proxy → aggregator → owner. Determine if a single EOA/multisig can push arbitrary answers, and whether the feed proxy is upgradeable.
4. **Audit freshness handling.** Confirm the contract checks `updatedAt` against a heartbeat, validates `answeredInRound >= roundId`, and rejects non-positive answers. Missing checks mean a stale or zero price is consumed.
5. **Audit the math.** Verify `decimals()` is read dynamically (not hardcoded), that `int256` answers are guarded against ≤0, division happens after multiplication, and cross-feed combinations normalize units.
6. **Build a fork PoC.** On `anvil --fork-url`, simulate a flash loan, move the trusted pool, call the victim action in the same transaction, and measure the value extracted vs. capital used.
7. **Quantify cost-to-move.** Compute the swap size needed to shift the trusted source past the contract's deviation tolerance, and compare to attacker profit.

## Key Weaknesses / Techniques

**Spot-price (single-block) manipulation.** The contract prices collateral from `getReserves()` or `slot0()` — both reflect the instantaneous state and can be flash-loan-bent inside one transaction. Validate with a forge test that flash-borrows, swaps to skew the pool, then calls the victim's borrow/mint:

```solidity
// inside a forge fork test
uint256 borrowed = pool.flashLoan(address(token), 50_000e18);
router.swapExactTokensForTokens(borrowed, 0, path, address(this), block.timestamp);
victim.depositAndBorrow(collateralAmt);   // prices collateral off the now-skewed pool
// repay flash loan, keep the delta
```

**Missing staleness / heartbeat check.** Code uses `(, int256 p,,,) = feed.latestRoundData();` and ignores `updatedAt`. If the feed stops updating (publisher outage, deprecated feed), the last price is consumed indefinitely. Confirm by reading the live `updatedAt` and comparing to `block.timestamp - heartbeat`:

```bash
cast call <FEED> "latestRoundData()(uint80,int256,uint256,uint256,uint80)" --rpc-url $RPC_URL
# if block.timestamp - updatedAt > heartbeat and contract has no guard -> stale read accepted
```

**Unchecked negative / zero answer.** `int256` answers can be `0` or negative on misconfiguration; if cast to `uint256` without a `require(p > 0)`, the price collapses to zero (free collateral) or wraps huge. Grep for casts of `latestAnswer`/`latestRoundData` results without a positivity guard.

**Round-completeness bypass.** Missing `require(answeredInRound >= roundId)` lets a not-yet-finalized or carried-over round price through.

**Decimals / scaling mismatch.** Hardcoding `1e8` when the feed reports a different `decimals()`, or mixing an 18-decimal token with an 8-decimal feed, mis-scales value by orders of magnitude. Re-derive the expected scale from the live `decimals()` call and compare to the constant in source.

**Manipulable derived price.** `getVirtualPrice()` / `pricePerShare()` / `convertToAssets()` can be inflated by a donation or first-deposit share-inflation attack, or read mid-reentrancy when the pool's invariant is temporarily false (read-only reentrancy). Check whether the consumer reads share price during a callback window.

**Untrusted / writable source.** The "oracle" is a custom contract whose setter (`setPrice`, `pushReport`) lacks access control or trusts an EOA the attacker can become, or a Pyth/Redstone update where the contract fails to verify the signed payload's feed id, publish time, or confidence interval.

**Single-source dependency.** No median across sources and no sanity bound (min/max bands), so any one compromised or thin feed dictates the value.

## Validation

- Reproduce on a pinned fork (`anvil --fork-block-number`) so the PoC is deterministic, then re-run to confirm stability.
- For manipulation: produce a single-transaction forge test that starts and ends with the attacker's capital (flash loan repaid) and shows net token outflow from the victim. Log balances before/after with `console.log`.
- For staleness: show the live feed's `updatedAt` exceeds the heartbeat window while the contract still returns the action as valid — call the gated function on the fork and confirm it does not revert.
- For decimals/sign bugs: drive the feed (via storage overwrite with `cast rpc anvil_setStorageAt` or a mock) to a boundary value and show the consumer mis-scales or accepts ≤0.
- Quantify impact in concrete numbers: capital required, profit extracted, and which protocol invariant (solvency, LTV, peg) is broken.

## False Positives

- A contract that reads `slot0()`/`getReserves()` but only for a **non-financial** purpose (UI hint, event emission) — no value is gated on it.
- TWAP over a sufficiently long window and a deep pool where the cost to sustain manipulation across the averaging period exceeds any profit — model the cost before claiming.
- Staleness "bugs" where an upstream guard (a wrapper library, a separate freshness modifier) already enforces the heartbeat — trace the full call chain, not one function.
- "Manipulable" spot reads that are bounded by a deviation circuit-breaker or chained against a second independent oracle.
- Negative-answer concern on feeds that are documented as always-positive AND guarded elsewhere; confirm the cast actually lacks a check.
- Fork PoCs that profit only because the test mints free tokens or skips flash-loan repayment — an unrealistic precondition is not a finding.

## Chaining & Impact

- Spot manipulation → inflated collateral value → over-borrow → protocol left insolvent (bad debt) once the price snaps back.
- Spot manipulation → deflated collateral value → trigger unjust liquidations → seize others' positions at a discount.
- Stale/zero price → mint or redeem at a wrong rate → drain the mint/redeem path or break a stablecoin peg.
- Read-only reentrancy on a derived price → skewed share price → mispriced deposit/withdraw → vault drain.
- Writable/untrusted source → push an arbitrary answer → settle a derivative or auction at attacker-chosen value.
- Each of these typically composes with a flash loan, so the attacker needs near-zero starting capital and exits in one transaction.

## Pro Tips

- Always resolve the proxy to its underlying aggregator and the aggregator's owner; the "Chainlink feed" may be a custom proxy a deployer can repoint.
- Cost-to-manipulate scales with pool depth and TWAP length. Read `liquidity()`/reserves first — a thin pool with a short or absent average is the cheapest break.
- The most common real bug is not exotic manipulation but a missing `updatedAt`/`answeredInRound`/`p > 0` check — grep every `latestRoundData` consumer for all three guards.
- Watch division-before-multiplication and hardcoded `1e8`/`1e18`; Slither's `divide-before-multiply` and a manual `decimals()` diff catch most scaling errors.
- Pin the fork block. Mainnet drift makes manipulation PoCs flaky and undermines the report; a fixed block plus repaid flash loan is what a defender will re-run.
- For Pyth/Redstone, verify the consumer checks the report's `publishTime`/confidence and the correct feed id — accepting an unvalidated signed blob is equivalent to a writable oracle.
- Prefer a forge test as the deliverable PoC over prose; an executable, self-funding transaction is the unambiguous proof.
