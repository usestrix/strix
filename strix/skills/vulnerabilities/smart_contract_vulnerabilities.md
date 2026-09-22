---
name: smart_contract_vulnerabilities
description: Solidity/EVM vulnerability class catalog — reentrancy, access control, oracle manipulation, share-math inflation, proxy storage collision, signature replay, flash-loan composability, and gas griefing, each with a Foundry PoC pattern
---

# Smart Contract Vulnerability Classes

Pair with `solidity_evm_smart_contracts` for setup, recon, and tooling. This skill is the vulnerability catalog: what each class looks like in source, and the minimum Foundry test shape that proves it. A described pattern is not a finding — a passing test that moves a balance is.

## Reentrancy

**Classic (single-function)** — external call before the state write it should have followed:
```solidity
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    (bool ok,) = msg.sender.call{value: amount}("");   // <-- external call
    require(ok);
    balances[msg.sender] -= amount;                     // <-- state write AFTER the call
}
```

**Cross-function** — the reentrant call re-enters a *different* function that shares the same unwritten state (e.g. `withdraw` reenters `transfer` before `withdraw` updates `balances`).

**Read-only reentrancy** — a `view` function returns stale/manipulated state mid-callback (e.g. a Curve-style pool's `get_virtual_price()` read during a callback before the pool finishes updating reserves); the *reader* contract (an oracle consumer, a lending protocol pricing LP tokens) is the victim, not the pool itself. Check every external `view` call used for pricing against whether the source contract has any external call in the same function before the state it reads is finalized.

**Prove it:**
```solidity
function test_reentrancy() public {
    attacker.attack{value: 1 ether}();
    assertGt(address(attacker).balance, 1 ether, "did not drain more than deposited");
}
```

## Access Control

- **Missing modifier** — a state-changing function with no `onlyOwner`/`onlyRole`/`require(msg.sender == ...)` where sibling functions have one. Compare against the writer matrix.
- **`tx.origin` authentication** — `require(tx.origin == owner)` is phishable: a malicious contract the owner interacts with can call the protected function as an intermediary.
- **Uninitialized proxy/implementation** — an upgradeable implementation contract left uninitialized lets anyone call `initialize()` directly on the implementation address and become its "owner" (irrelevant to the proxy's own storage, but often the initializer also has a `selfdestruct`-reachable path or is later used as a delegatecall target).
- **Missing `initializer` modifier / re-initialization** — a proxy `initialize()` callable more than once resets ownership/config.

**Prove it:**
```solidity
function test_unprotected_function() public {
    vm.prank(attacker);
    target.adminOnlyFunction(attacker);   // should revert, doesn't
    assertEq(target.owner(), attacker);
}
```

## Oracle Manipulation

- **Spot-price read** — `reserve0/reserve1` from a single AMM pool read in the same transaction as a large swap; manipulable within one block/flash-loan.
- **Flash-loan-funded manipulation** — borrow enough of one asset to swing the spot price, trigger the victim's price-dependent logic (liquidation, mint, borrow limit), repay the loan, keep the extracted value.
- **Missing staleness/deviation check** on a Chainlink-style feed — `latestRoundData()` consumed without checking `updatedAt` freshness or a max-deviation bound against a secondary source.

**Prove it (fork-based, this class rarely works without real liquidity):**
```solidity
function test_oracle_manipulation() public {
    vm.createSelectFork(vm.envString("RPC_URL"));
    uint256 priceBefore = victim.getPrice();
    attacker.flashLoanAndSwap();   // swing the pool
    uint256 priceAfter = victim.getPrice();
    assertGt(priceAfter, priceBefore * 2, "price did not move enough to matter");
    attacker.liquidateOrBorrowAtBadPrice();
    assertGt(attacker.profit(), 0);
}
```

## Share-Price / Rounding / First-Depositor (Inflation) Attack

ERC-4626-style vaults computing `shares = amount * totalShares / totalAssets`:

- **First-depositor inflation** — attacker deposits 1 wei (mints 1 share), then donates a large amount directly to the vault (not via `deposit`) to inflate `totalAssets` without minting shares, making the share price huge; the next legitimate depositor's amount rounds down to 0 shares and their funds are stolen.
- **Rounding direction** — check whether share math rounds in the protocol's favor (should round *down* on mint/deposit, *up* on withdraw/redeem to prevent value leakage per transaction).

**Prove it:**
```solidity
function test_first_depositor_inflation() public {
    vm.startPrank(attacker);
    vault.deposit(1, attacker);                          // 1 share
    asset.transfer(address(vault), 10_000e18);            // direct donation, no shares minted
    vm.stopPrank();
    vm.prank(victim);
    vault.deposit(1000e18, victim);
    assertEq(vault.balanceOf(victim), 0, "victim got 0 shares for a real deposit");
}
```

## Unchecked External Calls

`.call()`/`.send()`/low-level calls whose return value is discarded — a failed transfer looks like it succeeded to the calling contract, so accounting proceeds as if funds moved when they didn't (or a malicious callee can return `false` deliberately to desync state without reverting the whole transaction).

## Integer Overflow Outside `unchecked`

Solidity ≥0.8.0 checks arithmetic by default — overflow only exists inside an explicit `unchecked { }` block, in inline assembly, or in Solidity <0.8.0 code (still common in vendored/older dependencies). Grep `unchecked` blocks specifically; don't flag arithmetic outside them.

## Delegatecall / Storage Collision in Upgradeable Proxies

- **Storage layout mismatch** between proxy and implementation, or between implementation versions across an upgrade — a new implementation's variable at slot N overwrites what the proxy's existing data at slot N actually means.
- **`delegatecall` to an untrusted/attacker-controlled address** — if the target of a delegatecall is derived from user input or an unprotected setter, the callee executes with the caller's storage context and can overwrite arbitrary slots (including the admin/implementation slot itself).

**Check:** `forge inspect <Contract> storage-layout` on both old and new implementation versions; diff slot assignments.

## Signature Replay / Malleability

- **Missing nonce or domain separator** — a signed message (e.g. a meta-tx or permit) valid on one chain/contract/deployment is replayable on another if `chainid`/contract address isn't part of the signed digest (EIP-712 `domain` misconfiguration).
- **ECDSA malleability** — `(v, r, s)` has two valid `s` values for the same signature; code using the signature hash itself as a replay-protection key (rather than a separate nonce) can be replayed with the flipped-`s` variant. OpenZeppelin's `ECDSA.recover` rejects the high-`s` range by default — check for custom/vendored recovery code that doesn't.
- **`permit()` front-running** — a griefer observes a pending `permit` tx in the mempool and submits it themselves first, consuming the nonce and causing the victim's intended follow-up tx to revert (griefing, not fund loss, but breaks assumed atomicity).

## Flash-Loan Composability Attacks

Not a distinct bug on its own — a force-multiplier for any of the above (oracle manipulation, governance takeover via borrowed voting power, share-price inflation with borrowed capital) by removing the capital constraint. Whenever a vulnerability's exploitability depends on "attacker needs a large amount of asset X", assume a flash loan removes that constraint and re-evaluate severity accordingly.

## Front-Running / MEV-Sensitive Logic

- Sandwich-able swaps with no slippage/deadline parameter, or a slippage parameter the caller can set to `0`/max
- Commit-reveal schemes with a commit phase that leaks the committed value early (e.g. via gas cost differences or an event)
- Auction/liquidation logic where the first valid bid wins ties, letting a searcher win with an identical bid via priority gas

## Denial of Service via Unbounded Loops / Gas Griefing

- Loop bound by an attacker-growable array (e.g. iterate over all depositors to distribute rewards) — attacker adds enough entries to push the loop over the block gas limit, permanently bricking the function for everyone.
- A single reverting element in a batch operation (e.g. one blocklisted-token transfer in a loop of payouts) blocking all other legitimate payouts in the same transaction — pattern-match against the weird-ERC20 checklist in `solidity_evm_smart_contracts`.

**Prove it:**
```solidity
function test_dos_unbounded_loop() public {
    for (uint i = 0; i < 5000; i++) { vault.deposit(1, address(uint160(i + 1))); }
    vm.expectRevert();  // or measure gas exceeds block limit
    vault.distributeRewards();
}
```

## Testing Methodology

1. Start from the writer matrix built in `solidity_evm_smart_contracts` — every class above maps to a specific writer/reader pattern in it
2. Grep for the structural signal first (external call before state write, `unchecked`, `delegatecall`, `tx.origin`, share-math division) before reasoning about exploitability
3. For anything share/price-related, always ask "what if the attacker had unlimited capital for one transaction" — flash-loan composability changes the answer
4. Escalate every real hit to a Foundry test proving a balance/share delta, fork-based where real liquidity/oracle behavior matters

## Validation

A finding in this catalog is proven only by a passing Foundry test asserting a concrete balance, share, or ownership delta in the attacker's favor — never by "this pattern is present" alone.

## False Positives

- External call before state write, but the function has `nonReentrant` (OpenZeppelin `ReentrancyGuard`) correctly applied
- Share-math rounding that favors the protocol by design (rounds against the depositor on entry, against the withdrawer on exit) — check the actual direction, not just that rounding exists
- `delegatecall` to a fixed, immutable, audited library address (not user-controlled)
- Oracle read with a working staleness + deviation check that would reject the manipulated price

## Impact

Direct, often total and irreversible loss of protocol funds — smart-contract bugs typically have no "patch before exploitation" window once public, since anyone can read the deployed bytecode and replicate the PoC on mainnet.

## Pro Tips

1. Check whether the protocol has a prior audit report in-repo (`audits/`, `docs/audit`) — known-accepted risks save time, and un-remediated findings from old reports are still findings
2. `forge inspect <Contract> storage-layout` before touching any proxy/upgrade bug — most storage-collision claims collapse once you see the actual slot assignments
3. For share-math bugs, always test the *first* depositor path explicitly — it's the state most audits under-test

## Summary

Every class here reduces to the same question asked of the writer matrix: which function can move a balance/share/price variable in a way its author didn't intend, and can you prove it with a Foundry test that actually moves value. Reentrancy, access control, and oracle manipulation are the highest-yield starting points; flash loans remove the capital constraint from all of them.
