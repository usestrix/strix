---
name: defi_dapp
description: Authorized assessment of DeFi protocols and dApps — on-chain contract logic plus the frontend/wallet integration layer.
---

# DeFi Protocol / dApp

A DeFi protocol is on-chain logic (smart contracts) plus an off-chain dApp (web frontend, RPC/indexer backends, wallet integration) that users sign transactions against. The attacker's objective is to drain or freeze funds, mint/inflate tokens, manipulate prices or accounting, hijack governance/admin, or trick users into signing malicious transactions. Treat the contract bytecode as the trust boundary: the frontend can lie, but the chain is ground truth. Assess both the on-chain invariants (who can move money, can supply/price be manipulated) and the dApp layer (does the UI/wallet flow let an attacker substitute a hostile target, token, or signature).

## Attack Surface

**On-chain**
- Public/external state-changing functions: `deposit`, `withdraw`, `swap`, `borrow`, `liquidate`, `flashLoan`, `mint`, `redeem`, `claim`
- Privileged functions behind `onlyOwner`/roles: `setOracle`, `pause`, `upgradeTo`, `setFee`, `rescueTokens`, `mint`
- Upgradeability: proxy admin, implementation slot, UUPS `upgradeTo`, timelock, multisig threshold
- Price/data dependencies: on-chain DEX spot price, Chainlink/Pyth feeds, TWAP windows, `block.timestamp`, `block.number`
- External calls / token callbacks: ERC777 `tokensReceived`, ERC721 `onERC721Received`, ERC1155, arbitrary `call`/`delegatecall` targets
- Cross-chain: bridge mint/burn, message verifiers, relayers, replay across chainids

**Off-chain dApp**
- Frontend JS that builds calldata, contract addresses, and chainId (hardcoded vs. user/host-influenced)
- Wallet connect flow: `eth_sendTransaction`, `personal_sign`, `eth_signTypedData_v4` (EIP-712), `eth_sign` (blind)
- Token approvals: `approve(spender, amount)`, `Permit`/`Permit2`, infinite approvals
- RPC/indexer/API backends, The Graph subgraphs, price APIs, `tokenlist` JSON
- Source/CI exposure: deployer keys, mnemonics, RPC API keys, verified-vs-deployed bytecode mismatch

## Recon & Enumeration

Install the asset-specific tooling (sandbox already has the generic web tools):

```
pipx install slither-analyzer mythril crytic-compile     # static analysis + symbolic exec
pipx install panoramix-decompiler                          # decompile unverified bytecode
npm i -g @openzeppelin/upgrades-core surya                 # proxy/upgrade + call-graph analysis
curl -L https://foundry.paradigm.xyz | bash && foundryup   # cast/forge/anvil — forking & PoC
```

```bash
# 1. dApp frontend recon — find every contract address, chainId, RPC, and API
subfinder -d app.target.tld -silent | httpx -silent -title -tech-detect -o live.txt
katana -u https://app.target.tld -jc -d 3 -o crawl.txt
ffuf -w main.*.js -u https://app.target.tld/static/js/FUZZ          # source map / bundle hunting
# pull addresses & secrets out of the JS bundle
grep -rEoh '0x[a-fA-F0-9]{40}' ./bundle/ | sort -u                   # candidate contract addrs
trufflehog filesystem ./bundle/ --only-verified
gitleaks detect --source ./repo --report-format json -o gitleaks.json

# 2. On-chain — pull verified source / bytecode
cast etherscan-source -d ./src 0xCONTRACT --chain mainnet            # needs ETHERSCAN_API_KEY
cast code 0xCONTRACT --rpc-url $RPC                                   # raw bytecode if unverified
panoramix 0xCONTRACT                                                  # decompile if no source

# 3. Proxy / admin / upgrade posture
cast storage 0xCONTRACT 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc --rpc-url $RPC  # EIP-1967 impl slot
cast storage 0xCONTRACT 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103 --rpc-url $RPC  # EIP-1967 admin slot
cast call 0xCONTRACT "owner()(address)" --rpc-url $RPC

# 4. Static analysis of the contracts
slither ./src --checklist --markdown-root . > slither.md
slither ./src --print human-summary,modifiers,function-summary
myth analyze ./src/Vault.sol --solv 0.8.20 -t 3                       # symbolic; tune depth -t
surya graph ./src/*.sol | dot -Tpng > callgraph.png

# 5. dApp backend / API layer
nuclei -u https://api.target.tld -as -s critical,high -rl 40 -j -o nuclei.jsonl
nuclei -u https://app.target.tld -t http/exposures/ -tags graphql,swagger -silent
semgrep --config p/smart-contracts --config p/javascript ./repo
```

## Methodology

1. **Map the system.** Enumerate every contract address from the frontend bundle and on-chain. Diff verified source against deployed bytecode (`cast code` vs Etherscan) — an unverified or mismatched implementation is itself a finding. Build the call graph with `surya`/`slither`.
2. **Establish the trust model.** Who is `owner`/admin? Is it an EOA, a multisig (read threshold), or a timelock? Can admin `upgradeTo`, `mint`, `pause`, or `rescueTokens` arbitrarily? Single-EOA control of upgrade = rug/compromise risk.
3. **Identify value flows.** For each money-moving function, write the intended invariant (e.g. `totalSupply == sum(balances)`, `assets >= shares * pricePerShare`). These invariants are your test oracle.
4. **Hunt the classic on-chain bugs** (see Key Weaknesses) against each external function, prioritizing functions that move funds or read prices.
5. **Fork mainnet and reproduce.** Use `anvil --fork-url $RPC --fork-block-number N` and write a `forge` test that executes the candidate exploit against real state. This is how you turn a static finding into a confirmed one.
6. **Audit the dApp/wallet layer.** Can the contract address, chainId, token, or spender be influenced by the page/host/query? Does the UI request blind `eth_sign`, infinite approvals, or opaque EIP-712 structs?
7. **Assess oracle/price dependencies.** Is any price derived from manipulable on-chain spot (single-block DEX reserves) vs. a TWAP or external feed? Flash-loan price manipulation is the dominant DeFi loss vector.
8. **Validate, scope impact, chain, and report** with a reproducible forked PoC.

## Key Weaknesses / Techniques

### Reentrancy (single-function, cross-function, read-only)
State updated *after* an external call/transfer. Look for `.call{value:}`, ERC777/ERC721 callbacks, and any external call before balance bookkeeping.
- Detect: `slither ./src --detect reentrancy-eth,reentrancy-no-eth,reentrancy-benign`
- Read-only reentrancy: a `view` price/`getReserves` read during a callback returns stale state; downstream integrators consume it.
- PoC pattern (forge): malicious receiver re-enters `withdraw()` from its `receive()`/`tokensReceived()` and drains before balance decrements.

### Oracle / price manipulation
Pricing off `getReserves()`/spot or a too-short TWAP. Flash-loan to skew the pool, transact at the skewed price, repay.
```
# fork and skew a Uniswap pair, then call the victim's price-dependent fn
cast call 0xPAIR "getReserves()(uint112,uint112,uint32)" --rpc-url http://127.0.0.1:8545
```
Confirm with a forge test: flashloan -> swap -> victim borrow/mint at bad price -> close.

### Access control / privilege gaps
Missing or wrong modifier on a sensitive function: unguarded `initialize()` (uninitialized proxy), `mint`, `setOracle`, `upgradeTo`, `delegatecall` to attacker target.
- `slither ./src --detect unprotected-upgrade,suicidal,arbitrary-send-eth,controlled-delegatecall`
- Test calling each admin/init function from an unprivileged key on a fork: `cast send 0xC "initialize(address)" $ME --private-key $ATTACKER`.

### Arithmetic & accounting
First-depositor share inflation (ERC4626 donation attack), rounding that favors the caller, fee-on-transfer/rebasing tokens breaking `balanceBefore/After`, unchecked math in older Solidity, precision loss in `mulDiv`.

### Unchecked external calls / token assumptions
Ignored return value of `transfer`/`transferFrom` (USDT-style no-bool), assuming `transferFrom` pulls exact amount (deflationary tokens), or accepting arbitrary token addresses into a swap/router path.

### Signature & approval abuse (dApp + on-chain)
- EIP-2612 `permit`/`Permit2` with missing deadline or nonce reuse; signatures replayable across chainids if `DOMAIN_SEPARATOR` omits `chainid`.
- Frontend requesting `eth_sign` (blind hash) or `eth_signTypedData` for an opaque `spender`/`amount` — verify against `jwt_tool`-style decode; here decode the EIP-712 struct and confirm it matches what the UI claims.
- Infinite `approve(spender, 2**256-1)` to a contract the user never audited.

### dApp frontend integrity
- Contract address / chainId taken from a mutable source (query param, localStorage, host header, third-party tokenlist) — attacker substitutes a hostile contract.
- XSS/dependency compromise in the bundle that rewrites `to`/`data` of the pending transaction before signing (drainer pattern). Check CSP, SRI on the wallet-connect bundle.
- Verify with `nuclei -t http/exposures/configs/ -tags exposure` and a manual review of how calldata is assembled.

### Upgradeability & storage collisions
Proxy/implementation storage layout mismatch after upgrade, unprotected `upgradeTo` (UUPS), or a self-destructible implementation.
- `npx @openzeppelin/upgrades-core validate` / `slither-check-upgradeability`.

## Validation

1. **Fork the live chain** at a recent block: `anvil --fork-url $RPC --fork-block-number $N`.
2. **Write a `forge` PoC test** that starts from real on-chain state, executes the exploit, and asserts the broken invariant (attacker balance increased / victim balance drained / supply inflated).
3. Quantify: report the value extractable in one transaction/block and whether it is flash-loan-funded (no attacker capital required = higher severity).
4. For dApp/signature findings, demonstrate the malicious transaction the user would actually sign (decoded `to`/`value`/`data` or EIP-712 struct) and how the UI hides or misrepresents it.
5. Re-run the PoC against a second fork block to prove it is not state-specific. Never execute against mainnet with real funds — keep all PoCs on the local fork.

## False Positives

- Slither/Mythril "reentrancy" on functions guarded by `nonReentrant` or following checks-effects-interactions — read the modifier before reporting.
- "Arbitrary send" / "unprotected" flags on functions that are intentionally permissionless (e.g. public `claim` to `msg.sender`).
- Spot-price "manipulation" where the value is only displayed in the UI and never used for an on-chain financial decision.
- Admin "centralization" that is actually a multisig + timelock with reasonable threshold — note it as risk, not a critical exploit.
- Infinite approval to a *protocol's own* immutable, audited router (common UX) vs. an arbitrary/upgradeable spender.
- Decompiler artifacts on unverified contracts — confirm against bytecode behavior on a fork, not Panoramix guesses alone.

## Chaining & Impact

- Unguarded `initialize()` on a proxy → become owner → `upgradeTo(malicious)` → drain every deposit.
- Flash loan → oracle/spot manipulation → over-borrow or mint at bad price → repay loan, keep difference → protocol insolvency.
- Read-only reentrancy → poison a `view` price → an *integrating* protocol liquidates/prices wrong → losses one hop away from the original bug.
- Leaked deployer key/mnemonic from CI/bundle (`trufflehog`/`gitleaks`) → direct admin actions, no contract bug needed.
- Frontend XSS / compromised dependency → wallet drainer: rewrite pending tx target → mass user fund theft without touching the contracts.
- Signature replay across chains/forks → reuse a `permit` or governance vote on a sibling deployment.

## Pro Tips

1. Always diff deployed bytecode against verified source — `cast code` vs Etherscan. The audited code is not always what is running.
2. Read the access-control graph first; most catastrophic DeFi losses are an admin/upgrade/init gap, not exotic math.
3. The single highest-yield class is flash-loan price manipulation — for every price read, ask "can one transaction move this number?"
4. Don't trust a `view` function: read-only reentrancy makes "safe" getters lie mid-callback.
5. Test the dApp by intercepting the wallet RPC (`eth_sendTransaction`) and inspecting the real decoded calldata — the UI's summary is often wrong or omits the dangerous param.
6. Fork at the exact block of a suspected historical incident to learn the codebase's failure modes, then check whether the fix is complete.
7. Treat fee-on-transfer, rebasing, and ERC777 tokens as adversarial inputs — they break naive `balanceOf` accounting and enable reentrancy.
8. Keep every PoC on a local `anvil` fork; quantify loss in USD at fork-block prices so severity is unambiguous.
