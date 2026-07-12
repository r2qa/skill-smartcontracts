# Vulnerable Functions Checklist

> Walk every applicable item during a review. Grouped by contract type. For each: the grep-able pattern, why it's risky, and the concrete check to perform. 176 function patterns across 21 contract-type categories. Companion: [vulnerable-chains.md](vulnerable-chains.md).


## token

### `transfer(address,uint256) / transferFrom(address,address,uint256)`
- **Risk:** Core value movement; TRC-20/older tokens may not return bool or may revert differently than ERC-20, and non-standard implementations (USDT-style) break `require(token.transfer(...))` assumptions. Fee-on-transfer / deflationary / rebasing tokens silently deliver less than the amount argument.
- **Verify:** Confirm return value is checked via SafeERC20/safeTransfer; confirm balance is measured before/after for fee-on-transfer support where integrated; verify allowance is decremented in transferFrom; verify no arbitrary from without allowance; check for blacklist/pausable branches; confirm zero-address and self-transfer handling.

### `approve(address,uint256) / increaseAllowance / decreaseAllowance`
- **Risk:** Classic approve race condition (SWC-114 adjacent); non-zero-to-non-zero approve on USDT-style tokens reverts; unlimited approvals enable drain if spender is compromised.
- **Verify:** Check whether approve requires reset-to-zero first; verify increase/decrease pattern exists; verify allowance underflow reverts; confirm no hidden approve inside transfer paths; check integrators reset allowance to 0 before re-approving external tokens.

### `_mint / mint(address,uint256)`
- **Risk:** Unbounded or under-protected minting inflates supply and dilutes/destroys peg or LP value; missing cap; minter role compromise.
- **Verify:** Verify access control (onlyMinter/role), supply cap enforcement, no mint to address(0) unless intended, totalSupply overflow (pre-0.8) / unchecked blocks, and that mint cannot be called during initialize by arbitrary caller.

### `_burn / burn / burnFrom(address,uint256)`
- **Risk:** burnFrom without allowance check lets attacker burn others' tokens; burning can desync accounting in wrappers/vaults; missing balance checks.
- **Verify:** Verify burnFrom decrements allowance; verify caller can only burn own balance unless authorized; confirm totalSupply decremented; check reward/vault share accounting stays consistent after burn.

### `_transfer internal hook path / _beforeTokenTransfer / _afterTokenTransfer`
- **Risk:** ERC-777/ERC-1155/hook-enabled tokens invoke recipient callbacks enabling reentrancy (Cream/imBTC, Uniswap-ERC777 incidents). Custom fee logic here can be bypassed.
- **Verify:** Trace all external calls in hooks; confirm state (balances, totalSupply) updated before any callback; confirm reentrancy guard or checks-effects-interactions; verify fee/tax math cannot underflow or be gamed via self-transfer.

### `safeTransferFrom / _safeMint / onERC721Received / onERC1155Received / onERC1155BatchReceived`
- **Risk:** ERC-721/1155 safe callbacks execute attacker code before state finalization (reentrancy mint abuse, e.g. cheap-mint exploits).
- **Verify:** Confirm token IDs/balances and mint counters are updated BEFORE the receiver callback; confirm nonReentrant on mint; verify batch length mismatches revert; verify return-selector check on receiver.

### `setApprovalForAll(address,bool)`
- **Risk:** Grants blanket transfer rights over all NFTs/1155 balances; phishing and operator abuse vector.
- **Verify:** Verify events emitted; confirm no function auto-sets operator approvals; check marketplace/bridge integrations don't leave stale operators.

### `permit(...) EIP-2612 on the token`
- **Risk:** Gasless approval; signature replay, wrong domain separator, missing deadline, or fallback-permit (Uniswap Permit2/DAI-style) mismatches enable unauthorized approvals.
- **Verify:** Verify nonce increment, deadline check, DOMAIN_SEPARATOR includes chainid (recomputed on fork), ecrecover result != address(0), and s-value/malleability handling; check non-reverting permit fallbacks used by integrators.


## access-control

### `transferOwnership / renounceOwnership / setOwner / setAdmin / setPendingOwner+acceptOwnership`
- **Risk:** Single-step ownership transfer to wrong/zero address bricks admin; renounce locks upgrades/params forever; missing two-step allows typo lockout.
- **Verify:** Prefer two-step (pending + accept); verify zero-address guard; verify renounce is intended and not callable to strand critical funds; confirm event emission and that ownership guards all privileged setters.

### `grantRole / revokeRole / _setupRole / _grantRole / setRoleAdmin / renounceRole`
- **Risk:** AccessControl misconfiguration: DEFAULT_ADMIN_ROLE self-administration, role admin loops, over-broad minter/pauser roles.
- **Verify:** Map every role to the functions it gates; verify who holds DEFAULT_ADMIN_ROLE at deploy; confirm no function lets a role grant itself higher privilege; verify role admin hierarchy; check timelock/multisig ownership of admin roles.

### `addMinter / setMinter / setPauser / setGovernance / setFeeRecipient / setTreasury`
- **Risk:** Privileged parameter setters are prime targets; missing modifier = anyone can seize control (SWC-105/SWC-100 unprotected functions).
- **Verify:** Confirm each setter has correct access modifier; verify bounds on fee/rate params (no 100% fee, no fee-to-attacker); check event emission; ensure no default-visibility (public) sensitive setters.

### `modifier onlyOwner/onlyRole/onlyGovernance applied (or MISSING)`
- **Risk:** The highest-frequency real bug is an admin function that simply lacks its modifier (Parity wallet, many rugged tokens).
- **Verify:** Enumerate every state-changing external/public function and assert an access check exists or is deliberately public; grep for functions that write owner/implementation/rates without a modifier.

### `require(tx.origin == owner) / auth using tx.origin`
- **Risk:** tx.origin authentication (SWC-115) is phishing-exploitable via intermediary contract.
- **Verify:** Confirm auth uses msg.sender, not tx.origin; flag any tx.origin comparison.

### `initialize / __Ownable_init / __AccessControl_init (as an auth vector)`
- **Risk:** Unprotected initializer lets an attacker claim ownership/roles (see proxy-upgrade).
- **Verify:** Cross-check with proxy-upgrade section: initializer modifier present, ownership set to intended admin, cannot be re-run.


## lending

### `mint / supply / deposit (cToken/aToken)`
- **Risk:** Exchange-rate manipulation and first-depositor share inflation; accrueInterest must run first or shares misprice.
- **Verify:** Verify accrueInterest() called before rate use; verify share = amount * 1e18 / exchangeRate rounding favors protocol; check first-deposit inflation mitigation (dead shares / minimum liquidity); verify reentrancy guard and CEI.

### `redeem / redeemUnderlying / withdraw`
- **Risk:** Redeeming more than collateral allows, or before interest accrual, drains reserves; reentrancy via underlying token transfer (Cream reentrancy).
- **Verify:** Verify accrueInterest first; verify redeem checks account liquidity/shortfall AFTER reducing collateral; confirm token transfer is last (CEI) and nonReentrant; check rounding does not let redeemer over-withdraw.

### `borrow(uint256)`
- **Risk:** Under-collateralized borrow if price/oracle is stale or manipulable (bZx, Harvest, Mango); interest not accrued; borrow cap missing.
- **Verify:** Verify getAccountLiquidity uses fresh oracle and post-borrow hypothetical check; verify accrueInterest; check borrow caps, paused state, and that collateral factor uses conservative price; verify reentrancy guard.

### `repayBorrow / repayBorrowBehalf`
- **Risk:** Rounding lets debt round to zero or leaves dust; repay-behalf accounting; fee-on-transfer underpayment.
- **Verify:** Verify accrueInterest; verify actual received amount (fee-on-transfer) used; verify borrow index accounting; confirm repaying more than owed is capped and refunded.

### `liquidateBorrow / liquidate`
- **Risk:** Incorrect liquidation incentive, self-liquidation, liquidating healthy positions, or reentrancy; rounding that seizes too much/little collateral (bad-debt spiral).
- **Verify:** Verify shortfall required before liquidation; verify close factor and liquidation incentive bounds; verify seize amount math and oracle freshness; confirm cannot liquidate self to grief; check pause and reentrancy; verify bad-debt/collateral-shortfall handling.

### `seize(address,address,uint256)`
- **Risk:** Cross-market seize authorization; only the paired market/comptroller should call; mis-scoped access enables collateral theft.
- **Verify:** Verify caller must be a listed market approved by comptroller; verify seizer/borrower market compatibility; confirm token accounting and reentrancy guard.

### `accrueInterest()`
- **Risk:** Interest index update; if skippable, callable to grief, or has division-by-zero/overflow when totalBorrows or cash is zero, rates can be manipulated (empty-market donation attacks).
- **Verify:** Verify called at start of every state-changing action; verify borrowRate capped (per-block cap); check timestamp/block-number delta cannot be manipulated; verify no revert on zero utilization; check reserves accounting.

### `exchangeRateStored / exchangeRateCurrent / getExchangeRate`
- **Risk:** The central manipulable value: (cash + borrows - reserves)/supply. Donation of underlying inflates rate (empty market / first-depositor); used by oracles.
- **Verify:** Verify uses internal totalCash accounting not token.balanceOf (or is donation-resistant); verify reserves subtracted; verify zero-supply branch returns initial rate; assess donation/inflation attack surface.

### `getAccountLiquidity / getHypotheticalAccountLiquidity`
- **Risk:** Solvency check; wrong price source, ignoring a market, or stale collateral factor allows under-collateralized borrows/withdrawals.
- **Verify:** Verify all entered markets iterated; verify oracle price freshness and decimals normalization; verify collateral factor applied to collateral only; check hypothetical delta signs; verify no overflow on large positions.

### `setCollateralFactor / _setCollateralFactor / setPriceOracle / _setPriceOracle / _setReserveFactor`
- **Risk:** Admin params directly control solvency; setting oracle to malicious contract or CF too high enables instant insolvency.
- **Verify:** Verify access control + timelock; verify CF upper bound; verify new oracle sanity/liveness checks; confirm reserve factor <= 100%; verify param changes emit events and cannot front-run liquidations abusively.

### `transferTokens / transfer of cToken while used as collateral`
- **Risk:** Transferring collateral-bearing receipt tokens can bypass liquidity checks, moving collateral out of a risky account.
- **Verify:** Verify transfer runs redeemAllowed/liquidity check on sender; verify accrueInterest; confirm cannot transfer to evade seize.

### `flashLoan / flashLoanSimple`
- **Risk:** Reentrancy and fee/accounting manipulation; used as capital for oracle/governance attacks.
- **Verify:** Verify balance-before + fee <= balance-after invariant; verify callback cannot re-enter sensitive functions; verify fee rounding; confirm nonReentrant.

### `sweepToken / skim / rescueTokens`
- **Risk:** Admin sweep can drain user funds if it doesn't exclude the underlying/accounted assets.
- **Verify:** Verify cannot sweep the market's underlying or user-owed tokens; verify only excess/airdropped tokens; confirm access control.


## AMM-DEX

### `swap(uint,uint,address,bytes) [UniV2] / swap(...) [UniV3 core]`
- **Risk:** K-invariant enforcement and callback ordering; flash-swap callback enables reentrancy; missing slippage/minOut at router level enables sandwich/MEV (SWC-114). Price is instantaneously manipulable for oracle abuse.
- **Verify:** Verify constant-product/curve invariant checked AFTER transfers with fee applied; verify reserves updated via _update; confirm reentrancy lock; verify amountOut>0 and to != token addresses; check router enforces amountOutMin/deadline.

### `mint(address) [add liquidity, LP tokens]`
- **Risk:** First-liquidity-provider inflation / MINIMUM_LIQUIDITY lock; rounding of LP shares; donation attacks skewing share price (UniV2 clones, Cetus-style).
- **Verify:** Verify MINIMUM_LIQUIDITY burned on first mint; verify liquidity = min(amount0*supply/reserve0, ...) rounding down; verify reserves read from stored not balanceOf where relevant; check reentrancy and _update sync.

### `burn(address) [remove liquidity]`
- **Risk:** Rounding lets burner extract slightly more; reentrancy via token transfers; skim/sync interplay.
- **Verify:** Verify amounts = liquidity * balance / totalSupply rounding down; verify both token transfers then _update; confirm nonReentrant; verify totalSupply>0.

### `skim(address) / sync()`
- **Risk:** skim sends excess balance to caller; sync force-matches reserves to balances — both are donation/inflation and oracle-manipulation levers.
- **Verify:** Verify skim only moves balance-reserve surplus; verify sync cannot be abused to reset accumulators; assess how donations affect price/TWAP and dependent oracles.

### `flash(address,uint,uint,bytes) [UniV3] / flashLoan`
- **Risk:** Flash accounting must be repaid with fee in same tx; reentrancy; used to fund manipulation.
- **Verify:** Verify post-callback balance >= pre + fee for both tokens; verify fee computed correctly; confirm lock/reentrancy; verify callback target validation.

### `_update(uint,uint,uint112,uint112) [reserves + TWAP accumulator]`
- **Risk:** price0CumulativeLast/price1CumulativeLast feed on-chain TWAP oracles; overflow-desync or blockTimestampLast manipulation corrupts oracle consumers.
- **Verify:** Verify accumulator uses unchecked overflow-by-design (UQ112x112); verify timeElapsed uses block.timestamp % 2^32; confirm reserves fit uint112; assess whether downstream TWAP window is long enough to resist manipulation.

### `getReserves() used AS a price oracle`
- **Risk:** Spot reserves are flash-loan manipulable — the single most common DeFi exploit root cause (bZx, Harvest, Cheese Bank, Warp).
- **Verify:** Flag any consumer that prices assets from getReserves() spot; require TWAP or external oracle; verify reserve0/reserve1 decimals and ordering; check for read-only reentrancy on Curve/Balancer-style getters.

### `collect / increaseLiquidity / decreaseLiquidity / positions [UniV3 NFT manager]`
- **Risk:** Fee accounting per-position; tokensOwed overflow; wrong recipient; callback validation; tick math edge cases.
- **Verify:** Verify position ownership/approval; verify tokensOwed accounting and fee growth deltas; verify pool key authenticity (msg.sender is a canonical pool); check slippage on liquidity changes.

### `add_liquidity / remove_liquidity / remove_liquidity_imbalance / remove_liquidity_one_coin [Curve, Vyper]`
- **Risk:** Read-only reentrancy on get_virtual_price during remove_liquidity (Curve incidents); imbalanced ops have fee/rounding edge cases; Vyper reentrancy-lock compiler bug (2023) affected some pools.
- **Verify:** Verify @nonreentrant lock present and Vyper version not in the vulnerable set 0.2.15 / 0.2.16 / 0.3.0 (fixed in 0.3.1); verify get_virtual_price cannot be read mid-remove; check imbalance fee math; verify min_amounts slippage.

### `exchange / get_dy / get_dy_underlying [Curve]`
- **Risk:** Price/quote functions used as oracles are manipulable; fee and admin-fee accounting; A (amplification) ramping edge cases.
- **Verify:** Verify get_dy not used as spot oracle by integrators; verify fee applied; check A-ramp bounds and future_A timing; confirm rounding favors pool.

### `get_virtual_price() as oracle`
- **Risk:** Assumed manipulation-resistant but vulnerable to read-only reentrancy: can be inflated during a remove_liquidity callback.
- **Verify:** Verify integrators guard against read-only reentrancy (call a state-mutating nonReentrant fn first or check lock); verify pool token balances vs virtual price during external calls.

### `addLiquidity / removeLiquidity / swapExactTokensForTokens (router)`
- **Risk:** Router is where slippage/deadline live; missing amountMin/deadline = guaranteed MEV loss; fee-on-transfer variants must be used for taxed tokens.
- **Verify:** Verify amountOutMin/amountInMax and deadline enforced; verify SupportingFeeOnTransfer variants exist for taxed tokens; verify path validation; confirm no leftover approvals.


## stablecoin

### `join / exit (GemJoin, DaiJoin, ETHJoin)`
- **Risk:** Adapters move collateral into/out of the vat; wrong decimals normalization or missing auth mints/burns internal balances incorrectly.
- **Verify:** Verify auth (only permitted adapters can vat.slip/vat.move); verify decimal scaling to WAD; verify cage/live checks; confirm fee-on-transfer collateral handled; verify exit burns internal dai before transferring.

### `frob(bytes32,address,address,address,int,int) [modify vault]`
- **Risk:** The core CDP invariant function; sign errors on dink/dart, ilk rate math, dust/ceiling checks, and hope() delegation determine solvency.
- **Verify:** Verify safe/dust/ceiling checks (Line, line, dust); verify collateralization: tab <= ink*spot; verify only owner or hoped address can reduce collateral / increase debt; verify rate multiplication (rad = wad*ray) and no overflow.

### `draw / wipe (generate / repay Dai)`
- **Risk:** Rounding in stability-fee accrual; repaying with stale rate; ceiling bypass.
- **Verify:** Verify drip()/jug accrual run before draw; verify debt ceiling enforced; verify rate applied consistently on wipe; check dust minimum.

### `bite / bark / grab [liquidation]`
- **Risk:** Liquidation trigger; wrong penalty (chop), auction kick parameters, or missing safety check liquidates safe vaults or under-penalizes.
- **Verify:** Verify vault is unsafe (ink*spot < tab) before bite; verify chop penalty and dunk/hole limits; verify vice/sin bookkeeping; verify auction (flip/clip) started with correct lot/tab; check for reentrancy in clip take with callback.

### `heal / suck / fess / flog [debt/surplus bookkeeping]`
- **Risk:** vat.suck mints unbacked internal dai (system debt); heal cancels sin against dai; auth mistakes here create unbacked stablecoin.
- **Verify:** Verify only Vow/authorized modules call suck/heal; verify sin queue accounting; verify surplus/deficit invariants (debt == sum of art*rate); confirm no path lets a user call suck.

### `sellGem / buyGem [PSM]`
- **Risk:** PSM 1:1 swap; fee (tin/tout) rounding, decimal mismatch, and unlimited mint can be arbitraged or drained; USDC-decimals (6) vs Dai (18) scaling bugs.
- **Verify:** Verify tin/tout fee math and rounding direction; verify 6-vs-18 decimal conversion exact; verify debt ceiling (line) on PSM ilk; confirm no rounding lets attacker extract free value on repeated swaps.

### `drip / jug.drip / pot.drip [fee accrual]`
- **Risk:** Compounding rate accrual; if skippable or overflowing, stability fees/DSR miscompute; rate can be manipulated by timing.
- **Verify:** Verify rpow compounding correct; verify called before rate-dependent ops; verify no negative rate underflow; check duty/base bounds.

### `poke [OSM/Spotter price update]`
- **Risk:** Sets spot = price/mat; feeds liquidation solvency; stale or manipulable feed here is catastrophic (peg loss).
- **Verify:** Verify OSM one-hour delay and hop; verify median/quorum on price sources; verify mat (liquidation ratio) applied; confirm access to feed whitelist; verify circuit breaker / freeze.

### `hope / nope / rely / deny [auth delegation]`
- **Risk:** vat.hope grants another address permission to move your dai/collateral; rely grants module auth — over-broad rely is a system-wide compromise.
- **Verify:** Enumerate all rely'd addresses at deploy; verify governance/timelock controls rely/deny; verify hope only affects caller's own permissions; check no auto-hope in adapters.


## oracle

### `latestRoundData() / latestAnswer() [Chainlink]`
- **Risk:** Using price without staleness/round checks returns stale or zero prices (many liquidation/mint bugs); latestAnswer is deprecated and has no timestamp.
- **Verify:** Require answer > 0; require updatedAt != 0 and block.timestamp - updatedAt <= heartbeat (staleness); verify decimals() used for scaling. **`answeredInRound >= roundId` is deprecated** — on OCR feeds answeredInRound always equals roundId, so its absence is NOT a finding on current feeds (its presence is harmless). Check whether the *specific* aggregator has restrictive minAnswer/maxAnswer bounds (most modern feeds set unreachable values); flag consumers that trust a price clamped at the bounds only where bounds are meaningful (Venus/LUNA-style).

### `getReserves() / spot balanceOf-based price / getAmountOut as oracle`
- **Risk:** Spot AMM price is flash-loan manipulable — root cause of most oracle exploits.
- **Verify:** Flag any spot-price oracle; require TWAP or independent feed; verify reserve decimals and ordering; check read-only reentrancy exposure.

### `consult / TWAP: price0CumulativeLast, observe(), OracleLibrary`
- **Risk:** TWAP windows too short are still manipulable across few blocks (esp. low-liquidity pairs); observe() reverts if cardinality not increased; L2 timestamp quirks.
- **Verify:** Verify TWAP window length adequate for pool liquidity; verify observationCardinality increased and initialized; verify accumulator overflow handling; check that manipulation cost > potential profit.

### `setPrice / updatePrice / submitPrice [manual/pushed price]`
- **Risk:** Owner/keeper-set prices are a centralization + compromise risk and a rug vector.
- **Verify:** Verify access control + multisig/timelock; verify deviation bounds and rate-of-change limits; verify staleness on last update; check for signature/quorum requirement on pushed prices.

### `peek / read / peep [Maker OSM/median]`
- **Risk:** read reverts if price invalid; peek returns validity bool that must be checked; delayed OSM value may be stale during volatility.
- **Verify:** Verify has-value bool checked; verify OSM delay acceptable for use case; verify feed whitelist and quorum; verify caller whitelist (osm bud).

### `getUnderlyingPrice(cToken) [Compound-style oracle]`
- **Risk:** Decimal normalization by asset (18 - underlyingDecimals) errors misprice markets; oracle returning 0 for unlisted market.
- **Verify:** Verify per-asset decimal scaling; verify revert/zero handling for unconfigured assets; verify source freshness and that setter is protected.

### `L2 sequencer uptime check (Arbitrum/Optimism/Base and other sequencer rollups — N/A on TRON: L1 DPoS, no sequencer)`
- **Risk:** On sequencer-based L2s, Chainlink feeds can be stale during sequencer downtime; missing uptime check enables liquidations on stale prices. **Not applicable to TRON (L1 DPoS, no sequencer) or other L1s.**
- **Verify:** On a sequencer L2, verify sequencerUptimeFeed checked (started, grace period) before trusting price; on an L1 like TRON this check is N/A — do not flag its absence.


## proxy-upgrade

### `initialize(...) / initializer / reinitializer(n) / _disableInitializers`
- **Risk:** Unprotected or front-runnable initializer lets attacker seize ownership (multiple mainnet incidents, e.g. uninitialized proxy takeovers); re-initialization via reinitializer misuse; logic-contract left uninitialized (Parity multisig selfdestruct).
- **Verify:** Verify initializer modifier prevents re-run; verify constructor calls _disableInitializers() on the implementation; verify all parent __X_init chains called exactly once; verify ownership/roles set to intended admin; check initialize cannot be front-run (deploy+init atomic or access-restricted).

### `_authorizeUpgrade(address) [UUPS]`
- **Risk:** If not overridden with access control, ANYONE can upgrade the implementation (UUPS footgun); wrong impl bricks or hijacks the proxy.
- **Verify:** Verify _authorizeUpgrade has onlyOwner/onlyRole/timelock; verify new implementation is itself UUPS-compatible (proxiableUUID) to avoid non-upgradeable brick; confirm upgrade emits event and goes through governance.

### `upgradeTo / upgradeToAndCall / setImplementation / changeAdmin (Transparent/Beacon)`
- **Risk:** Direct implementation swap is the ultimate privilege; admin-vs-user function clashing (transparent proxy); beacon upgrade affects all proxies at once.
- **Verify:** Verify only ProxyAdmin/timelock can call; verify transparent-proxy admin cannot call impl functions (selector clash); verify beacon owner is secured; verify upgradeToAndCall init data can't be abused; check implementation address non-zero and has code.

### `delegatecall(...) in proxy fallback or elsewhere`
- **Risk:** delegatecall executes external code in caller's storage context (SWC-112); storage-layout collision or delegatecall to attacker-controlled address = total compromise (Parity).
- **Verify:** Verify delegatecall target is immutable/trusted (not user-supplied); verify storage layout compatibility between proxy and impl; verify no delegatecall in a library that could selfdestruct; check for arbitrary-delegatecall in multicall/execute patterns.

### `storage layout / __gap[] / struct ordering across versions`
- **Risk:** Reordering, inserting, or removing state variables between upgrades corrupts all storage (silent fund misaccounting).
- **Verify:** Diff storage layout between old/new impl; verify appended-only variables; verify __gap reduced by exactly the number of new slots; verify inheritance order unchanged; verify no immutable/constant assumptions moved to storage.

### `ERC-7201 namespaced storage (OZ 5.x) — @custom:storage-location / erc7201:... slots`
- **Risk:** OZ 5.x abandons sequential slots + `__gap` for **namespaced storage** (`keccak256(abi.encode(uint256(keccak256("id")) - 1)) & ~0xff`). Auditing such a contract with the old `__gap`/sequential-layout mental model misses real collisions: a wrong or duplicated namespace string, a hand-written slot that doesn't match the `@custom:storage-location`, or mixing sequential and namespaced state across an upgrade.
- **Verify:** For OZ 5.x / namespaced contracts, recompute each `erc7201:` slot from its label and confirm the struct is read/written there; verify namespaces are unique and stable across versions; confirm no legacy sequential state coexists in a colliding slot.

### `constructor logic in an upgradeable contract`
- **Risk:** Constructors don't run in proxy context, so state set in a constructor is absent behind the proxy (uninitialized critical state).
- **Verify:** Verify no critical state set in constructor of upgradeable impls; verify moved to initialize(); verify immutables used only for genuinely constant values.

### `selfdestruct / SELFDESTRUCT reachable from impl or delegatecalled lib`
- **Risk:** A selfdestruct in the implementation (esp. via delegatecall) can destroy the logic contract and brick every proxy pointing to it (Parity library kill). **EIP-6780 neutralizes this: SELFDESTRUCT deletes code only when called in the same tx as creation. It is live on post-Cancun mainnet EVM AND — as of 2026-04-10 — on TRON mainnet (Proposal 94 / GreatVoyage-v4.8.1; SELFDESTRUCT energy raised 0→5000). So the impl/library brick is DEAD on both post-Cancun EVM and current TRON; it is a finding only on pre-6780 chains or a contract destroyed inside its own creation tx (metamorphic CREATE2+SELFDESTRUCT). Balance transfer to the target still happens, so force-feed still works.** TRON gates the behavior behind **network parameter #94** (shipped in GreatVoyage-v4.8.1 Democritus) — on a fork / private net / testnet where #94 is still 0 the old brick vector is live, so **verify #94's state on the actual target chain** rather than assuming either way.
- **Verify:** Grep for selfdestruct/suicide; verify none reachable in implementation/library; confirm the target chain's EIP-6780 status (dead on post-Cancun EVM and on TRON since 2026-04-10; live only on pre-6780 chains or same-tx create+destroy); ensure no arbitrary-call path reaches it.


## bridge

### `deposit / lock / burn (source chain)`
- **Risk:** Amount/event mismatch, fee-on-transfer under-lock, or reentrancy lets attacker mint more on destination than locked; wrong recipient encoding.
- **Verify:** Verify actual received amount (fee-on-transfer) is what gets credited in the emitted message; verify recipient/chainId encoded correctly; verify reentrancy guard; confirm token allowlist; verify event is the single source of truth relayers use.

### `withdraw / unlock / exit / mintFromChain / claim (destination chain)`
- **Risk:** The highest-value target: forged/replayed proofs mint unbacked tokens (Ronin $625M, Wormhole $326M, Nomad $190M, Harmony). Double-spend via missing nonce/used-flag.
- **Verify:** Verify proof/signature verified against the CURRENT validator set; verify message hash includes chainId, nonce, recipient, amount, token; verify used/processed mapping set BEFORE external transfer (replay protection); verify mint amount exactly matches verified message; confirm no default-trusted root (Nomad zero-root bug).

### `verifyProof / verifySignatures / _verify / checkQuorum [validator/guardian set]`
- **Risk:** Threshold errors, signature malleability, non-sorted/duplicate signer acceptance, or wrong messageHash construction bypass consensus (Wormhole guardian bug class).
- **Verify:** Verify m-of-n threshold enforced and counts UNIQUE signers (reject duplicates); verify signers sorted/deduped; verify ecrecover != 0 and signer in current set; verify messageHash uses EIP-191/712 with domain + chainId; verify guardian-set index matches; check for signature malleability (s in lower half).

### `updateValidators / setValidators / setGuardianSet / setThreshold / addSigner`
- **Risk:** Validator-set rotation is a takeover vector (Ronin: attacker gained 5/9 keys); missing verification or single-key control undermines the whole bridge.
- **Verify:** Verify update itself requires current-set quorum or secured multisig/timelock; verify set-index increments and old sets expire; verify threshold sane vs set size; verify no single EOA controls rotation; check event emission and monitoring.

### `processMessage / receiveMessage / executeMessage / relay`
- **Risk:** Generic message execution can call arbitrary targets (arbitrary-call bridges); missing source/sender authentication enables spoofed cross-chain calls.
- **Verify:** Verify source chainId and source sender authenticated; verify target/selector allowlist if arbitrary calls possible; verify replay nonce consumed; verify reentrancy and gas handling; confirm failed messages can't be replayed to double-execute.

### `Merkle root / setRoot / confirmedRoots mapping`
- **Risk:** Accepting an unconfirmed or zero root (Nomad) validates any leaf; root-update auth weakness forges all withdrawals.
- **Verify:** Verify roots only accepted after confirmation window/attestation; verify zero/default root is NOT auto-trusted; verify leaf encoding domain-separated; verify proof length and index bounds; verify root update authorization.

### `standard cross-chain messaging integrations (LayerZero lzReceive / CCIP ccipReceive / Wormhole VAA / Axelar _execute)`
- **Risk:** Beyond hand-rolled lock/mint: an app built on a messaging protocol has its own trust assumptions — is the caller the trusted endpoint/router, is the `srcChainId`+`srcAddress` (trusted-remote) enforced, is the VAA/message replay-protected and its emitter/sequence bound, is `payloadHash`/nonce checked? TRON runs a live LayerZero endpoint, so TRON-side apps are in scope. Missing remote/endpoint authentication = forged messages mint/unlock at will.
- **Verify:** Confirm the receive entrypoint asserts `msg.sender == endpoint/router`; that the source chain + remote address are allowlisted (`trustedRemote`/`getPeer`); replay protection on VAA/message (consumed sequence/nonce, emitter bound); payload integrity; and that failed/blocked messages can't be force-resumed to double-execute.


## liquid-staking

### `stake / submit / deposit (mint shares)`
- **Risk:** First-depositor/inflation attack: attacker mints 1 wei share then donates assets to skew exchange rate, stealing later depositors' funds (classic ERC4626/LST bug); share rounding.
- **Verify:** Verify inflation mitigation (dead shares minted at init, virtual shares/offset, or minimum deposit); verify shares = assets * totalShares / totalAssets rounds DOWN for user; verify totalAssets uses accounted value not raw balanceOf (donation resistance); verify reentrancy guard.

### `unstake / withdraw / requestWithdrawal / redeem`
- **Risk:** Rounding lets redeemer extract more; withdrawal queue manipulation; reentrancy on native transfer; slashing not reflected before withdrawal.
- **Verify:** Verify assets = shares * totalAssets / totalShares rounds DOWN for user; verify queue/epoch accounting; verify oracle/slashing update applied before pricing; confirm CEI and nonReentrant on ETH/TRX send; verify no withdraw of others' queued funds.

### `getPooledEthByShares / getSharesByPooledEth / convertToAssets / convertToShares / exchangeRate`
- **Risk:** The pricing core; if totalAssets/totalPooled is balanceOf-based it's donation-manipulable; rounding direction must consistently favor the protocol.
- **Verify:** Verify rounding directions (deposit down-shares, withdraw down-assets); verify total uses internal accounting; verify zero-supply init branch; check consistency between forward and inverse conversions (no round-trip profit).

### `rebase / handleOracleReport / reportBeacon / pushReport`
- **Risk:** Oracle report updates total staked incl. rewards/slashing; unbounded or unsigned report can inflate shares (Lido-style report sanity limits exist for a reason).
- **Verify:** Verify report from authorized oracle quorum; verify sanity bounds on reward/slashing delta per report (max APR, max slash); verify frame/epoch replay protection; verify fee minting math on rewards; check for reentrancy during finalization.

### `harvest / distributeRewards / claim`
- **Risk:** Reward accounting bugs (accRewardPerShare) let users claim more than earned or grief via deposit-before-harvest; rounding dust drain.
- **Verify:** Verify accumulator updated before balance changes; verify rewardDebt bookkeeping on deposit/withdraw; verify no double-claim; verify pending reward rounding; check pool weight/alloc updates use massUpdate.

### `slash / penalize / applySlashing`
- **Risk:** Slashing socialization must reduce shares' value fairly; mis-scoped or front-runnable slashing lets some exit before loss is applied.
- **Verify:** Verify slashing applied to totalAssets atomically before any withdrawals in the same frame; verify cannot be sandwiched by stake/unstake; verify authorization and bounds.


## governance

### `propose(targets,values,calldatas,description)`
- **Risk:** Proposal threshold too low or flash-loan-borrowed votes let attacker propose+pass malicious action (Beanstalk $182M); duplicate/self-referential actions.
- **Verify:** Verify proposalThreshold checked against votes at a PAST snapshot (not current balance); verify targets/values/calldatas length match; verify proposer cannot include upgrade-to-drain without timelock delay; check spam/duplicate-proposal guards.

### `castVote / castVoteWithReason / castVoteBySig`
- **Risk:** Voting power must be snapshotted before proposal to prevent flash-loan/borrow-to-vote; BySig replay and wrong domain; double voting.
- **Verify:** Verify getPastVotes at proposal snapshot block used (not getVotes/current balance); verify hasVoted mapping prevents double vote; verify castVoteBySig nonce/deadline/domain and ecrecover != 0; verify support value range.

### `queue(...) / timelock scheduling`
- **Risk:** Missing or too-short timelock removes the safety window; queue without delay lets malicious proposals execute instantly.
- **Verify:** Verify successful proposals must pass through timelock with adequate delay; verify eta = now + delay enforced; verify grace period; verify the timelock admin is the governor (not an EOA).

### `execute(...) / executeTransaction (Timelock)`
- **Risk:** Arbitrary target/calldata execution with protocol privileges; if callable before eta or without prior queue, it's game over; reentrancy on execute.
- **Verify:** Verify state == Queued and block.timestamp >= eta and <= eta+grace; verify txHash matches queued hash exactly; verify only timelock (via governor) executes; verify value/target match; check reentrancy and that execute marks executed before external calls.

### `cancel(...) / veto / guardian`
- **Risk:** Missing cancel path prevents stopping a malicious queued proposal; over-broad guardian cancel is centralization.
- **Verify:** Verify legitimate cancel conditions (proposer below threshold, guardian veto); verify guardian scope limited and time-bounded; verify cannot cancel already-executed.

### `delegate / delegateBySig / _moveVotingPower / checkpoints`
- **Risk:** Checkpoint math (ERC20Votes) errors under- or over-count votes; delegateBySig replay; double-count on transfer; SafeCast to uint96/uint224 overflow.
- **Verify:** Verify checkpoint binary search and write-on-transfer logic; verify delegateBySig nonce/expiry/domain; verify voting power moves on transfer/mint/burn; check SafeCast bounds on vote weight; verify getPastVotes reverts for future blocks.

### `quorum / proposalThreshold / votingDelay / votingPeriod setters`
- **Risk:** Governance parameter setters that lower quorum/threshold enable takeover; must be governed by the DAO itself, not an EOA.
- **Verify:** Verify only governance/timelock can change; verify bounds; verify quorum denominator source (total supply snapshot) not manipulable; check votingDelay >= 1 block to enforce snapshot.


## signature

### `ecrecover(hash,v,r,s) usage`
- **Risk:** Returns address(0) for invalid sig (auth bypass if 0 matches an unset admin, SWC-117/122); signature malleability (SWC-117) via high-s / v flip enables replay with a second valid signature.
- **Verify:** Verify result checked != address(0); verify s is in lower half (s <= secp256k1n/2) and v in {27,28} (use OZ ECDSA); verify recovered signer compared to expected; confirm not used to gate mappings keyed by address(0).

### `permit / permitBySig / EIP-712 typed-data verification`
- **Risk:** Wrong DOMAIN_SEPARATOR (missing chainId → cross-chain replay; not recomputed after fork), missing deadline, or missing nonce enables replay/forgery.
- **Verify:** Verify domain separator includes name, version, chainId, verifyingContract and is recomputed if chainId changes; verify per-owner nonce increments; verify deadline >= block.timestamp; verify typehash matches struct; check hashStruct encoding (dynamic types hashed).

### `replay protection: nonces mapping / usedHashes / consumed signatures`
- **Risk:** Missing or mis-keyed nonce lets the same signature be used repeatedly (payment/meta-tx replay); cross-contract or cross-chain replay if domain not bound.
- **Verify:** Verify nonce consumed atomically before effects; verify hash includes contract address + chainId; verify used-mapping set before external call; check nonce ordering (sequential vs bitmap) matches intended UX.

### `isValidSignature(bytes32,bytes) EIP-1271 / SignatureChecker`
- **Risk:** Smart-contract wallet signatures; must handle both EOA (ecrecover) and 1271; a permissive isValidSignature or unchecked magic-value enables forgery; reentrancy via the callee.
- **Verify:** Verify exact magic value 0x1626ba7e returned/compared; verify fallback to ecrecover only for EOAs (code.length==0) — **note: post-EIP-7702 (Pectra, mainnet May 2025) a delegated EOA carries a 23-byte `0xef0100||delegate` designator, so `code.length==0` no longer proves EOA and `code.length>0` no longer proves "cannot ECDSA-sign"; route delegated EOAs through the 1271/delegate path and do not use extcodesize for auth (it breaks onlyEOA/anti-bot/relayer gates)**; verify the 1271 contract itself validates properly; consider signature-validation reentrancy.

### `abi.encodePacked(...) fed into signed/hashed message with multiple dynamic args`
- **Risk:** Hash collision (SWC-133): encodePacked of adjacent dynamic types lets different inputs produce the same hash, forging authorization.
- **Verify:** Verify abi.encode (not encodePacked) used when >1 dynamic type; or verify fixed-length/separator; confirm hashed message is unambiguous.


## math

### `mulDiv / a*b/c full-precision multiply-then-divide`
- **Risk:** Intermediate overflow if not using 512-bit mulDiv; division-before-multiplication truncation; rounding direction determines who profits (share/LP/interest math).
- **Verify:** Verify FullMath.mulDiv or equivalent for products that can overflow 256-bit; verify multiply-before-divide ordering; verify explicit round-up (mulDivRoundingUp) only where protocol should gain; check denominator != 0.

### `rounding direction in share<->asset, interest, and fee conversions`
- **Risk:** Rounding in the user's favor, even by 1 wei, compounds into drains (inflation attacks, dust exploits, ERC4626 round-trip).
- **Verify:** Verify EIP-4626 rounding is always against the user — **deposit rounds shares DOWN, mint rounds assets UP, withdraw rounds shares UP, redeem rounds assets DOWN**; convertToShares/convertToAssets round DOWN; verify fee rounds toward protocol; verify no round-trip (deposit/withdraw or mint/redeem) yields profit; test 1-wei and empty-pool edge cases.

### `unchecked { ... } blocks`
- **Risk:** Solidity 0.8 checked math bypassed; overflow/underflow reintroduced (SWC-101) — common in loop counters (safe) but dangerous in balance/supply math.
- **Verify:** Audit each unchecked block for reachable overflow/underflow with attacker-controlled inputs; verify invariants proven before the block (e.g., a>=b before a-b); confirm only truly-safe arithmetic is unchecked.

### `casting / SafeCast: uint256->uint128/uint112/uint96, int<->uint`
- **Risk:** Silent truncation on downcast corrupts balances/reserves/votes; int/uint sign flips (Compound, many reserve-fit bugs).
- **Verify:** Verify SafeCast used for downcasts of user-influenced values; verify values provably fit target width; verify int-to-uint conversions can't wrap negative; check reserve fields (uint112) and vote weights (uint96/uint224).

### `sqrt / pow / rpow / exp fixed-point routines (WAD/RAY)`
- **Risk:** Fixed-point scale (1e18/1e27) mismatches, overflow in exponentiation, and precision loss misprice pools/rates.
- **Verify:** Verify consistent WAD/RAY scaling across a computation; verify rpow/exp overflow guards; verify sqrt rounding (e.g., Babylonian) and edge cases (0, 1); check decimal normalization across tokens with differing decimals.

### `division: x / y where y can be 0 or where truncation matters`
- **Risk:** Division by zero reverts (DoS) or truncation zeroes out amounts (free actions); order of operations loses precision.
- **Verify:** Verify denominators guarded (utilization=0, totalSupply=0, reserves=0); verify precision scaling before division; verify truncation-to-zero can't grant free mint/borrow/redeem.


## general

### `external call before state update (reentrancy) — any .call/.transfer/token.transfer/callback`
- **Risk:** Classic reentrancy (SWC-107): The DAO, Cream, Fei/Rari ($80M), cross-function and read-only reentrancy variants.
- **Verify:** Verify checks-effects-interactions ordering; verify nonReentrant on all externally-facing state-changers that make external calls; assess cross-function and read-only reentrancy (view getters used by others during a callback); verify ERC777/hook tokens considered. When checking that a guard *exists*, also grep `tstore`/`tload` — EIP-1153 transient guards (OZ `ReentrancyGuardTransient`, Uniswap v4, Solady) don't use a bool storage mutex, so a mutex-only grep false-negatives "guard missing".

### `address.call{value:}(...) / low-level call/staticcall/delegatecall with unchecked return`
- **Risk:** Unchecked low-level call return (SWC-104) silently continues on failure; arbitrary call target/calldata enables privilege escalation and token theft.
- **Verify:** Verify (bool ok, ) checked and reverted; verify call target is not user-controlled for privileged actions; verify no arbitrary delegatecall; check gas forwarding and return-data handling; verify multicall/aggregate can't self-authorize.

### `selfdestruct(address) / SELFDESTRUCT`
- **Risk:** Can force-send native balance bypassing invariants (SWC-106); library selfdestruct bricks proxies (Parity) — but **EIP-6780 restricts code deletion to the creation tx, so on post-Cancun EVM AND on TRON (mainnet since 2026-04-10, Proposal 94 / GreatVoyage-v4.8.1) the library-brick vector is DEAD, while force-feeding the target's balance still works. Live brick only on pre-6780 chains or a same-tx create+destroy.**
- **Verify:** Grep for selfdestruct/suicide; verify unreachable or access-controlled + intended; verify no reliance on `this.balance` invariant that force-send breaks; confirm the chain's EIP-6780 status (TRON adopted it 2026-04-10; SELFDESTRUCT energy is now 5000).

### `block.timestamp / block.number / block.difficulty(prevrandao) / blockhash for randomness or timing`
- **Risk:** Miner/validator-influenceable (SWC-116, SWC-120); weak randomness enables lottery/NFT-mint manipulation; TVM block time and block.number semantics differ from EVM.
- **Verify:** Verify no security-critical randomness from on-chain values (use VRF/commit-reveal); verify timestamp tolerance (~15s manipulation) acceptable; on TVM confirm block time (~3s) assumptions in rate/vesting math; avoid block.number-as-time on TVM. **On TVM `block.difficulty`/`prevrandao` (0x44) == 0 and `block.gaslimit` == 0 are CONSTANTS, and `gasprice`/`basefee` are fixed — any randomness OR fee/gas-branch keyed on these is dead/constant, not merely weak (a whole dead-branch class an EVM port misses).**

### `for/while loops over unbounded arrays (users, holders, markets)`
- **Risk:** Gas-limit DoS (SWC-128): a growable array iterated in a single tx can be bricked; push-payment loops let one failing recipient block all.
- **Verify:** Verify loop bounds are capped or paginated; verify no push-to-many payments (use pull pattern); verify array growth is permissioned or bounded; on TVM confirm energy limits.

### `transfer() / send() with 2300-gas stipend for native value`
- **Risk:** Fixed 2300 gas breaks when recipient is a contract with non-trivial receive (post-Istanbul repricing); can brick withdrawals.
- **Verify:** Prefer call{value:}('') with reentrancy guard and checked return; verify recipient-contract compatibility; on TVM verify TRX-send semantics and energy costs differ from EVM gas.

### `pause / unpause / emergencyStop / freeze / shutdown`
- **Risk:** Missing pause on critical flows prevents incident response; OR over-powerful/un-timelocked pause is a censorship/rug lever; asymmetric pause (can pause deposits but not withdrawals, or vice versa) traps funds.
- **Verify:** Verify pauser role is secured (multisig); verify which functions whenNotPaused gates (withdrawals should usually remain open, or be justified); verify unpause path exists; check pause can't be used to freeze user funds indefinitely.

### `receive() / fallback() payable and forced-ETH assumptions`
- **Risk:** Contracts relying on `address(this).balance` can be griefed by forced sends (selfdestruct/coinbase); unexpected fallback routing.
- **Verify:** Verify accounting uses internal ledgers not raw balance; verify fallback doesn't silently accept/route value; verify no invariant like `balance == expected` that force-send breaks.

### `front-running / MEV-sensitive ops (swaps, liquidations, auctions, commit-less reveals)`
- **Risk:** Public mempool ordering (SWC-114) enables sandwiching, JIT liquidity, and priority-gas auctions extracting user value.
- **Verify:** Verify slippage/minOut and deadline params on all user-facing swaps/mints; verify commit-reveal where ordering matters; assess whether admin actions (oracle/param updates) can be front-run for profit.

### `TRON/TVM-specific: energy & bandwidth, address format, precompiles, CREATE2, tx fee model`
- **Risk:** TVM diverges from EVM: gas→energy/bandwidth, different precompile set, address encoding (base58 T-address vs 0x41 hex), some EVM opcodes/precompiles absent or behave differently, and `block.coinbase`/`block.number` semantics differ — code ported from Ethereum may silently misbehave.
- **Verify:** Verify assembly/precompile usage (ecrecover, modexp, bn256) is TVM-supported; verify address handling for the 0x41 prefix; verify energy-limit assumptions in loops/callbacks; verify CREATE2 address derivation matches TVM; re-validate any hardcoded gas values and time-based math against TRON's ~3s blocks. **Details in the `tvm-native` section below.**


## erc4626-vault

### `deposit(uint256 assets,address receiver) / mint(uint256 shares,address receiver)`
- **Risk:** First-depositor inflation (attacker mints 1 wei share, donates assets, later deposits round to 0 shares — Sonne Finance $20M, Hundred, Onyx-class), share rounding in the depositor's favor, and no slippage bound (the EIP-4626 signature has NO minSharesOut, so a router-less deposit is silently sandwichable). Fee-on-transfer/TRC-20 assets credit the argument not the received amount.
- **Verify:** Verify inflation mitigation (OZ `_decimalsOffset()` virtual shares/assets, dead-share seed, or protocol-seeded initial deposit); verify `shares = assets.mulDiv(totalSupply+10**offset, totalAssets+1, Rounding.Down)` rounds shares DOWN on deposit and assets UP on mint; verify received = balanceAfter-balanceBefore for fee-on-transfer assets; verify callers wrap with a `minShares`/`maxAssets` slippage check; confirm nonReentrant and CEI (asset pulled before share mint).

### `withdraw(uint256 assets,address receiver,address owner) / redeem(uint256 shares,address receiver,address owner)`
- **Risk:** Rounding in the redeemer's favor drains other holders over repeated round-trips; missing allowance check on `owner != msg.sender` burns someone else's shares; reentrancy on the asset transfer-out; no minAssetsOut slippage bound in the standard signature.
- **Verify:** Verify withdraw rounds shares UP and redeem rounds assets DOWN (both against the user); verify `_spendAllowance(owner, msg.sender, shares)` when caller != owner; verify shares burned BEFORE the asset `safeTransfer` (CEI) and nonReentrant; verify no profitable deposit→withdraw or mint→redeem round-trip at 1-wei and empty-pool edges; verify callers enforce a `minAssets`.

### `totalAssets()`
- **Risk:** The pricing denominator. If it returns `asset.balanceOf(address(this))` (plus naive strategy value) it is donation-manipulable and enables the inflation attack; if it prices strategy positions from an AMM spot/`get_virtual_price`/LP reserves it is flash-loan manipulable; unrealized/pending harvest not counted desyncs share price.
- **Verify:** Verify `totalAssets` derives from internal accounting (a stored `_totalAssets`/strategy-reported figure mutated only via deposit/withdraw/harvest), not raw `balanceOf`; verify any strategy valuation uses a manipulation-resistant oracle not spot reserves; verify idle + deployed + accrued are summed once with no double-count; confirm a direct token donation cannot move it.

### `previewDeposit / previewMint / previewWithdraw / previewRedeem vs the actual mutating call`
- **Risk:** EIP-4626 requires `previewDeposit <= deposit` shares and `previewRedeem <= redeem` assets (preview must not over-promise), and previews MUST include fees and MUST NOT revert on vault-specific caps. A preview that ignores the deposit/withdraw fee, or rounds the opposite direction from the real call, lets integrators/aggregators mis-quote and be arbitraged or sandwiched.
- **Verify:** Verify each preview uses the SAME rounding direction and fee math as its mutating counterpart; verify `previewDeposit`/`previewRedeem` never return MORE than the real call yields; verify previews do not apply `maxDeposit`/user caps (those belong to `maxX`); confirm preview is `view` and free of state-dependent divergence from the executed path.

### `convertToShares(uint256) / convertToAssets(uint256)`
- **Risk:** Spec-defined ideal conversions that MUST round DOWN and MUST NOT reflect per-user limits or fees; if an integrator prices collateral off `convertToAssets` it can be inflated by the same donation that skews `totalAssets`; inconsistent forward/inverse rounding creates a round-trip profit.
- **Verify:** Verify both round DOWN; verify they exclude fees and caps (else previews/maxes are wrong); verify zero-supply branch returns the offset-adjusted initial rate not a divide-by-zero; flag any external consumer treating `convertToAssets(1e18)` as a manipulation-resistant price.

### `maxDeposit / maxMint / maxWithdraw / maxRedeem`
- **Risk:** Caps that gate strategy capacity, pause state, and per-user limits. A `maxDeposit` returning `type(uint256).max` while the strategy has a real deposit cap causes deposits to revert after quoting (integrator DoS); a `maxWithdraw` that ignores illiquid/deployed capital lets a redeem revert or force a fire-sale.
- **Verify:** Verify `maxWithdraw`/`maxRedeem` reflect actually-liquid assets (idle + instantly-withdrawable strategy), not total; verify caps return 0 when paused; verify `maxDeposit` matches the strategy/supply cap so `previewDeposit` at the cap does not later revert; confirm caps are honored inside `deposit`/`mint` (not advisory only).

### `_decimalsOffset() / virtual shares / dead-share seed [first-depositor mitigation]`
- **Risk:** The inflation-attack mitigation itself. A `_decimalsOffset()` of 0 (OZ default) leaves only a ~1-share buffer — insufficient for high-value assets; a hand-rolled "mint to dead address" seed that is too small, or seeded AFTER the first external deposit is allowed, still permits the donation attack.
- **Verify:** Verify the offset is large enough that a donation can't profitably round a real deposit to 0 (attacker's donation cost must exceed victim's rounding loss); verify virtual shares/assets are added in BOTH directions of every conversion; if using a dead-share seed, verify it is minted atomically at initialization before any user can deposit and is non-withdrawable.

### `strategy harvest / report / _deposit-into-strategy / _withdraw-from-strategy (yield aggregator)`
- **Risk:** Harvest swaps rewards→asset with `minOut=0` (loss socialized — sandwichable keeper tx); a report that marks unrealized strategy P&L from a manipulable price lets an attacker deposit before a favorable mark and redeem after; loss on `_withdraw` not reflected before pricing lets the last-out redeemer avoid a loss others absorb; harvest callable by anyone to time accruals.
- **Verify:** Verify internal harvest swaps compute `minOut` from an independent oracle/TWAP; verify strategy reports are bounded (max gain/loss per report, like Yearn's `managementFee`/loss limits) and use realized or oracle-priced value; verify a loss is applied to `totalAssets` atomically before any same-block withdrawal can exit; verify harvest access/rounding and reentrancy across the vault↔strategy boundary (cross-contract guard).

### `TVM: SUN 6-decimal native TRX in share math / TRC-20 asset decimals`
- **Risk:** A vault whose underlying is native TRX receives value in SUN (1e6), not wei (1e18) — 18-dec share math over a 6-dec asset changes the inflation-attack economics and can mis-scale conversions by 1e12; TRON USDT/USDD are 6 decimals, so a hardcoded 18-dec `totalAssets`/offset misprices shares.
- **Verify:** Confirm the offset and conversion scaling match the ACTUAL asset decimals (6 for TRX-SUN, USDT, USDD); keep native-TRX (SUN) vault math distinct from TRC-20 token math; verify the virtual-share buffer is sized in the asset's real decimals, not an assumed 18.


## staking-rewards

### `accRewardPerShare / rewardDebt accounting [MasterChef]`
- **Risk:** The core reward invariant `pending = user.amount * accRewardPerShare / PRECISION - user.rewardDebt`. If `updatePool` is not called before every `user.amount` change, or `rewardDebt` isn't reset to `user.amount * accRewardPerShare / PRECISION` after deposit/withdraw, users over/under-claim. `PRECISION` too small (classic `1e12`) truncates `accRewardPerShare` for high-decimal or low-emission pools, silently zeroing rewards or leaving drainable dust.
- **Verify:** Verify `updatePool(pid)` runs at the start of deposit/withdraw/harvest BEFORE touching `user.amount`; verify `rewardDebt` recomputed on every balance change; verify `accRewardPerShare` scaled by `1e12`/`1e18` and that `reward * PRECISION / lpSupply` doesn't truncate to 0 for the pool's decimals; verify `lpSupply == 0` branch skips accrual (no divide-by-zero).

### `updatePool(uint256 pid) / massUpdatePools()`
- **Risk:** Accrual uses `(block.number - lastRewardBlock) * rewardPerBlock * allocPoint / totalAllocPoint`. Skipping it before `set()`/`add()` changing `allocPoint` retroactively re-prices past blocks; `massUpdatePools` looping over an unbounded pool array hits the gas/energy limit (add-pool DoS); adding a pool without `massUpdatePools` first steals allocation from existing pools.
- **Verify:** Verify `add`/`set` call `massUpdatePools()` (or `updatePool` on affected pools) BEFORE changing allocPoints; verify pool count is bounded / `massUpdatePools` can't be bricked by array growth; verify `lastRewardBlock` advances even when `lpSupply==0` so blocks aren't double-counted.

### `deposit(uint256 pid,uint256 amount) / withdraw(uint256 pid,uint256 amount) [MasterChef]`
- **Risk:** Harvest-on-deposit pattern pays pending before updating `amount`; if `updatePool` is skipped or CEI is violated (LP pulled after reward paid via a hook token) it reenters; flash-deposit right before a harvest captures a same-block reward share.
- **Verify:** Verify order: `updatePool` → pay pending (`amount*acc/PREC - rewardDebt`) → change `user.amount` → reset `rewardDebt` → transfer LP; verify reward accrues per-block so a same-block deposit-then-harvest earns ~0; verify nonReentrant and received-amount for fee-on-transfer LP.

### `emergencyWithdraw(uint256 pid)`
- **Risk:** Must return principal while forfeiting rewards; a bug that doesn't zero `user.rewardDebt`/`user.amount` lets the user later re-claim rewards on withdrawn principal or leaves `accRewardPerShare` desynced; must never revert (it's the escape hatch).
- **Verify:** Verify it sets `user.amount = 0` and `user.rewardDebt = 0` BEFORE transferring LP; verify it does NOT pay rewards; verify it can't underflow pool bookkeeping and remains callable when the rest of the contract is paused.

### `stake-token == reward-token single-pool accounting`
- **Risk:** If the staking token and reward token are the same and rewards are paid from the same contract balance that holds stakes, `pendingReward` computed from `balanceOf(this)` (or an `lpSupply` read from balance) counts deposited principal as distributable reward — the pool pays out other users' stake (classic MasterChef fork drain).
- **Verify:** Verify staked principal is tracked in internal accounting separate from the reward reserve; verify `lpSupply`/`pending` never reads `token.balanceOf(this)` when stake==reward; verify a deposit cannot increase any other user's claimable reward.

### `Synthetix StakingRewards: notifyRewardAmount / rewardRate / periodFinish / rewardPerToken / earned`
- **Risk:** `rewardRate = reward / rewardsDuration` rounds to 0 if `reward < duration` (rewards stranded); `notifyRewardAmount` recomputing `rewardRate = (reward + leftover) / duration` and resetting `periodFinish` lets an authorized-but-careless (or attacker-controlled) caller DILUTE the rate and stretch the period; the transferred reward balance must cover `rewardRate*duration` or the last claimers get nothing (insolvent distribution).
- **Verify:** Verify `rewardRate > 0` after notify (reward >= duration in the reward token's decimals); verify the reward token is actually transferred in and `rewardRate*rewardsDuration <= balance` (Synthetix's explicit `require`); verify `notifyRewardAmount` is access-controlled to the distributor; verify `lastTimeRewardApplicable = min(block.timestamp, periodFinish)` and `rewardPerTokenStored` updated via the `updateReward` modifier on every stake/withdraw/getReward.

### `getReward / harvest / claim / claimRewards`
- **Risk:** Double-claim if `rewards[account]`/`userRewardPerTokenPaid` not zeroed before transfer; reentrancy via the reward token; rounding dust accumulation drained over many claims.
- **Verify:** Verify `rewards[msg.sender]` set to 0 BEFORE the reward `safeTransfer` (CEI); verify `updateReward(msg.sender)` runs first; verify per-claim rounding favors the protocol; nonReentrant on the reward token path.

### `gauge vote / vote_for_gauge_weights / user_checkpoint [Curve/veToken gauge]`
- **Risk:** Vote weight derived from a `ve` balance that can be flash-acquired or double-counted across gauges; a missing `user_checkpoint` before weight change back-dates emissions; vote-power decay (linear over lock) mis-integrated lets a stale checkpoint over-count.
- **Verify:** Verify voting power is read from a checkpointed veBalance at a bias/slope, not spot; verify per-user and per-gauge checkpoints run before any weight/emission change; verify a user can't vote the same ve weight across gauges beyond 100%; verify emission integration handles the linear decay boundary.

### `bribe / claim_bribe / feeDistributor claim [ve(3,3) / Velodrome-style]`
- **Risk:** Bribe/fee rewards claimed for an epoch the voter didn't actually vote in, or claimed twice across epochs; bribe accounting keyed on a manipulable current-vote snapshot rather than the epoch-finalized weight; rounding lets last-claimer over-draw.
- **Verify:** Verify bribes accrue against the FINALIZED per-epoch vote weight (not live), keyed by (epoch, gauge, user) with a claimed flag; verify no claim before the epoch flips; verify total distributed <= deposited per epoch; verify vote power used matches the epoch it's claimed for.

### `TVM: rewardPerBlock over ~3s TRON blocks (block.number emission)`
- **Risk:** MasterChef emits `rewardPerBlock` per BLOCK. TRON's ~3s block time (vs Ethereum ~12s) means an EVM→TRON port keeping the same `rewardPerBlock` (or a `bonusEndBlock`/`startBlock` copied from Ethereum) emits ~4× faster in wall-clock — over-inflating rewards and exhausting the reward reserve early.
- **Verify:** Verify block-number-denominated emission/schedule constants are re-derived for TRON's ~3s blocks (or switch to timestamp-based like Synthetix); confirm `startBlock`/`bonusEndBlock`/`rewardPerBlock` weren't copied from an Ethereum deployment; verify the reward reserve covers the real wall-clock emission.


## perps-derivatives

### `funding rate accrual: cumulativeFundingRate / _updateFunding / fundingIndex / _settleFunding`
- **Risk:** Funding = premium `(markPrice - indexPrice)/indexPrice` integrated over time; if not accrued (via a global `cumulativeFundingRate` index applied to each position on interaction) BEFORE a position is opened/closed, a trader opens right before a large funding payment and closes right after to dodge it, or harvests funding they didn't hold through; per-block accrual on `block.number` misprices the time integral.
- **Verify:** Verify a global funding index is updated on every position mutation and settlement, and each position settles funding against the delta since its last-touched index; verify funding accrues over elapsed TIME (timestamp), not block count; verify the mark-index spread feeding funding can't be single-block manipulated; verify funding cannot be gamed by open-just-before/close-just-after (accrual is continuous, not stepped at settlement points).

### `mark price vs index/oracle price separation`
- **Risk:** Using ONE price for both entry/PnL (mark) and collateral/liquidation (index) collapses the safeguard: if mark = an internal AMM/orderbook spot, it's manipulable to open/close at a favorable price; if collateral valuation uses the same spot, the whole book is flash-manipulable (Mango Markets $114M — attacker pumped the MNGO oracle and borrowed out the treasury against inflated perp collateral).
- **Verify:** Verify mark price (for PnL) and index price (for margin/liquidation/settlement) are distinct and that the COLLATERAL/liquidation price is a manipulation-resistant oracle (median/Chainlink/long TWAP), never a thin spot; verify no path lets a trader's own action move the price that values their collateral; cross-check the index against a second source with deviation bounds.

### `openPosition / increasePosition / decreasePosition / closePosition [PnL & margin]`
- **Risk:** PnL and margin math sign errors (long vs short), notional computed from a manipulable mark, leverage cap not enforced post-open, and unrealized PnL counted as free collateral to open more (reflexive leverage). Rounding of margin/notional in the trader's favor accumulates.
- **Verify:** Verify margin ratio checked AFTER the position change with a conservative price; verify max-leverage/initial-margin enforced on increase; verify unrealized profit isn't usable as margin beyond protocol rules; verify PnL sign per direction and that notional uses the index for margin checks; verify rounding favors the protocol; nonReentrant on collateral transfer.

### `liquidatePosition / liquidate [liquidation engine] + keeper incentive / liquidationReward`
- **Risk:** Liquidating a healthy position (stale/manipulated mark), seizing too much collateral (bad-debt spiral), self-liquidation to capture the keeper reward, or a liquidation reward large enough to itself push a marginal position into bad debt. Partial-liquidation rounding and reentrancy on payout.
- **Verify:** Verify position is provably below maintenance margin at a FRESH manipulation-resistant price before liquidation; verify seize/close-factor bounds and that the keeper reward is capped and cannot create bad debt; verify a trader can't profitably self-liquidate; verify remaining position stays solvent or routes to the bad-debt path; nonReentrant and CEI on collateral/reward transfer.

### `ADL (auto-deleveraging) / socializeLoss / insuranceFund draw`
- **Risk:** When a liquidation leaves bad debt exceeding the insurance fund, missing ADL/socialization leaves unbacked positions (protocol insolvency); mis-ranked ADL (deleveraging the wrong counterparties) or an insurance-fund draw callable/gameable lets an attacker force losses onto specific traders.
- **Verify:** Verify a defined path handles bad debt beyond the insurance fund (ADL by PnL/leverage ranking or pro-rata socialization); verify the insurance fund can only be drawn by the liquidation engine and can't go negative unhandled; verify ADL selection is deterministic and not attacker-steerable; verify conservation (sum of margins + insurance = deposits) holds after settlement.

### `index/settlement oracle: getPrice / getIndexPrice / updatePrice keeper`
- **Risk:** The single most catastrophic dependency (Mango, Deus, many perps). A pushed/keeper price with no deviation/staleness bound, or an index averaging thin venues, lets an attacker set the settlement price; traders front-run a mempool-visible oracle update (GMX-avax-class) to open/close around a known price move.
- **Verify:** Verify oracle staleness (`updatedAt` within heartbeat), `answer>0`, and deviation/rate-of-change bounds; verify pushed prices require quorum/signature; verify index is a robust median resistant to single-venue manipulation; assess whether a pending oracle update is front-runnable and whether opens/closes should be delayed/committed relative to price updates.

### `order matching / fillOrder / settle / matchOrders [orderbook / RFQ perp]`
- **Risk:** Off-chain-signed orders replayed (missing nonce/expiry/domain), a maker order filled at a stale price, self-trade/wash to move mark or harvest maker rebates, and matching that doesn't enforce price-time priority letting an operator fill against users adversely.
- **Verify:** Verify each order has a per-maker nonce + deadline + EIP-712 domain (chainId + verifyingContract) and a consumed-digest guard; verify fill price respects the order limit and a fresh index; verify self-trade prevention; verify the settling party can't pick which side to fill for profit (price-time priority / no operator discretion on price).

### `self-liquidation / liquidate own position`
- **Risk:** A trader liquidates their own position to (a) capture the keeper reward from their own collateral at a better rate than closing, or (b) after manipulating price, dump a losing position's loss onto the insurance fund/counterparties while extracting the incentive.
- **Verify:** Verify liquidator != position owner (or the incentive is structured so self-liquidation is never more profitable than a normal close); verify liquidation requires genuine under-margin at a manipulation-resistant price so a self-liquidation can't be price-triggered; verify the keeper reward can't exceed the trader's own retained collateral.

### `TVM: funding/emission accrual over ~3s blocks; SUN 6-decimal collateral`
- **Risk:** Per-block funding or interest accrual ported from Ethereum over-accrues ~4× on TRON's ~3s blocks; native-TRX collateral is SUN (1e6) — 18-dec margin math over 6-dec collateral misprices notional and liquidation thresholds.
- **Verify:** Verify funding/interest integrate over timestamp not block count (or re-derive per-block rates for ~3s blocks); verify collateral decimals (SUN 1e6 for TRX, 6 for TRON USDT/USDD) match the margin math; keep native-TRX and TRC-20 collateral scaling distinct.


## account-abstraction-4337

> ERC-4337 account abstraction (EntryPoint + smart accounts + paymasters + aggregators). **EVM-mainly.** The canonical EntryPoint singleton (v0.6 `0x5FF137...5789`, v0.7 `0x0000000071727De22E5E9d8BAf0edAc6f37da032`) is deployed deterministically via Nick's method on EVM chains; TVM CREATE2 uses a `0x41` prefix so the canonical address does NOT reproduce on TRON, and there is no assumption a live EntryPoint exists on TVM. **Verify an EntryPoint is actually deployed on the TVM target and that the account binds TRON's chainId (`0x2b6653dc`) before assuming any of this applies.**

### `validateUserOp(PackedUserOperation,bytes32 userOpHash,uint256 missingAccountFunds) [smart account]`
- **Risk:** The account's sole security gate. Two dominant bugs: (1) not restricting the caller — `validateUserOp`/`execute` must be callable ONLY by the trusted EntryPoint, else anyone drives account actions directly; (2) validating a signature over an attacker-recomputable hash instead of the EntryPoint-supplied `userOpHash` (which binds `entryPoint` + `chainId`), enabling cross-account / cross-chain / cross-entrypoint replay.
- **Verify:** Confirm `require(msg.sender == entryPoint)` (or `_requireFromEntryPoint`) on `validateUserOp` and on `execute`/`executeBatch`; confirm the signature is checked against the passed `userOpHash` (not a locally re-derived hash that omits entryPoint/chainId); confirm `missingAccountFunds` is repaid to the EntryPoint; confirm validation has no external calls that could reenter.

### `validationData packing: authorizer | validUntil(48) | validAfter(48)`
- **Risk:** The 256-bit return encodes auth result + time bounds. Returning raw `0`/`1` where the code intends time-bounded validity, packing `validUntil`/`validAfter` in the wrong bit positions, or returning `address(0)` (success) on a failed signature branch silently authorizes every op. `SIG_VALIDATION_FAILED` is `address(1)` in the low 160 bits — a `return 0` on the failure path is an auth bypass.
- **Verify:** Confirm the failure path returns `SIG_VALIDATION_FAILED` (1), not 0; confirm `validUntil`/`validAfter` occupy the correct bits (`validUntil<<160`, `validAfter<<208`) and are enforced by the EntryPoint; confirm a non-zero low-160 that isn't `1` is a deliberate aggregator address, not an accident.

### `nonce: EntryPoint NonceManager (192-bit key + 64-bit sequence) vs account-local nonce`
- **Risk:** 4337 replay protection lives in the EntryPoint's 2D nonce (`getNonce(sender,key)`), not the account. An account that ALSO rolls its own nonce (or trusts a nonce field inside its signed payload) can desync, double-execute, or brick; an account that reads/writes nonce state outside its own associated storage violates validation rules.
- **Verify:** Confirm the account relies on EntryPoint nonce sequencing for replay protection (or, if it keys ops itself, that the value is consumed atomically in validation and bound into the signed hash); confirm no second, unsynchronized nonce path; confirm 2D-nonce keys can't be chosen to skip replay checks.

### `validatePaymasterUserOp(PackedUserOperation,bytes32,uint256 maxCost) / postOp(mode,context,actualGasCost,...) [paymaster]`
- **Risk:** The paymaster stakes/deposits real value to sponsor gas. Sponsoring without constraints, or pricing an ERC-20 charge in `validatePaymasterUserOp` and settling it in `postOp` off state that moved between the two phases, lets an attacker drain the deposit or pay less than the gas consumed. `postOp` reverting (or not being idempotent across `opReverted`) can grief or double-charge.
- **Verify:** Confirm the paymaster restricts WHICH ops it sponsors (sender allowlist, spending caps, per-op gas cap) and that `maxCost` bounds exposure; confirm the ERC-20/price used to charge in `postOp` cannot be manipulated between validation and `postOp` (no spot-AMM price, use a guarded oracle); confirm `postOp` handles both `opSucceeded` and `opReverted` without reverting and charges from the `context` it committed to; confirm `msg.sender == entryPoint` on `postOp`.

### `IAggregator: validateUserOpSignature / aggregateSignatures / validateSignatures`
- **Risk:** A signature aggregator (e.g. BLS) validates a batch's signatures on behalf of opted-in accounts; the account trusts whatever aggregator it names in `validationData`. A malicious/broken aggregator validates arbitrary ops for its accounts; BLS aggregation without proof-of-possession is open to rogue-key attacks; `validateSignatures` that doesn't bind each `userOpHash` lets one valid aggregate cover forged members.
- **Verify:** Confirm each account only points to a trusted, audited aggregator; confirm `validateSignatures` binds every member `userOpHash` and reverts on any invalid member (no partial acceptance); for BLS confirm proof-of-possession / rogue-key defense and correct domain separation; confirm the aggregator is itself staked per the bundler's reputation rules.

### `validation-scope rules (ERC-7562): banned opcodes + restricted storage during validation`
- **Risk:** During `validateUserOp`/`validatePaymasterUserOp` the entity may only touch its own + "associated" storage and must avoid environment opcodes (`TIMESTAMP`, `NUMBER`, `COINBASE`, `BLOCKHASH`, `BASEFEE`, `GASPRICE`, `BALANCE`/`SELFBALANCE` of others, `ORIGIN`, `CREATE`, `SELFDESTRUCT`, unbounded `GAS`). Validation that reads externally-mutable state passes the bundler's simulation but can be invalidated en masse on-chain — a mempool DoS/griefing vector (unstaked entities get throttled/banned).
- **Verify:** Confirm validation reads only the account's own or associated storage (slots keyed by the account address) and no forbidden opcodes; confirm entities that legitimately need broader access are staked; flag any validation-time branch on `block.timestamp`/`block.number`/balances/oracle reads that could pass simulation yet revert on inclusion.

### `EntryPoint deposit & stake: depositTo / addStake(unstakeDelaySec) / unlockStake / withdrawStake / withdrawTo`
- **Risk:** Stake underwrites an entity's right to use associated storage; deposit pays for gas. Griefing surfaces: withdrawing/unlocking stake to escape reputation, a paymaster whose deposit is drained by spam ops (denying real users), or a factory/paymaster with no stake mass-invalidating the mempool. `withdrawTo`/`withdrawStake` without correct auth lets funds leave early.
- **Verify:** Confirm `addStake` uses an adequate `unstakeDelaySec` and that `withdrawStake` respects the unlock delay; confirm deposit top-ups and spend caps prevent a single attacker from draining a shared paymaster deposit; confirm `withdrawTo`/`withdrawStake` are owner/governance-gated; assess reputation/throttling assumptions for unstaked entities.

### `handleOps / handleAggregatedOps / innerHandleOp / executeUserOp — batch execution boundary`
- **Risk:** The EntryPoint runs validation for the whole batch then execution; a bug in an account/paymaster that lets validation succeed but execution consume unexpected gas socializes cost to the bundler. Custom `executeUserOp` hooks or `execute(dest,value,func)` on the account that don't re-assert the EntryPoint caller are a direct call surface.
- **Verify:** Confirm the account's execute path is EntryPoint-only and cannot be reached with attacker calldata directly; confirm no reentrancy from execution back into validation state; confirm gas limits (`verificationGasLimit`, `callGasLimit`, `paymasterPostOpGasLimit`) are honored so a griefing op can't overrun.

## eip-7702

> EIP-7702 lets an **EOA delegate to contract code** via a signed set-code authorization (Pectra, Ethereum mainnet May 2025); the delegate's code then executes in the EOA's own storage/balance context. **EVM-only: TVM has no SetCode (type-4) transaction type — 7702 does not exist on TRON today. Verify TVM support before assuming any of this applies; currently none.** This section also fixes the `code.length==0 ⇒ EOA` assumption that 7702 breaks (see also the 1271 entry in the `signature` section).

### `EIP-7702 authorization tuple (chainId, address, nonce) signed by the EOA`
- **Risk:** Signing an authorization is equivalent to installing arbitrary code as your account. A phishing signature to a malicious/attacker "delegate" grants full control of the EOA (sweeper bots drain the instant funds arrive). The authorization is a plain secp256k1 signature over `keccak256(0x05 || rlp(chainId, address, nonce))` — no on-chain confirmation dialog beyond the wallet.
- **Verify:** Treat any code path that induces a 7702 authorization as maximum-privilege; confirm the wallet/UX shows the delegate target and that the delegate address is a known, audited implementation (not arbitrary); confirm the delegate itself cannot be swapped by an unrelated signature flow.

### `delegate code runs in the EOA's context — unprotected entrypoint / missing self-auth`
- **Risk:** ANY caller can invoke the delegated EOA address and run the delegate's code with the EOA's funds and storage. A delegate exposing `execute(target,value,data)` / batch-call without its own authorization (owner check, per-op signature, or `require(msg.sender == address(this))`) lets anyone drain the account — the delegate must re-implement all access control because the "EOA" no longer implies "only the key acts."
- **Verify:** Confirm every value-moving/state-changing function on the delegate enforces its own auth (ECDSA-over-op, 4337-style validation, or self-call), not merely "it's my EOA"; confirm there is no unguarded `call`/`delegatecall` forwarder; confirm `receive`/`fallback` can't be abused by arbitrary callers.

### `chainId == 0 authorization (cross-chain replay of set-code)`
- **Risk:** EIP-7702 permits `chainId == 0` to mean "valid on ANY chain." A `chainId==0` authorization can be replayed on every chain where the signer's account nonce matches, installing the delegate account-wide. Even a well-meaning delegate becomes a cross-chain liability if its storage/logic differs per chain, and a malicious replay installs attacker code everywhere.
- **Verify:** Confirm authorizations are scoped to the specific `chainId` (non-zero) unless universal delegation is genuinely intended and safe; flag any signing flow that emits `chainId==0`; confirm the delegate behaves identically and safely across all chains it could land on.

### `initialize() / setup on a freshly-delegated EOA not bound to the authorization`
- **Risk:** Delegation installs code but does NOT call any initializer. If the account is set up (owner set, keys configured) in a separate, unauthenticated tx, an attacker front-runs `initialize()` between delegation and setup and seizes the account — the 7702 analog of the uninitialized-proxy takeover.
- **Verify:** Confirm initialization is atomic with delegation or authenticated to the same authority (e.g. init params bound into the authorization or gated by the signer); confirm `initialize` cannot be re-run or front-run; confirm the delegate has a sane default owner if uninitialized.

### `storage collision across re-delegation (set-code does not clear storage)`
- **Risk:** Re-delegating an EOA to a new implementation does NOT wipe its storage; slots written by the previous delegate persist and are reinterpreted by the new one — a proxy-style storage-layout collision on an account that can be re-pointed at any time. Two implementations with different layouts corrupt owner/nonce/allowance slots.
- **Verify:** Confirm delegates use namespaced storage (ERC-7201) rather than sequential slots so re-delegation can't collide; confirm any migration between delegate versions accounts for pre-existing storage; treat an EOA that has ever been delegated as having "dirty" storage.

### `code.length==0 / extcodesize / msg.sender==tx.origin used to prove "EOA"`
- **Risk:** A delegated EOA carries a 23-byte `0xef0100||delegate` designator, so `code.length == 0` no longer proves EOA and `code.length > 0` no longer proves "cannot ECDSA-sign." Worse, a 7702 account can be `msg.sender == tx.origin` AND run contract code — the classic `require(msg.sender == tx.origin)` anti-contract/anti-flashloan gate is defeated, and `extcodesize`-based allowlists both false-negative (reject delegated EOAs) and false-positive.
- **Verify:** Flag any auth/anti-bot/relayer gate using `extcodesize`/`code.length`/`tx.origin==msg.sender` to distinguish EOAs from contracts — post-7702 none of these are sound; route contract-wallet and delegated-EOA signatures through ERC-1271 + ECDSA (OZ `SignatureChecker`) instead of code-size heuristics.

## intents-solvers

> Signed intents / orders settled by third-party solvers/fillers (CoW-style, UniswapX/Fusion Dutch auctions, Permit2-based flows). The user signs limits off-chain; a solver supplies liquidity and calldata on-chain. **Permit2, UniswapX reactors, and CoW settlement are EVM-mainly** — Permit2's canonical CREATE2 address (`0x000000000022D473030F116dDEE9F6B43aC78BA3`) does NOT reproduce under TVM's `0x41` CREATE2 derivation. **Verify Permit2 / the settlement contract are actually deployed on the TVM target before assuming this flow exists on TRON.**

### `Permit2 SignatureTransfer: permitTransferFrom / permitWitnessTransferFrom (witness binding)`
- **Risk:** A plain `permitTransferFrom` signature authorizes moving `(token, amount, nonce, deadline)` to the `spender` — it does NOT bind the order/intent it's meant to fund. A solver/filler can reuse that signature to pull the tokens under a DIFFERENT (worse) order unless the intent is bound as a `witness` via `permitWitnessTransferFrom`. Missing witness = the user's minOut/recipient limits are not covered by the signature.
- **Verify:** Confirm order flows use `permitWitnessTransferFrom` with the full order struct as the witness (correct witness typehash + typestring), so the Permit2 signature is inseparable from the specific order; confirm the unordered-nonce bitmap slot is consumed and can't be reused; confirm `deadline` and `spender` are enforced.

### `Permit2 AllowanceTransfer: approve/permit(expiration,nonce) + infinite allowance to router/settlement`
- **Risk:** Users grant a single large/infinite Permit2 allowance to a settlement/router; if that contract exposes an arbitrary-call interaction (solver-supplied targets/calldata), it can be pointed back at `Permit2.transferFrom` to pull any approved user's balance. AllowanceTransfer packs `(amount, expiration, nonce)` — a missing/oversized expiration or a nonce not advanced enables replay.
- **Verify:** Confirm the settlement/router cannot be induced to call `transferFrom`/Permit2 on behalf of a user beyond that user's signed order (interactions can't reach the approval/token contracts for other users' funds); confirm allowance `expiration` is bounded and `nonce` advances; flag infinite Permit2 approvals to any contract with arbitrary-call solver hooks.

### `order/intent EIP-712 signing (sellToken/buyToken/minBuy/validTo/nonce/kind/receiver) + settlement`
- **Risk:** Off-chain orders are replayable/forgeable if the EIP-712 domain omits `chainId`/`verifyingContract`, if there's no `validTo`/deadline, or if fill accounting lets an order over-fill. `abi.encodePacked` of order fields into the hash can collide (hash-collision forgery). A settlement that verifies the signature but not that the executed prices respect the signed limits pays the user less than they agreed. The core invariant is that the user receives at least their signed `minBuy` at their `receiver`; a solver keeping surplus beyond protocol rules, or filling at the solver's price rather than the user's limit, is value theft.
- **Verify:** Confirm the EIP-712 domain binds `chainId` (recomputed on fork) + `verifyingContract`, and the struct hash uses `abi.encode` (not packed) for multi-field/dynamic orders; confirm `validTo`/deadline and per-order nonce/filled-amount tracking prevent replay and over-fill; confirm the settlement checks post-trade balances so every order's `minBuy`/`receiver` limit holds regardless of solver behavior.

### `settlement solver interactions / arbitrary-call callback (filler-provided calldata)`
- **Risk:** Solver-driven settlements (CoW `settle` interactions, UniswapX reactor `reactorCallback`) execute filler-supplied calls. Without strict boundaries the callback can transfer out user or other-order funds, reenter settlement, or leave the settlement contract holding an allowance an attacker exploits. The solver is a trust boundary: the contract must enforce user limits even against a malicious solver.
- **Verify:** Confirm the arbitrary-call surface cannot touch token approvals/`transferFrom` for funds outside the batch being settled; confirm reentrancy protection around the callback and that clearing-price/limit checks run AFTER interactions on measured balances; confirm the solver set is permissioned where the design assumes it, and that a rogue solver still cannot violate signed limits.

### `Dutch-auction / decaying-price order fill + filler front-running`
- **Risk:** UniswapX/Fusion orders decay from a start to an end price; a filler executing at the worst-for-user allowed point, or front-running/sandwiching the fill, extracts the decay spread. An order with no effective minimum (end price ≈ 0) or an unbounded `deadline` is guaranteed value loss (MEV) analogous to `minOut = 0`.
- **Verify:** Confirm decaying orders have a non-degenerate end price / effective `minBuy` and a bounded `deadline`/`validTo`; confirm the fill price is checked against the decay curve at the fill block; assess exclusivity/private-mempool assumptions and that a non-exclusive filler cannot fill below the user's floor.

## cross-chain-messaging

> App-level integrations on generic cross-chain messaging (LayerZero, CCIP, Wormhole, Axelar) — complements the hand-rolled lock/mint items in the `bridge` section. **TRON runs a live LayerZero endpoint, so LZ OApps on TVM are in scope.** For CCIP / Wormhole / Axelar, **verify the specific protocol is actually deployed on the TVM target before assuming** — do not presume parity with EVM deployments.

### `lzReceive(uint16,bytes,uint64,bytes) [LZ v1] / _lzReceive(Origin,...) [OApp v2] — endpoint + peer/trustedRemote auth`
- **Risk:** The single most common LZ-integration bug: the receive entrypoint doesn't assert BOTH that `msg.sender` is the LayerZero endpoint AND that the source `(srcChainId/srcEid, srcAddress/sender)` matches the configured `trustedRemote`/`getPeer`. Missing either check lets anyone deliver a forged message and mint/unlock/execute at will. Applies on TRON (live LZ endpoint).
- **Verify:** Confirm `msg.sender == endpoint` (LzApp `lzEndpoint` / OAppReceiver check); confirm the source path is allowlisted (`trustedRemote[srcChainId] == srcAddress` in v1, `peers[srcEid] == _origin.sender` in v2); confirm nonce ordering/replay handling (v1 ordered nonces vs v2 configurable) and that blocked/stored payloads can't be force-retried to double-execute.

### `ccipReceive(Client.Any2EVMMessage) [Chainlink CCIP] — router + source chain/sender allowlist`
- **Risk:** `ccipReceive` must be callable only by the CCIP router, and the app must allowlist `message.sourceChainSelector` and decode+allowlist the ABI-encoded `sender`. Trusting any router caller or any source lets a spoofed message drive privileged actions.
- **Verify:** Confirm `onlyRouter` (CCIPReceiver) is present; confirm `sourceChainSelector` is allowlisted and the decoded `sender` is checked against the expected remote; confirm `extraArgs` gas limits and that a failed/manually-executed message can't be replayed; confirm token/amount handling on `destTokenAmounts`.

### `receiveWormholeMessages / parseAndVerifyVM VAA — emitter binding + consumed hash`
- **Risk:** A VAA is only trustworthy after guardian verification AND after checking WHO emitted it. Consuming a VAA without validating `emitterChainId` + `emitterAddress` against the registered remote, or without recording `vm.hash` as processed, allows spoofed-emitter messages and VAA replay (double-execute across calls/chains). Guardian-set index and `valid` bool must be checked.
- **Verify:** Confirm `(valid, )` from `parseAndVerifyVM` is checked and reverts on false; confirm `emitterChainId`+`emitterAddress` match the registered emitter; confirm `vm.hash` recorded in a consumed mapping set BEFORE effects (replay guard); confirm the guardian-set index is current and `payload` decoding is unambiguous.

### `_execute(commandId,sourceChain,sourceAddress,payload) [Axelar AxelarExecutable]`
- **Risk:** The public `execute` validates via `gateway.validateContractCall`, but the app's `_execute` override must still check `sourceChain` + `sourceAddress` against the trusted remote — otherwise any origin that can emit through the gateway can invoke privileged logic.
- **Verify:** Confirm `_execute`/`_executeWithToken` compare `sourceChain` and `sourceAddress` to the allowlisted remote (string comparison, case-normalized); confirm `commandId` replay is prevented by the gateway/app; confirm token amounts on `_executeWithToken` match the message.

### `finality / block-confirmations / optimistic challenge window before crediting`
- **Risk:** Crediting a destination action before the source event is FINAL invites reorg loss: the source deposit is reorged out while the destination already minted/released (unbacked supply). LayerZero DVN block-confirmation configs set too low, or optimistic bridges (Nomad/Across-class) whose challenge/fraud window is bypassed or set to zero, both realize this. Probabilistic-finality source chains need conservative confirmations.
- **Verify:** Confirm the app's messaging config requires adequate source confirmations / a real challenge window before the destination acts; confirm no path credits on an unconfirmed or default/zero root (Nomad); confirm reorg exposure is modeled for the specific source chain's finality; on LZ confirm the DVN/library security stack and block-confirmation count are explicitly set, not left at a permissive default.

### `message replay guard: sequence/nonce consumed + emitter/chain bound into the hash`
- **Risk:** Cross-protocol constant: a message must be executed once. Missing a processed-marker, or a marker not bound to `(sourceChain, emitter/sender, sequence/nonce)`, permits replay on the same chain or across destination chains for one source event.
- **Verify:** Confirm each message's unique id (`vm.hash` / LZ nonce / CCIP messageId / Axelar commandId) is recorded in a processed mapping, checked-and-set atomically before external effects; confirm `destinationChainId` and emitter/sender are bound so the same message can't be replayed on a sibling deployment.

## modular-proxy-diamond

> EIP-2535 diamonds/facets, EIP-1167 minimal clones, beacon proxies, and ERC-7201 namespaced storage. TVM is EVM-bytecode-compatible so these patterns can deploy on TRON, but **CREATE2 uses a `0x41` prefix on TVM** — any counterfactual clone/facet/factory address precompute must use the TVM formula (see `tvm-native`), and `delegatecall` drops `calltokenvalue`/`calltokenid`, so facet code doing TRC-10 accounting reads them as zero.

### `diamondCut(FacetCut[],address _init,bytes _calldata) [EIP-2535]`
- **Risk:** The upgrade primitive for a diamond. Two critical bugs: (1) missing/weak auth (`LibDiamond.enforceIsContractOwner`) lets anyone add/replace/remove facets — total compromise; (2) the `_init` address is `delegatecall`ed with `_calldata` during the cut, so an attacker-influenced `_init` (or an unprotected cut) executes arbitrary code in the diamond's storage context — a delegatecall backdoor equivalent to arbitrary owner overwrite.
- **Verify:** Confirm `diamondCut` is owner/governance/timelock-gated; confirm `_init` is restricted to trusted, known initializer contracts (not caller-supplied); confirm Add/Replace/Remove semantics are enforced (can't Replace a selector to a malicious facet without auth); confirm the cut emits `DiamondCut` for monitoring.

### `facet selector collision / loupe uniqueness / selectorToFacet mapping`
- **Risk:** Each 4-byte selector must map to exactly one facet. Adding a selector that already exists (or two facets exposing the same selector) either reverts, silently shadows a function, or — if mishandled — routes a privileged call to the wrong facet. Removing a selector still referenced elsewhere bricks a code path.
- **Verify:** Confirm `diamondCut` rejects Add of an existing selector and Replace/Remove of a non-existent one; confirm loupe (`facets()/facetFunctionSelectors()`) shows no duplicate selectors; run a selector-clash check across all facets including inherited/standard interfaces (ERC-165, ownership).

### `diamond shared storage: AppStorage / Diamond Storage (keccak slot) across facets`
- **Risk:** All facets share the diamond's storage. With **AppStorage** (a struct every facet declares first) any facet that adds/reorders struct fields, or declares extra sequential state variables, collides with sibling facets and corrupts state. With **Diamond Storage** (per-library keccak256 slot structs), a duplicated/wrong position string collides two modules onto the same slot.
- **Verify:** Confirm facets use a disciplined storage pattern (AppStorage-only-and-append, or Diamond Storage with unique, stable position strings); confirm no facet declares ad-hoc sequential state variables that land in slot 0..n; diff struct layout across facet upgrades exactly as with proxy `__gap`.

### `minimal clone (EIP-1167) initialize() front-run / uninitialized implementation`
- **Risk:** Clones `delegatecall` a fixed implementation and have their own (empty) storage, so each clone must be initialized. If the factory deploys the clone and initializes it in a SEPARATE tx, an attacker front-runs `initialize()` to seize ownership (init-takeover). The shared implementation left directly callable/uninitialized is a secondary surface.
- **Verify:** Confirm clone deployment and initialization are atomic (factory initializes in the same tx / constructor-equivalent) or init is authenticated to the intended owner; confirm `initializer`/`_disableInitializers` semantics on the implementation; confirm a front-run `initialize` on a fresh clone cannot set attacker ownership.

### `UpgradeableBeacon.upgradeTo / BeaconProxy — one beacon upgrades ALL proxies`
- **Risk:** A beacon holds the single implementation address that every `BeaconProxy` reads; `upgradeTo` swaps logic for all of them at once. A compromised/EOA beacon owner instantly hijacks or bricks the entire proxy fleet; upgrading to an address with no code or an incompatible layout corrupts all.
- **Verify:** Confirm `upgradeTo` is gated by a timelock/multisig, not an EOA; confirm the new implementation is non-zero, has code, and is storage-layout-compatible with the old; confirm the blast radius (all proxies) is acceptable and monitored; confirm the beacon address stored in proxies is immutable/trusted. (get-source.sh resolves the EIP-1967 beacon slot to fetch the impl.)

### `ERC-7201 namespaced storage per facet/module (@custom:storage-location erc7201:...)`
- **Risk:** In diamonds/modular systems each facet/module should isolate state in its own ERC-7201 namespace (`keccak256(abi.encode(uint256(keccak256("id")) - 1)) & ~0xff`). A duplicated namespace string across two facets, a hand-written slot that doesn't match its `@custom:storage-location`, or mixing sequential and namespaced state re-introduces cross-facet collisions the old `__gap` mental model won't catch. (See the `proxy-upgrade` ERC-7201 entry for the base check.)
- **Verify:** Recompute each `erc7201:` slot from its label and confirm the facet reads/writes there; confirm namespaces are unique per module and stable across upgrades; confirm no facet mixes legacy sequential state into a colliding slot.


## tvm-native

> TRON/TVM-specific attack surface an EVM auditor's checklist misses. TVM is EVM-bytecode-compatible but diverges in native-token channels, precompiles, opcode semantics, and address width. Walk this on every TRON target — especially EVM→TRON ports.

### `msg.tokenvalue / callTokenValue (0xd2) crediting inbound TRC-10 WITHOUT a msg.tokenid (0xd3) check`
- **Risk:** TRON's dual native channel — a payable path can receive a *TRC-10* token via `msg.tokenvalue`, with `msg.tokenid` saying WHICH token. Crediting `msg.tokenvalue` without asserting the id lets an attacker deposit a worthless self-issued TRC-10 and withdraw a real asset (BTTBank drain). `msg.tokenid` is attacker-controlled.
- **Verify:** Grep `msg.tokenvalue` / `callTokenValue` / `msg.tokenid` (inline `0xd2`/`0xd3`). Every path crediting from `msg.tokenvalue` MUST `require(msg.tokenid == EXPECTED_ID)`; verify the withdraw/settle side pays the SAME asset it credited (no deposit-cheap-id / withdraw-real-token asymmetry).

### `native value decimals: msg.value / callValue is SUN (1 TRX = 1e6), NOT 1e18 wei`
- **Risk:** TRX is **6 decimals** on the native channel — `msg.value` is denominated in SUN (1e6/TRX), not wei (1e18/ETH). An EVM→TRON port with hardcoded `1e18`, `ether`, or 18-dec scaling on the native path misprices by 1e12× (free value or bricked accounting).
- **Verify:** Grep `1e18` / `ether` / `1 ether` / `wei` on any native-value path; confirm SUN (1e6) scaling; keep native-TRX math distinct from TRC-20 token math (TRC-20 decimals vary — USDT/USDD are 6).

### `TVM precompiles DIVERGE at the same addresses (no revert on misuse)`
- **Risk:** Same address, different function on TVM: `0x03` = **double-SHA256** (NOT RIPEMD160), `0x09` = **BatchValidateSign** (NOT Blake2F), plus TRON-specific `validatemultisign`/`verifymintproof`. Ethereum assembly calling `0x03` expecting RIPEMD160 silently gets a wrong hash — no revert.
- **Verify:** Grep `staticcall`/`call` to `0x01..0x0a` and `precompile`; confirm each precompile's TVM meaning (not address parity); flag ecrecover/hash/pairing assembly ported from Ethereum.

### `CREATE2 / CREATE address derivation on TVM (0x41 prefix, not 0xff)`
- **Risk:** TVM CREATE2 derivation uses prefix `0x41`, not `0xff`: `addr = keccak256(0x41 ++ deployer ++ salt ++ keccak256(init_code))[12:]`. Any counterfactual/precompute (Permit2-style, factory, deterministic vault) assuming the Ethereum `0xff` formula computes the WRONG address on TRON → funds sent to an unclaimable/attacker address.
- **Verify:** Confirm any address precomputation uses the `0x41` prefix; re-derive one live deployed address to prove the formula (as SunSwap V3's PoolAddress was checked); CREATE (non-2) address is tx-hash-derived on TVM.

### `staking / resource opcodes as a privileged value surface: FREEZE 0xd5 / UNFREEZE 0xd6 / FREEZEBALANCEV2 0xda / UNFREEZEBALANCEV2 0xdb / DELEGATERESOURCE / WITHDRAWREWARD / VOTE`
- **Risk:** TRON-only opcodes let a contract freeze/unfreeze TRX for Energy/Bandwidth, delegate resources, vote for SRs, and withdraw rewards — a value/authority surface with NO EVM analog. An unprivileged `unfreeze`/`undelegate`/`withdrawreward` = principal exit or reward theft; missing access control here is invisible to an EVM checklist.
- **Verify:** Grep the staking/resource builtins/opcodes; treat each as a privileged state-changer — verify access control, and that freeze/unfreeze/delegate/reward-withdraw/vote can't be triggered by an unauthorized caller to exit principal or steal rewards.

### `DELEGATECALL does NOT forward calltokenvalue / calltokenid on TVM`
- **Risk:** TVM `delegatecall` forwards `callvalue` + `msg.sender` like EVM, but **not** `calltokenvalue`/`calltokenid` — a delegatecalled library / proxy-impl / diamond-facet reads them as **zero**, silently zeroing any TRC-10 accounting done in delegated code.
- **Verify:** In any code reachable via delegatecall (library/impl/facet), flag reads of `msg.tokenvalue`/`msg.tokenid` — they will be 0; TRC-10 handling must live in the top-level (non-delegated) frame.

### `ecrecover / on-chain 20-byte address vs TRON 21-byte 0x41 identity — at the SERIALIZATION boundary`
- **Risk:** **Inside Solidity/TVM an `address` is 20 bytes** — `ecrecover(...) == someStoredAddress` and `== msg.sender` work normally, so a plain in-contract signer comparison is NOT the bug. The 21-byte `0x41`-prefixed form is the TRON identity only at the **Base58 / node-API / SDK / cross-chain-serialization boundary**. The real risk is a MISMATCH there: an EIP-712 digest or a cross-chain proof that binds the 21-byte (or Base58) identity on one side and the bare 20-byte word on the other, or a signature scheme that assumes Ethereum's address derivation.
- **Verify:** For a *pure in-Solidity* `ecrecover` check, verify the usual EVM concerns (result `!= address(0)`, low-s/malleability) — the 0x41 prefix does NOT apply. Where a signer/identity crosses to Base58, a node API, an SDK, or another chain, verify BOTH sides use the SAME encoding (21-byte 0x41 vs 20-byte) and the EIP-712 domain uses TRON's chainid (`0x2b6653dc`).

### `TRON account-level permission model (owner / active / witness, key weights, threshold) — custody is NOT (only) in Solidity`
- **Risk:** A **regular (key-controlled) account** — the deployer, an admin/owner EOA, a treasury, a "multisig" — has its control set at the ACCOUNT level via `AccountPermissionUpdateContract` (owner/active/witness permissions, each with a key list, per-key **weights**, a **threshold**, an operations bitmap), NOT by Solidity `onlyOwner`. A treasury "owned" by a single active key whose weight ≥ threshold is a **1-of-1 EOA** even if the app looks multisig-gated; a genuine N-of-M lives in the permission graph, invisible to source review. **This does NOT apply to a contract account:** a contract has no private key — it is governed by its code, and its TRX/assets move only via that code (not via account-permission signatures). So classify the *privileged key-holders* (admin/owner/deployer/treasury), not the contract itself.
- **Verify:** For each privileged **key-controlled** account behind the protocol (owner/admin/governance-executor/treasury/deployer), pull the permission graph via `getaccount` (`owner_permission` + `active_permission`: keys, weights, threshold, operations) and classify custody from THAT — the real M-of-N, whether one key alone meets threshold, whether `AccountPermissionUpdate` is itself guarded. For a contract account, verify custody is the code (upgrade/withdraw paths), not a key. Feed both into the Centralization class + the report's custody column.

### `Stake 2.0 economics: UnfreezeBalanceV2 unbonding delay (chain parameter) + OPTIONAL delegation lock`
- **Risk:** Staking/resource ops carry TIME economics an EVM checklist ignores. `UnfreezeBalanceV2` enforces an **unbonding delay before `WithdrawExpireUnfreeze`** — but that delay is a **governance chain parameter** (`getUnfreezeDelayDays` / `getchainparameters`), ~14 days on mainnet, **1 day on Nile, and adjustable** — NOT a hardcoded constant. `DelegateResource` locking is **OPTIONAL**: a `lock` flag with a configurable `lock_period`; **without lock, delegation can be undone immediately** (only with `lock=true` are resources locked for `lock_period`). A rental/withdrawal-queue/liquid-staking contract that hardcodes the wrong delay, or assumes delegation is always/never locked, mis-accounts → insolvency, stuck funds, or a serviceability DoS.
- **Verify:** Read the **live** unbonding delay from `getchainparameters` for the TARGET network (don't hardcode 14d); model pending-unbond reserves against it. For delegation, check whether `lock=true` and the actual `lock_period` used (not an assumed 3 days); confirm share/exit math never pays out TRX still locked and handles the immediate-undelegate case when unlocked.

### `TVM execution limits: 64-deep call stack + per-tx CPU-time (getMaxCpuTimeOfOneTx) → OUT_OF_TIME / fee_limit loss`
- **Risk:** TVM caps the **CALL depth at 64** (not EVM's 1024) and bounds each tx by a wall-clock **CPU-time limit** (`getMaxCpuTimeOfOneTx`, ~80ms). A deep recursion / batch loop / long call-chain that is fine on EVM hits `OUT_OF_TIME` or the depth cap on TVM and **reverts with the full `fee_limit` consumed** (no partial refund). A design relying on many nested external calls, an unbounded loop over user-growable state, or an exact 1024-frame assumption breaks, and an attacker can grief by pushing an operation past the CPU/depth cap so it always reverts (DoS on a critical path).
- **Verify:** Bound recursion/loop depth well under 64 frames; ensure critical paths (liquidation, withdrawal, settlement) complete within the CPU-time budget for realistic state sizes; confirm a revert-with-fee-loss can't brick a required operation or be induced by an attacker growing the iterated set.

### `Dynamic Energy model: energy_factor / penalty on popular contracts (getEnergyFee-class chain params)`
- **Risk:** TRON's Dynamic Energy raises the Energy cost of a contract that consumes a large share of network Energy (an `energy_factor` penalty that grows with popularity, decays when idle). A contract/integration that hardcodes an Energy or `fee_limit` budget, or whose economic model assumes fixed execution cost, can suddenly under-provision (txs revert) or overpay during high-usage windows — and an attacker can deliberately inflate a target's factor to price users out (griefing).
- **Verify:** Confirm any on-chain `fee_limit`/Energy budgeting accounts for the dynamic factor (read the live energy params); confirm the protocol degrades gracefully (not a hard revert on a critical path) when execution cost spikes; assess whether an adversary can pump a contract's `energy_factor` to DoS legitimate users.

### `Deploy-time system parameters invisible in Solidity: origin_energy_limit / consume_user_resource_percent / origin_address`
- **Risk:** A TRON contract carries deployment settings NOT expressible in Solidity: `consume_user_resource_percent` (how much Energy the CALLER pays vs the contract), `origin_energy_limit` (max Energy the contract owner will subsidize per call), and `origin_address` (the deployer/owner used by these + `SetContract` updates). Misconfiguration is a real availability/economic bug: `consume_user_resource_percent=0` + a too-low `origin_energy_limit` lets an attacker drain the owner's Energy (griefing / forced fee burn); the `origin_address` is a custody/upgrade surface (it can adjust these and, historically, is the account that could `SetContract`).
- **Verify:** Read these via `getcontract` (not the source); confirm `consume_user_resource_percent` / `origin_energy_limit` can't be abused to exhaust the owner's Energy or to shift unexpected cost onto users; treat `origin_address` as a privileged key-controlled account (run the account-permission custody check on it).


---
_Notes:_ Scope: defensive audit-coverage inventory (what to locate and scrutinize), not exploitation. Walk each contract type's function list against the target codebase; a function that is ABSENT can itself be a finding (e.g., no accrueInterest before pricing, no staleness check on latestRoundData, no two-step ownership, no reentrancy guard on token-transfer paths).

Cross-cutting checks to run on EVERY contract regardless of type: (1) reentrancy (checks-effects-interactions + guards, incl. read-only and cross-function); (2) access control on every state-changing external/public function (grep for missing modifiers); (3) integer/rounding safety and rounding-direction (must favor protocol); (4) oracle freshness/manipulation resistance; (5) initializer protection and storage-layout for anything upgradeable; (6) unchecked low-level calls and arbitrary call/delegatecall targets; (7) fee-on-transfer / rebasing / non-standard-return token compatibility; (8) event emission on privileged changes for monitoring.

TRON/TVM notes: energy+bandwidth replace gas (revalidate hardcoded gas, loop bounds, .transfer/.send stipends); base58 T-address vs 0x41 hex; confirm precompiles (ecrecover/modexp/bn256) and opcodes (SELFDESTRUCT — TVM ADOPTED EIP-6780 on mainnet 2026-04-10 (Proposal 94 / GreatVoyage-v4.8.1, energy 0→5000): post-creation self-destruct no longer deletes code/storage (brick vector dead, as post-Cancun EVM), only transfers balance to the target; full deletion only in a same-tx create+destroy; CREATE2; PREVRANDAO; TSTORE/TLOAD — TVM added transient storage in GreatVoyage-v4.8.0/Kant, mainnet mid-2025, so verify node/chain version before trusting a transient reentrancy guard) are present but **NOT all EVM-identical** — see the `tvm-native` section: precompiles diverge at the same addresses, CREATE2 uses a `0x41` prefix (not `0xff`), `block.difficulty`/`prevrandao`/`gaslimit` are constants, native value is SUN (1e6), and `delegatecall` drops `calltokenvalue`/`calltokenid`; ~3s block time affects any block.number/timestamp-based rate, vesting, or TWAP math. For Vyper (Curve-style) pools, check the compiler version against the 2023 reentrancy-lock miscompilation set 0.2.15 / 0.2.16 / 0.3.0 (fixed in 0.3.1) and confirm @nonreentrant coverage — but note **Vyper on TVM is experimental** (EVM-bytecode compatibility only; TRON officially supports Solidity), so treat a Vyper-on-TRON target's compiler/verification/toolchain as best-effort and lean harder on bytecode-level checks.

Grounding basis — established references: SWC Registry IDs (SWC-100/101/104/105/106/107/112/114/115/116/117/120/122/128/133) as a **legacy** map only (the SWC registry has been frozen since 2020); prefer the maintained EEA EthTrust Security Levels and OWASP SCSVS baselines. Also grounded in Trail of Bits / Consensys Diligence / OpenZeppelin audit checklists, ERC-4626 inflation-attack guidance, and known postmortems — The DAO, Parity multisig, bZx, Harvest, Cream, Fei/Rari, Compound rounding, Beanstalk governance, Nomad, Ronin, Wormhole, Harmony, Euler, and Curve/Vyper reentrancy. Re-verify incident details and any post-cutoff issues against primary postmortems before publishing.

Sources: [SWC Registry](https://swcregistry.io/), [SWC-registry GitHub](https://github.com/SmartContractSecurity/SWC-registry).


## Additional coverage (extended checklist)

- ERC-4626 core: deposit/mint/withdraw/redeem plus previewDeposit/previewMint/previewWithdraw/previewRedeem, convertToShares/convertToAssets, maxDeposit/maxMint/maxWithdraw/maxRedeem, totalAssets — verify rounding direction is always against the user, preview matches actual, and totalAssets uses internal accounting not balanceOf (only the first-depositor CHAIN is covered, the full 4626 interface is not)
- Rebasing / share-based balance functions: rebase(), _gonsPerFragment (Ampleforth), getPooledEthByShares/getSharesByPooledEth (stETH-style) — integrators must store shares not balanceOf; verify negative rebase (slashing) cannot make shares insolvent and positive rebase donations are not miscounted
- Fee-on-transfer / deflationary token handling on the INTEGRATOR side: measure received = balanceAfter - balanceBefore rather than trusting the amount argument in every deposit/repay/addLiquidity path (transfer() mentions it but no dedicated verify item for consumers)
- pause()/unpause()/whenNotPaused and blacklist/freeze/addToBlacklist/isBlacklisted (USDT/USDC-style) — verify pause access control and that a frozen/blacklisted recipient cannot permanently DoS withdrawals, refunds, or liquidations
- ERC-1155 batch: _mintBatch/safeBatchTransferFrom/balanceOfBatch — array length mismatch, per-element reentrancy via onERC1155BatchReceived, and id/amount array desync
- Permit2 / allowanceTransfer / permitTransferFrom / SignatureTransfer (Uniswap) — unordered nonce bitmap, witness binding, deadline, and integrator over-reliance on a single infinite Permit2 approval
- Non-standard TRC-20 metadata/return handling: decimals()/name()/symbol() as unchecked external calls, and transfer/approve implementations that return no bool or revert differently (USDT-on-TRON) breaking require(token.transfer(...))
- Arbitrary external call / delegatecall with user-controlled target or calldata (SWC-112) — execute(address,bytes), functionCall in a loop, generic call-forwarding routers that can be pointed at the token/approval contract
- multicall / aggregate / batch executor using delegatecall — msg.value reuse across sub-calls and self-delegatecall privilege escalation
- selfdestruct / SELFDESTRUCT-gated functions and any invariant relying on address(this).balance (force-feed via selfdestruct breaks it)
- EIP-1271 isValidSignature and off-chain-signer verification for contract-wallet auth — order signing, signature-based roles, and signers whose validity can change after a signature is consumed
- Compound comptroller policy hooks: enterMarkets/exitMarket and mintAllowed/borrowAllowed/redeemAllowed/seizeAllowed/transferAllowed/liquidateBorrowAllowed — misconfigured allow-hooks bypass solvency gating
- Interest-rate model: getBorrowRate/getSupplyRate/utilizationRate/kink (jump-rate) — division-by-zero at 0% or 100% utilization, unbounded rate, and per-block rate cap
- Risk-parameter setters not yet listed: setCloseFactor, setLiquidationIncentive, setMarketBorrowCaps/supplyCaps, supportMarket, reduceReserves/addReserves — verify bounds (close factor <=100%, incentive vs collateral factor consistency) and timelock
- borrowBalanceStored/borrowBalanceCurrent borrow-index accounting and Aave-style healthFactor computation — index desync, rounding of debt, and per-asset scaling
- getUnderlyingPrice oracle adapter inside lending — decimals normalization (scale by 1e(36-decimals)), zero/stale guard, and feed decimals mismatch between assets
- Uniswap v3 tick/price math: initialize() first-price set, observe()/observeSingle TWAP, sqrtPriceX96, TickMath/SqrtPriceMath overflow, uninitialized-pool price manipulation
- Uniswap v4: hooks (beforeSwap/afterSwap/beforeAddLiquidity/beforeInitialize), hook-permission address bits, singleton PoolManager unlock/take/settle flash-accounting, and untrusted-hook trust boundary
- Balancer joinPool/exitPool/batchSwap/flashLoan and getPoolTokens read-only reentrancy (Vault manager) — extends the Curve read-only-reentrancy item to Balancer
- Router functions: swapExactTokensForTokens / swapTokensForExactTokens / addLiquidity / removeLiquidity — amountOutMin/amountInMax, deadline, path validation, and the swapSupportingFeeOnTransferTokens variants
- quote() / getAmountsOut() / getAmountOut() used as a spot price oracle (router analog of the flagged getReserves oracle abuse)
- Curve get_virtual_price() and calc_token_amount() as read-only-reentrancy-exposed fair-value sources, plus ramp_A/stop_ramp_A amplification-ramp manipulation and get_D Newton convergence
- Stablecoin/CDP engine (MakerDAO): frob (lock collateral / draw debt), join/exit adapters (GemJoin/DaiJoin), debt ceiling (Line/line) and dust minimum-debt enforcement
- Peg Stability Module: sellGem/buyGem 1:1 swap — fee asymmetry arbitrage, decimals of the underlying stable, and effectively unbounded debt mint against the PSM
- drip/jug stability-fee accrual and pot join/exit (DSR) rate accumulation — rate overflow and time-delta manipulation
- Liquidation auctions: bite/bark (Dog) and take (Clipper Dutch auction) — price-curve math, zero/low-bid auctions under congestion, and keeper-incentive griefing
- Oracle PROVIDER side: aggregator transmit/submit/setPrice/median (OCR) — signer quorum, deviation threshold, staleness, and single-signer/compromised-oracle mispricing
- MakerDAO OSM peek/peep/poke delayed-price module — 1-hour delay bypass and reader-whitelist enforcement
- minAnswer/maxAnswer circuit-breaker bounds on price feeds — clamped price returned during a flash crash (Venus/LUNA-style) as a distinct verify item
- Bridge lock/deposit (source) and mint/release/unlock/withdraw (destination) — supply-conservation invariant (minted on dest == locked on source)
- Bridge validator/relayer signature-set verification — threshold ECDSA/multisig, duplicate-signer counting, and validator-set update/rotation authorization
- Bridge merkle/message proof verification (verifyMerkleProof/processMessage) — forged leaf, non-canonical/ambiguous encoding, zero-root initialization (Nomad), and proof/message replay
- Bridge per-message nonce / processedMessages replay guard with chainId + source/dest domain bound into the message hash (cross-chain replay)
- Liquid staking: submit/stake (mint LST) and requestWithdrawal/claimWithdrawal queue (often NFT) — withdrawal-queue griefing/DoS and claim ordering
- Liquid staking handleOracleReport/rebase — beacon-balance report trust, slashing accounting, exchange-rate spike bounds, and first-depositor inflation on the LST
- Liquid staking node-operator/validator registration and deposit-to-deposit-contract front-running (1-ETH front-run / deposit-front-run attack)
- Governance: propose/castVote/castVoteBySig/castVoteWithReason and queue/execute/cancel with a Timelock — proposal payload executes arbitrary calls; verify timelock delay and timelock admin
- Governance vote accounting: getVotes/getPastVotes/getPastTotalSupply snapshots and delegate/delegateBySig — checkpoint double-vote via same-block transfer, and voting power measured at the wrong block
- Governance config: quorum/proposalThreshold/votingDelay/votingPeriod — flash-loan-defeating snapshot timing and parameter bounds
- Proxy upgrade: upgradeTo/upgradeToAndCall and _authorizeUpgrade (UUPS) — access control, malicious/rug upgrade, and upgrade behind a timelock
- Proxy initializer/reinitializer/_disableInitializers on the IMPLEMENTATION contract — uninitialized-implementation takeover and delegatecall-to-selfdestruct bricking (OZ UUPS advisory)
- Proxy fallback delegatecall + storage layout/__gap collision (EIP-1967 admin/implementation slots) and Transparent-proxy function-selector clash
- Staking/MasterChef: deposit/withdraw/harvest/pendingReward and accRewardPerShare rounding, plus the staking-token == reward-token pool-accounting drain
- MasterChef massUpdatePools/updatePool and add/set pool management — unbounded pool loop gas/energy DoS and emergencyWithdraw reward-accounting consistency
- Merkle airdrop distributor: claim(index,account,amount,proof) — double-claim bitmap/claimed mapping, setMerkleRoot re-initialization, and leaf/proof forgery
- Multisig/smart wallet: submitTransaction/confirmTransaction/executeTransaction/revokeConfirmation and Gnosis execTransaction — threshold, owner add/remove, nonce, and delegatecall inside execution
- TVM-specific: reliance on .transfer()/.send() 2300-gas stipend (TVM energy/opcode-cost divergence can break fixed-gas value sends) and hardcoded-gas external calls (SWC-134)
- TVM-specific: TRC-10 native-token handling (transferToken/tokenBalance/msg.tokenid) and TRX/SUN msg.value assumptions distinct from TRC-20
- Vyper-specific: raw_call/send/create_forwarder_to and @nonreentrant lock correctness on vulnerable compiler versions (0.2.15-0.3.0)
- Weak randomness from block.timestamp/blockhash/block.number for mint order, lottery, or allowlist selection (SWC-120) and 3s-block timestamp dependence (SWC-116)
- Vesting/escrow/timelock release(): cliff and schedule math, revoke, and pull-vs-push payout (a stuck recipient must not lock the schedule)


### Contract types also to cover

- Stablecoin / CDP engine (MakerDAO-style Vat-Jug-Pot-Dog-Clipper) and the Peg Stability Module (PSM) — collateralized debt, stability fee, liquidation auctions, 1:1 peg swap
- Oracle provider / price-feed aggregator (Chainlink OCR aggregator, MakerDAO OSM/Median) — the price-PRODUCING contracts, not just the consumers already covered
- Cross-chain bridge (lock/mint and burn/unlock, validator/relayer signature set, merkle/message proof verification, per-message nonce and chainId replay guards)
- Liquid staking token / LST protocol (stETH/rETH-style: stake, exchange rate/rebase, withdrawal queue, oracle balance report, node-operator management)
- Governance / DAO (OpenZeppelin Governor or Compound GovernorBravo plus Timelock, snapshot voting power, delegation, quorum/threshold config)
- Proxy / upgradeable pattern (UUPS, Transparent, Beacon; EIP-1967 slots; initializer/reinitializer; storage layout and __gap)
- ERC-4626 tokenized vault / yield aggregator as a first-class type (deposit/mint/withdraw/redeem, strategy/harvest, preview vs actual) beyond the single first-depositor chain
- Staking & reward distributor (MasterChef, Synthetix StakingRewards, gauge/veToken) — accRewardPerShare/rewardPerToken accounting and multi-pool update loops
- Merkle airdrop / token distributor (claim with proof, double-claim guard, root management)
- Multisig / smart-contract wallet (Gnosis Safe-style execTransaction, EIP-1271 signer validation, owner/threshold management)
- Rebasing / algorithmic-supply token (Ampleforth _gonsPerFragment, stETH shares model) as distinct from fixed-supply TRC-20
- Meta-transaction / gasless-relayer infrastructure (EIP-2771 trusted forwarder, Permit2, forwarder-based _msgSender) as its own trust boundary
- Vesting / timelock / escrow and payment splitter (release schedule, cliff, revoke, pull-vs-push payout)
- Wrapped-native / token-wrapper contracts (WTRX/WETH deposit-withdraw invariant, TRC-10<->TRC-20 wrappers)
- TVM / Vyper deployment target as a cross-cutting contract-environment concern (energy/bandwidth DoS surface, 2300-gas send divergence, TRC-10 semantics, Vyper reentrancy-lock compiler versions) that should scope every other type
