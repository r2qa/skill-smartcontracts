# Vulnerable Functions Checklist

> Walk every applicable item during a review. Grouped by contract type. For each: the grep-able pattern, why it's risky, and the concrete check to perform. 110 functions across 14 categories. Companion: [vulnerable-chains.md](vulnerable-chains.md).


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

### `constructor logic in an upgradeable contract`
- **Risk:** Constructors don't run in proxy context, so state set in a constructor is absent behind the proxy (uninitialized critical state).
- **Verify:** Verify no critical state set in constructor of upgradeable impls; verify moved to initialize(); verify immutables used only for genuinely constant values.

### `selfdestruct / SELFDESTRUCT reachable from impl or delegatecalled lib`
- **Risk:** A selfdestruct in the implementation (esp. via delegatecall) can destroy the logic contract and brick every proxy pointing to it (Parity library kill). **Post-Cancun (EIP-6780) this brick vector is neutralized on mainnet EVM — SELFDESTRUCT only deletes code if called in the same tx as creation — so it is a finding only on pre-Cancun/non-6780 chains. TVM has NOT adopted EIP-6780, so it still applies on TRON; confirm the target chain's status.**
- **Verify:** Grep for selfdestruct/suicide; verify none reachable in implementation/library; confirm the target chain's EIP-6780 status (still a live brick vector on TRON/pre-Cancun; dead on post-Cancun EVM); ensure no arbitrary-call path reaches it.


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
- **Risk:** Destroys contract and can force-send ETH bypassing invariants (SWC-106); library selfdestruct bricks proxies (Parity) — but **only pre-Cancun: EIP-6780 restricts code deletion to the creation tx, so on post-Cancun EVM the brick vector is dead while force-feed ETH still works. TVM has not adopted EIP-6780, so both apply on TRON.**
- **Verify:** Grep for selfdestruct/suicide; verify unreachable or access-controlled + intended; verify no reliance on `this.balance` invariant that force-send breaks; confirm TVM SELFDESTRUCT-equivalent semantics on target chain.

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

### `ecrecover returns a 20-byte word, but TVM on-chain identity is 21 bytes (0x41 prefix)`
- **Risk:** `ecrecover` yields a 20-byte address while TRON accounts/contracts are addressed as 21-byte `0x41`-prefixed. In permit/EIP-712/meta-tx/cross-chain-proof code comparing a recovered signer to a stored/derived on-chain identity, the 21-vs-20-byte mismatch (or naive prefix handling) enables a spoof or a check that never matches.
- **Verify:** Confirm signer comparisons normalize the 0x41 prefix consistently on both sides; EIP-712 domain uses the correct chainid (TRON `0x2b6653dc`); cross-chain proofs bind the 21-byte identity.


---
_Notes:_ Scope: defensive audit-coverage inventory (what to locate and scrutinize), not exploitation. Walk each contract type's function list against the target codebase; a function that is ABSENT can itself be a finding (e.g., no accrueInterest before pricing, no staleness check on latestRoundData, no two-step ownership, no reentrancy guard on token-transfer paths).

Cross-cutting checks to run on EVERY contract regardless of type: (1) reentrancy (checks-effects-interactions + guards, incl. read-only and cross-function); (2) access control on every state-changing external/public function (grep for missing modifiers); (3) integer/rounding safety and rounding-direction (must favor protocol); (4) oracle freshness/manipulation resistance; (5) initializer protection and storage-layout for anything upgradeable; (6) unchecked low-level calls and arbitrary call/delegatecall targets; (7) fee-on-transfer / rebasing / non-standard-return token compatibility; (8) event emission on privileged changes for monitoring.

TRON/TVM notes: energy+bandwidth replace gas (revalidate hardcoded gas, loop bounds, .transfer/.send stipends); base58 T-address vs 0x41 hex; confirm precompiles (ecrecover/modexp/bn256) and opcodes (SELFDESTRUCT — TVM has NOT adopted EIP-6780, so the pre-Cancun brick/force-feed semantics still apply; CREATE2; PREVRANDAO; TSTORE/TLOAD — TVM added transient storage in GreatVoyage-v4.8.0/Kant, mainnet mid-2025, so verify node/chain version before trusting a transient reentrancy guard) are present but **NOT all EVM-identical** — see the `tvm-native` section: precompiles diverge at the same addresses, CREATE2 uses a `0x41` prefix (not `0xff`), `block.difficulty`/`prevrandao`/`gaslimit` are constants, native value is SUN (1e6), and `delegatecall` drops `calltokenvalue`/`calltokenid`; ~3s block time affects any block.number/timestamp-based rate, vesting, or TWAP math. For Vyper (Curve-style) pools, check the compiler version against the 2023 reentrancy-lock miscompilation set 0.2.15 / 0.2.16 / 0.3.0 (fixed in 0.3.1) and confirm @nonreentrant coverage.

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
