# Vulnerable Call-Chains Checklist

> Multi-step compositions that cause loss even when each function looks fine alone. For each: the ordered chain, the invariant/guard whose presence blocks it (confirm it exists), where it applies, and severity. 52 chains. Companion: [vulnerable-functions.md](vulnerable-functions.md).


## CRITICAL

### Classic single-function reentrancy (withdraw-before-effects)  ·  _reentrancy_
**Chain:**
1. Attacker contract calls withdraw()/claim()
2. Contract sends ETH via low-level call BEFORE zeroing the attacker's balance
3. Attacker receive()/fallback re-invokes withdraw()
4. Balance still non-zero, funds sent again
5. Loop until contract is drained

- **Blocked by (confirm present):** Checks-Effects-Interactions: internal balance/state zeroed BEFORE any external transfer, and/or a nonReentrant mutex on the function (a storage bool mutex OR an EIP-1153 `tstore`/`tload` transient guard — grep both, since a mutex-only grep misses transient guards)
- **Where it applies:** Token vaults, escrow, payment splitters, staking, any withdraw() using call{value:}

### Cross-function reentrancy (shared state via second entrypoint)  ·  _reentrancy_
**Chain:**
1. Attacker calls withdraw() which transfers ETH before updating balance
2. In the callback attacker calls a DIFFERENT function (e.g. transfer()/transferShares()) that reads the not-yet-updated balance
3. Moves credited balance/shares to a second account
4. Original withdraw completes -> value double-counted

- **Blocked by (confirm present):** A single shared reentrancy mutex covering EVERY function that reads/writes the same state (not per-function guards), plus CEI on all mutating paths
- **Where it applies:** ERC20 vaults where withdraw and transfer share the balance mapping; reward + principal split contracts

### Cross-contract reentrancy (shared state across modules)  ·  _reentrancy_
**Chain:**
1. Contract A performs an external call/transfer with attacker in the path
2. Callback enters Contract B which reads or mutates A's state (or A's balances stored in B) mid-update
3. B acts on inconsistent/stale state (mints, borrows, distributes)
4. Control returns to A which finalizes -> system-wide invariant violated

- **Blocked by (confirm present):** System-wide/global reentrancy guard shared across cooperating contracts, or CEI enforced so no contract exposes stale cross-contract state during an external call
- **Where it applies:** Modular protocols (controller + pool + collateral), staking + reward distributor pairs, tokenized-vault + strategy

### Read-only reentrancy (stale view during LP callback)  ·  _reentrancy_
**Chain:**
1. Attacker flash-borrows and calls remove_liquidity on a Curve/Balancer-style pool
2. Pool sends ETH/token, triggering attacker callback WHILE pool internal balances are mid-update
3. During callback attacker calls a consumer protocol whose pricing/LTV reads pool.get_virtual_price()/getReserves()
4. Consumer reads the transiently manipulated value and lets attacker borrow/mint against inflated collateral
5. Attacker returns, pool state normalizes, attacker keeps over-borrowed funds

- **Blocked by (confirm present):** Consumer checks the pool's reentrancy lock before reading price (e.g. call a lock-guarded method / withdraw_admin_fees pattern), or prices off a reentrancy-safe oracle; never read raw get_virtual_price/getReserves that can be observed mid-callback
- **Where it applies:** Lending markets and oracles consuming Curve/Balancer LP prices; any getReserves/virtual_price-derived valuation

### Flash-loan -> spot-AMM oracle -> undercollateralized borrow  ·  _flash-loan_
**Chain:**
1. Flash-borrow a large amount
2. Swap to skew the AMM spot price of the collateral token upward
3. Deposit collateral valued by the manipulated spot price
4. Borrow the maximum against the inflated valuation
5. Swap back / repay the flash loan in the same tx, leaving protocol with bad debt

- **Blocked by (confirm present):** Collateral valuation uses a manipulation-resistant oracle (Chainlink/median or a sufficiently long TWAP) rather than spot getReserves/getAmountOut, with sanity bounds cross-checked against a second source
- **Where it applies:** Compound/Aave-style lending, CDP/stablecoin mint, any collateral valuation path

### Flash-loan -> spot price down -> force-liquidate victim  ·  _flash-loan_
**Chain:**
1. Flash-borrow a large amount
2. Dump into the AMM to crash spot price of a victim's collateral
3. Victim position now reads as undercollateralized
4. Attacker liquidates it at a discount, seizing collateral
5. Restore price and repay the flash loan

- **Blocked by (confirm present):** Liquidation health uses the same manipulation-resistant oracle/TWAP as borrows; positions cannot flip to liquidatable from a single-block spot move
- **Where it applies:** Lending liquidation paths, perps, CDP liquidation

### Flash-loan governance takeover (borrow votes -> propose -> execute in one block)  ·  _governance_
**Chain:**
1. Attacker flash-borrows the governance token
2. Acquires quorum-level voting power instantly
3. Creates a malicious proposal and/or votes for it
4. If there is no voting delay/timelock, executes it in the same block/transaction to drain the treasury
5. Repays the flash loan

- **Blocked by (confirm present):** Voting power snapshotted at a PAST block (ERC20Votes getPastVotes with proposal snapshot strictly before the vote), a voting delay + multi-block voting period, a timelock between success and execution, and proposal threshold measured at the past snapshot
- **Where it applies:** Governor/GovernorBravo DAOs, on-chain token voting, parameter-control modules

### Timelock bypass / self-granted admin  ·  _access-escalation_
**Chain:**
1. A malicious or compromised proposer queues an action
2. Timelock roles are misconfigured (executor open to all, admin not renounced, delay = 0), or protocol admin is an EOA not the timelock
3. Action executes without the intended delay, or grants the attacker an admin role
4. Full protocol control obtained

- **Blocked by (confirm present):** The timelock (with min delay > 0) is the sole owner/admin of all protocol contracts; proposer/executor/canceller roles are correctly separated; a guardian can cancel; deployer admin is renounced
- **Where it applies:** TimelockController wiring, protocol admin/ownership configuration

### Bridge deposit -> forged proof -> mint  ·  _bridge-mint_
**Chain:**
1. Attacker crafts a fake deposit/burn event or Merkle proof on the source chain
2. Submits it to the destination bridge's mint/release function
3. A verification flaw (wrong/attacker-supplied root, unchecked signer set, missing membership check, uninitialized guardian) accepts it
4. Bridge mints unbacked tokens or releases locked funds

- **Blocked by (confirm present):** Destination validates the proof against a trusted, finalized source root / light-client state it does not let the caller supply; validator signature threshold verified; correct leaf encoding and domain; no trust in caller-provided roots
- **Where it applies:** Lock/mint bridges, Merkle-proof bridges, message-passing bridges (Nomad/Wormhole-class)

### Bridge proof/message replay -> double mint  ·  _bridge-mint_
**Chain:**
1. A legitimate deposit proof/message exists
2. Attacker submits the same proof/message twice (or on multiple destination chains)
3. No processed-marker / nonce check exists
4. Mint or release happens multiple times for a single source lock

- **Blocked by (confirm present):** Each message has a unique nonce/hash recorded in a processed mapping, checked-and-set atomically; destination chainId is bound into the message; nonces are monotonic
- **Where it applies:** All bridges and generic cross-chain messaging

### Bridge validator threshold / signature verification flaw  ·  _bridge-mint_
**Chain:**
1. Bridge authorizes withdrawals via a validator multisig
2. Flaw: duplicate signers counted, off-by-one threshold, attacker-updatable signer set, or malleable/zero-address recovery
3. Attacker reaches 'quorum' with fewer or forged signatures
4. Authorizes an unbacked mint/withdrawal (Ronin/Harmony-class)

- **Blocked by (confirm present):** Strictly-increasing/unique signer enforcement, correct threshold arithmetic, immutable or governance-gated signer-set updates, and malleability-safe recovery (OZ ECDSA)
- **Where it applies:** Multisig/validator bridges, oracle attestation committees

### Bridge lock/mint accounting mismatch (mint > locked)  ·  _bridge-mint_
**Chain:**
1. Source lock path records the requested amount, not the actually-received amount (e.g. fee-on-transfer token)
2. Event/message carries the inflated amount
3. Destination mints the event amount
4. More tokens minted than are backed; reserves drain on later redemptions

- **Blocked by (confirm present):** Mint amount derived from the measured balance delta actually received on the source; fee-on-transfer/rebasing handled; conservation invariant totalMinted <= totalLocked enforced
- **Where it applies:** Lock/mint and wrapped-asset bridges

### Uninitialized proxy -> attacker initialize -> upgrade takeover  ·  _upgrade_
**Chain:**
1. Proxy is deployed but initialize() is not called atomically in the same tx
2. Attacker calls initialize() first, setting themselves as owner
3. Attacker (now owner) calls upgradeTo(malicious) or directly withdraws
4. Full takeover

- **Blocked by (confirm present):** Initializer runs atomically at deployment (constructor/factory in the same tx), the initializer modifier blocks re-init, and the implementation constructor calls _disableInitializers(); deployment scripts verify initialization occurred
- **Where it applies:** UUPS/Transparent proxies, upgradeable tokens/vaults/bridges

### Unprotected UUPS implementation -> selfdestruct/re-init (Parity-class)  ·  _upgrade_
**Chain:**
1. Logic contract left uninitialized and callable directly
2. Attacker initializes the implementation (not the proxy) and becomes its owner
3. Attacker calls upgradeToAndCall/selfdestruct or a delegatecall on the implementation
4. All proxies pointing to it are bricked or hijacked

- **Blocked by (confirm present):** Implementation constructor calls _disableInitializers(); _authorizeUpgrade is owner-gated; no selfdestruct or arbitrary delegatecall in the implementation. *(The selfdestruct-brick half of this chain is neutralized by EIP-6780 — only a same-tx-as-creation destroy deletes code — on post-Cancun EVM AND on TRON since 2026-04-10 (Proposal 94 / GreatVoyage-v4.8.1); the re-init/hijack half applies everywhere.)*
- **Where it applies:** UUPS implementation contracts

### delegatecall -> storage collision -> owner overwrite  ·  _upgrade_
**Chain:**
1. Proxy delegatecalls the implementation
2. Implementation storage layout is not aligned with the proxy (or two modules share slots)
3. A write to variable X in the implementation lands on the proxy's owner/admin slot
4. Attacker gains admin / corrupts critical state

- **Blocked by (confirm present):** EIP-1967 hashed admin/impl slots, storage gaps (__gap) or namespaced/unstructured storage, append-only layout across upgrades, and an automated storage-layout diff between versions
- **Where it applies:** Proxies, diamond/multi-facet systems, libraries invoked via delegatecall

### delegatecall to attacker-controlled target  ·  _access-escalation_
**Chain:**
1. Contract exposes a function that delegatecalls a target address taken from calldata
2. Attacker passes a malicious contract
3. Malicious code executes in the victim's storage context
4. Overwrites owner / drains funds

- **Blocked by (confirm present):** No delegatecall to untrusted addresses — restrict to a whitelisted library set; multicall/aggregators use call (not delegatecall) for external targets
- **Where it applies:** Multicall, router/aggregator adapters, smart-contract wallets

### Fake-TRC-10 deposit / real-token withdraw asymmetry drain (TVM-native)  ·  _asset-confusion_
**Chain:**
1. Attacker issues a worthless TRC-10 token cheaply (TRON native token creation)
2. Calls a payable `deposit()`/`buy()` that credits the caller from `msg.tokenvalue` (CALLTOKENVALUE 0xd2) but does NOT check `msg.tokenid` (CALLTOKENID 0xd3)
3. Contract books the attacker as having deposited "value", while the withdraw/settle side pays out a REAL asset (TRX or a valuable TRC-10/TRC-20) it hardcodes
4. Attacker withdraws the real asset against the fake-token credit — repeat until drained (BTTBank)

- **Blocked by (confirm present):** Every path that credits from `msg.tokenvalue` asserts `require(msg.tokenid == EXPECTED_ID)`; the credited asset and the paid-out asset are provably the same; `msg.tokenid` treated as attacker-controlled
- **Where it applies:** Any TRON contract with a payable/deposit path reading `msg.tokenvalue`/`callTokenValue`; TRC-10-accepting DeFi, banks, games
- **Severity:** CRITICAL (unprivileged, direct fund loss). No EVM analog — invisible to an EVM-only checklist.


## HIGH

### Token-hook reentrancy (ERC777/721/1155 receive hooks)  ·  _reentrancy_
**Chain:**
1. Contract calls _mint/_safeTransfer/safeTransferFrom to the attacker
2. Attacker's tokensReceived / onERC721Received / onERC1155Received hook fires
3. Hook reenters deposit/claim/mint before the contract finalizes supply/accounting
4. Double-credit or mint beyond cap

- **Blocked by (confirm present):** CEI with all state (supply, minted count, cap check) updated BEFORE the safe-transfer/mint callback; nonReentrant on mint/claim; awareness that ERC777/1155/safeMint invoke untrusted callbacks
- **Where it applies:** NFT sales/mints, ERC777 integrations, ERC1155 batch operations, allowlist mints

### Oracle-lag / stale-price liquidation front-run  ·  _oracle-manipulation_
**Chain:**
1. Real market price moves sharply
2. On-chain oracle has not yet updated (heartbeat/deviation lag)
3. Attacker sees the pending oracle update in the mempool
4. Front-runs to liquidate or borrow at the stale favorable price before the update lands

- **Blocked by (confirm present):** Consumer validates updatedAt freshness against the heartbeat and reverts on stale data; deviation checks; liquidation/borrow gated so a single stale round cannot be exploited
- **Where it applies:** Every Chainlink/push-oracle consumer; liquidation and borrow gating

### Chainlink round/staleness/sequencer validation missing  ·  _oracle-manipulation_
**Chain:**
1. Consumer calls latestRoundData()
2. Ignores answer<=0, updatedAt==0/stale, or (on a sequencer-based L2) sequencer-down
3. Uses a zero, stale, or unavailable price
4. Mispriced borrow/mint/liquidation executes

- **Blocked by (confirm present):** Validate answer>0 and updatedAt within heartbeat; on a sequencer-based L2 also check the sequencer-uptime feed plus a grace period; revert otherwise. (`answeredInRound>=roundId` is deprecated — always equals roundId on OCR feeds — so do not require it or flag its absence; N/A on TRON L1.)
- **Where it applies:** All Chainlink integrations, especially L2 deployments

### Short-window / thin-liquidity TWAP manipulation  ·  _oracle-manipulation_
**Chain:**
1. Attacker targets a pool with thin liquidity and/or a short TWAP window
2. Pushes price and sustains it across the (too-short) averaging window, or single-block if window ~= 0
3. Consumer reads the TWAP
4. Acts on a still-manipulated average

- **Blocked by (confirm present):** TWAP window long enough that cost-to-manipulate exceeds gain; minimum-liquidity requirement on the pool; cross-check against an independent oracle
- **Where it applies:** Uniswap v2/v3 TWAP oracles used by lending/CDP/derivatives

### LP-token / virtual_price fair-value manipulation  ·  _oracle-manipulation_
**Chain:**
1. Attacker imbalances underlying reserves via a large swap or direct donation
2. get_virtual_price / naive LP fair-value inflates
3. Attacker deposits the LP token as collateral
4. Over-borrows against the inflated LP valuation

- **Blocked by (confirm present):** LP pricing uses a fair-reserves formula (e.g. invariant with min of independently-oracled underlying prices), reentrancy-guarded reads, and bounds checks — not raw get_virtual_price
- **Where it applies:** Lending accepting Curve/Balancer LP as collateral; structured-product pricing

### First-depositor / donation share inflation (ERC-4626)  ·  _share-inflation_
**Chain:**
1. Vault is empty; attacker deposits 1 wei and receives 1 share
2. Attacker directly transfers (donates) a large asset amount to the vault, inflating assets-per-share
3. Victim deposits X assets; shares = X * totalSupply / totalAssets rounds down to 0 (or 1)
4. Attacker redeems their 1 share, capturing the victim's deposit

- **Blocked by (confirm present):** Virtual shares / decimal offset (OZ ERC4626 _decimalsOffset), OR a minimum initial mint burned to a dead address, OR internal accounting (track totalAssets in storage rather than balanceOf), OR protocol-seeded initial liquidity at deploy
- **Where it applies:** ERC4626 vaults, yield aggregators, lending pools with share tokens, LST minting

### Balance-based share price manipulation via direct donation (non-4626)  ·  _share-inflation_
**Chain:**
1. Vault computes pricePerShare from balanceOf(address(this))
2. Attacker transfers tokens directly to the vault
3. pricePerShare jumps discontinuously
4. Attacker exploits any function priced off it (borrow, mint, reward, redeem)

- **Blocked by (confirm present):** Internal accounting variable for totalAssets mutated only through deposit/withdraw (never balanceOf); any sweep of unexpected tokens is access-gated and does not affect share price
- **Where it applies:** Custom vaults, staking pools, reward distributors, LST rate calculations

### Permit signature replay across chains (chainId not bound)  ·  _signature-replay_
**Chain:**
1. Token deployed on multiple chains shares a DOMAIN_SEPARATOR (chainId hardcoded at deploy or omitted)
2. User signs a permit on chain A
3. Attacker replays the identical signature on chain B where the user also holds tokens
4. Gains an unauthorized approval / spends tokens on chain B

- **Blocked by (confirm present):** EIP-712 domain separator includes block.chainid computed dynamically (recomputed on fork) and address(this); per-owner incrementing nonce; deadline enforced
- **Where it applies:** ERC20Permit / DAI-style permit tokens, meta-transactions, multi-chain deployments

### Generic signature replay (missing nonce/deadline/domain)  ·  _signature-replay_
**Chain:**
1. Contract verifies an ECDSA signature over a message lacking a nonce (or reusing one)
2. Attacker resubmits the same signed message
3. Action re-executes (double withdraw/mint/claim/order-fill)

- **Blocked by (confirm present):** Per-signer incrementing nonce consumed atomically, a deadline, and an EIP-712 domain separator binding contract+chain; used-digest set where applicable
- **Where it applies:** Meta-tx, gasless claims, off-chain order settlement, multisig, ERC1271

### Vote double-count via token transfer (no snapshot)  ·  _governance_
**Chain:**
1. Governance tallies by current balanceOf at vote time
2. Attacker votes with an account, transfers the tokens to a second account
3. Votes again from the second account
4. Voting power counted multiple times for the same tokens

- **Blocked by (confirm present):** Checkpointed voting power (ERC20Votes/delegation checkpoints) evaluated at the proposal snapshot block, so each token's weight is fixed per proposal
- **Where it applies:** Naive on-chain voting contracts, token-weighted polls

### Proxy function-selector clash  ·  _upgrade_
**Chain:**
1. An admin function selector on the proxy collides with an implementation function selector (4-byte collision)
2. A call is routed to the wrong target
3. Either the admin path is bricked or an access check is bypassed
4. Unexpected privileged execution or lockout

- **Blocked by (confirm present):** Transparent-proxy admin-vs-user routing by msg.sender (or use UUPS), selector-clash detection in the build, and diamond loupe selector uniqueness
- **Where it applies:** Transparent proxies, diamond (EIP-2535) proxies

### Storage layout mismatch across upgrade (variable reorder)  ·  _upgrade_
**Chain:**
1. v2 reorders, inserts before, removes, or changes the type of an existing storage variable
2. After upgrade, existing slots are reinterpreted
3. Balances/owner/config are corrupted
4. Funds mislabeled or access lost

- **Blocked by (confirm present):** Append-only variable additions, storage gaps reserved, and an automated storage-layout comparison in CI that blocks reorders/removals/type changes
- **Where it applies:** Any upgradeable contract's upgrade process

### Sandwich around minAmountOut = 0 (missing slippage bound)  ·  _MEV_
**Chain:**
1. Victim (or a router/zap) submits a swap/addLiquidity with amountOutMin = 0
2. Attacker front-runs, buying to push price against the victim
3. Victim executes at a badly skewed price
4. Attacker back-runs, selling to pocket the spread

- **Blocked by (confirm present):** A user-supplied minAmountOut/minShares > 0 derived from a fresh quote with slippage tolerance is enforced; zero/defaulted minimums are rejected; deadline set
- **Where it applies:** Swap routers, zaps, and any contract initiating swaps on behalf of users

### Protocol-owned swap/harvest with no slippage bound  ·  _MEV_
**Chain:**
1. Auto-compounder/harvester swaps rewards->asset internally with minOut = 0
2. Attacker sandwiches the keeper/harvest tx
3. The realized value loss is socialized to all depositors

- **Blocked by (confirm present):** Internal swaps compute minOut from an independent oracle/TWAP; keeper txs use a private mempool/commit-reveal where feasible
- **Where it applies:** Yield vaults, harvest/compound routines, liquidation and buyback swaps

### JIT liquidity / spot-tick manipulation of v3 pricing  ·  _oracle-manipulation_
**Chain:**
1. Attacker mints concentrated liquidity or donates to shift the active tick/slot0 spot immediately before an oracle read or in-protocol swap
2. Consumer reads the manipulated slot0 tick/price
3. Mispriced action executes
4. Attacker removes the liquidity

- **Blocked by (confirm present):** Never price off slot0/spot; use cumulative-tick TWAP observations or an external oracle for any valuation
- **Where it applies:** Uniswap v3 oracle consumers, in-protocol pricing off pool spot

### Missing interest/index accrual before state change  ·  _rounding-drain_
**Chain:**
1. A state-mutating market action (borrow/repay/liquidate/cToken transfer) runs without first calling accrueInterest/updateIndex
2. A stale interest/reward index is used
3. Interest/rewards are over- or under-credited
4. Attacker times actions around accrual to extract value

- **Blocked by (confirm present):** accrueInterest()/updateIndex() is invoked at the start of every state-mutating market function, with a timestamp/block checkpoint
- **Where it applies:** Lending markets, staking reward indexes, MasterChef-style distributors

### Flash-loan snapshot reward/fee theft  ·  _flash-loan_
**Chain:**
1. Protocol distributes rewards/fees pro-rata to current balances at claim time
2. Attacker flash-borrows, deposits a huge amount
3. Claims a disproportionate share of pending rewards/fees
4. Withdraws and repays the flash loan in the same tx

- **Blocked by (confirm present):** Rewards accrue over time (per-second/per-block) with a checkpoint on deposit, so a same-block deposit-then-claim earns ~0; deposit locks or minimum-holding-period where needed
- **Where it applies:** Reward distributors, fee-sharing/staking, veToken systems

### Self-liquidation / bad-debt socialization  ·  _flash-loan_
**Chain:**
1. Attacker opens a leveraged position
2. Manipulates price (flash loan) or donates to move the health factor
3. Triggers their own liquidation or leaves an uncollateralized position
4. Bad debt is absorbed by other lenders / the reserve

- **Blocked by (confirm present):** Bad-debt handling with a reserve buffer, liquidation that covers full exposure, borrow caps, and a manipulation-resistant oracle
- **Where it applies:** Lending, perps, CDP systems

### PSM fee/rounding arbitrage  ·  _rounding-drain_
**Chain:**
1. PSM swaps stable<->collateral at a fixed rate with a fee (or zero fee / asymmetric fees)
2. Attacker exploits rounding or the fee asymmetry
3. Repeatedly swaps in/out (or mints stable cheaply and dumps)
4. Extracts value / drains reserves / pressures the peg

- **Blocked by (confirm present):** Symmetric in/out fees, rounding always against the user, mint/burn/debt-ceiling caps, and a 1:1 backing invariant maintained on every swap
- **Where it applies:** MakerDAO-style PSM, stablecoin mint/redeem modules

### CDP liquidation via oracle move / zero-bid auction  ·  _oracle-manipulation_
**Chain:**
1. Attacker manipulates collateral price down (flash loan) or exploits network congestion
2. Triggers a CDP liquidation auction
3. Wins collateral at a discount, or submits a 0/dust bid in an under-competed auction (Black Thursday-class)
4. Seizes collateral far below value

- **Blocked by (confirm present):** Oracle Security Module delaying price by a fixed window, auction minimum-bid/duration parameters, and circuit breakers so a single-block move cannot both trigger and settle a discounted auction
- **Where it applies:** MakerDAO-style vaults and CDP liquidation auctions

### Fee-on-transfer / rebasing token accounting mismatch  ·  _rounding-drain_
**Chain:**
1. Pool/vault records amount = the transfer parameter rather than the amount actually received
2. A fee-on-transfer token delivers less than the parameter (or a rebasing token drifts from the recorded figure)
3. Contract credits the full amount
4. Attacker withdraws more than they deposited, draining other users

- **Blocked by (confirm present):** Received amount computed from the balanceOf(this) delta (measure before/after); rebasing/fee-on-transfer tokens whitelisted or explicitly handled; never assume amountIn == credited
- **Where it applies:** AMM pools, vaults, bridges, staking accepting arbitrary ERC20s

### Non-standard ERC20 return handling (silent transfer failure)  ·  _rounding-drain_
**Chain:**
1. Contract calls token.transfer/transferFrom and ignores the bool return, assuming a revert on failure
2. A USDT-style token returns false / no bool on failure
3. The transfer silently does not move funds while the contract proceeds to credit the user
4. Loss / accounting desync

- **Blocked by (confirm present):** SafeERC20 (safeTransfer/safeTransferFrom/forceApprove) used everywhere, tolerating no-return and false-return tokens
- **Where it applies:** Every ERC20 integration (USDT/BNB-style tokens)

### LST exchange-rate manipulation via donation / reward-report front-run  ·  _share-inflation_
**Chain:**
1. LST computes rate = totalPooled / totalShares from spot balances
2. Attacker donates the underlying or front-runs a large reward/oracle report
3. The rate jumps discontinuously
4. Attacker mints before / redeems after to capture rewards they did not earn (or inflates for the first depositor)

- **Blocked by (confirm present):** Internal accounting for totalPooled, oracle-report smoothing, deposit/withdraw not priced off raw spot balance, front-run protection on rebase, and an initial protocol seed
- **Where it applies:** Lido-style stETH, rETH, and other liquid-staking token vaults

### tx.origin authentication phishing  ·  _access-escalation_
**Chain:**
1. Contract authorizes via tx.origin == owner
2. Owner is tricked into calling an attacker contract
3. Attacker contract calls the victim; tx.origin is still the owner
4. Auth check passes and the attacker drains funds

- **Blocked by (confirm present):** Authorization uses msg.sender, never tx.origin
- **Where it applies:** Smart-contract wallets, access-controlled admin functions

### Payable multicall msg.value reuse  ·  _access-escalation_
**Chain:**
1. A payable multicall batches sub-calls each of which reads msg.value
2. Attacker includes the same value-consuming function twice in one multicall
3. msg.value is observed in full by every sub-call
4. Attacker pays once but is credited multiple times

- **Blocked by (confirm present):** Do not read msg.value inside functions reachable through a delegatecall-style multicall; make multicall non-payable or explicitly track and decrement consumed value
- **Where it applies:** Router/aggregator multicall, batched deposit/mint helpers


## MEDIUM

### Rounding-in-attacker-favor repeated round-trips (rounding drain)  ·  _rounding-drain_
**Chain:**
1. Attacker finds an operation that rounds in the user's favor (i.e. the INVERSE of spec — e.g. deposit rounds shares UP, or redeem rounds assets UP)
2. Repeatedly deposits then withdraws small amounts, each round capturing 1 wei of rounding error
3. Iterates many times
4. Cumulatively drains value from other holders / the reserve

- **Blocked by (confirm present):** Rounding is always against the user on every path — per EIP-4626: **deposit rounds shares DOWN, mint rounds assets UP, withdraw rounds shares UP, redeem rounds assets DOWN** (convertToShares/convertToAssets round DOWN) — via mulDiv with an explicit rounding direction; no profitable zero-sum round-trip exists
- **Where it applies:** ERC4626, AMM share/LP math, interest-index accrual, staking reward math

### ERC20 approve-race front-run (allowance double-spend)  ·  _signature-replay_
**Chain:**
1. Owner has an existing allowance N to a spender
2. Owner submits approve(spender, M) to change it
3. Spender front-runs with transferFrom of N
4. After the new approval lands, spender transferFrom of M
5. Spender has moved N+M instead of the intended M

- **Blocked by (confirm present):** Use increaseAllowance/decreaseAllowance, or require current allowance == 0 before setting a non-zero value; integrations set allowance to 0 before re-approving
- **Where it applies:** All ERC20 approve() usage; router/vault approval flows

### Permit front-run griefing (DoS of permit+action)  ·  _signature-replay_
**Chain:**
1. User submits a tx bundling permit() then an action
2. Attacker extracts the permit signature from the mempool
3. Attacker submits permit() alone first, consuming the nonce
4. Victim's permit() reverts (nonce used), reverting the whole bundled tx and blocking the action

- **Blocked by (confirm present):** Wrap permit() in try/catch (or skip if allowance already sufficient) so a pre-submitted permit does not brick the action
- **Where it applies:** Routers/vaults/zaps using the permit-then-act pattern

### ECDSA malleability / ecrecover(0) acceptance  ·  _signature-replay_
**Chain:**
1. Contract uses raw ecrecover without checking s in the lower half-order or v validity
2. Attacker flips (r,s,v) to a second valid signature for the same message, bypassing a 'signature already used' set; or crafts input recovering address(0) matched against an uninitialized signer slot
3. Replays or forges authorization

- **Blocked by (confirm present):** Use OpenZeppelin ECDSA (rejects high-s and returns error on malformed input), reject recovered == address(0), and validate the signer against a non-zero configured set
- **Where it applies:** Any ecrecover-based auth, permit, ERC1271, bridge attestation verification

### Missing deadline -> stale-tx execution  ·  _MEV_
**Chain:**
1. Swap tx uses deadline = type(uint).max or leaves the deadline param unenforced
2. Tx sits in the mempool
3. A validator/attacker executes it much later (or holds it until profitable) at a worse price

- **Blocked by (confirm present):** A user-supplied deadline is enforced (require block.timestamp <= deadline), never hardcoded to max or ignored
- **Where it applies:** AMM routers and any time-sensitive on-chain swap

### Liquidation front-run / grief  ·  _MEV_
**Chain:**
1. A liquidator broadcasts a liquidation tx
2. Attacker front-runs to self-liquidate on better terms, or repays a dust amount to flip the position healthy and block the liquidation
3. Value is extracted from the liquidator, or the liquidation is denied and bad debt lingers

- **Blocked by (confirm present):** Bounded, predictable liquidation incentive and close-factor; partial-liquidation rules; keeper submission via private mempool; no ordering-dependent profit leak
- **Where it applies:** Compound/Aave-style liquidation engines

### LST withdrawal-queue rate timing (request vs claim / slashing)  ·  _share-inflation_
**Chain:**
1. User requests a withdrawal that locks the exchange rate at request time
2. A negative rebase (slashing) is reported before claim
3. If the rate was locked at request, the protocol overpays the exiting user, or an attacker times the request just before a known slashing report to exit whole
4. Loss socialized to remaining stakers

- **Blocked by (confirm present):** Redemption rate finalized at claim/report time (not request), a withdrawal delay covering the oracle-report cadence, and correct slashing socialization
- **Where it applies:** Liquid-staking withdrawal queues

### Unbounded-loop gas-griefing DoS  ·  _DoS_
**Chain:**
1. A function iterates over a user-growable array (holders, positions, queue)
2. Attacker inflates the array with many dust entries
3. The loop's gas exceeds the block gas limit
4. The function permanently reverts, locking funds or blocking distributions

- **Blocked by (confirm present):** Pull-over-push pattern, pagination/bounded iteration, and no unbounded loops over user-controllable sets
- **Where it applies:** Reward distribution, airdrops, withdrawal queues, snapshotting

### Push-payment revert DoS  ·  _DoS_
**Chain:**
1. Contract loops paying a list of recipients via a direct send/transfer
2. One recipient is a contract that reverts on receive (or consumes all gas)
3. The entire payout transaction reverts
4. All recipients are blocked from being paid

- **Blocked by (confirm present):** Pull-payment (per-recipient withdraw) pattern, or wrap each external call in try/catch and continue, crediting on failure
- **Where it applies:** Auctions, splitters, batch refunds, prize/dividend distribution

### Force-fed ETH breaks strict balance invariant  ·  _DoS_
**Chain:**
1. Contract assumes address(this).balance equals its internal accounting
2. Attacker selfdestructs ETH into the contract (or pre-funds the counterfactual address before deploy)
3. balance now exceeds internal accounting
4. Logic using an exact-equality balance invariant reverts or misbehaves, locking funds

- **Blocked by (confirm present):** Never use address(this).balance for critical logic; rely on internal accounting and use >= comparisons rather than strict equality
- **Where it applies:** Games, lotteries, vaults enforcing balance invariants
- **TVM note:** the force-feed surface is BROADER on TRON — a plain TRX Transfer (system tx) does NOT invoke the recipient's `receive()`/`fallback()` (only a `TriggerSmartContract` call with callvalue does), so even ordinary transfers silently inflate `address(this).balance` past internal accounting, not just selfdestruct/force-feed. Any `balance == expected` invariant is even easier to break.


---
_Notes:_ Coverage: 52 vulnerable call-chains grouped into reentrancy (classic/cross-function/cross-contract/read-only/token-hook), oracle+flash-loan manipulation (spot-price borrow & forced-liquidation, oracle lag, Chainlink staleness/sequencer, thin TWAP, LP fair-value, v3 tick JIT), share-inflation/rounding (4626 first-depositor donation, rounding round-trips, balance-based donation, LST rate manipulation), approvals/signatures (approve-race, permit cross-chain replay, permit-griefing, generic nonce/domain replay, ECDSA malleability), governance (flash-loan takeover, no-snapshot double-vote, timelock bypass), bridges (forged proof, replay double-mint, validator-threshold, lock/mint mismatch), proxy/upgrade (uninitialized init-takeover, unprotected UUPS, storage collision, selector clash, layout reorder, arbitrary delegatecall), MEV (minOut=0 sandwich, missing deadline, protocol-swap sandwich, liquidation front-run), plus lending accrual, PSM/CDP, fee-on-transfer/non-standard-ERC20, DoS (unbounded loop, push-payment revert, force-fed ETH), tx.origin, and payable-multicall value reuse.

How to use: for each chain the auditor treats the **Blocked by (confirm present)** entry as a positive checklist item — confirm the named guard EXISTS and is correct (grep the entrypoints named under **Where it applies**), rather than trying to prove exploitability. Chains are the point: each individual function can pass review while the composition loses funds, so the invariants to verify are cross-function (shared mutex, single accrual point), cross-contract (system-wide guard, conservation invariants), and temporal (past-block snapshots, deadlines, staleness windows, OSM/timelock delays).

Grounding: ERC-4626 mitigations (virtual shares / decimal offset, internal accounting, dead-shares) confirmed against OpenZeppelin's ERC4626 docs and Euler's exchange-rate-manipulation write-up during this session. The remaining chains map to SWC entries (SWC-107 reentrancy, SWC-114 tx-ordering/approve-race, SWC-115 tx.origin, SWC-116 timestamp, SWC-117/121 signature replay, SWC-109 uninitialized-storage-pointer (note: SWC-118 is *Incorrect Constructor Name*, not uninitialized storage), SWC-120 weak randomness/oracle, SWC-128 gas DoS) and documented postmortems (bZx/Harvest/Cheese flash-oracle, Curve/Balancer read-only reentrancy, Rari/Fei first-depositor, Beanstalk flash-loan governance, Ronin/Harmony/Wormhole/Nomad bridges, Parity uninitialized proxy, Black Thursday zero-bid auctions). A few incident citations draw on established references rather than freshly fetched pages; re-verify specific postmortem details against primary sources before publishing the audit report. Severity reflects typical realized impact; TVM note: TRON now aligns SELFDESTRUCT with EIP-6780 (mainnet since 2026-04-10) but still differs on EIP-1967 tooling, precompiles, and the energy model, so verify proxy-slot and force-feed assumptions against TVM behavior for TRON deployments.


## Additional coverage (extended checklist)

- DoS via unbounded loop over user/holder/pool/validator arrays exceeding the block gas / TRON energy limit — reward distribution, rebase, mass liquidation, or massUpdatePools permanently reverts once the array grows, and an attacker can grow it cheaply (griefing)
- DoS via push-payment: a single reverting recipient (USDT-frozen address, contract with no payable receive, deliberate out-of-gas fallback) blocks refunds, auction settlement, or batch reward payout for everyone — fix is pull-payment / try-catch isolation
- MEV sandwich on swaps/deposits/zaps/liquidations with missing or zero slippage (amountOutMin/minShares == 0) and/or missing deadline — guaranteed value extraction; includes JIT-liquidity front-running of large adds
- Flash-loan governance takeover: borrow the governance token within one block, self-delegate, reach proposalThreshold/quorum, propose+vote+execute a malicious action, repay — defeated only by snapshotting voting power at proposal creation and a delegation/timelock delay
- Chainlink circuit-breaker clamp: during a flash crash/depeg the feed returns minAnswer or maxAnswer (aggregator floor/cap), not the true price, so borrows/liquidations execute at the clamped price (Venus/UST-style) — consumer must reject prices at the bounds
- Precision/decimals mismatch: protocol assumes 18 decimals but TRON USDT is 6 decimals, mis-valuing collateral/shares; and div-before-mul ordering rounds low-decimal amounts to zero, enabling free mints or zero-cost debt
- ecrecover returns address(0) on a malformed signature and the code compares it to an uninitialized/zeroed signer slot -> authentication bypass (SWC-117 combined with a missing zero-address check)
- Signature malleability / cross-contract replay: a signature that omits address(this) or chainId in its domain, or does not enforce low-s (EIP-2), is replayed on a sibling contract, a forked chain, or via flipped (r,s,v)
- EIP-1271 contract-wallet signature bypass: isValidSignature is trusted for approval/order auth, then the wallet's signer-set or state changes so a consumed or forged signature validates again
- Bridge forged-deposit / fake-event mint: attacker fabricates a deposit proof or replays a validator signature (message hash missing chainId or a per-message nonce) to mint on the destination without a real source-chain lock, breaking the lock==mint supply invariant (Nomad/Wormhole-class)
- Bridge source-chain reorg / insufficient finality: destination mints after N confirmations, the source deposit is later reorged out, leaving unbacked minted tokens on the destination
- Proxy bricking via self-destruct or storage collision: attacker initializes an uninitialized UUPS implementation and triggers a delegatecall->selfdestruct (Parity-style — brick vector is dead on post-Cancun EVM and on TRON per EIP-6780, adopted on TRON 2026-04-10; live only on pre-6780 chains or same-tx create+destroy), or a proxy/implementation storage-layout collision overwrites the EIP-1967 admin/implementation slot
- PSM / peg arbitrage drain: asymmetric buyGem vs sellGem fees, or a collateral depeg still valued at $1, lets an attacker cycle mint<->redeem for risk-free profit or mint effectively unlimited stablecoin
- Liquidation-auction failure under congestion (MakerDAO Black Thursday): network/energy congestion prevents keepers from bidding, collateral is auctioned near zero, and the protocol is left holding bad debt
- Read-only reentrancy generalized beyond Curve: Balancer getPoolTokens/getRate and any custom-vault view getter read mid-callback returns a transiently manipulated value to a pricing/LTV consumer
- Multi-feed oracle divergence: two price feeds with different decimals or heartbeats (e.g. 8-dec ETH/USD vs 18-dec asset feed) produce systematic mispricing even without active manipulation
- Front-running an unprotected initializer or first deposit/first liquidity: attacker back-runs the deploy tx to call initialize() and seize ownership/roles, or seeds the pool to capture MINIMUM_LIQUIDITY
- Gas-griefing via the 63/64 rule (SWC-126): caller supplies just enough gas that a nested external call (transfer, hook, or subcall) runs out of gas and is silently swallowed, corrupting accounting while the outer tx succeeds
- Force-fed ETH/TRX via selfdestruct breaking a strict this.balance == internalAccounting invariant (SWC-132), bricking sync/swap or skewing share price
- Uninitialized storage pointer / delegatecall module writing to slot 0 (owner/implementation) — SWC-109 storage collision in legacy Solidity/Vyper libraries
- Vyper 0.2.15 / 0.2.16 / 0.3.0 (fixed in 0.3.1) malfunctioning @nonreentrant lock: reentrancy remains possible despite the decorator (Curve July-2023 exploit) — treat the compiler-version gate as an explicit attack chain, not just a note
- Rebasing / share-token integration desync: a vault or lending market records balanceOf at deposit but the token rebases (stETH/Ampleforth), so a positive rebase donation over-credits and a negative rebase (slashing) leaves shares insolvent
- Meta-transaction / EIP-2771 trusted-forwarder _msgSender spoofing: a malicious or misconfigured forwarder appends an arbitrary address, letting the relayer impersonate any user
- Approve-then-act (zap/router) allowance front-run generalized: attacker consumes a just-granted allowance between the approve and the protocol's transferFrom pull — superset of the ERC-20 approve-race applied to routers/vaults
