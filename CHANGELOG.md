# Changelog

All notable changes to the `reviewing-smart-contracts` skill.

## [Unreleased]

### Added (best-in-class checklist expansion)
- **8 new first-class checklist sections** in `vulnerable-functions.md` (110→173 patterns, 21 categories): `erc4626-vault`, `staking-rewards` (MasterChef/Synthetix/gauge/bribe), `perps-derivatives`, `account-abstraction-4337`, `eip-7702`, `intents-solvers` (Permit2/CoW/UniswapX), `cross-chain-messaging` (LayerZero/CCIP/Wormhole/Axelar), `modular-proxy-diamond` (EIP-2535/1167/beacon/ERC-7201). Each entry is concrete + grep-able with the real mitigation; grounded in real incidents (Sonne, Mango $114M, Nomad, Synthetix solvency require). **TVM honesty:** AA/7702/Permit2 flagged EVM-mainly with "verify TVM support" caveats; LayerZero noted live on TRON; CREATE2 `0x41` / delegatecall-token-drop cross-referenced to `tvm-native`.
- **9 new exploit chains** in `vulnerable-chains.md` (52→61): vault strategy-mark inflation, MasterChef stake==reward drain, Synthetix rate-dilution, perp oracle-collateral inflation, perp self-liquidation, 4337 paymaster drain, 7702 delegate sweep, Permit2 witness-less reuse, cross-chain message forgery.
- **`checklist-ids-and-crosswalk.md`** — stable `VF-<SECTION>-NN` / `VC-<FAMILY>-NN` ID scheme (cite exact items in findings + coverage.md) and a web-verified crosswalk to OWASP SCSVS (11 control groups, with the SCSVS-ORACLE=arithmetic quirk) and EEA EthTrust v3 (March 2025). TVM-native flagged as out-of-scope of both standards (a real delta + differentiator).

### Added (semgrep-tron ruleset: 7 → 14 rules)
- 7 new TRON-framed EVM-assumption rules: `tron-native-send-stipend` (2300-gas stipend vs Energy), `tron-tx-origin-auth`, `tron-delegatecall-usage` (arbitrary target + TVM token-context drop), `tron-ecrecover-usage` (0-addr/malleability/21-byte), `tron-selfdestruct-usage` (post-6780/param-#94), `tron-lowlevel-call-value`, `tron-create2-new-salt` (0x41 prefix). All validate + fire on the fixture (18 matches / 14 rules, 0 on the safe contract). Dropped two that Semgrep's experimental Solidity can't express (inline-assembly block, tstore/tload). **Ran on 2 real TRON codebases** (JustLend → 9 inventory hits: delegatecall×5/ecrecover×3/tx.origin×1; SunSwap-v2 → 1) — low-noise, no FP flood.

### Validated (gate 6 — real fuzzing campaign) + tooling trap documented
- Ran a genuine **Echidna campaign on the real `SunswapV2Pair`** (Uniswap-V2 fork from the catalog): a MiniFactory-backed harness fuzzed mint/swap/burn/skim over **200,292 calls**; both safety invariants held (`reserves ≤ balances`, reserves can't both drain while LP outstanding). Plus a **Halmos** symbolic pass on the canary models (proved the fix, refuted the vuln).
- **Documented the crytic-compile `--evm-version osaka` trap** (SKILL.md gate 6): crytic-compile ≥0.4.1 hardcodes `--evm-version osaka`, which every TRON-era solc (0.4–0.7) rejects, silently breaking slither/echidna/medusa — fix by pinning `solc`/`evm_version` via a `foundry.toml` so crytic uses the Foundry framework. Affects most TRON contracts (old solc).

### Improved (gate 2 — Decurity security subset)
- Gate 2 now points Semgrep at the Decurity **`solidity/security`** subdir, not all of `solidity/`. Discovered during a protocol-mode run on JustLend: the full `solidity/` (which includes 13 `performance` + 2 `best-practice` rulefiles) produced **823 hits dominated by gas/style** (use-custom-error, short-revert, prefix-increment); `solidity/security` (42 rulefiles) cuts that to 213 and surfaces the Compound-fork-specific security rules that matter (`compound-borrowfresh-reentrancy`, `compound-precision-loss`). Auditors can still add `performance`/`best-practice` explicitly for a gas review.

### Improved (get-source.sh)
- **Immutables-aware recompile:** requests full `deployedBytecode` (with `immutableReferences`), masks the immutable byte-ranges (set at construction, legitimately differ from the compiled placeholder) so an immutable-bearing contract can still reach **FULL_MATCH** (metadata intact) instead of collapsing to PARTIAL.
- **Multi-hop + beacon proxy resolution:** adds the EIP-1967 beacon slot (`0xa3f0…3d50` → `beacon.implementation()`) and raises the recursion limit to 3 hops (proxy→beacon→impl / nested proxies); logs the resolution method. Validated live: USDD recompile=FULL-MATCH via the newly-installed `tron-solc-0.5.8` fork.

### Fixed (external Fable review, verified)
- **get-source.sh robustness (High).** `curl` now uses `--fail` and the parser distinguishes an **API error** (403 / rate-limit / no `data` object → exit 2) from a genuinely **unverified** contract (exit 3) — previously an API hiccup was silently reported as "no source," pushing the auditor to the bytecode branch. Added strict **T-address validation** (blocks JSON-injection into the POST body and path traversal in the output dir). Removed dead `vbyte` (parsed, never used — implied a source↔bytecode check that didn't exist).
- **Decurity pin is now actually used (High).** Gate 2 previously ran `semgrep --config p/smart-contracts` (floating registry) while `bootstrap.sh` cloned Decurity separately — so the pin did nothing and the clone was dead weight. Gate 2 now runs the **pinned local clone** (`$AUDIT_HOME/semgrep-smart-contracts/solidity`).
- **Subagent env (Medium).** `bootstrap.sh` writes PATH + audit.env sourcing to `~/.zshenv` (sourced by non-interactive shells) instead of `~/.zshrc` — tools/keys now reach shells spawned by subagents.
- **Semgrep `trcToken` rule (High).** `pattern: trcToken $ID` matched only state/local declarations, missing the primary risk — a `trcToken` **function parameter** from calldata. Added the body-form `function $F(..., trcToken $ID, ...) { ... }` pattern (verified: now flags params in any position).
- **ERC-4626 rounding contradiction (Medium).** `vulnerable-chains.md` stated muddled/incorrect rounding directions ("withdrawals round assets down", "mint rounds shares up") contradicting the correct matrix in `vulnerable-functions.md` — corrected to spec (deposit shares DOWN, mint assets UP, withdraw shares UP, redeem assets DOWN).
- **Consistency.** report-template: "Critical requires a PoC" reworded — PoC governs the Proven-status field, not severity (matches SKILL.md). Removed the dead `../../methodology.md` link that would appear in every client report. Aligned `SKILL.md` frontmatter `name:` to `skill-smartcontracts` (dir/id).
- **EIP-6780 refinement.** Added the network-**parameter-#94** framing: TRON gates the behavior behind param #94 (GreatVoyage-v4.8.1); on forks/testnets with #94=0 the brick vector is still live, so verify #94 on the actual target chain rather than asserting an absolute.

### Added (TVM coverage gaps flagged by Fable)
- **`tvm-native`: TRON account-permission model** (owner/active/witness, key weights, threshold via `AccountPermissionUpdateContract`) — custody is set at the account level, not (only) Solidity modifiers; classify via `getaccount`. Also added a gate-3 sub-step. This was the most material TVM gap (custody mis-rating).
- **`tvm-native`: Stake 2.0 economics** — the mandatory 14-day `UnfreezeBalanceV2` window and 3-day delegation lock that any energy-rental / withdrawal-queue / liquid-staking contract must model.
- **ERC-7201 namespaced storage** (OZ 5.x) in the proxy-upgrade section (beyond `__gap`); **standard cross-chain messaging** integrations (LayerZero/CCIP/Wormhole-VAA/Axelar) in the bridge section (TRON runs a live LayerZero endpoint).

### Fixed (external Codex review, verified)
- **FACTUAL: TRON adopted EIP-6780.** Corrected every checklist claim that "TVM has NOT adopted EIP-6780 / the SELFDESTRUCT proxy-brick is still live on TRON." TRON activated EIP-6780-aligned SELFDESTRUCT on mainnet **2026-04-10** (Proposal 94 / GreatVoyage-v4.8.1; SELFDESTRUCT energy 0→5000): post-creation self-destruct no longer deletes code/storage (brick vector dead, as post-Cancun EVM), only transfers balance; full deletion only in a same-tx create+destroy. Verified against tronprotocol/tips#827 and dated coverage. (`vulnerable-functions.md`, `vulnerable-chains.md`.)
- **get-source.sh attestation honesty.** The `keccak256(runtime)==code_hash` check is node self-consistency, NOT source→runtime proof — relabeled `node_runtime_hash_match` and stopped calling it "authoritative." Source is authoritative ONLY on recompile `FULL_MATCH`. Recompile result is now written machine-readably to `compiler.json` (`recompile_status`: FULL_MATCH|PARTIAL|NO_MATCH|SKIPPED, `source_authoritative`, `explorer_source_status`) so audits can gate on it. SKILL.md gate 1 rewritten to separate the two trust levels.
- **Semgrep ruleset hardening.** Corrected severities (inventory rules WARNING→INFO; Semgrep WARNING≈MEDIUM); rewrote the noisy `1e18` rule to fire only when combined with `msg.value` in one expression (plain WAD/TRC-20 18-decimal math no longer false-positives) with a documented no-dataflow limitation; added realistic `// ok:` negatives to the fixture; added richer metadata (confidence/references). Added two precise rules: `tron-weak-randomness-tvm-constants` (block.difficulty/prevrandao/gaslimit are TVM constants) and `tron-create2-eth-prefix` (0xff vs TVM 0x41). Now 7 rules; fixture smoke-test = 8 matches on the vulnerable contract, 0 on the safe one.
- **Reproducibility.** `bootstrap.sh` now PINS the Decurity ruleset by commit (`DECURITY_REF`, default `2e878a8`) instead of a floating `git pull`; gate 2 records the ruleset commit + per-target `recompile_status` into the evidence manifest.

### Tooling
- **`bootstrap.sh` step 5 — multi-version TRON solc forks.** Was: only `tron-solc 0.8.27`. Now installs a spread across the major bands (`0.4.25 0.5.8 0.5.17 0.6.12 0.7.6 0.8.18 0.8.22 0.8.25 0.8.26 0.8.27`) so `get-source.sh` recompile-match reaches **FULL-MATCH** on old and new targets alike (vanilla solc of the same version emits different bytecode than the TVM fork). Resolves both release asset schemes automatically — plain `solc-macos`/`solc-static-linux` binary for ≥0.8.18, and the zip-with-codename (e.g. `solidity-mac_0.7.6_Plato_v4.2.zip`, irregular `0.4.25_Odyssey_v3.2.3` tag) for older — via the GitHub releases index, extracting the inner `solc`. Override with `TRON_SOLC_VERSIONS="…"`. Resolves the prior Known-TODO.
- **`tooling/semgrep-tron/`** — custom TRON/TVM-native Semgrep ruleset (5 rules) turning the `tvm-native` checklist into automatic audit-inventory hotspots: `msg.tokenvalue/tokenid` context, `transferToken`/`tokenBalance` token-id trust, `trcToken` calldata params, and SUN-vs-1e18 native decimals. LOW/inventory by design — a match is a pointer, not a finding. Ships in-repo (no install); `bootstrap.sh` step 10 validates it; wired into `SKILL.md` gate 2 (`semgrep --config tooling/semgrep-tron/`). Fixture `tron-tvm-native.sol` (vulnerable + safe contracts) smoke-tests every rule.

## [0.1.0] — initial public version

First published version. Consolidates everything built and validated to date.

### Skill (`SKILL.md`)
- 9 non-negotiable review gates (get-source → build → static analysis → map/trust-boundaries → fork-diff → walk-checklists → invariants+fuzz → PoC → deployment-data → mechanical checks).
- **Actor / attacker-role classification** — classify by who can trigger a finding *before* rating severity; privileged-admin powers go in a separate Centralization/trust-assumption class, not rated as unprivileged vulnerabilities.
- **Realized vs latent severity** tied to live deployment data.
- **Reproduce-and-match** discipline: source is authoritative only when `keccak256(runtime) == on-chain code_hash`.
- **Bytecode-only branch** for unverified contracts (decompile + selector-match + `code_hash` attestation).
- **Backdoor / deployer-history hunt** (a "verified" badge and a prior audit are not trust).
- Compiler-known-bugs triage; TronBox event-assertion false-PASS trap; readiness red flags.
- Hybrid tooling policy, macOS `gtimeout` note, API-key handling.

### Checklists
- `vulnerable-functions.md` — ~110 function patterns across 14 categories, including a dedicated **`tvm-native`** category (TRC-10 `msg.tokenid` confusion, SUN 1e6 native decimals, precompile divergence at identical addresses, CREATE2 `0x41`-not-`0xff`, staking/resource opcodes as a privileged surface, delegatecall dropping `calltokenvalue/id`, ecrecover 20-byte vs 21-byte identity).
- `vulnerable-chains.md` — 52 exploit compositions, including a CRITICAL **fake-TRC-10 deposit / real-token withdraw** drain and a TVM-sharpened force-fed-balance chain.
- Factual fixes: TVM opcodes are no longer claimed to "behave as on EVM" (`block.difficulty/prevrandao/gaslimit` are constants); EIP-6780 / EIP-7702 / EIP-1153 transient-storage notes; Chainlink `answeredInRound` deprecation; ERC-4626 rounding matrix corrected.

### Deliverables
- `report-template.md` — client-acceptance-ready per-address report with a pre-submission acceptance checklist, an Actor column, and a Centralization (§5b) section.

### Tooling
- `bootstrap.sh` — one-shot workstation setup (compilers incl. TRON `tv_` fork, Foundry, Slither/Aderyn/Semgrep/Mythril, heimdall, Echidna/Medusa, TronBox, API-key template).
- `get-source.sh` — verified-source fetch via TronScan `POST /api/solidity/contract/info`, strict `keccak256(runtime)==smart_contract.code_hash` attestation, proxy → implementation resolution, best-effort recompile-match, `code_hash` cache, heimdall fallback.

### Validation
- Built via test-driven skill authoring (RED baseline → GREEN verify → REFACTOR).
- Validated on a live canary: independently re-found a known Critical (missing `transferFrom` auth gate) in an unverified TRON proxy from bytecode alone.
- Enriched by a 30-source deep-research pass (Trail of Bits, EthTrust, OWASP SCSVS, Secureum, SCSFG, and major incident post-mortems); only TVM-native, non-generic findings were integrated.

### Known TODO
- _(resolved in Unreleased — multi-version TRON solc forks now installed by `bootstrap.sh` step 5.)_
