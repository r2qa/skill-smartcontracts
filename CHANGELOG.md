# Changelog

All notable changes to the `reviewing-smart-contracts` skill.

## [Unreleased]

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
