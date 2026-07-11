# Changelog

All notable changes to the `reviewing-smart-contracts` skill.

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
- Add the TRON solc **forks** (`tron-0.4.25_Odyssey`, `tron_v0.5.x/0.6.12/0.7.6/0.8.18`, …) to `bootstrap.sh` so `get-source.sh` recompile-match yields FULL-MATCH instead of skipping (currently only `tron-solc 0.8.27` is installed).
