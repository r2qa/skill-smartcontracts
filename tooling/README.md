# Audit workstation tooling

One-time, idempotent bootstrap for the TRON/EVM smart-contract audit workflow:

```bash
bash tooling/bootstrap.sh      # installs everything below (safe to re-run)
```

This table is the contract between `bootstrap.sh` and `SKILL.md`: **every tool it installs is used by the skill**, and every tool the skill invokes is installed here. Column "Used by the skill" cites the gate/place in `../SKILL.md` (and `get-source.sh`) so nothing is installed for nothing.

## Directly used by the skill

| Tool | bootstrap step | What it is | Used by the skill |
|---|---|---|---|
| **Foundry** — `forge`/`cast`/`anvil` | 6 | Solidity dev/test framework | `forge` compiles + runs **PoC/fork tests** (gate 1, gate 7); `cast keccak` computes the on-chain **`code_hash`** for the runtime attestation + recompile-match (`get-source.sh`, gate 9); `anvil` for local mainnet-fork PoCs (SAFE-TESTING). *(`chisel` REPL ships with Foundry; not required.)* |
| **solc-select** + solc 0.5–0.8 | 4 | Manage/pin vanilla solc versions | **Pin & compile** the exact solc a contract used (gate 1); drives the **recompile-match** in `get-source.sh`; the analyzers compile through it. |
| **TRON solc fork** (`tv_` / tron-solc) | 5 | tronprotocol/solidity — TVM compiler | **Byte-accurate TVM compilation/verification** (gate 1). Required for `get-source.sh` recompile-match to reach **FULL-MATCH** (vanilla solc ≠ TVM bytecode). Installs a spread across the major bands (`0.4.25`→`0.8.27`); resolves both asset schemes (plain binary ≥0.8.18, zip for older) from the releases index. Override with `TRON_SOLC_VERSIONS="…"`. |
| **Slither** | 7 | Static analyzer (SlithIR) | Mandatory **static analysis** + printers for the trust-boundary map (gate 2, gate 3). Handles solc 0.5.x. |
| **Aderyn** | 11 | Rust AST static analyzer | Second static pass (gate 2). *Caveat: can't parse solc <0.6 → marked `NOT covered` there.* |
| **Semgrep** + Decurity rules | 10 | Pattern/taint static analysis | Static pass, two rulesets (gate 2): the Decurity DeFi set `p/smart-contracts` **and** the in-repo TRON/TVM-native set `tooling/semgrep-tron/` (ships with the skill, no install — see its `README.md`). |
| **Mythril** (`myth`) | 9 | Symbolic execution over bytecode | Symbolic pass on high-value / **bytecode-only** targets (gate 2). *Degraded on TVM prologue opcodes — see the TVM caveat in SKILL.md.* |
| **Echidna** | 15 | Coverage-guided property fuzzer | **Invariant/property fuzzing** (gate 6). |
| **Medusa** | 15 | Parallel fuzzer (Echidna-model) | Invariant fuzzing, larger campaigns (gate 6). |
| **Halmos** | 15 | Symbolic unit tester (z3) | A **symbolic counterexample counts as proof** for math/live-only findings (gate 7). |
| **heimdall-rs** | 12 | EVM decompiler | **Bytecode-only branch**: decompile the runtime of an unverified contract (gate 1 substitute); `get-source.sh` falls back to it when `status≠2`. |
| **panoramix** | 13 | Fallback decompiler (by-address) | Fallback when heimdall aborts on TVM opcodes (bytecode branch). Needs `WEB3_PROVIDER_URI`. |
| **TronBox** | 14 | TRON build/test framework (Truffle-fork) | Toolchain **detection** (`tronbox.js`, gate 1) and the **on-TVM PoC harness** against Nile/Shasta (gate 7, gate 9). |
| **TronGrid / TronScan API keys** | 16 | `~/.config/fearsoff/audit.env` (`TRON-PRO-API-KEY`) | Read-only recon + **verified-source fetch** (`get-source.sh` → `POST /api/solidity/contract/info`) + on-chain state/attestation reads. See `../audit.env.example`. |

## Install-time dependencies (not invoked directly — required by the tools above)

| Tool | step | Needed by |
|---|---|---|
| OS prereqs (build tools, python3, git) | 0 | everything |
| **coreutils** (`gtimeout`) + **gnu-sed** (`gsed`) + **jq** | 0 (macOS) | `gtimeout` for the skill's macOS timeout note; `jq` for JSON in shell recipes/`get-source.sh` helpers |
| **pipx** | 1 | isolated installs of Slither, Mythril, solc-select, Semgrep, Halmos |
| **Rust / cargo** | 2 | builds heimdall-rs (via bifrost) |
| **Node.js / npm** | 3 | runs TronBox |
| **crytic-compile** | 8 | the compilation driver used by Slither / Echidna / Medusa (crytic toolchain); not called directly |

## Notes

- **Idempotent** — every step checks for an existing install; safe to re-run.
- **Overrides** — `SOLC_VERSIONS="…" TRON_SOLC_VERSIONS="…" bash bootstrap.sh`.
- **macOS** — GNU tools are `g`-prefixed (`gtimeout`, `gsed`); the TRON solc binaries are x86_64, so Apple Silicon runs them via Rosetta 2 (`softwareupdate --install-rosetta`).
- **TRON solc forks** — step 5 installs `0.4.25 0.5.8 0.5.17 0.6.12 0.7.6 0.8.18 0.8.22 0.8.25 0.8.26 0.8.27` by default and handles both release asset schemes (plain binary for ≥0.8.18, zip-with-codename for older, plus the irregular `0.4.25_Odyssey_v3.2.3` tag). Each lands as `~/.local/bin/tron-solc-<ver>`, which is exactly what `get-source.sh`'s `find_solc` looks for. Need another version? `TRON_SOLC_VERSIONS="0.6.13 0.8.20" bash bootstrap.sh`.
