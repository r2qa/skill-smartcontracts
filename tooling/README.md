# Audit workstation tooling

> One-time bootstrap for the TRON/EVM smart-contract audit workflow. Run: `bash tooling/bootstrap.sh`


## Compilers & Version Management

- **solc-select** — Manage and pin multiple vanilla Ethereum solc versions (0.5.x/0.6.x/0.7.x/0.8.x) so Slither/Mythril/crytic-compile compile each audited codebase with its exact pragma version.  
  verify: `solc-select versions && solc --version`
- **TRON solidity fork (tv_ solc)** — TRON's official Solidity compiler fork (tronprotocol/solidity, tags tv_0.4.24..tv_0.8.27). Required for byte-accurate TVM compilation/verification: TRON adds TRX/energy builtins and gates opcodes by TRON network upgrades (e.g. Cancun opcodes via GreatVoyage v4.8.x), so vanilla solc output does not match on-chain TVM bytecode.  
  verify: `tron-solc --version   # version string carries the .mod marker, e.g. 0.8.x+commit.<hash>.mod`

## Build, Test & Compilation Frameworks

- **Foundry (forge/cast/anvil/chisel)** — Primary EVM audit harness: forge for PoC tests/exploit repros, cast for RPC/ABI/storage inspection of live contracts, anvil for local mainnet-fork testing of findings.  
  verify: `forge --version && cast --version && anvil --version`
- **TronBox** — TRON's Truffle-derived framework: compiles with the tv_ solc fork, deploys/migrates to Nile/Shasta testnets or TronGrid mainnet — used to reproduce client build artifacts and validate TVM behavior of findings.  
  verify: `tronbox version`
- **crytic-compile** — Unified compilation driver (standalone + used internally by Slither/Echidna/Medusa); normalizes Foundry/Hardhat/Truffle/solc builds into one artifact format so every analyzer sees identical compilation units.  
  verify: `crytic-compile --version`

## Static Analysis

- **Slither** — Baseline static analyzer (90+ detectors) plus audit printers (call graph, storage layout, upgradeability checks); its findings seed the standardized issue list in the report.  
  verify: `slither --version`
- **Semgrep + Decurity smart-contract rules** — Pattern-based scanning with the Decurity ruleset built from real DeFi exploits (proxy storage collisions, arbitrary delegatecall, ERC-2771/Multicall spoofing) plus gas/performance rules; complements Slither with exploit-derived signatures.  
  verify: `semgrep --version && semgrep --config ~/audit-tools/semgrep-smart-contracts/solidity/security --metrics=off --quiet /dev/null; test -d ~/audit-tools/semgrep-smart-contracts/solidity`
- **Aderyn (via cyfrinup)** — Rust-based Solidity AST analyzer from Cyfrin; fast second-opinion scanner whose markdown report output slots directly into deliverable appendices. cyfrinup is Cyfrin's cross-platform tool manager (re-run it to upgrade).  
  verify: `aderyn --version`

## Symbolic Execution & Fuzzing

- **Mythril** — Symbolic-execution engine (z3-backed) for reachability of integer overflows, unprotected selfdestruct/delegatecall, and assertion violations; also analyzes raw deployed bytecode, which pairs with heimdall on unverified TRON contracts.  
  verify: `myth version`
- **Echidna** — Property-based fuzzer (Haskell, Trail of Bits) for invariant testing of audited contracts; standard evidence generator for 'we fuzzed invariant X for N iterations' claims in reports.  
  verify: `echidna --version`
- **Medusa** — Parallelized coverage-guided mutational fuzzer (go-ethereum based) — faster corpus-driven complement to Echidna, shares crytic-compile targets and assertion/property test styles.  
  verify: `medusa --version`

## Decompilers for UNVERIFIED contracts (key gap closed)

- **heimdall-rs (via bifrost)** — PRIMARY decompiler for unverified contracts: `heimdall decompile` reconstructs Solidity-like source + ABI from raw TVM/EVM runtime bytecode; also `disassemble`, `cfg`, `dump` and calldata `decode`. Essential when TRON targets or their dependencies (delegatecall targets, proxy implementations) have no verified source on Tronscan.  
  verify: `heimdall --version`
- **panoramix (fallback decompiler)** — Second-opinion decompiler (engine behind Eveem/Oko): storage-layout-centric pseudo-Python output that often recovers mappings/arrays heimdall renders opaquely; run both and diff interpretations before asserting behavior of unverified bytecode.  
  verify: `panoramix --help`

## API keys (higher read-only rate limits)

- TronGrid: create an account at https://www.trongrid.io -> Dashboard -> API Keys -> Add. Keys grant 15 QPS within daily quota; keyless mainnet requests get dynamic throttling with 30s penalty bans (HTTP 403/429). Shasta/Nile testnets do not require a key.
- Tronscan: log in at https://tronscan.org/#/developer/api -> API Keys -> Add (optionally enable JWT auth + origin whitelist). Since 2025-08-31 Tronscan no longer guarantees QPS without a key, and contract-search/proxy endpoints return 401 keyless — a key is effectively mandatory for audit tooling.
- Both services use the SAME HTTP header name: TRON-PRO-API-KEY. TronGrid example: curl -s -H "TRON-PRO-API-KEY: $TRONGRID_API_KEY" https://api.trongrid.io/wallet/getnowblock. Tronscan example: curl -s -H "TRON-PRO-API-KEY: $TRONSCAN_API_KEY" "https://apilist.tronscanapi.com/api/contract?contract=<T-addr>".
- The bootstrap writes ~/.config/fearsoff/audit.env (chmod 600) exporting TRONGRID_API_KEY, TRONSCAN_API_KEY, endpoint URLs (TRONGRID_MAINNET/NILE/SHASTA, TRONSCAN_API) and WEB3_PROVIDER_URI (needed by panoramix for by-address decompilation), and sources it from the shell profile. Fill in the two empty key values after running the script; never commit this file.
- TronWeb usage: new TronWeb({ fullHost: 'https://api.trongrid.io', headers: { 'TRON-PRO-API-KEY': process.env.TRONGRID_API_KEY } }). Keep polling ≤1 req/3s per endpoint (TRON block time) to stay under limits during long enumeration jobs.

_Script written to /Users/gg/Documents/work/tron-web3/bootstrap.sh; passed `bash -n`, and the GitHub release-asset helper plus set -u empty-array handling were smoke-tested live. All install paths were grounded via web research (July 2026) and live GitHub API checks. Key facts verified: (1) TRON solc fork lives at tronprotocol/solidity with tags tv_0.4.24..tv_0.8.27 (latest tv_0.8.27, release name 0.8.27_Democritus_v4.8.1) shipping assets solc-static-linux / solc-macos / soljson.js with GPG .sig files; historical binaries also in tronprotocol/solc-bin under linux-amd64|macosx-amd64 as solc-<platform>-v<ver>+commit.<hash>; TRON builds carry a ".mod" version marker. (2) heimdall-rs installs via bifrost (official one-liner curl -L http://get.heimdall.rs | bash; script uses the equivalent https raw-GitHub URL) and compiles from source, hence the Rust step. (3) Aderyn's current manager is Cyfrin/up (curl .../Cyfrin/up/main/install | bash, then run cyfrinup); installs to ~/.cyfrin/bin. (4) Echidna v2.3.2 assets: echidna-<ver>-{x86_64,aarch64}-{linux,macos}.tar.gz; Medusa v1.5.1 assets: medusa-linux-x64/mac-arm64; both also on Homebrew, Medusa also via `go install github.com/crytic/medusa@latest`. (5) Decurity rules: github.com/Decurity/semgrep-smart-contracts (solidity/security + solidity/performance; Solidity support in Semgrep is experimental; taint rules need --pro). (6) TronGrid and Tronscan both use header TRON-PRO-API-KEY; TronGrid keyed = 15 QPS in-quota, keyless = 403 penalty bans; Tronscan made keys effectively mandatory after 2025-08-31. Caveats: solc <0.8.24 and TRON solc-macos are x86_64-only (Rosetta 2 on Apple Silicon); Mythril pinned to Python 3.10-3.12 via pipx with a documented Docker (mythril/myth) fallback for z3 build failures; Vyper coverage was not requested per-tool but Slither/Semgrep/Foundry handle Vyper targets — add `pipx install vyper` if the engagement includes Vyper sources. Script is re-runnable: every step is guarded, profile edits are grep-guarded, and audit.env is never overwritten. Sources: github.com/tronprotocol/solidity/releases, github.com/tronprotocol/solc-bin, github.com/Jon-Becker/heimdall-rs, github.com/Cyfrin/up, github.com/Cyfrin/aderyn, github.com/Decurity/semgrep-smart-contracts, github.com/crytic/{echidna,medusa,slither,crytic-compile}, github.com/palkeo/panoramix (pypi panoramix-decompiler), mythril-classic.readthedocs.io, developers.tron.network/reference/{api-key,rate-limits}, docs.tronscan.org, support.tronscan.org._

## get-source.sh — verified-source fetcher (audit source-acquisition)
`bash tooling/get-source.sh <T-address> [outdir]` — pulls a contract's VERIFIED `.sol` (all files),
exact compiler settings (`compiler.json`), and ABI from TronScan's `POST /api/solidity/contract/info`
(needs `TRON-PRO-API-KEY`), attests verified-bytecode == on-chain bytecode, and caches by `code_hash`.
`status=2` → real source; `status≠2` → unverified (saves bytecode → use the skill's bytecode-only branch / heimdall).
