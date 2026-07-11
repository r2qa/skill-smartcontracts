---
name: reviewing-smart-contracts
description: Use when reviewing, auditing, or security-checking a smart contract or protocol before sign-off — a single Solidity/Vyper contract or a whole repo, on EVM/TVM/TRON. Covers reentrancy, access control, oracle, bridge, proxy/upgrade, and DeFi-logic vulnerabilities. Triggers on "audit this contract", "review for vulnerabilities", "security review", smart-contract audit.
---

# Reviewing Smart Contracts

## Overview

A security review is **not done** until (a) the code builds and the analyzers have run, (b) every applicable item on both checklists has been walked, and (c) **every material finding has a reproducible test**. Reasoning is a hypothesis; a passing proof-of-issue test is a finding.

**Two rules that override every excuse:**
- **"Tool not installed" means install it, not skip it.** Abandoning static analysis / compilation because a binary is absent is the #1 failure mode.
- **No finding is "confirmed" without a passing PoC.** A missing PoC lowers a finding's *confidence/status* (mark it `Unproven`), not necessarily its impact×likelihood severity — demonstrate an unproven high/medium finding, or deliver it `Unproven` carrying the severity it would have if real, clearly flagged.

**Violating the letter of these gates is violating the spirit of the review.**

## Scope — two modes

- **Contract mode** — `scope` is one `.sol`/`.vy` file or contract. Review it directly, but still map its imports, callers, and the external contracts it trusts.
- **Protocol mode** — `scope` is a repo/directory. **Map the whole thing first** (inventory, inheritance/call graph, what's actually deployed vs dead code), then review component by component, highest value-at-risk first.

Detect the mode from what you're given; if a repo, default to protocol mode.

## The gates — do in order, do not skip

1. **Get source, then build to green.** For an on-chain target, fetch verified source FIRST: `tooling/get-source.sh <address>` pulls every `.sol` + the **exact compiler settings** (`compiler.json`) + ABI from TronScan's `POST /api/solidity/contract/info` (sends `TRON-PRO-API-KEY`), attests that the verified bytecode == on-chain bytecode (`attest=MATCH`), and caches by `code_hash`. `status=2` → you have the real deployed source (pin the compiler from `compiler.json`); `status≠2` → no source exists, drop to the **bytecode-only branch** below. Then detect toolchain (foundry.toml / hardhat.config / tronbox.js / truffle-config / vyper). Install and **pin** the exact compiler (`solc-select`/`svm`, or the TRON `tv_*` solc fork for TVM), install deps, compile. If it won't compile, fix that before reasoning — but **build fixes must never alter in-scope contract logic**; restrict them to toolchain/config/dependency/remapping fixes, and if a source edit is unavoidable, make it in a scratch copy or record it as a `*.patch` under `poc/` and disclose it, keeping the frozen baseline pristine.
2. **Static analysis (required).** Run `slither` + `aderyn` + `semgrep --config p/smart-contracts` **and `semgrep --config tooling/semgrep-tron/`** (the TRON/TVM-native ruleset — see `tooling/semgrep-tron/README.md`) (+ `mythril` on the highest-value contracts). Capture machine-readable output; triage every hit to true/false/needs-PoC. **A Semgrep match is a POINTER, never a finding** — the TRON rules are LOW/inventory by design; before writing anything up, trace the chain *entrypoint → access control → user data → checks → sink → financial impact* and prove it (gate 7). Record which tools ran, capturing exact versions to `evidence/tool-manifest.txt` (e.g. `forge --version; slither --version; aderyn --version; myth version; semgrep --version; solc --version`). **Legacy compilers:** for `solc <0.6`, some analyzers (e.g. `aderyn`) can't parse the AST — record the tool/version incompatibility as *not-covered* and lean on the analyzers that do work (slither handles 0.5.x); a genuine incompatibility is not the same as "gave up." **Known compiler bugs:** cross-reference the pinned version + the `compiler.json` settings (optimizer/runs/ABIEncoderV2/viaIR/evmVersion) against the [solc known-bugs list](https://docs.soliditylang.org/en/latest/bugs.html) — a vulnerable version is necessary but NEVER sufficient. Confirm all three: (1) exact vulnerable version range, (2) the enabling setting is actually set, (3) a reachable source construct that triggers it. Old TRON 0.4.x/0.5.x contracts are a high-value window (storage-overwrite / experimental-ABIEncoderV2 corruption / dirty-storage families).
3. **Map & trust boundaries.** Inventory contracts, entry points, **privileged roles** (owner/admin/governor/timelock/upgrader), external calls, oracles, callbacks, and delegatecall/proxy topology. Analyze **compromised-admin and oracle-manipulation paths**, not just external-attacker flows. **Backdoor / premeditation hunt:** a "verified" badge and a prior audit are NOT trust (both were clean on TronBank Pro, whose runtime carried a hidden trigger). Actively hunt any fund-moving/ownership function gated by an exact-equality on a weird hardcoded literal (a magic sentinel amount/address), and **pivot on the deployer** — enumerate the deployer's OTHER deployments and pre-production txs for a near-identical "rehearsal" contract or a magic-value sentinel tx; premeditated backdoors leave this on-chain footprint even when the source looks clean.
4. **Diff forks against pinned upstream.** If it's a fork (Compound/Uniswap/Maker/Chainlink/Polygon…), fetch the actual upstream at the closest commit and **diff line-by-line**; check the known-exploit list for that fork family. Never diff "from memory".
5. **Walk BOTH checklists in full** (see files below) — every applicable vulnerable-function pattern and every vulnerable call-chain.
6. **Invariants + fuzz.** Write protocol invariants explicitly and test them (Foundry invariant/property tests, Echidna/Medusa). Don't assert invariants narratively.
7. **Prove every material finding** with an executable PoC (Foundry/fork test that passes on the vulnerable code and fails after the fix). Flag each finding `proven` / `unproven`. The PoC should **exercise the REAL in-scope contract** whenever it compiles; fall back to a clearly-labelled `MODEL` reimplementation only when instantiating the real contract is impractical, and say so. For math-heavy or live-only issues, a **fuzzer/symbolic counterexample** (Echidna/Medusa/Halmos) or **`Empirically-proven-on-chain`** evidence (live tx history / state-reachability reads) also counts as proof. **TVM verification trap:** do NOT assert PoC correctness off TronBox event fields for *memory* (non-storage) variables — TronBox can render them `undefined`, silently PASSing an assertion against a WRONG emitted value; drive assertions off storage reads or decoded on-chain logs.
8. **Resolve contingent findings against real deployment data** — enumerate actually-listed markets/tokens/admin config from migrations/deploy scripts so "if X is configured" becomes a concrete yes/no.
9. **Mechanical checks over source-level claims** — e.g. prove proxy/implementation storage-layout equivalence with `solc --storage-layout`, not by reading; validate chain/VM assumptions (TVM energy/gas stipend, TRC-20 non-standard returns) against docs/tests. **For TRON/TVM scope specifically:** a stock-`solc` Foundry PoC models a recent EVM hardfork (solc/forge default to Cancun/Prague-era semantics), not the TVM — either build a TVM harness (`tronbox` test against Nile/Shasta) or explicitly label the PoC `EVM-model` and list the TVM-specific caveats (`.transfer` 2300-gas stipend, energy model, TRC-20 return quirks) that still need on-TVM confirmation.

**Source-unverified / bytecode-only targets.** When `get-source.sh` returns unverified (`status≠2`) — no source on TronScan (only deployed bytecode): substitute **gate 1** with disassembly/decompilation (`heimdall`; `panoramix` as a fallback decompiler; or match the runtime to canonical upstream by function selectors) plus a `code_hash` attestation (`keccak256(runtime) == on-chain code_hash`); mark source-AST analyzers (slither/aderyn/semgrep) **NOT covered** and run `mythril` on the bytecode instead (**gate 2**); **gate 4** diffs the *recovered* logic against canonical source; and **gate 7**'s PoC uses a clearly-labelled `MODEL` reimplementation, corroborated by read-only on-chain behavioral evidence.
> **TVM caveat (TRON):** `mythril`'s EVM symbolic engine aborts on TRON-specific opcodes (e.g. `0xd2`/`0xd3`) in the contract prologue and emits spurious findings *without ever reaching the target function*. On TVM, treat local disassembly + selector-mapping as **authoritative**, mark mythril `degraded / NOT covered`, and do not surface its prologue findings. (First strip/patch the TVM opcodes only if you specifically need symbolic coverage.)

## Hybrid tooling policy

For each tool: `command -v <tool>` → **present:** run it. **Absent but installable:** install it (`pipx install slither-analyzer`, `cyfrinup` for aderyn, `foundryup`, `solc-select install <v>`), then run. **Genuinely unavailable:** state it explicitly and mark that analyzer/PoC class as **NOT covered** — never present a manual-only pass as complete. A one-shot install of the whole toolchain is in `tooling/bootstrap.sh` (see the bundle).

> **API keys:** read-only TronGrid/TronScan calls (recon, `get-source.sh`, state reads) should send `TRON-PRO-API-KEY` from `~/.config/fearsoff/audit.env` (auto-sourced via `~/.zshenv`) — required for rate limits and for verified-source fetch. Verified `.sol` comes from TronScan's `POST /api/solidity/contract/info` (see gate 1 / `get-source.sh`), NOT from the node — a node gives bytecode/`code_hash` only.

> **macOS note:** GNU tools are `g`-prefixed via Homebrew coreutils — `timeout` is `gtimeout`, `sed` is `gsed`. Use the `g`-prefixed name (or `brew install coreutils` and add `gnubin` to PATH) rather than assuming GNU `timeout` exists.

## Red flags — STOP and fix

- "slither/solc/tronbox not installed, so I skipped it" → install it and run.
- "I reasoned about it but didn't test" → write the PoC, or mark `unproven` and downgrade.
- "diffed against upstream from memory" → fetch the pinned upstream and diff for real.
- "reviewed the external-attacker flow" (only) → also do compromised-admin + oracle manipulation.
- "storage layout matches" (by reading) → prove with `solc --storage-layout`.
- "it's verified on the explorer / it was audited" → **not trust.** Reproduce-and-match the runtime AND hunt magic-value backdoors + deployer-history rehearsal contracts (TronBank Pro shipped a backdoor under a clean-looking, "verified" source).
- Suppressed/ignored compiler warnings, or no Slither+Mythril in the project's CI → **readiness red flag** (TRON's secure-dev process treats unsuppressed warnings as a hard fail); surface unaddressed warnings as leads, not noise.
- **Rating an admin-only / by-design privileged power (owner can mint / pause / seize / upgrade) as a High/Critical *vulnerability*** → it isn't an exploit, it's a **centralization / trust-assumption** finding. Put it in its own class, name the actor, cap severity by the *trust model* (single-EOA/no-timelock = worse; multisig+timelock = often acceptable), and mark whether the client can `acknowledge — by design`. Every finding must name **who can trigger it**.
- All findings clustered at `low`/`info` with none proven → suspect surface-read anchoring: re-verify both checklists were fully walked and PoCs were attempted on the highest-value paths. A clean result *after* full, evidenced coverage is a valid outcome — never invent or inflate a finding to hit an expected severity.

## Checklists — walk every applicable item

- **[vulnerable-functions.md](vulnerable-functions.md)** — high-risk function patterns by contract type (token, access-control, lending, AMM/DEX, stablecoin, oracle, proxy/upgrade, bridge, liquid-staking, governance, signature, math, general, **tvm-native**) with the concrete check per function. **access-control, general, and tvm-native apply to every contract — always walk them (tvm-native = the TRON attack surface an EVM checklist misses: TRC-10 id confusion, SUN decimals, precompile divergence, CREATE2 0x41, staking opcodes, delegatecall token-context loss, 21-byte identity).**
- **[vulnerable-chains.md](vulnerable-chains.md)** — multi-step exploit compositions (reentrancy variants, flash-loan→oracle→borrow, share inflation, bridge-mint, governance takeover, signature replay, rounding drain, proxy takeover) with the invariant/guard whose presence blocks each.

## Deliverable layout & acceptance (client-ready)

**One directory per on-chain contract address:**

```
findings/<address>/          # <address> = Base58 T-form (source/repo-only findings may use a descriptive slug)
  report.md                  # filled from report-template.md — ONE address per report
  metadata.json              # address forms, network, code_hash, compiler, baseline, severity counts, finding IDs
  src-fetched/               # verified .sol + compiler.json + abi.json + bytecode.hex (get-source.sh writes here by default)
  poc/                       # Foundry project / scripts / *.patch — the dir run commands cd into
  evidence/                  # immutable read-only on-chain captures (TronGrid/TronScan JSON, disassembly)
  coverage.md                # gate-5/6 evidence: per-checklist-item disposition + invariant/fuzz-campaign table
```

**One directory holds EVERYTHING for a contract** — source, PoC, evidence, coverage, report all under `findings/<address>/`. `get-source.sh <address>` defaults its output to `findings/<address>/src-fetched/` for exactly this; keep all per-contract artifacts together there, nothing scattered elsewhere.

**`coverage.md`** makes gates 5–6 auditable: a table of every *applicable* checklist item → `pass` / `finding-ID` / `not-covered (+why)` (whole non-applicable sections may be dispositioned at the section level), plus an invariant/fuzz table (invariant · tool · runs/depth · held/broke · finding-ID).

> **Writing the deliverables:** these on-disk artifacts are **required, not optional**. Write them with your file-writing tool. If you are running as a subagent and a guardrail blocks writing report `.md` files (some harnesses instruct subagents to "return findings as text"), write them via a shell heredoc (`cat > report.md <<'EOF' … EOF`) instead — and also summarize the findings in your text reply.

Fill every report from **[report-template.md](report-template.md)**. A report is **not submittable** until it passes the acceptance checklist in that file — the load-bearing gates:
- Every finding has a **precise location** (`file:line:function`; + selector/offset for bytecode findings), pinned to the baseline commit.
- Every finding names its **actor / attacker role** (unprivileged / authorized-user / external-protocol / privileged-admin); privileged-only findings live in the **Centralization** section, not rated as unprivileged vulnerabilities.
- Every finding has explicit **Steps to reproduce / actions taken** (copy-pasteable; local-PoC vs read-only-on-chain separated; **no mainnet state-changing actions**).
- Every finding has a **PoC with the exact run command AND exact expected output**; `Proven` requires the PoC to **PASS on the vulnerable baseline** (demonstrating the exploit) and **FAIL/revert once the fix is applied**.
- Every **live-contract** finding has an on-chain **evidence block** (read-only method, live reads, behavioral evidence with real tx hashes) saved under `evidence/`.
- Every finding has a **recommended fix (unified diff / patch)** — or, for immutable contracts, the only viable mitigation.
- **Read-only attestation** present; nothing marked `Proven` without a passing PoC and a completed Verification note. **Human sign-off gates *delivery*, not the `Proven` label.**

## Execution mode & terminal state

- **Autonomous run:** gates 1–9 and report assembly are agent-closable. Independent verification, **human sign-off**, and delivery approval are human-only.
- The agent's terminal state is a **complete DRAFT** with `sign-off: pending` — never fill in a human's signature. `Proven` is set from a passing PoC + Verification note; it does not require sign-off.
- If a required capability is genuinely unavailable (offline/sandbox), stop after **one** install attempt, mark the affected gate `NOT covered`, and say so — do not loop on installs.

## Attacker role & finding class — classify BEFORE rating severity

Every finding names **who can trigger it** (the actor). The actor decides the *class*, and the class caps how it is rated — an admin-only capability is a trust assumption, not an exploit.

| Actor / role | Class | How to rate |
|---|---|---|
| **Unprivileged / anonymous** — any external address, no role | **Vulnerability** | Full severity rubric. The real exploit surface — rank these FIRST. |
| **Authorized user** — a legitimate participant acting on *others'* funds/state (any depositor, any veToken holder) | **Vulnerability** | Full rubric if it harms others or breaks an invariant. |
| **External protocol / config** — a third party or governance-set param you don't control (e.g. Tether enabling a fee) | **Conditional** | Severity gated on that precondition; state it (tie to gate 8). |
| **Privileged role** — owner/admin/minter/governance/upgrader | **Centralization / trust-assumption — NOT a vulnerability** | Report in its own section. Do NOT rate as an unprivileged High/Critical. Severity reflects the *trust model* (single-EOA/no-timelock = worse; multisig+timelock = often acceptable); mark whether the client can `acknowledge — by design`. *Latent* severity = the "key compromised / rogue admin" case. |

**Rank by actor reachability:** unprivileged > authorized-user > external-protocol/config > privileged-admin. If a protocol's only High/Critical items are admin-only, that is a **centralization** finding, not an exploitable one — say so plainly; never dress a by-design owner power up as a code bug (a Tether-style `issue()` under `onlyOwner` is expected — the *reportable delta* is the key custody: single-EOA vs multisig+timelock + immutability, not "issue() is vulnerable").

## Severity rubric

Applies to the **Vulnerability** class (unprivileged / authorized-user actor). Privileged-only findings use the Centralization class above, not this table.

| Level | Definition |
|---|---|
| Critical | Direct loss/seizure of funds by an **unprivileged or authorized** actor, no special preconditions |
| High | Loss of funds by an **unprivileged/authorized** actor under realistic, reachable conditions |
| Medium | Conditional loss, griefing, or value leak; needs specific state |
| Low | Best-practice / defense-in-depth; no direct loss path |
| Informational | Non-security or stylistic |
| Centralization | Privileged-role power / trust assumption — rated by trust model, may be `acknowledged — by design` |

**Inherited-but-contingent findings** (a fork deviation or upstream property that only fires under specific config, e.g. "only if a callback/hook token is listed"): set **likelihood from actual deployment data** (tie to gate 8 — enumerate the real listed tokens/config), not from the worst case; label the finding `inherited-from-upstream` or `fork-deviation`, and state the exact precondition. This pins down severity so two reviewers don't diverge High vs Medium on the same bug.

## Common mistakes (observed in unguided reviews)

- Treating "tool absent" as a stop condition instead of installing it.
- Findings reasoned but never driven in a PoC (everything `unproven`).
- Fork deviations compared from memory, not a real diff → planted changes slip through.
- Contingent findings left as "if a callback token is listed" without checking the actual deployment.
- Scope narrowed to external-attacker value flow; admin/oracle/governance surfaces skipped — where fork bugs actually live.
- Severity labels asserted without an explicit impact×likelihood rubric.

## Keep (good instincts to preserve)

Map before diving; review what's **deployed**, not what merely exists (spot dead code); enumerate every state-mutating entry point for guard coverage; separate fork-introduced changes from inherited behavior; keep honest `proven` vs `reasoned` hygiene.
