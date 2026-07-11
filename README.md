# reviewing-smart-contracts — a Claude Code skill for TRON/EVM smart-contract security review

A disciplined, tool-backed **audit skill** for [Claude Code](https://claude.com/claude-code). Point Claude at a contract address or a repo and it runs a repeatable, evidence-first review — build → static analysis → trust-boundary map → upstream diff → checklist walk → invariants/fuzz → **reproducible PoC** → deployment-data resolution → mechanical checks — and produces a client-ready, per-address report with a proof-of-issue test.

Works on **EVM and TVM/TRON** (Solidity + Vyper), a single contract or a whole protocol. It is deliberately strong on the **TRON attack surface an EVM checklist misses** (TRC-10 asset-id confusion, SUN decimals, precompile divergence, CREATE2 `0x41`, staking opcodes, delegatecall token-context loss, 21-byte identity).

> This repo is the **single source of truth** for the skill. Colleagues install once and `git pull` to update — no more passing tarballs around.

---

## Install

Clone directly into your Claude Code skills directory so `git pull` updates the live skill:

```bash
git clone git@github.com:r2qa/skill-smartcontracts.git ~/.claude/skills/skill-smartcontracts
```

Claude Code auto-discovers it (the skill's `name:` is `reviewing-smart-contracts`). It triggers on *"audit this contract"*, *"review for vulnerabilities"*, *"security review"*, or invoke it with `/skills`.

**Install the toolchain once per machine:**

```bash
bash ~/.claude/skills/skill-smartcontracts/tooling/bootstrap.sh
```

This installs solc-select + solc versions (+ the TRON `tv_` fork), Foundry, Slither, Aderyn, Semgrep + Decurity rules, **heimdall** (decompiler for unverified contracts), Mythril, Echidna/Medusa, TronBox, panoramix. Idempotent — safe to re-run.

**API keys (read-only rate-limit relief + verified-source fetch).** The bootstrap creates an empty template at `~/.config/fearsoff/audit.env`. Put your own **read-only** TronGrid + TronScan keys there and source it from `~/.zshenv`:

```sh
# ~/.config/fearsoff/audit.env
export TRONGRID_API_KEY="<your-trongrid-key>"    # https://www.trongrid.io  → API Keys
export TRONSCAN_API_KEY="<your-tronscan-key>"    # https://tronscan.org/#/myaccount/apiKeys
# ~/.zshenv
[ -f ~/.config/fearsoff/audit.env ] && source ~/.config/fearsoff/audit.env
```

The repo ships **no keys** — everyone uses their own. `.zshenv` (not `.zshrc`) is read by non-interactive shells, so subagents pick the keys up automatically.

**Update:** `cd ~/.claude/skills/skill-smartcontracts && git pull`.

---

## What's in here (what / where-from / why)

| Path | What it is | Why |
|---|---|---|
| `SKILL.md` | The skill itself: 9 non-negotiable gates, scope modes, hybrid-tooling policy, **actor/attacker-role classification**, severity rubric, red flags, deliverable + acceptance. | The entry point Claude loads. Encodes the *process* so reviews are consistent and evidence-first, not vibes. |
| `vulnerable-functions.md` | ~110 high-risk **function patterns** across 14 categories (token, access-control, lending, AMM/DEX, stablecoin, oracle, proxy, bridge, liquid-staking, governance, signature, math, general, **tvm-native**), each with a grep-able pattern + concrete check. | The "what to locate" checklist. `tvm-native` is the TRON delta EVM checklists miss. |
| `vulnerable-chains.md` | 52 multi-step **exploit compositions** (reentrancy variants, flash-loan→oracle→borrow, share inflation, bridge-mint, proxy takeover, governance, MEV, rounding, DoS, fake-TRC-10 drain…), each with the invariant/guard whose presence blocks it. | Bugs that only appear across functions. You confirm the guard *exists*, rather than trying to prove exploitability. |
| `report-template.md` | Client-acceptance-ready per-address report template with a pre-submission acceptance checklist, actor column, and a Centralization (§5b) section. | Standardizes deliverables so reports get accepted; separates real vulns from by-design centralization. |
| `tooling/bootstrap.sh` | One-shot workstation setup (compilers, analyzers, fuzzers, decompiler, TronBox, API-key template). | So the skill's "tool absent → install it" policy actually holds. |
| `tooling/get-source.sh` | Fetch a TRON contract's **verified source** (+ exact compiler settings + ABI) from TronScan's `POST /api/solidity/contract/info`, attest it against the on-chain runtime (`keccak256(runtime) == smart_contract.code_hash`), resolve **proxies** to their implementation, best-effort **recompile-match**, and cache by `code_hash`. Falls back to heimdall decompile when unverified. | The source-acquisition backbone. Makes reviews independent of trusting an explorer's "verified" badge. |
| `tooling/README.md` | Toolchain reference. | — |

### How the skill works (the 9 gates)

1. **Get source, then build to green** — `get-source.sh` fetches verified `.sol` + pinned compiler; `status≠2` → bytecode-only branch.
2. **Static analysis** — Slither/Aderyn/Semgrep (+ Mythril on high-value); triage every hit; cross-check the compiler-known-bugs list.
3. **Map & trust boundaries** — roles, external calls, oracles, proxy topology; compromised-admin + oracle paths; **backdoor/deployer-history hunt**.
4. **Diff forks vs pinned upstream** — line-by-line, never from memory.
5. **Walk both checklists** — every applicable function pattern + call-chain (`tvm-native` always).
6. **Invariants + fuzz** — explicit invariants, property/invariant tests.
7. **Prove every material finding** with a PoC (pass-on-vulnerable → fail-on-fix); fuzzer/symbolic counterexample or on-chain evidence also count.
8. **Resolve contingent findings against real deployment data** — turn "if X is configured" into a concrete yes/no.
9. **Mechanical checks** — storage-layout equivalence, TVM/VM assumptions.

### What it produces

One directory per contract address:

```
findings/<address>/
  report.md        # client-ready, from report-template.md (acceptance-gated)
  coverage.md      # per-checklist-item disposition + invariant/fuzz campaign
  metadata.json    # address forms, code_hash, compiler, severity counts, finding IDs
  poc/             # runnable Foundry PoC (+ fix .patch)
  evidence/        # read-only on-chain captures
```

---

## Why it's built the way it is (design decisions)

- **Evidence over assertion.** No finding is `Proven` without a reproducible PoC (pass on the vulnerable baseline → fail after the fix), a fuzzer/symbolic counterexample, or on-chain behavioral evidence. This kills the #1 LLM-audit failure mode: confident-but-wrong findings.
- **Actor/attacker role decides the class.** An admin-only power (owner can mint/pause/upgrade) is **not an exploit** — it's a Centralization/trust-assumption finding, rated by the trust model (single-EOA/no-timelock vs multisig+timelock), often `acknowledged — by design`. Every finding names *who can trigger it*; unprivileged findings rank first.
- **Realized vs latent severity, tied to live deployment.** A code-level bug not reachable on the current deployment is downgraded, with the precondition stated. This has repeatedly turned scary-looking "Critical" claims into their true severity.
- **Reproduce-and-match, don't trust the badge.** Source is authoritative only when `keccak256(runtime) == on-chain code_hash`; a verified badge and a prior audit are not trust (backdoors have shipped under clean-looking verified source).
- **TVM-native first-class.** TRON is EVM-bytecode-compatible but diverges in native-token channels, precompiles, opcode semantics, and address width — a dedicated `tvm-native` category and a fake-TRC-10 CRITICAL chain cover what EVM-derived checklists miss.
- **Bytecode-only branch.** Unverified contracts are reviewed from decompiled/selector-matched runtime with a `code_hash` attestation, not skipped.

## Provenance

Built and hardened with Claude Code via a test-driven process (baseline → skill → verify → refactor), reviewed adversarially, validated on a live canary (independently re-found a known Critical in an unverified TRON proxy from bytecode alone), and enriched by a 30-source deep-research pass over the leading smart-contract-security literature and incident post-mortems (methodology corpus: Trail of Bits *Building Secure Contracts*, EEA EthTrust, OWASP SCSVS, Secureum, SCSFG, and major hack post-mortems). See `CHANGELOG.md`.

## License

Add a license before public release (e.g. MIT). Report-template branding (`FEARSOFF`) can be genericized for external distribution if desired.

## Maintaining

Edit the files here, commit, push — colleagues `git pull`. Keep the `tooling/` scripts and `SKILL.md` gate references in sync. When adding checklist items, update the counts in the file headers.
