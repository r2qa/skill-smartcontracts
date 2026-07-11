# Smart Contract Security Review — `{{CONTRACT_ADDRESS_BASE58}}`

> **FEARSOFF** · Authorized defensive security review for **{{CLIENT_NAME}}** (TRON)
> Engagement: `{{ENGAGEMENT_ID}}` · Report version `{{REPORT_VERSION}}` · {{REPORT_DATE}}
> Classification: **CONFIDENTIAL — client delivery** · Distribution: {{DISTRIBUTION}}
>
> ⚠️ All **on-chain** interaction was **read-only** — no transaction was signed or broadcast to any public network, and nothing was exploited on mainnet. Local PoCs, patch files, and fork/EVM simulations run entirely off-chain. Every "Proven" finding carries a reproducible PoC; human reviewer sign-off gates delivery.

---

## 1. Contract identity (report key)

This report is keyed to a single on-chain contract address. One address = one `report.md`.

| Field | Value |
|---|---|
| **Address (Base58 / T-form)** | `{{CONTRACT_ADDRESS_BASE58}}` |
| **Address (hex, 0x41 / 41-form)** | `{{CONTRACT_ADDRESS_HEX41}}` |
| **Address (EVM 20-byte)** | `{{CONTRACT_ADDRESS_EVM20}}` |
| **Chain / network** | {{CHAIN}} (e.g. TRON mainnet, chainId `0x2b6653dc` / Nile / Shasta) |
| **Contract name** | {{CONTRACT_NAME}} |
| **Source verified on explorer?** | {{SOURCE_VERIFIED}} (Yes / No — logic recovered by bytecode disassembly) |
| **Compiler** | {{COMPILER}} (e.g. solc 0.6.8 / tronprotocol solc fork / vyper 0.3.x) |
| **Runtime code_hash** | `{{CODE_HASH}}` |
| **Proxy?** | {{IS_PROXY}} (No / Transparent / UUPS / Unitroller-delegate → impl `{{IMPL_ADDRESS}}`) |
| **Deployer** | `{{DEPLOYER_ADDRESS}}` |
| **Creation tx** | `{{CREATION_TX}}` |
| **Owner / admin (live)** | `{{OWNER_ADDRESS}}` ({{OWNER_TYPE}} — EOA / multisig / timelock) |
| **Upstream lineage** | {{UPSTREAM}} (e.g. Compound v2 @ `cce8c88`, Uniswap V3, Wyvern+0x) |
| **Live value-at-risk / TVL band** | {{TVL_BAND}} |
| **Review baseline commit (source)** | `{{BASELINE_COMMIT}}` in `{{REPO}}` |
| **Explorer link** | {{EXPLORER_URL}} |

**Bytecode-to-source attestation.** {{ATTESTATION}}
State here whether the reviewed source matches the deployed runtime, and how it was proven — e.g. "`keccak256(runtime)` equals the on-chain `code_hash` `{{CODE_HASH}}`" for verified/recovered source, or "source unverified; logic recovered by local disassembly and matched to canonical `{{UPSTREAM}}`; confidence {{CONFIDENCE}}."

---

## 2. Executive summary

{{EXECUTIVE_SUMMARY}}
2–5 sentences: what the contract is, what was reviewed, the headline result, and the single most important action for the client. If a **Critical/live** issue exists, lead with it and the required user action (e.g. "affected approvers must revoke").

**Findings by severity**

| Severity | Count | Open | Acknowledged | Fixed-verified |
|---|---|---|---|---|
| Critical | {{N_CRIT}} | {{N_CRIT_OPEN}} | {{N_CRIT_ACK}} | {{N_CRIT_FIXED}} |
| High | {{N_HIGH}} | {{N_HIGH_OPEN}} | {{N_HIGH_ACK}} | {{N_HIGH_FIXED}} |
| Medium | {{N_MED}} | {{N_MED_OPEN}} | {{N_MED_ACK}} | {{N_MED_FIXED}} |
| Low | {{N_LOW}} | {{N_LOW_OPEN}} | {{N_LOW_ACK}} | {{N_LOW_FIXED}} |
| Informational | {{N_INFO}} | {{N_INFO_OPEN}} | {{N_INFO_ACK}} | {{N_INFO_FIXED}} |
| **Total** | **{{N_TOTAL}}** | {{N_OPEN}} | {{N_ACK}} | {{N_FIXED}} |

**Findings index**

| ID | Title | Severity | Actor | Status | Proven? | Live? |
|---|---|---|---|---|---|---|
| {{ID-01}} | {{TITLE}} | {{SEV}} | {{ACTOR}} | {{STATUS}} | {{PROVEN}} | {{LIVE}} |
| {{ID-02}} | {{TITLE}} | {{SEV}} | {{ACTOR}} | {{STATUS}} | {{PROVEN}} | {{LIVE}} |

Actor = `unprivileged` / `authorized-user` / `external-protocol` / `privileged-admin`. Privileged-admin items are **Centralization** findings (§5b), not unprivileged vulnerabilities.

---

## 3. Scope, methodology & coverage

- **In scope.** Address `{{CONTRACT_ADDRESS_BASE58}}` and its source at baseline `{{BASELINE_COMMIT}}`. Files: {{FILES_IN_SCOPE}}.
- **Out of scope.** {{OUT_OF_SCOPE}} (e.g. off-chain relayers, front end, governance social layer, economic/oracle assumptions unless stated).
- **Method.** {{METHOD}} — whitebox source review + upstream-diff against `{{UPSTREAM}}`, static analysis (Slither/Aderyn/Semgrep/Mythril), property/invariant reasoning, Foundry proof-of-issue tests, and read-only on-chain state/bytecode verification via TronGrid/TronScan. See `../../methodology.md`.
- **TRON/TVM specifics considered.** Non-standard TRC-20 return values (USDT), 21-byte `0x41` addresses, Energy/Bandwidth vs gas, `tronprotocol` solc fork, forge-runs-EVM-not-TVM caveats.
- **Coverage statement.** {{COVERAGE}} — what was tested, what remains **unproven**, and residual risk.
- **Limitations.** Time-boxed review; not a guarantee of absence of all bugs. Findings reference the frozen baseline; later changes are not covered.

---

## 4. Severity methodology

**Classify each finding by ACTOR first — this sets the class and caps the rating.**
- **Unprivileged / authorized-user** (any external address, or any legitimate participant acting on others' funds/state) → a real **Vulnerability**; rate on the matrix below.
- **External-protocol / config** (a third party or governance-set param you don't control, e.g. Tether enabling a fee) → **Conditional**; severity gated on that precondition (tie to the deployment data).
- **Privileged-role** (owner/admin/minter/governance/upgrader) → **Centralization / trust-assumption**, NOT an unprivileged vulnerability. List it in **§5b**, rate by the *trust model* (single-EOA / no-timelock = worse; multisig + timelock = often `acknowledged — by design`); the *latent* case is key-compromise / rogue-admin. Do not dress a by-design owner power (e.g. Tether-style `issue()` under `onlyOwner`) up as a code vulnerability — the reportable delta is the key custody, not the power's existence.

Within the **Vulnerability** class: Severity = **Impact × Likelihood**, then adjusted to *realized* severity by live deployment facts (a code-level bug not reachable on the current deployment is downgraded, with the precondition stated explicitly).

**Likelihood × Impact matrix**

| Impact \ Likelihood | High | Medium | Low |
|---|---|---|---|
| **High** | Critical | High | Medium |
| **Medium** | High | Medium | Low |
| **Low** | Medium | Low | Informational |

**Severity definitions**

- **Critical** — Direct, likely loss/lockup of user or protocol funds, unauthorized mint, or bridge/lending insolvency reachable by an unprivileged actor under realistic conditions. Requires a reproducible PoC.
- **High** — Significant fund risk or integrity breach requiring a specific but attainable precondition, or a privileged-role compromise with outsized blast radius.
- **Medium** — Limited/conditional loss, temporary DoS of a core function, bounded accounting/rounding error, or an access-control gap mitigated by trust assumptions.
- **Low** — Minor deviations with small/improbable impact: tight-margin rounding still favoring the pool, DoS needing unrealistic conditions, missing event, non-independently-exploitable defense-in-depth gaps.
- **Informational** — No direct security impact: code quality, gas/Energy optimization, TRON-portability notes, style, NatSpec, best practice.
- **Centralization** — a privileged-role power / trust assumption (owner can mint, pause, seize, upgrade). Rated by the trust model, not the Impact×Likelihood matrix; may be `acknowledged — by design`. Reported in §5b, not counted as an unprivileged vulnerability.

**Status values:** `Open` · `Acknowledged` · `Fixed-verified` · `Fixed-incomplete` · `Disputed`
**Proven status:** `Proven` (reproducible PoC that PASSES on the vulnerable baseline and FAILS/reverts after the fix) · `Unproven` (hypothesis / static observation without an executable PoC) · `Empirically-proven-on-chain` (live tx history, or state/config/reachability reads, establish the behavior). A fuzzer/symbolic counterexample (Echidna/Medusa/Halmos) also qualifies as `Proven`.

---

## 5. Detailed findings

> For **every** finding, all fields below are **mandatory**. Do not delete a heading — if it does not apply, write "N/A" and say why. A finding may not be marked `Proven` without a passing PoC and a completed Verification note.

---

### {{ID-01}} — [{{SEVERITY}}] {{TITLE}}

| | |
|---|---|
| **Finding ID** | {{ID-01}} |
| **Severity (realized)** | {{SEVERITY}} — Impact: {{IMPACT_RATING}} · Likelihood: {{LIKELIHOOD_RATING}} |
| **Severity (latent/max)** | {{LATENT_SEVERITY}} (if precondition ever met — else "same") |
| **Status** | {{STATUS}} |
| **Proven?** | {{PROVEN_STATUS}} |
| **Live contract?** | {{LIVE}} (Yes → on-chain evidence required below) |
| **Actor / attacker role** | {{ACTOR}} — `unprivileged` / `authorized-user` / `external-protocol` / `privileged-admin`. If `privileged-admin`, move this to §5b (Centralization) and rate by trust model. |
| **Class / Category** | {{CATEGORY}} (e.g. access-control) · **Checklist** {{CHECKLIST_REF}} · **SWC** {{SWC_ID}} *(legacy map, optional — SWC frozen since 2020; prefer EthTrust/SCSVS)* |
| **Invariant violated** | {{INVARIANT}} |

**Precise location**
- File: `{{FILE_PATH}}` · lines `{{LINE_RANGE}}` · function `{{FUNCTION}}({{SIGNATURE}})`
- On-chain: selector `{{SELECTOR}}` · runtime offset `{{OFFSET}}` (for bytecode-level findings)
- Baseline commit: `{{BASELINE_COMMIT}}`

**Description (root cause)**
{{DESCRIPTION}}
Explain the defect and *why* it is wrong. For fork deviations, show the upstream-safe code vs the forked code. Include a minimal code excerpt:

```solidity
{{CODE_EXCERPT}}
```

**Impact**
{{IMPACT}}
Who loses what, how much, and under what conditions. Quantify the blast radius (bounded by `min(allowance, balance)`, per-market, protocol-wide, etc.).

**Preconditions / assumptions**
{{PRECONDITIONS}}
Everything that must hold for exploitation (token type, empty market, ordering, privileged key, outstanding approval). If none, write "None — permissionless."

**Steps to reproduce / actions taken**
Exact, ordered, copy-pasteable steps. Distinguish **local PoC** steps from **read-only on-chain** actions. Never include steps that change mainnet state.
1. {{STEP_1}}
2. {{STEP_2}}
3. {{STEP_3}}

**Proof of Concept**
- Location: `poc/{{POC_FILE}}`
- Type: {{POC_TYPE}} (Foundry test against real contract / faithful model / read-only on-chain script)
- **Run command** (exact):
  ```bash
  cd findings/{{CONTRACT_ADDRESS_BASE58}}/poc && {{RUN_COMMAND}}
  ```
- **Expected output** (exact, paste the asserting line(s)):
  ```
  {{EXPECTED_OUTPUT}}
  ```
  e.g. `[PASS] test_vuln_unauthenticated_drain — attacker drained victim balance=... ; UNBACKED BAD DEBT=40e18`
- **PoC caveats:** {{POC_CAVEATS}} (IRM set to zero for readable arithmetic; forge-EVM vs TVM differences; only underlyings/attacker are scaffolding; real target contracts used via remapping).

**On-chain evidence** *(mandatory for live contracts; "N/A — not deployed / source-only" otherwise)*
- **Method (read-only only):** {{ONCHAIN_METHOD}} — e.g. TronGrid `POST /wallet/triggerconstantcontract` (constant calls), `/wallet/getcontract` + `/wallet/getcontractinfo` (runtime bytecode), TronScan `GET /api/contract` + `/api/token_trc20` (proxy/impl + token metadata), `/wallet/gettransactionbyid` (tx confirmation). A throwaway `owner_address` used only to satisfy the constant-call schema is never signed or broadcast.
- **Live constant reads:** {{LIVE_READS}} (e.g. `owner()=... DELAY_PERIOD()=... getProxyId()=...`)
- **Behavioral evidence** *(where historical transactions exist; for a novel/unexploited bug write "N/A — no historical exploit txs; reachability shown via the state/config reads above")*: {{ONCHAIN_BEHAVIOR}} (e.g. "544 `transferFrom` txns, all from non-authenticated callers, 490 succeeded — impossible if the auth gate existed"). Cite tx hashes: `{{TX_HASHES}}`.
- **Evidence artifacts:** `evidence/{{EVIDENCE_FILES}}` (raw JSON responses, disassembly, tx dumps).
- **Data confidence:** {{DATA_CONFIDENCE}} (High/Medium + residual uncertainty).

**Recommended fix**
{{FIX_NARRATIVE}}
Concrete change + the exact test that must pass after the fix. Provide a diff:

```diff
{{FIX_DIFF}}
```

Patch file: `poc/{{PATCH_FILE}}` — applies with:
```bash
git -C {{REPO}} apply findings/{{CONTRACT_ADDRESS_BASE58}}/poc/{{PATCH_FILE}}
```
If the contract is immutable/non-upgradeable, state the **only** available mitigation (e.g. users revoke approvals; redeploy fixed instance; migrate).

**Verification note**
{{VERIFICATION_NOTE}}
Record the adversarial verification: what refutation attempts were made and failed, that the PoC flips PASS→FAIL after the fix, that on-chain reads were independently re-run, and the reviewer's judgment. State residual uncertainty honestly.
- PoC on baseline: {{RESULT_BASELINE}} · PoC after fix: {{RESULT_AFTER_FIX}}
- Independent reviewer: `{{VERIFIER}}` · sign-off: {{SIGNOFF_STATUS}}

**References**
{{REFERENCES}} — SWC entry, upstream source/commit, related CVEs/incidents, prior audits.

---

*(Repeat section 5 per finding, most-severe first.)*

---

## 5b. Centralization & trust-assumption risks

> Powers that require a **privileged role** (owner/admin/minter/governance/upgrader) — NOT unprivileged exploits. Listed separately so they are not read as code vulnerabilities. Rate each by the **trust model**, state the **latent** (key-compromise / rogue-admin) case, and mark whether the client can `acknowledge — by design`.

| ID | Privileged power | Role holder (live) | Trust model | Value at risk | Latent severity | Disposition |
|---|---|---|---|---|---|---|
| {{C-01}} | {{POWER}} (e.g. unbounded `issue()` mint) | `{{ROLE_ADDR}}` ({{ROLE_TYPE}} — EOA / multisig N-of-M / timelock) | {{TRUST_MODEL}} | {{VALUE}} | {{LATENT}} | Open / `acknowledged — by design` |

For each row: the *reportable delta* is the **key custody**, not the power's existence — a single-EOA / no-timelock holder over large value is the finding; a multisig+timelock holder is often acceptable. Recommend: migrate the role to **N-of-M multisig behind a timelock**, and (where applicable) an on-chain proof-of-reserves / mint-authorization control. Note contract immutability (no on-chain fix → operational mitigation only).

---

## 6. Appendix A — Tooling & versions

Record the exact tool manifest used (captured to `evidence/tool-manifest.txt` during gate 2).

| Tool | Version | Purpose |
|---|---|---|
| Foundry (forge/cast/anvil) | {{FORGE_VERSION}} | PoC tests, fork sim |
| Slither | {{SLITHER_VERSION}} | static analysis |
| Aderyn | {{ADERYN_VERSION}} | static analysis |
| Mythril | {{MYTH_VERSION}} | symbolic analysis |
| Semgrep | {{SEMGREP_VERSION}} | pattern rules |
| Echidna / Medusa | {{FUZZ_VERSION}} | fuzzing/invariant |
| Halmos | {{HALMOS_VERSION}} | symbolic tests |
| solc-select / vyper | {{SOLC_VYPER}} | compilers |
| TronGrid / TronScan API | read-only | on-chain evidence |

## 7. Appendix B — Status & severity definitions

(See §4. Reproduce the rubric here for standalone readability.)

## 8. Appendix C — On-chain evidence method (read-only attestation)

{{ONCHAIN_METHOD_FULL}}
Full description of every read-only endpoint used, and an explicit statement: "No transaction was built, signed, or broadcast; no state was changed; no funds moved."

## 9. Acceptance checklist (pre-submission gate)

A report is **not submittable** until every box is checked (or explicitly N/A with reason):

- [ ] Keyed to exactly ONE contract address; all address forms + `code_hash` + compiler + baseline recorded in §1 and `metadata.json` (which agrees with this report).
- [ ] Bytecode-to-source attestation present (keccak256(runtime)==code_hash, or recovery method + confidence stated).
- [ ] Executive summary leads with any Critical/live issue and the required client/user action; severity table and index reconcile with the detailed findings.
- [ ] EVERY finding has: precise location (file:line:function, + selector/offset for bytecode) pinned to baseline; explicit **Steps to reproduce / actions taken** (copy-pasteable, local-PoC vs read-only separated, **no mainnet state changes**); a **PoC with exact run command AND exact expected output**; a recommended fix (diff/patch) or the only mitigation; a completed Verification note; and an explicit `Proven`/`Unproven`/`Empirically-proven-on-chain` status.
- [ ] Every `Proven` finding: PoC PASSES on baseline and FAILS after the fix patch (or a fuzzer/symbolic counterexample).
- [ ] Every live-contract finding: on-chain **evidence block** (read-only method + live reads; behavioral tx evidence where it exists) with artifacts under `evidence/`.
- [ ] `coverage.md` present: every applicable checklist item dispositioned; invariant/fuzz campaign recorded.
- [ ] `poc/` compiles and runs cleanly from a fresh checkout; any patch applies cleanly to the pinned baseline; working tree left clean.
- [ ] Read-only attestation present; `sign-off: pending` in an autonomous run (agent never fills a human signature).

## 10. Disclaimer

This report reflects a time-boxed review of the code and on-chain state at the stated baseline and dates. It is not an endorsement or a guarantee that the code is free of vulnerabilities. Findings should not be considered a comprehensive list of all issues. FEARSOFF performed all analysis on a read-only basis under an authorized engagement with {{CLIENT_NAME}}.

## 11. Sign-off

| Role | Name | Date | Signature |
|---|---|---|---|
| Lead reviewer | {{LEAD}} | {{DATE}} | |
| Independent verifier | {{VERIFIER}} | {{DATE}} | |
| Delivery approved | {{APPROVER}} | {{DATE}} | |
