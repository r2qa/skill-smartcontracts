# Checklist IDs & standards crosswalk

Two things: a **stable ID scheme** so findings/reports cite exact checklist items and `coverage.md` is mechanically checkable, and a **crosswalk** from this skill's coverage to OWASP SCSVS and EEA EthTrust.

## 1. Stable checklist ID scheme (drop-in)

IDs are **derived**, not stored: compute an item's ID from its section and position, so no bulk renumbering or editing of the checklist files is required.

### Naming rules

**Vulnerable-functions items → `VF-<SECTION>-NN`**
- `<SECTION>` is the fixed short token for the `##` section the item lives under (table below). One token per `##` heading; never reused.
- `NN` is the 2-digit, 1-based ordinal of the item within that section, counting `###` entries top-to-bottom.
- "Additional coverage (extended checklist)" bullets get suffix `-Xnn` (e.g. `VF-GEN-X01`) so appended bullets never collide with numbered `###` items.

**Vulnerable-chains items → `VC-<FAMILY>-NN`**
- The italic family tag already printed on each chain (`_reentrancy_`, `_flash-loan_`, `_bridge-mint_`, …) is the stable key — severity can change, family rarely does.
- `<FAMILY>` is the fixed short token for that tag; `NN` is the 2-digit ordinal of the chain within that family, in document order.

**Section / family tokens (fixed):**

| VF section (`##`) | token | | VF section (`##`) | token |
|---|---|---|---|---|
| token | `TOKEN` | | governance | `GOV` |
| access-control | `AC` | | signature | `SIG` |
| lending | `LEND` | | math | `MATH` |
| AMM-DEX | `AMM` | | general | `GEN` |
| stablecoin | `STABLE` | | erc4626-vault | `VAULT` |
| oracle | `ORACLE` | | staking-rewards | `STAKE` |
| proxy-upgrade | `PROXY` | | perps-derivatives | `PERP` |
| bridge | `BRIDGE` | | account-abstraction-4337 | `AA` |
| liquid-staking | `LST` | | eip-7702 | `7702` |
| tvm-native | `TVM` | | intents-solvers | `INTENT` |
| cross-chain-messaging | `XCHAIN` | | modular-proxy-diamond | `DIAMOND` |

| VC family tag | token | | VC family tag | token |
|---|---|---|---|---|
| _reentrancy_ | `REENT` | | _share-inflation_ | `SHARE` |
| _flash-loan_ | `FLASH` | | _signature-replay_ | `SIG` |
| _governance_ | `GOV` | | _rounding-drain_ | `ROUND` |
| _access-escalation_ | `ACCESS` | | _oracle-manipulation_ | `ORACLE` |
| _bridge-mint_ | `BRIDGE` | | _account-abstraction_ | `AA` |
| _upgrade_ | `UPGRADE` | | _MEV_ | `MEV` |
| _asset-confusion_ | `ASSET` | | _DoS_ | `DOS` |

**Stability rules (so IDs never silently shift):**
1. **Append-only.** New items are added at the end of their section/family and take the next ordinal. Never insert in the middle (that renumbers everything below).
2. **Retire, don't reuse.** A deleted item's ID is retired permanently; never reassign it.
3. **Re-title freely.** Renaming an item's `###` heading does not change its ID (ID = section + position, not title text).
4. Namespaces are disjoint: `VF-*` never collides with `VC-*`; `VF-BRIDGE-*` (functions) is distinct from `VC-BRIDGE-*` (bridge-mint chains).

### How to reference an ID

**In a report finding** — cite the driving IDs (most-specific first, VF then VC): the `VF-*` item(s) whose "Verify" step failed, plus any `VC-*` chain whose "Blocked by" guard was found absent.

```
| **Class / Category** | oracle · **Checklist** VF-ORACLE-02, VC-ORACLE-04 · **SWC** SWC-107 (legacy) |
```

**In `coverage.md`** — one row per applicable checklist ID so coverage is provable:

```markdown
| Checklist ID | Item | Applicable? | Disposition | Evidence / Finding |
|---|---|---|---|---|
| VF-TOKEN-01 | transfer/transferFrom | Yes | Pass — SafeERC20, balance-delta measured | tests/token.t.sol |
| VF-TVM-01 | msg.tokenid check | Yes | Pass — require(tokenid==EXPECTED) | evidence/tokenid.json |
| VC-BRIDGE-02 | proof replay double-mint | N/A | Not a bridge | — |
```
Disposition: `Pass` / `FAIL` (→ links a finding ID) / `N/A` (state why) / `Unproven`. Every ID whose section applies to the target type MUST appear with a non-blank disposition.

## 2. Standards crosswalk → OWASP SCSVS & EEA EthTrust

### Verified standard structure

**OWASP SCSVS** — the post-2024/2025 refactor under the OWASP Smart Contract Security (SCS) project: **11 control groups**, labelled by code (`SCSVS-XXXX`) and by `S1…S11`:

| # | Code | Title (verbatim) |
|---|---|---|
| S1 | `SCSVS-ARCH` | Architecture, Design, and Threat Modeling |
| S2 | `SCSVS-CODE` | Policies, Procedures, and Code Management |
| S3 | `SCSVS-GOV` | Business Logic and Economic Security |
| S4 | `SCSVS-AUTH` | Access Control and Authentication |
| S5 | `SCSVS-COMM` | Secure Interactions and Communications |
| S6 | `SCSVS-CRYPTO` | Cryptographic Practices |
| S7 | `SCSVS-ORACLE` | Arithmetic and Logic Security |
| S8 | `SCSVS-BLOCK` | Denial of Service (DoS) |
| S9 | `SCSVS-BRIDGE` | Blockchain Data and State Management |
| S10 | `SCSVS-DEFI` | Gas Usage, Efficiency, and Limitations |
| S11 | `SCSVS-COMP` | Component-Specific Security |

> **Verified quirk — do NOT "correct" it:** the code suffixes are legacy labels that do not track their titles. `SCSVS-ORACLE` = *Arithmetic and Logic Security* (not price oracles); `SCSVS-BRIDGE` = *Blockchain Data and State Management* (not cross-chain bridges); `SCSVS-DEFI` = *Gas Usage, Efficiency, and Limitations*. Cite code **and** title together.
>
> **Gap:** the fetched pages did not print an explicit numeric SCSVS version. Cite "current 11-group SCSVS" (supersedes the legacy V1–V14), not a version integer.

**EEA EthTrust Security Levels — Version 3, March 2025.** Three cumulative certification levels: **[S]** automated static checks · **[M]** stricter checks needing human judgment · **[Q]** full business-logic/documentation review. Requirements are `MUST`/`MUST NOT` tagged by level, plus non-binding **[GP]** good practices.
> **Gap (honest):** only these v3 requirement families were verified verbatim on the fetched page — Text and Homoglyphs · External Calls · Compiler Bugs · Access Control · Signature Management · Documentation Requirements. Other families (arithmetic, randomness, gas/DoS) exist but their exact identifiers were not loaded, so this doc cites EthTrust by level + verified family only, and invents no requirement numbers.

### Crosswalk — skill `##` sections / IDs → SCSVS + EthTrust

| Skill section (ID prefix) | OWASP SCSVS control group(s) | EEA EthTrust v3 (level · family) |
|---|---|---|
| token (`VF-TOKEN`) | `SCSVS-COMM` S5; `SCSVS-COMP` S11; `SCSVS-GOV` S3 | [S]/[M] External Calls (SafeERC20/returns); [M] Access Control (mint/burn) |
| access-control (`VF-AC`) | `SCSVS-AUTH` S4 | [S]/[M] Access Control; [S] no `tx.origin` |
| lending (`VF-LEND`) | `SCSVS-GOV` S3; `SCSVS-ORACLE` S7; `SCSVS-COMP` S11 | [Q] business-logic; arithmetic *(family not confirmed)* |
| AMM-DEX (`VF-AMM`) | `SCSVS-GOV` S3; `SCSVS-ORACLE` S7; `SCSVS-COMP` S11 | [M]/[Q] External Calls (callback ordering); [Q] business-logic |
| stablecoin (`VF-STABLE`) | `SCSVS-GOV` S3; `SCSVS-COMP` S11 | [Q] business-logic *(family not itemized)* |
| oracle (`VF-ORACLE`) | `SCSVS-GOV` S3 (price/econ manipulation); `SCSVS-COMM` S5 | [Q] business-logic — **note:** `SCSVS-ORACLE` is arithmetic, NOT price feeds; price risk lives in `SCSVS-GOV` |
| proxy-upgrade (`VF-PROXY`) | `SCSVS-ARCH` S1; `SCSVS-CODE` S2; `SCSVS-AUTH` S4; `SCSVS-BRIDGE` S9 | [M] Access Control (upgrade auth); Documentation; [S] Compiler Bugs |
| bridge / cross-chain (`VF-BRIDGE`,`VF-XCHAIN`) | `SCSVS-BRIDGE` S9; `SCSVS-COMM` S5; `SCSVS-CRYPTO` S6 | [M] Signature Management (threshold/malleability/replay); External Calls |
| liquid-staking / vault / staking (`VF-LST`,`VF-VAULT`,`VF-STAKE`) | `SCSVS-GOV` S3; `SCSVS-ORACLE` S7 (rounding/inflation); `SCSVS-COMP` S11 | [Q] business-logic; arithmetic/rounding *(family not confirmed)* |
| governance (`VF-GOV`) | `SCSVS-GOV` S3; `SCSVS-AUTH` S4 | [M] Access Control; [Q] business-logic |
| signature (`VF-SIG`) | `SCSVS-CRYPTO` S6; `SCSVS-AUTH` S4 | [M] Signature Management (malleability, `ecrecover(0)`, domain/nonce replay) |
| math (`VF-MATH`) | `SCSVS-ORACLE` S7 | [S] Compiler Bugs (overflow/`unchecked`); arithmetic *(family not confirmed)* |
| general (`VF-GEN`) | `SCSVS-COMM` S5 (reentrancy/CEI); `SCSVS-BLOCK` S8 (DoS); `SCSVS-DEFI` S10 (gas); `SCSVS-ARCH` S1 | [S]/[M] External Calls (CEI, unchecked returns, `delegatecall`) |
| AA / 7702 / intents / diamond (`VF-AA`,`VF-7702`,`VF-INTENT`,`VF-DIAMOND`) | `SCSVS-AUTH` S4; `SCSVS-CRYPTO` S6; `SCSVS-ARCH` S1; `SCSVS-COMP` S11 | [M] Access Control; [M] Signature Management; Documentation |
| tvm-native (`VF-TVM`) | **No direct group** — partial only: `SCSVS-COMM` S5, `SCSVS-CRYPTO` S6, `SCSVS-COMP` S11 | **No mapping** — see gap note |

Chain families roll up the same way: `VC-REENT-*`→S5; `VC-FLASH-*`/`VC-ORACLE-*`→S3; `VC-SHARE-*`/`VC-ROUND-*`→S7+S3; `VC-SIG-*`→S6; `VC-GOV-*`/`VC-ACCESS-*`→S4+S3; `VC-BRIDGE-*`→S9+S6; `VC-AA-*`→S4+S6; `VC-ASSET-*` (fake-TRC-10)→**no standard mapping** (TRON-native).

### Coverage gaps flagged (not guessed)

- **TVM-native (`VF-TVM-*`, `VC-ASSET-*`) is out of scope of both standards.** OWASP SCSVS and EEA EthTrust are Solidity/EVM-centric. The TRON surface — `msg.tokenid`/TRC-10, SUN 6-dec native value, `0x41`-prefix CREATE2/identity, precompile divergence, FREEZE/DELEGATERESOURCE, `delegatecall` token-drop, account-level permission custody — has no control group or EthTrust requirement. This is a real delta *in the standards* and a differentiator of this skill; carry these in `coverage.md` as items no external standard cross-validates.
- SCSVS has no explicit numeric version on the fetched pages — cited as the current 11-group standard.
- EthTrust v3 requirement families only partially verified; no requirement IDs asserted.

Sources (fetched): https://scs.owasp.org/SCSVS/ · https://scs.owasp.org/checklists/ · https://entethalliance.org/specs/ethtrust-sl/ · https://entethalliance.org/eea-releases-v2-of-ethtrust-security-levels-specification/
