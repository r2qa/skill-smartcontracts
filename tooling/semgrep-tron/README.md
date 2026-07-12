# TRON/TVM-native Semgrep rules

A small custom ruleset that turns the `tvm-native` checklist (in
[`../../vulnerable-functions.md`](../../vulnerable-functions.md)) into automatic **audit
inventory hotspots**. It complements — does not replace — the stock DeFi ruleset:

```bash
semgrep --config p/smart-contracts        <src>   # Decurity — known-exploit patterns
semgrep --config tooling/semgrep-tron/    <src>   # this — TRON/TVM extensions
```

Wired into **gate 2** of `../../SKILL.md`.

## What it flags

Severity maps to Semgrep's scale: **INFO** = LOW/inventory hotspot, **WARNING** = higher-signal (something concrete to confirm). Nothing is ERROR — a match is never proof.

| Rule id | Sev | Fires on | Why it matters (verify before writing up) |
|---|---|---|---|
| `tron-trc10-msgtoken-context` | INFO | `msg.tokenvalue` / `msg.tokenid` | Is `msg.tokenid` checked against the expected token *before* `msg.tokenvalue` is trusted? If not → deposit a worthless self-issued TRC-10, withdraw a real asset (BTTBank-class drain). |
| `tron-transfertoken-call` | INFO | `…transferToken(…)` | Is the `tokenId` arg trusted/allowlisted (not user-controlled) and the intended asset? |
| `tron-tokenbalance-call` | INFO | `…tokenBalance(…)` | Is the queried `tokenId` trusted? A balance of an attacker-chosen fake token can spoof accounting. |
| `tron-trctoken-param` | INFO | a `trcToken` value in scope | If it comes from calldata, is it range-checked / allowlisted before transfer/accounting? |
| `tron-native-value-decimals` | WARNING | `msg.value` combined with `1e18`/`ether` in one expression | Native TRON value is **SUN** (1 TRX = 1e6); 1e18 on a native path misprices by 1e12×. **Plain WAD/TRC-20 18-decimal math is NOT flagged** (needs the `msg.value` co-occurrence). Semgrep Solidity has no dataflow, so the cross-statement form (`x = msg.value; … x * 1e18`) is NOT caught — grep native paths by hand too. |
| `tron-weak-randomness-tvm-constants` | WARNING | `block.difficulty` / `block.prevrandao` / `block.gaslimit` | These are **constants** on the TVM, not per-block entropy — trivially predictable if used for randomness or as a guard. |
| `tron-create2-eth-prefix` | WARNING | `bytes1(0xff)` / `hex"ff"` | TVM computes CREATE2 addresses with a **`0x41`** prefix, not Ethereum's `0xff`; a hand-rolled `0xff` preimage predicts the wrong address. |
| `tron-native-send-stipend` | WARNING | `$X.send(…)` / `payable($X).transfer(…)` | The EVM 2300-gas stipend assumption differs under TVM's Energy model; verify the recipient path. |
| `tron-tx-origin-auth` | WARNING | `tx.origin == $X` (auth) | Phishing-vulnerable; post-EIP-7702 also stops distinguishing EOA from contract. |
| `tron-delegatecall-usage` | WARNING | `$X.delegatecall(…)` | Arbitrary/trusted target check; TVM drops `calltokenvalue`/`calltokenid` in delegated code. |
| `tron-ecrecover-usage` | INFO | `ecrecover(…)` | Verify zero-addr check + malleability + 20-vs-21-byte identity reconciliation. |
| `tron-selfdestruct-usage` | INFO | `selfdestruct(…)` / `suicide(…)` | Post-EIP-6780 semantics on TRON (param #94) — verify brick/force-feed assumptions. |
| `tron-lowlevel-call-value` | INFO | `$X.call{value:}(…)` | Verify the boolean return is checked + reentrancy guarded. |
| `tron-create2-new-salt` | INFO | `new C{salt:…}(…)` | CREATE2 deploy — TVM `0x41`-prefix address derivation, not `0xff`. |

## Discipline — a match is a POINTER, not a finding

Solidity support in Semgrep is **experimental**; these rules are pattern-based (no reliable
dataflow), so they are deliberately LOW / inventory severity. Every hit still has to be walked
by hand:

```
entrypoint → access control → user data → checks → sink → financial impact
```

Only a proven chain (gate 7 PoC) is a finding.

## Not covered here (do by hand — Semgrep/Solidity can't express them reliably)

Staking/resource opcodes (FREEZE/UNFREEZE/DELEGATERESOURCE) without access control, precompile
divergence at `0x01–0x0a`, `delegatecall` dropping `calltokenvalue/id`, and any cross-statement
native-value/decimals dataflow — these need real dataflow or context Semgrep's experimental
Solidity can't express, so they live in the `tvm-native` checklist and the vulnerable-chains
file and are checked manually in gates 3/5. (The CREATE2 `0x41`-vs-`0xff` assumption is now
partially automated by `tron-create2-eth-prefix`, but still confirm the full preimage by hand.)

## Maintaining the rules

`tron-tvm-native.sol` is the fixture: a vulnerable contract (`// ruleid:` — every construct
must fire) plus a safe contract carrying realistic negatives (`// ok:` — 18-decimal WAD/share
math with no `msg.value` in scope, which must NOT fire). Validate + smoke-test after any edit:

```bash
semgrep --validate --config tron-tvm-native.yml
semgrep --config tron-tvm-native.yml tron-tvm-native.sol   # 18 matches (14 rules), none in the safe contract
```

(`semgrep --test` is the intended harness but crashes in 1.168.0 on the path-matching step;
the direct scan above is the fallback smoke test.)
