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

| Rule id | Fires on | Why it matters (verify before writing up) |
|---|---|---|
| `tron-trc10-msgtoken-context` | `msg.tokenvalue` / `msg.tokenid` | Is `msg.tokenid` checked against the expected token *before* `msg.tokenvalue` is trusted? If not → deposit a worthless self-issued TRC-10, withdraw a real asset (BTTBank-class drain). |
| `tron-transfertoken-call` | `…transferToken(…)` | Is the `tokenId` arg trusted/allowlisted (not user-controlled) and the intended asset? |
| `tron-tokenbalance-call` | `…tokenBalance(…)` | Is the queried `tokenId` trusted? A balance of an attacker-chosen fake token can spoof accounting. |
| `tron-trctoken-param` | a `trcToken` value in scope | If it comes from calldata, is it range-checked / allowlisted before transfer/accounting? |
| `tron-native-value-decimals` | `1 ether` / `1e18` literals | Native TRON value is **SUN** (1 TRX = 1e6). A native-value path scaled by 1e18 misprices by 1e12×. |

## Discipline — a match is a POINTER, not a finding

Solidity support in Semgrep is **experimental**; these rules are pattern-based (no reliable
dataflow), so they are deliberately LOW / inventory severity. Every hit still has to be walked
by hand:

```
entrypoint → access control → user data → checks → sink → financial impact
```

Only a proven chain (gate 7 PoC) is a finding.

## Not covered here (do by hand — Semgrep/Solidity can't express them reliably)

Staking/resource opcodes (FREEZE/UNFREEZE/DELEGATERESOURCE) without access control, the
CREATE2 `0x41` address-prefix assumption, precompile divergence at `0x01–0x0a`, and
`delegatecall` dropping `calltokenvalue/id` — these live in the `tvm-native` checklist and the
vulnerable-chains file, and are checked manually in gates 3/5.

## Maintaining the rules

`tron-tvm-native.sol` is the fixture: a vulnerable contract (every construct must fire) plus a
plain-ERC20 safe contract (nothing may fire). Validate + smoke-test after any edit:

```bash
semgrep --validate --config tron-tvm-native.yml
semgrep --config tron-tvm-native.yml tron-tvm-native.sol   # 7 matches, none in PlainErc20Like
```

(`semgrep --test` is the intended harness but crashes in 1.168.0 on the path-matching step;
the direct scan above is the fallback smoke test.)
