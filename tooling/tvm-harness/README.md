# TVM differential harness

A **local, real TVM** to run a PoC on — so a gate-7 proof is TVM-authoritative, not an
`EVM-model`. Foundry/Anvil/Halmos/Echidna all execute the *EVM*, which diverges from the TVM
at exactly the points in the `tvm-native` checklist (TRC-10, SUN decimals, precompiles at
`0x03`/`0x09`, `block.*` constants, CREATE2 `0x41`, staking opcodes). This harness deploys the
same bytecode to a private **java-tron** node (`tron-quickstart`, "anvil for TVM") and compares
the result to the EVM-model expectation — a **divergence is itself a finding**, and a match
**corroborates** the PoC on real TVM opcodes.

## Use

```bash
bash tooling/tvm-harness/up.sh          # start local java-tron (:9090), print a funded account
node tooling/tvm-harness/differential.js  # deploy the probe + report the EVM-vs-TVM diff
bash tooling/tvm-harness/down.sh         # tear down
```

Requires: Docker, TronWeb (`npm i -g tronweb`), and the TRON solc fork (`tron-solc`) — all from
`bootstrap.sh`. On Apple Silicon the image is x86_64, so `up.sh` runs it under emulation (slower
start, ~1–3 min).

## Worked example (`contracts/TvmDiff.sol` + `differential.js`)

- **Precompile `0x03`** — RIPEMD160 on EVM, **TIP-272 "TwiceHash"** = `sha256(sha256(x)[:20])` on
  TVM (inner sha256 truncated to 20 bytes, then sha256). The harness deploys the probe, calls it,
  and shows the on-chain result **matches TwiceHash and not RIPEMD160** → an EVM-ported contract
  calling `0x03` silently gets the wrong hash. (Real RIPEMD160 is at `0x20003`.) *This run
  empirically confirmed the exact formula on a live node.*
- **`block.difficulty` / `block.gaslimit`** — per-block on EVM, **constant `0`** on TVM.

Verified output (`node differential.js`): `DIVERGENCE CONFIRMED: true`, `block.difficulty=0`,
`block.gaslimit=0`, `RESULT: PASS`.

## Writing your own differential

Drop your target (or a MODEL of it) + mock tokens into `contracts/`, compile with `tron-solc`,
deploy via TronWeb in a copy of `differential.js`, exercise the exploit sequence, and assert the
state. Run the *same* logic on Foundry (EVM) and compare. Reach for this whenever a finding
depends on a `tvm-native` construct — TRC-10 `msg.tokenid`, native SUN value, a precompile, a
staking opcode, CREATE2 address derivation.

## Honest limitation

`tron-quickstart` (like a public testnet) runs a **fresh private net** — it does **not fork
mainnet state** (TRON has no `anvil --fork-url` equivalent). So the harness proves TVM **opcode
semantics** on a re-deployed contract/model, but **not** mainnet storage/balances. Mainnet-state
findings still rely on read-only on-chain reads + a model PoC. Label a TVM-harness PoC
`TVM-proven (re-deploy, not mainnet-state)`.

## Safety

Everything here is **write transactions on a LOCAL private net only** — never mainnet. This is
the sanctioned place to reproduce an exploit (local/testnet), per the engagement's SAFE-TESTING
rules.
