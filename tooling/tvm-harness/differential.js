#!/usr/bin/env node
/* TVM differential harness — deploy a probe to the LOCAL java-tron (tron-quickstart)
 * and compare its result to the EVM-model expectation. A divergence proves the
 * behaviour is TVM-specific (and confirms the tvm-native checklist empirically).
 *
 *   node differential.js            # uses http://127.0.0.1:9090 (quickstart)
 *
 * Safety: this deploys + calls on a LOCAL private net only. Never mainnet.
 */
const { execSync } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const _tw = require("tronweb");
const TronWeb = _tw.TronWeb || _tw.default || _tw;   // v6 exports { TronWeb }; older = default

const HOST = process.env.TVM_HOST || "http://127.0.0.1:9090";
const SOLC = process.env.TRON_SOLC || "tron-solc"; // TRON solc fork (emits TVM bytecode)
const SRC = path.join(__dirname, "contracts", "TvmDiff.sol");

async function main() {
  // 1) a pre-funded quickstart account (the endpoint returns TEXT, not JSON)
  let priv = process.env.TVM_PRIV;
  if (!priv) {
    const txt = await (await fetch(`${HOST}/admin/accounts?format=all`)).text().catch(() => "");
    const pkSection = (txt.split(/Private Keys/)[1] || "");
    priv = (pkSection.match(/\b[0-9a-f]{64}\b/i) || [])[0];
  }
  if (!priv) throw new Error("no quickstart account key — is the node up on " + HOST + " ?");
  const tw = new TronWeb({ fullHost: HOST, privateKey: priv });

  // 2) compile with the TRON solc fork (TVM bytecode)
  // evm-version istanbul: avoid PUSH0 (0x5f), which the old quickstart java-tron rejects.
  const EVMV = process.env.TRON_EVM_VERSION || "istanbul";
  const out = JSON.parse(execSync(
    `${SOLC} --combined-json abi,bin --optimize --evm-version ${EVMV} ${SRC}`, { encoding: "utf8" }));
  const key = Object.keys(out.contracts).find(k => k.endsWith(":TvmDiff"));
  const { abi, bin } = out.contracts[key];
  const abiJson = typeof abi === "string" ? JSON.parse(abi) : abi;

  // 3) deploy to the local TVM (low-level: build -> sign -> broadcast -> wait for a block)
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const owner = tw.defaultAddress.hex;
  const unsigned = await tw.transactionBuilder.createSmartContract(
    { abi: abiJson, bytecode: bin, feeLimit: 1e9, callValue: 0, name: "TvmDiff" }, owner);
  const caddr = unsigned.contract_address;               // hex 41...
  const rec = await tw.trx.sendRawTransaction(await tw.trx.sign(unsigned));
  if (!(rec.result || rec.txid)) throw new Error("deploy broadcast rejected: " + JSON.stringify(rec));
  let info;
  for (let i = 0; i < 25; i++) { await sleep(3000);
    info = await tw.trx.getTransactionInfo(unsigned.txID).catch(() => ({}));
    if (info && info.id) break; }
  if (!info || !info.id) throw new Error("deploy not confirmed in ~75s");
  if (info.receipt && info.receipt.result && info.receipt.result !== "SUCCESS")
    throw new Error("deploy reverted: " + info.receipt.result + " " + (info.resMessage || ""));
  console.log("deployed TvmDiff at", tw.address.fromHex(caddr), "(block", info.blockNumber + ")");

  // 4) call the probes (view calls against the confirmed contract)
  const c = await tw.contract(abiJson, caddr);
  const x = Buffer.from("fearsoff-tvm-differential", "utf8");
  const raw = await c.p3("0x" + x.toString("hex")).call();
  const onchain = "0x" + String(raw).replace(/^0x/, "");
  const diff = (await c.difficulty().call()).toString();
  const glim = (await c.gaslimit().call()).toString();

  // 5) EVM-model expectations, computed off-chain
  const ripemd = crypto.createHash("ripemd160").update(x).digest();          // EVM 0x03
  const evmExpect = "0x" + Buffer.concat([Buffer.alloc(12), ripemd]).toString("hex"); // left-padded to 32
  const inner = crypto.createHash("sha256").update(x).digest().slice(0, 20);  // TIP-272: inner sha256 truncated to 20 bytes
  const tvmExpect = "0x" + crypto.createHash("sha256").update(inner).digest().toString("hex"); // TwiceHash = sha256(sha256(x)[:20])

  // 6) report the differential
  const eq = (a, b) => a.toLowerCase() === b.toLowerCase();
  console.log("\n=== precompile 0x03 differential (input: 'fearsoff-tvm-differential') ===");
  console.log("  on-chain (LOCAL TVM) :", onchain);
  console.log("  EVM model RIPEMD160  :", evmExpect, eq(onchain, evmExpect) ? "  <- MATCHES on-chain" : "");
  console.log("  TVM  TwiceHash(2xSHA):", tvmExpect, eq(onchain, tvmExpect) ? "  <- MATCHES on-chain" : "");
  const p3ok = eq(onchain, tvmExpect) && !eq(onchain, evmExpect);
  console.log("  >> DIVERGENCE CONFIRMED:", p3ok,
    "— real TVM 0x03 = TwiceHash, NOT RIPEMD160 (an EVM port breaks silently)");

  console.log("\n=== block constants (EVM: per-block, TVM: constant 0) ===");
  console.log("  block.difficulty :", diff, diff === "0" ? "(0 on TVM ✓)" : "");
  console.log("  block.gaslimit   :", glim, glim === "0" ? "(0 on TVM ✓)" : "");

  const pass = p3ok && diff === "0";
  console.log("\nRESULT:", pass ? "PASS — harness reproduces TVM-specific semantics on a real node" : "CHECK");
  process.exit(pass ? 0 : 1);
}
main().catch(e => {
  console.error("ERROR:", e.message || e);
  if (e.response || e.config) console.error("  ->", (e.config?.method||"?").toUpperCase(),
    e.config?.url, "status", e.response?.status);
  process.exit(2);
});
