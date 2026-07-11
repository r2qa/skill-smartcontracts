#!/usr/bin/env bash
# get-source.sh — fetch a TRON contract's VERIFIED source (+ exact compiler settings + ABI)
# from TronScan, attest it against the on-chain RUNTIME (keccak256==code_hash), and cache it.
# Falls back to on-chain runtime bytecode + heimdall decompilation when unverified.
#
# Usage:  get-source.sh <T-address|0x41-hex> [outdir]
#   default outdir: findings/<address>/src-fetched   (override with arg2 or FINDINGS_DIR)
# Needs:  TRONSCAN_API_KEY / TRONGRID_API_KEY (from ~/.config/fearsoff/audit.env), curl, python3, cast (foundry).
#         Optional decompile fallback: heimdall.
#
# Source endpoint (undocumented, used by the TronScan frontend):
#   POST https://apilist.tronscanapi.com/api/solidity/contract/info  {"contractAddress":"T..."}
#   -> data.status (2=verified), data.contract_code[]{name,code(base64)}, byte_code, abi,
#      compiler, optimizer, optimizer_runs, evm_version, via_ir, license.
# Runtime + code_hash (authoritative):
#   POST https://api.trongrid.io/wallet/getcontractinfo {"value":"T...","visible":true} -> runtimecode
#   code_hash := keccak256(runtimecode)  (TVM definition; computed with `cast keccak`).

set -uo pipefail
[ -f "$HOME/.config/fearsoff/audit.env" ] && source "$HOME/.config/fearsoff/audit.env"

ADDR="${1:?usage: get-source.sh <T-address> [outdir]}"
OUT="${2:-${FINDINGS_DIR:-./findings}/$ADDR/src-fetched}"
CACHE="${TRON_SRC_CACHE:-$HOME/.cache/fearsoff/tron-src}"
TSN="${TRONSCAN_API_KEY:-}"; TG="${TRONGRID_API_KEY:-}"
TS_API="https://apilist.tronscanapi.com"; TG_API="https://api.trongrid.io"
[ -z "$TSN" ] && echo "WARN: TRONSCAN_API_KEY unset — requests rate-limited; verified source may be stripped" >&2
command -v cast >/dev/null 2>&1 || { echo "FATAL: 'cast' (foundry) required for code_hash attestation" >&2; exit 2; }
mkdir -p "$OUT"

# 1) verified source + compiler settings + abi (may be empty if unverified)
curl -sS --compressed --max-time 40 "$TS_API/api/solidity/contract/info" \
  -H 'Content-Type: application/json' -H "TRON-PRO-API-KEY: $TSN" \
  --data "{\"contractAddress\":\"$ADDR\"}" > "$OUT/_info.json" || { echo "FATAL: source fetch failed" >&2; exit 2; }

# 2) authoritative on-chain RUNTIME bytecode (getcontractinfo.runtimecode — NOT the creation blob)
curl -sS --max-time 30 -X POST "$TG_API/wallet/getcontractinfo" \
  -H "TRON-PRO-API-KEY: $TG" -H 'Content-Type: application/json' \
  --data "{\"value\":\"$ADDR\",\"visible\":true}" > "$OUT/_gci.json" 2>/dev/null || true

RUNTIME=$(python3 -c "import json;print((json.load(open('$OUT/_gci.json')).get('runtimecode') or '').strip().lower())" 2>/dev/null || true)
CODE_HASH=""
if [ -n "$RUNTIME" ]; then
  printf '%s' "$RUNTIME" > "$OUT/runtime.hex"
  CODE_HASH=$(cast keccak "0x$RUNTIME" 2>/dev/null | sed 's/^0x//')
fi

STATUS=$(python3 - "$OUT" "$ADDR" "$RUNTIME" "$CODE_HASH" "$CACHE" <<'PY'
import sys, json, base64, os, shutil
out, addr, runtime, code_hash, cache = sys.argv[1:6]
d = (json.load(open(f"{out}/_info.json")).get("data") or {})
status = d.get("status"); name = d.get("contract_name")
comp, opt, runs = d.get("compiler"), d.get("optimizer"), d.get("optimizer_runs")
evm, viair, lic  = d.get("evm_version"), d.get("via_ir"), d.get("license")
code  = d.get("contract_code") or []
vbyte = (d.get("byte_code") or "").lower().removeprefix("0x")   # bytecode TronScan verified against

meta = {"address": addr, "status": status, "contract_name": name,
        "compiler": comp, "optimizer": opt, "optimizer_runs": runs,
        "evm_version": evm, "via_ir": viair, "license": lic,
        "files": [c.get("name") for c in code],
        "code_hash": code_hash or None,           # keccak256(runtime), authoritative
        "runtime_len_bytes": len(runtime)//2 if runtime else 0}

# attestation (authoritative): keccak256(runtime) must equal the on-chain code_hash.
# The on-chain hash is getcontractinfo.smart_contract.code_hash — NOT any init/deployment
# bytecode field (/api/solidity/contract/info.byte_code, /api/contracts/code.byteCode and
# /wallet/getcontract.bytecode are DEPLOYMENT code with the constructor, so never compare those).
onchain_ch = ""
try:
    onchain_ch = ((json.load(open(f"{out}/_gci.json")).get("smart_contract") or {}).get("code_hash") or "").lower().removeprefix("0x")
except Exception:
    pass
meta["onchain_code_hash"] = onchain_ch or None
att = ("no-runtime" if not runtime
       else "no-onchain-hash" if not onchain_ch
       else "MATCH" if code_hash == onchain_ch else "DIFFER")
meta["bytecode_attestation"] = att

if status == 2 and code:
    srcdir = f"{out}/src"; os.makedirs(srcdir, exist_ok=True)
    for c in code:
        fn = (c.get("name") or "Unnamed.sol").replace("..", "_")
        p = os.path.join(srcdir, fn)
        if "/" in fn: os.makedirs(os.path.dirname(p), exist_ok=True)
        try: open(p, "w").write(base64.b64decode(c.get("code","")).decode("utf-8","replace"))
        except Exception as e: open(p+".b64err","w").write(str(e))
    if d.get("abi"): open(f"{out}/abi.json","w").write(d["abi"] if isinstance(d["abi"],str) else json.dumps(d["abi"]))
    open(f"{out}/compiler.json","w").write(json.dumps(meta, indent=2))
    if code_hash:  # cache real copy by code_hash
        cdir = os.path.join(os.path.expanduser(cache), code_hash)
        if not os.path.isdir(cdir):
            shutil.copytree(srcdir, os.path.join(cdir,"src")); shutil.copy(f"{out}/compiler.json", cdir)
    print(f"VERIFIED status=2 files={len(code)} compiler={comp} opt={opt}/{runs} evm={evm} attest={att}")
    print(f"  contract={name}  -> {out}/src/  (+ compiler.json, abi.json, runtime.hex)")
    print(f"  code_hash={code_hash}")
    sys.exit(0)
else:
    open(f"{out}/compiler.json","w").write(json.dumps(meta, indent=2))
    print(f"UNVERIFIED status={status} — no source on TronScan. Runtime saved to {out}/runtime.hex "
          f"(code_hash={code_hash}); use the bytecode-only branch (heimdall + selector-match + code_hash attestation).")
    sys.exit(3)
PY
)
RC=$?
echo "$STATUS"

# 3) unverified → heimdall decompile of the true RUNTIME
if [ "$RC" = "3" ] && command -v heimdall >/dev/null 2>&1 && [ -s "$OUT/runtime.hex" ]; then
  echo "  running heimdall decompile on runtime…"
  heimdall decompile "$(cat "$OUT/runtime.hex")" -o "$OUT/decompiled" >/dev/null 2>&1 \
    && echo "  -> $OUT/decompiled/" || echo "  heimdall decompile failed (TVM opcodes may abort it)"
fi

# 4) recompile-match (gold standard): recompile the fetched source and compare deployedBytecode
#    to the on-chain runtime. FULL = keccak(recompiled)==code_hash; PARTIAL = matches after
#    stripping trailing CBOR metadata (source correct, only metadata/immutables differ).
if [ "$RC" = 0 ]; then
python3 - "$OUT" <<'PY' || true
import sys, json, os, subprocess, shutil, re
out = sys.argv[1]
meta = json.load(open(f"{out}/compiler.json"))
comp = meta.get("compiler") or ""; target = meta.get("contract_name")
onchain = (meta.get("onchain_code_hash") or "").lower()
try: runtime = open(f"{out}/runtime.hex").read().strip().lower()
except Exception: runtime = ""
m = re.search(r'(\d+\.\d+\.\d+)', comp)
if not m: print("  recompile: skipped (no compiler version parsed)"); sys.exit(0)
ver = m.group(1)
def find_solc(ver):
    home = os.path.expanduser("~")
    # exact TRON solc fork of this version = the only path to an exact byte match
    for c in (f"tron-solc-{ver}", f"tron_v{ver}"):
        w = shutil.which(c)
        if w: return w, "tron"
    w = shutil.which("tron-solc")   # generic — use only if its version actually matches
    if w:
        try:
            if ver in subprocess.run([w,"--version"],capture_output=True,text=True,timeout=15).stdout: return w, "tron"
        except Exception: pass
    # exact stock solc: compiles for logic review but will NOT byte-match the TRON fork
    p = f"{home}/.solc-select/artifacts/solc-{ver}/solc-{ver}"
    if os.path.exists(p): return p, "stock"
    return None, None
solc, kind = find_solc(ver)
if not solc:
    print(f"  recompile: skipped (need solc {ver}; TRON fork = exact match, stock solc = approximate). `solc-select install {ver}` to enable.")
    sys.exit(0)
srcdir = f"{out}/src"; sources = {}
for root,_,files in os.walk(srcdir):
    for f in files:
        if f.endswith(".sol"):
            rel = os.path.relpath(os.path.join(root,f), srcdir)
            sources[rel] = {"content": open(os.path.join(root,f), encoding="utf-8", errors="replace").read()}
settings = {"optimizer": {"enabled": bool(meta.get("optimizer")), "runs": int(meta.get("optimizer_runs") or 200)},
            "outputSelection": {"*": {"*": ["evm.deployedBytecode.object"]}}}
evm = meta.get("evm_version")
if evm and evm != "default": settings["evmVersion"] = evm
if meta.get("via_ir"): settings["viaIR"] = True
inp = {"language":"Solidity","sources":sources,"settings":settings}
try:
    r = subprocess.run([solc,"--standard-json"], input=json.dumps(inp), capture_output=True, text=True, timeout=240)
    oj = json.loads(r.stdout or "{}")
except Exception as e:
    print(f"  recompile: skipped (solc failed: {str(e)[:80]})"); sys.exit(0)
dep = ""
for cs in (oj.get("contracts") or {}).values():
    for cname, obj in cs.items():
        b = (obj.get("evm",{}).get("deployedBytecode",{}).get("object") or "").lower()
        if cname == target and b: dep = b
if not dep:
    allb = [ (obj.get("evm",{}).get("deployedBytecode",{}).get("object") or "").lower()
             for cs in (oj.get("contracts") or {}).values() for obj in cs.values() ]
    dep = max(allb, key=len, default="")
if not dep:
    errs = [e.get("formattedMessage","") for e in oj.get("errors",[]) if e.get("severity")=="error"]
    print("  recompile: no deployedBytecode (compile error: %s)" % (errs[0][:100] if errs else "unknown")); sys.exit(0)
def strip_meta(hx):
    try:
        n = int(hx[-4:], 16); return hx[:-(n+2)*2]
    except Exception: return hx
kh = subprocess.run(["cast","keccak","0x"+dep], capture_output=True, text=True).stdout.strip().lower().replace("0x","")
if kh and kh == onchain:
    print(f"  recompile=FULL-MATCH (solc {ver} {kind}) — source→deployed bytecode independently verified")
elif runtime and strip_meta(dep) and strip_meta(dep) == strip_meta(runtime):
    print(f"  recompile=PARTIAL-MATCH (solc {ver} {kind}; only trailing metadata differs) — source is the deployed one")
else:
    note = "" if kind=="tron" else " — used STOCK solc; the TRON solc fork is needed for exact bytes"
    print(f"  recompile=NO-MATCH{note} (review source/settings, or get the exact TRON compiler)")
PY
fi

# 5) proxy resolution: if this is a proxy, resolve the implementation and fetch its source too
if [ "${GETSRC_DEPTH:-0}" -lt 1 ]; then
IMPL=$(python3 - "$ADDR" <<'PY' 2>/dev/null || true
import sys, os, json, urllib.request, hashlib
addr = sys.argv[1]; tg = os.environ.get("TRONGRID_API_KEY","")
ALPH='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
try:
    num=0
    for c in addr: num=num*58+ALPH.index(c)
    evm20 = num.to_bytes(25,'big')[1:21].hex()
except Exception: sys.exit(0)
def rpc(method, params):
    req = urllib.request.Request("https://api.trongrid.io/jsonrpc",
        data=json.dumps({"jsonrpc":"2.0","method":method,"params":params,"id":1}).encode(),
        headers={"Content-Type":"application/json","TRON-PRO-API-KEY":tg})
    return json.load(urllib.request.urlopen(req, timeout=20)).get("result")
def nonzero20(v):
    if not v: return ""
    h = v[-40:]
    try: return h if int(h,16)!=0 else ""
    except Exception: return ""
impl = ""
for s in ("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",   # EIP-1967 impl
          "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7"):  # EIP-1822 proxiable
    try: impl = nonzero20(rpc("eth_getStorageAt", ["0x"+evm20, s, "latest"]))
    except Exception: impl = ""
    if impl: break
if not impl:
    for sel in ("0x5c60da1b",):  # implementation()
        try: impl = nonzero20(rpc("eth_call", [{"to":"0x"+evm20,"data":sel}, "latest"]))
        except Exception: impl = ""
        if impl: break
if impl and impl.lower()!=evm20.lower():
    payload = b'\x41'+bytes.fromhex(impl)
    full = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n=int.from_bytes(full,'big'); b58=''
    while n>0: n,rem=divmod(n,58); b58=ALPH[rem]+b58
    for byte in full:
        if byte==0: b58='1'+b58
        else: break
    print(b58)
PY
)
  if [ -n "$IMPL" ]; then
    echo "  proxy detected → implementation $IMPL — fetching its source into $OUT/impl/"
    GETSRC_DEPTH=$(( ${GETSRC_DEPTH:-0} + 1 )) bash "$0" "$IMPL" "$OUT/impl" || true
  fi
fi

rm -f "$OUT/_info.json" "$OUT/_gci.json" 2>/dev/null || true
exit "$RC"
