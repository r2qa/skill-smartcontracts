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
# validate the address BEFORE it reaches a POST body or a path — blocks JSON injection and
# path traversal, and keeps proxy base58-decode well-defined. Base58 T-address, 34 chars.
case "$ADDR" in
  T[1-9A-HJ-NP-Za-km-z]*) [ "${#ADDR}" -eq 34 ] || { echo "FATAL: '$ADDR' is not a 34-char base58 T-address" >&2; exit 2; } ;;
  *) echo "FATAL: address must be a base58 T-address (got '$ADDR'); hex 0x41… is not supported here" >&2; exit 2 ;;
esac
OUT="${2:-${FINDINGS_DIR:-./findings}/$ADDR/src-fetched}"
CACHE="${TRON_SRC_CACHE:-$HOME/.cache/fearsoff/tron-src}"
TSN="${TRONSCAN_API_KEY:-}"; TG="${TRONGRID_API_KEY:-}"
TS_API="https://apilist.tronscanapi.com"; TG_API="https://api.trongrid.io"
[ -z "$TSN" ] && echo "WARN: TRONSCAN_API_KEY unset — requests rate-limited; verified source may be stripped" >&2
command -v cast >/dev/null 2>&1 || { echo "FATAL: 'cast' (foundry) required for code_hash attestation" >&2; exit 2; }
mkdir -p "$OUT"

# 1) verified source + compiler settings + abi (may be empty if unverified)
curl -fsS --compressed --max-time 40 "$TS_API/api/solidity/contract/info" \
  -H 'Content-Type: application/json' -H "TRON-PRO-API-KEY: $TSN" \
  --data "{\"contractAddress\":\"$ADDR\"}" > "$OUT/_info.json" \
  || { echo "FATAL: source fetch failed (HTTP error / rate-limit / network) — this is NOT a 'no source' verdict" >&2; exit 2; }

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
raw = json.load(open(f"{out}/_info.json"))
# distinguish an API/transport anomaly from a genuinely-unverified contract: a real response
# (verified OR not) carries a `data` object. Its absence = rate-limit/403/error payload → exit 2,
# NOT the "no source exists" verdict (exit 3) that would wrongly push the auditor to bytecode-only.
if not isinstance(raw.get("data"), dict):
    sys.stderr.write("API-ERROR: TronScan returned no `data` object (rate-limit/403/invalid response) — "
                     "this is NOT a verification verdict. Raw: %s\n" % (json.dumps(raw)[:200]))
    sys.exit(2)
d = raw["data"]
status = d.get("status"); name = d.get("contract_name")
comp, opt, runs = d.get("compiler"), d.get("optimizer"), d.get("optimizer_runs")
evm, viair, lic  = d.get("evm_version"), d.get("via_ir"), d.get("license")
code  = d.get("contract_code") or []

meta = {"address": addr, "status": status, "contract_name": name,
        "compiler": comp, "optimizer": opt, "optimizer_runs": runs,
        "evm_version": evm, "via_ir": viair, "license": lic,
        "files": [c.get("name") for c in code],
        "code_hash": code_hash or None,           # keccak256(node runtimecode)
        "runtime_len_bytes": len(runtime)//2 if runtime else 0}

# node self-consistency check ONLY — this is NOT source authority.
# keccak256(node runtimecode) vs the node's own smart_contract.code_hash proves the runtime
# blob we hashed is the real deployed one (guards a truncated/corrupt field); it says NOTHING
# about whether the fetched .sol produced that runtime. Source authority = recompile FULL_MATCH
# (see recompile_status below). The on-chain hash is getcontractinfo.smart_contract.code_hash —
# NOT any init/deployment bytecode field (/api/solidity/contract/info.byte_code,
# /api/contracts/code.byteCode, /wallet/getcontract.bytecode are DEPLOYMENT code w/ constructor).
onchain_ch = ""
try:
    onchain_ch = ((json.load(open(f"{out}/_gci.json")).get("smart_contract") or {}).get("code_hash") or "").lower().removeprefix("0x")
except Exception:
    pass
meta["onchain_code_hash"] = onchain_ch or None
att = ("no-runtime" if not runtime
       else "no-onchain-hash" if not onchain_ch
       else "MATCH" if code_hash == onchain_ch else "DIFFER")
meta["node_runtime_hash_match"] = att            # node self-consistency, NOT source→runtime proof
meta["explorer_source_status"] = status          # 2 = TronScan says verified (explorer trust only)
meta["recompile_status"] = "PENDING"             # overwritten by the recompile step below

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
    print(f"EXPLORER-VERIFIED status=2 files={len(code)} compiler={comp} opt={opt}/{runs} evm={evm} node_runtime_hash={att}")
    if att == "DIFFER":
        print("  WARNING: node runtimecode does NOT hash to the node's own code_hash (data anomaly) — treat runtime with suspicion")
    print("  NOTE: 'verified' here = TronScan's badge only. Source is authoritative ONLY on recompile=FULL-MATCH below.")
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
def finish(status, msg):
    # persist machine-readable recompile state so the audit can GATE on it
    meta["recompile_status"] = status                 # FULL_MATCH | PARTIAL | NO_MATCH | SKIPPED
    meta["source_authoritative"] = (status == "FULL_MATCH")
    json.dump(meta, open(f"{out}/compiler.json","w"), indent=2)
    print(msg); sys.exit(0)
m = re.search(r'(\d+\.\d+\.\d+)', comp)
if not m: finish("SKIPPED", "  recompile=SKIPPED (no compiler version parsed) — source NOT authoritative")
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
    finish("SKIPPED", f"  recompile=SKIPPED (need solc {ver}; TRON fork = exact match, stock solc = approximate). `bash tooling/bootstrap.sh` or `solc-select install {ver}` to enable. — source NOT authoritative")
srcdir = f"{out}/src"; sources = {}
for root,_,files in os.walk(srcdir):
    for f in files:
        if f.endswith(".sol"):
            rel = os.path.relpath(os.path.join(root,f), srcdir)
            sources[rel] = {"content": open(os.path.join(root,f), encoding="utf-8", errors="replace").read()}
settings = {"optimizer": {"enabled": bool(meta.get("optimizer")), "runs": int(meta.get("optimizer_runs") or 200)},
            "outputSelection": {"*": {"*": ["evm.deployedBytecode"]}}}   # full object -> also immutableReferences
evm = meta.get("evm_version")
if evm and evm != "default": settings["evmVersion"] = evm
if meta.get("via_ir"): settings["viaIR"] = True
inp = {"language":"Solidity","sources":sources,"settings":settings}
try:
    r = subprocess.run([solc,"--standard-json"], input=json.dumps(inp), capture_output=True, text=True, timeout=240)
    oj = json.loads(r.stdout or "{}")
except Exception as e:
    finish("SKIPPED", f"  recompile=SKIPPED (solc failed: {str(e)[:80]}) — source NOT authoritative")
dep = ""; immrefs = {}
for cs in (oj.get("contracts") or {}).values():
    for cname, obj in cs.items():
        dbc = obj.get("evm",{}).get("deployedBytecode",{}) or {}
        b = (dbc.get("object") or "").lower()
        if cname == target and b: dep = b; immrefs = dbc.get("immutableReferences") or {}
if not dep:
    best = None
    for cs in (oj.get("contracts") or {}).values():
        for obj in cs.values():
            dbc = obj.get("evm",{}).get("deployedBytecode",{}) or {}
            b = (dbc.get("object") or "").lower()
            if b and (best is None or len(b) > len(best[0])): best = (b, dbc.get("immutableReferences") or {})
    if best: dep, immrefs = best
if not dep:
    errs = [e.get("formattedMessage","") for e in oj.get("errors",[]) if e.get("severity")=="error"]
    finish("SKIPPED", "  recompile=SKIPPED (no deployedBytecode; compile error: %s) — source NOT authoritative" % (errs[0][:100] if errs else "unknown"))
def strip_meta(hx):
    try:
        n = int(hx[-4:], 16); return hx[:-(n+2)*2]
    except Exception: return hx
def mask_imm(hx, refs):
    # zero the immutable byte-ranges (set at CONSTRUCTION, legitimately differ from the
    # compiled placeholder) so an immutable-bearing contract can still prove FULL identity.
    if not refs: return hx
    try: b = bytearray.fromhex(hx)
    except Exception: return hx
    for lst in refs.values():
        for r in lst:
            s, l = int(r.get("start",0)), int(r.get("length",0))
            for i in range(s, min(s+l, len(b))): b[i] = 0
    return b.hex()
nimm = sum(len(v) for v in immrefs.values()) if immrefs else 0
kh = subprocess.run(["cast","keccak","0x"+dep], capture_output=True, text=True).stdout.strip().lower().replace("0x","")
if kh and kh == onchain:
    finish("FULL_MATCH", f"  recompile=FULL-MATCH (solc {ver} {kind}) — source→deployed bytecode independently verified; source IS authoritative")
elif immrefs and runtime and len(dep)==len(runtime) and mask_imm(dep,immrefs)==mask_imm(runtime,immrefs):
    finish("FULL_MATCH", f"  recompile=FULL-MATCH (solc {ver} {kind}; {nimm} immutable region(s) masked — set at construction, metadata intact) — source IS authoritative")
elif runtime and strip_meta(dep) and strip_meta(dep) == strip_meta(runtime):
    finish("PARTIAL", f"  recompile=PARTIAL-MATCH (solc {ver} {kind}; only trailing metadata differs) — source is very likely the deployed one, but NOT a full byte-proof")
elif immrefs and runtime and strip_meta(mask_imm(dep,immrefs)) and strip_meta(mask_imm(dep,immrefs)) == strip_meta(mask_imm(runtime,immrefs)):
    finish("PARTIAL", f"  recompile=PARTIAL-MATCH (solc {ver} {kind}; {nimm} immutable region(s) masked + trailing metadata differs) — source likely the deployed one, not a full byte-proof")
else:
    note = "" if kind=="tron" else " — used STOCK solc; the TRON solc fork is needed for exact bytes"
    finish("NO_MATCH", f"  recompile=NO-MATCH{note} (review source/settings, or get the exact TRON compiler) — source NOT authoritative")
PY
fi

# 5) proxy resolution: if this is a proxy, resolve the implementation and fetch its source too
#    (multi-hop: proxy -> beacon -> impl, or nested proxies, up to 3 levels)
if [ "${GETSRC_DEPTH:-0}" -lt 3 ]; then
IMPL_LINE=$(python3 - "$ADDR" <<'PY' 2>/dev/null || true
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
impl = ""; via = ""
for s in ("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",   # EIP-1967 impl
          "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7"):  # EIP-1822 proxiable
    try: impl = nonzero20(rpc("eth_getStorageAt", ["0x"+evm20, s, "latest"]))
    except Exception: impl = ""
    if impl: via = "slot"; break
if not impl:   # EIP-1967 BEACON slot -> beacon.implementation()
    try: beacon = nonzero20(rpc("eth_getStorageAt", ["0x"+evm20, "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50", "latest"]))
    except Exception: beacon = ""
    if beacon:
        try: impl = nonzero20(rpc("eth_call", [{"to":"0x"+beacon,"data":"0x5c60da1b"}, "latest"]))  # implementation()
        except Exception: impl = ""
        if impl: via = "beacon"
if not impl:
    for sel in ("0x5c60da1b",):  # implementation() getter on the proxy itself
        try: impl = nonzero20(rpc("eth_call", [{"to":"0x"+evm20,"data":sel}, "latest"]))
        except Exception: impl = ""
        if impl: via = "getter"; break
if impl and impl.lower()!=evm20.lower():
    payload = b'\x41'+bytes.fromhex(impl)
    full = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n=int.from_bytes(full,'big'); b58=''
    while n>0: n,rem=divmod(n,58); b58=ALPH[rem]+b58
    for byte in full:
        if byte==0: b58='1'+b58
        else: break
    print(f"{b58} {via}")
PY
)
  IMPL="${IMPL_LINE%% *}"; IMPL_VIA="${IMPL_LINE#* }"
  if [ -n "$IMPL" ]; then
    echo "  proxy detected (via ${IMPL_VIA}) → implementation $IMPL — fetching its source into $OUT/impl/"
    GETSRC_DEPTH=$(( ${GETSRC_DEPTH:-0} + 1 )) bash "$0" "$IMPL" "$OUT/impl" || true
  fi
fi

rm -f "$OUT/_info.json" "$OUT/_gci.json" 2>/dev/null || true
exit "$RC"
