#!/usr/bin/env bash
# =============================================================================
# review-ledger.sh — dedup guard: don't re-audit the same contract twice.
# =============================================================================
# Identity = on-chain code_hash (+ implementation code_hash for proxies).
# "Knowledge version" = the skill's VERSION file (bump it when checklists / rules
# / methodology change so prior reviews are flagged stale).
#
# A review is SKIPPED only when ALL hold: same address, same code_hash, same
# impl_hash, same skill VERSION — AND the user did not force a re-check.
# It PROCEEDS (with a reason) when the code changed, the impl changed, the skill
# knowledge version bumped, the address is new, or RECHECK=1 is set.
#
#   review-ledger.sh check  <T-address>            # after gate 1 (needs get-source output)
#   review-ledger.sh record <T-address> [report]   # after gate 9
#
# exit codes (check):  0 = PROCEED   10 = SKIP (already current)   2 = run get-source first
# env: FINDINGS_DIR (default ./findings), RECHECK=1 to force a re-review.
# =============================================================================
set -u
CMD="${1:-}"; ADDR="${2:-}"
FINDINGS="${FINDINGS_DIR:-./findings}"
LEDGER="$FINDINGS/.review-ledger.json"
SKILL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(cat "$SKILL_DIR/VERSION" 2>/dev/null | tr -d '[:space:]' || echo '0.0.0')"
COMMIT="$(git -C "$SKILL_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)"
SRC="$FINDINGS/$ADDR/src-fetched"

[ -z "$CMD" ] || [ -z "$ADDR" ] && { echo "usage: review-ledger.sh check|record <address> [report]"; exit 64; }

# pull code_hash (+ impl hash) from the get-source output for this address
read_hashes() {
  python3 - "$SRC" <<'PY'
import sys, json, os
src = sys.argv[1]
try: ch = (json.load(open(f"{src}/compiler.json")).get("code_hash") or "")
except Exception: ch = ""
ih = ""
p = f"{src}/impl/compiler.json"
if os.path.exists(p):
    try: ih = (json.load(open(p)).get("code_hash") or "")
    except Exception: ih = ""
print((ch or "-") + " " + (ih or "-"))
PY
}

case "$CMD" in
  check)
    [ -f "$SRC/compiler.json" ] || { echo "RUN-GETSOURCE — fetch first: tooling/get-source.sh $ADDR"; exit 2; }
    read CH IH < <(read_hashes)
    [ "$CH" = "-" ] && { echo "NO-CODEHASH — cannot dedup (bytecode read failed); PROCEED"; exit 0; }
    python3 - "$LEDGER" "$ADDR" "$CH" "$IH" "$VERSION" "${RECHECK:-0}" <<'PY'
import sys, json, os
ledger, addr, ch, ih, ver, recheck = sys.argv[1:7]
try: L = json.load(open(ledger)).get("entries", [])
except Exception: L = []
if recheck == "1":
    print(f"PROCEED — forced re-check (RECHECK=1)"); sys.exit(0)
mine = next((e for e in L if e.get("address") == addr), None)
same_code_elsewhere = next((e for e in L if e.get("code_hash") == ch and e.get("address") != addr), None)
if mine is None:
    if same_code_elsewhere:
        print(f"NEW-ADDRESS-SAME-BYTECODE — identical code_hash already reviewed at "
              f"{same_code_elsewhere['address']} (report {same_code_elsewhere.get('report','?')}); "
              f"those findings likely transfer — PROCEED (verify realized severity vs THIS deployment)")
    else:
        print("NEW — never reviewed; PROCEED")
    sys.exit(0)
if mine.get("code_hash") != ch:
    print(f"CODE-CHANGED — contract redeployed/changed (was {mine.get('code_hash','?')[:10]} now {ch[:10]}); PROCEED (re-review)")
    sys.exit(0)
if (mine.get("impl_hash") or "-") != (ih or "-"):
    print(f"IMPL-CHANGED — proxy implementation upgraded (was {(mine.get('impl_hash') or '-')[:10]} now {(ih or '-')[:10]}); PROCEED (re-review)")
    sys.exit(0)
if mine.get("skill_version") != ver:
    print(f"SKILL-UPDATED — reviewed under skill v{mine.get('skill_version','?')}, now v{ver}; PROCEED (new knowledge may surface new findings)")
    sys.exit(0)
print(f"REVIEWED-CURRENT — static code review already done {mine.get('date','?')} under skill "
      f"v{ver} (code_hash {ch[:10]}, unchanged); report: {mine.get('report','?')}. "
      f"REUSE the static findings + SKIP code-analysis gates (2,4,5,6,7) — but STILL re-run the "
      f"LIVE-STATE gates (3 custody/permissions, 8 deployment/markets/chain-params) and re-assess "
      f"realized severity. Full re-review only if RECHECK=1.")
sys.exit(10)
PY
    exit $?
    ;;
  record)
    [ -f "$SRC/compiler.json" ] || { echo "cannot record — no get-source output at $SRC" >&2; exit 2; }
    read CH IH < <(read_hashes)
    REPORT="${3:-$FINDINGS/$ADDR/report.md}"
    DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    mkdir -p "$FINDINGS"
    python3 - "$LEDGER" "$ADDR" "$CH" "$IH" "$VERSION" "$COMMIT" "$DATE" "$REPORT" <<'PY'
import sys, json, os
ledger, addr, ch, ih, ver, commit, date, report = sys.argv[1:9]
try: data = json.load(open(ledger))
except Exception: data = {}
L = data.get("entries", [])
L = [e for e in L if e.get("address") != addr]   # replace any prior entry for this address
sev = {}
mp = f"{os.path.dirname(report)}/metadata.json"
try: sev = json.load(open(mp)).get("severity_counts", {})
except Exception: pass
L.append({"address": addr, "code_hash": ch, "impl_hash": (ih if ih != "-" else None),
          "skill_version": ver, "skill_commit": commit, "date": date,
          "report": report, "severity": sev})
data["entries"] = L
json.dump(data, open(ledger, "w"), indent=2)
print(f"recorded {addr} @ code_hash {ch[:10]} under skill v{ver} ({commit}) -> {ledger}")
PY
    exit $?
    ;;
  *) echo "usage: review-ledger.sh check|record <address> [report]"; exit 64 ;;
esac
