#!/usr/bin/env bash
# =============================================================================
# bootstrap.sh — FEARSOFF TRON/EVM smart-contract audit workstation bootstrap
# =============================================================================
# One-time, idempotent tooling bootstrap for macOS + Linux (Debian/Ubuntu/Fedora).
# Every step checks for an existing install before acting; safe to re-run.
#
# Covers:
#   solc-select (+ 0.5.x/0.6.x/0.7.x/0.8.x), TRON tv_ solc fork, Foundry,
#   Slither, Mythril, Semgrep + Decurity rules, Aderyn (cyfrinup),
#   heimdall-rs (bifrost), panoramix, TronBox, crytic-compile,
#   Echidna, Medusa, TronGrid/Tronscan API key env setup.
#
# Usage:   bash bootstrap.sh
# Options: SOLC_VERSIONS="0.5.17 0.6.12 0.7.6 0.8.19 0.8.26" bash bootstrap.sh
#          TRON_SOLC_VERSIONS="0.4.25 0.5.8 0.7.6 0.8.18 0.8.27" bash bootstrap.sh
# =============================================================================

set -u -o pipefail

# ------------------------------ configuration -------------------------------
SOLC_VERSIONS="${SOLC_VERSIONS:-0.5.17 0.6.12 0.7.6 0.8.19 0.8.26}"
# Spread across the major TRON bands so get-source.sh recompile-match can reach FULL-MATCH
# for old and new targets alike. Tags are tv_<ver> (except 0.4.25 → 0.4.25_Odyssey_v3.2.3).
TRON_SOLC_VERSIONS="${TRON_SOLC_VERSIONS:-0.4.25 0.5.8 0.5.17 0.6.12 0.7.6 0.8.18 0.8.22 0.8.25 0.8.26 0.8.27}"
AUDIT_HOME="${AUDIT_HOME:-$HOME/audit-tools}"
ENV_DIR="$HOME/.config/fearsoff"
ENV_FILE="$ENV_DIR/audit.env"
LOCAL_BIN="$HOME/.local/bin"

# ------------------------------ logging helpers -----------------------------
BOLD=$(tput bold 2>/dev/null || true); RESET=$(tput sgr0 2>/dev/null || true)
log()  { printf '%s\n' "${BOLD}==> $*${RESET}"; }
ok()   { printf '    [ok] %s\n' "$*"; }
warn() { printf '    [warn] %s\n' "$*" >&2; }
FAILURES=()
fail() { printf '    [FAIL] %s\n' "$*" >&2; FAILURES+=("$*"); }
have() { command -v "$1" >/dev/null 2>&1; }

# ------------------------------ platform detection --------------------------
OS="$(uname -s)"; ARCH="$(uname -m)"
case "$OS" in
  Darwin) PLATFORM=macos ;;
  Linux)  PLATFORM=linux ;;
  *) echo "Unsupported OS: $OS" >&2; exit 1 ;;
esac

# Use .zshenv (NOT .zshrc) for zsh: it is sourced by NON-interactive shells too, so the PATH
# and audit.env exports reach tools spawned by subagents/scripts. .zshrc would only apply to
# interactive terminals and silently leave agent shells without the toolchain/keys.
PROFILE="$HOME/.bashrc"
case "${SHELL:-}" in *zsh) PROFILE="$HOME/.zshenv" ;; esac
touch "$PROFILE"

# idempotent: append a line to the shell profile only if absent
ensure_profile_line() {
  local line="$1"
  grep -qsF "$line" "$PROFILE" || printf '%s\n' "$line" >> "$PROFILE"
}

# make a dir active in PATH for this run AND persist it in the profile
path_add() {
  local dir="$1"
  case ":$PATH:" in *":$dir:"*) ;; *) export PATH="$dir:$PATH" ;; esac
  ensure_profile_line "export PATH=\"$dir:\$PATH\""
}

mkdir -p "$LOCAL_BIN" "$AUDIT_HOME" "$ENV_DIR"
path_add "$LOCAL_BIN"

# download latest github release asset matching a pattern -> stdout is the url
github_latest_asset_url() { # repo pattern (URL must END with pattern)
  curl -fsSL "https://api.github.com/repos/$1/releases/latest" \
    | grep -o "\"browser_download_url\": *\"[^\"]*$2\"" \
    | head -1 | sed 's/.*"\(https[^"]*\)"/\1/'
}

# =============================================================================
log "[0/16] OS prerequisites (compilers, libs, python, git)"
# =============================================================================
if [ "$PLATFORM" = macos ]; then
  xcode-select -p >/dev/null 2>&1 || { warn "Xcode CLT missing; launching installer (re-run after)"; xcode-select --install || true; }
  if ! have brew; then
    log "Installing Homebrew"
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" || fail "homebrew"
    [ -x /opt/homebrew/bin/brew ] && eval "$(/opt/homebrew/bin/brew shellenv)"
    [ -x /usr/local/bin/brew ]    && eval "$(/usr/local/bin/brew shellenv)"
  fi
  have brew && ok "Homebrew $(brew --version | head -1)"
  # GNU coreutils (gtimeout) + gnu-sed (gsed) + jq — the skill's macOS note and get-source.sh rely on these
  brew install coreutils gnu-sed jq >/dev/null 2>&1 && ok "coreutils/gnu-sed/jq (use gtimeout, gsed)" || warn "coreutils/gnu-sed/jq"
else
  if have apt-get; then
    sudo apt-get update -y
    sudo apt-get install -y build-essential curl git jq pkg-config libssl-dev libudev-dev \
      python3 python3-pip python3-venv pipx unzip || fail "apt prerequisites"
  elif have dnf; then
    sudo dnf install -y gcc gcc-c++ make curl git jq pkgconf-pkg-config openssl-devel systemd-devel \
      python3 python3-pip pipx unzip || fail "dnf prerequisites"
  else
    warn "No apt/dnf found — install build tools, python3, pip, git manually."
  fi
fi

# =============================================================================
log "[1/16] pipx (isolated Python CLI installs)"
# =============================================================================
if ! have pipx; then
  if [ "$PLATFORM" = macos ]; then brew install pipx || fail "pipx"
  else python3 -m pip install --user pipx || fail "pipx"; fi
fi
have pipx && { pipx ensurepath >/dev/null 2>&1 || true; path_add "$HOME/.local/bin"; ok "pipx $(pipx --version 2>/dev/null)"; }

# =============================================================================
log "[2/16] Rust toolchain (required to build heimdall-rs via bifrost)"
# =============================================================================
if ! have cargo && [ ! -x "$HOME/.cargo/bin/cargo" ]; then
  curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs | sh -s -- -y --no-modify-path || fail "rustup"
fi
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
path_add "$HOME/.cargo/bin"
have cargo && ok "$(cargo --version)"

# =============================================================================
log "[3/16] Node.js + npm (required by TronBox)"
# =============================================================================
if ! have node; then
  if [ "$PLATFORM" = macos ]; then brew install node || fail "node"
  elif have apt-get; then sudo apt-get install -y nodejs npm || fail "node"
  elif have dnf; then sudo dnf install -y nodejs npm || fail "node"; fi
fi
if have npm; then
  # avoid sudo for `npm -g` by using a user-writable prefix
  NPM_PREFIX="$(npm config get prefix 2>/dev/null)"
  if [ -n "$NPM_PREFIX" ] && [ ! -w "$NPM_PREFIX/lib" ] 2>/dev/null; then
    npm config set prefix "$HOME/.npm-global"
    path_add "$HOME/.npm-global/bin"
  fi
  ok "node $(node --version) / npm $(npm --version)"
fi

# =============================================================================
log "[4/16] solc-select + Ethereum solc versions ($SOLC_VERSIONS)"
# =============================================================================
have solc-select || pipx install solc-select || fail "solc-select"
if have solc-select; then
  for v in $SOLC_VERSIONS; do
    solc-select versions 2>/dev/null | grep -q "^$v" || solc-select install "$v" || fail "solc $v"
  done
  solc-select use "$(printf '%s\n' $SOLC_VERSIONS | tail -1)" >/dev/null 2>&1 || true
  ok "solc-select: $(solc-select versions 2>/dev/null | tr '\n' ' ')"
  [ "$PLATFORM" = macos ] && [ "$ARCH" = arm64 ] && \
    warn "solc <0.8.24 binaries are x86_64; Apple Silicon needs Rosetta 2 (softwareupdate --install-rosetta)"
fi

# =============================================================================
log "[5/16] TRON solidity fork (tv_ solc) — versions: $TRON_SOLC_VERSIONS"
# =============================================================================
# TVM contracts MUST be compiled with tronprotocol/solidity, not vanilla solc:
# same version number, DIFFERENT bytecode (TVM opcodes/metadata/prologue). This is
# what lets get-source.sh recompile-match reach FULL-MATCH. Two asset schemes:
#   - modern tags (>=0.8.18): ship a plain solc-macos / solc-static-linux binary
#   - old tags (<=0.8.11 .. 0.4.25): ship a ZIP whose codename suffix varies per
#     release (0.4.25 also has an irregular tag), so the exact asset is resolved
#     from the GitHub releases index rather than guessed from the version.
TRON_SOLC_DIR="$HOME/.tron-solc"
[ "$PLATFORM" = macos ] && TV_PLAT=mac || TV_PLAT=linux
TV_RELEASES="$(mktemp)"
curl -fsSL "https://api.github.com/repos/tronprotocol/solidity/releases?per_page=100" -o "$TV_RELEASES" 2>/dev/null \
  || { warn "TRON solc: releases index fetch failed; only plain-binary tags (>=0.8.18) will resolve"; : > "$TV_RELEASES"; }

# <version> -> prints "<download_url>\t<is_zip:0|1>" (empty if no asset for this platform)
resolve_tv_asset() {
  python3 - "$1" "$TV_PLAT" "$TV_RELEASES" <<'PY'
import json, sys
ver, plat, path = sys.argv[1], sys.argv[2], sys.argv[3]
try: rels = json.load(open(path))
except Exception: sys.exit(0)
rel = next((r for r in rels if r.get("tag_name") == f"tv_{ver}"), None) \
   or next((r for r in rels if r.get("tag_name","").startswith(f"{ver}_")), None)
if not rel: sys.exit(0)
assets = {a["name"]: a["browser_download_url"] for a in rel.get("assets", [])}
exact = "solc-macos" if plat == "mac" else "solc-static-linux"
if exact in assets:
    print(assets[exact] + "\t0"); sys.exit(0)
needle = f"-{plat}_"   # matches solidity-mac_ / tron-solidity-mac_ / solidity-linux_ ...
for name, url in assets.items():
    if needle in name and name.endswith(".zip"):
        print(url + "\t1"); sys.exit(0)
PY
}

for v in $TRON_SOLC_VERSIONS; do
  dest="$TRON_SOLC_DIR/tv_$v/solc"
  if [ -x "$dest" ]; then ok "tron-solc $v already installed"; ln -sf "$dest" "$LOCAL_BIN/tron-solc-$v"; continue; fi
  mkdir -p "$(dirname "$dest")"
  line="$(resolve_tv_asset "$v")"; url="${line%%$'\t'*}"; is_zip="${line##*$'\t'}"
  if [ -z "$url" ]; then   # fallback: direct URL (valid only for plain-binary >=0.8.18 tags)
    [ "$PLATFORM" = macos ] && asset="solc-macos" || asset="solc-static-linux"
    url="https://github.com/tronprotocol/solidity/releases/download/tv_$v/$asset"; is_zip=0
  fi
  if [ "$is_zip" = 1 ]; then
    z="$(mktemp)"; td="$(mktemp -d)"
    if curl -fL -o "$z" "$url" && unzip -oq "$z" -d "$td"; then
      inner="$(find "$td" -type f -name solc | head -1)"
      [ -n "$inner" ] && cp "$inner" "$dest" || fail "tron-solc $v (no solc in zip)"
    else fail "tron-solc $v (zip $url)"; fi
    rm -rf "$z" "$td"
  else
    curl -fL -o "$dest" "$url" || fail "tron-solc $v (download $url)"
  fi
  if [ -f "$dest" ]; then
    chmod +x "$dest"
    [ "$PLATFORM" = macos ] && xattr -dr com.apple.quarantine "$dest" 2>/dev/null || true
    ln -sf "$dest" "$LOCAL_BIN/tron-solc-$v"
    ok "tron-solc $v -> $LOCAL_BIN/tron-solc-$v"
  else
    warn "tron-solc $v: no $TV_PLAT asset resolved (skipped)"
  fi
done
rm -f "$TV_RELEASES"
# default symlink = last successfully-installed version in the list
last_tv="$(printf '%s\n' $TRON_SOLC_VERSIONS | tail -1)"
[ -x "$TRON_SOLC_DIR/tv_$last_tv/solc" ] && ln -sf "$TRON_SOLC_DIR/tv_$last_tv/solc" "$LOCAL_BIN/tron-solc"
[ "$PLATFORM" = macos ] && [ "$ARCH" = arm64 ] && \
  warn "TRON solc binaries are x86_64; run via Rosetta 2 on Apple Silicon (softwareupdate --install-rosetta)"

# =============================================================================
log "[6/16] Foundry (forge / cast / anvil / chisel)"
# =============================================================================
path_add "$HOME/.foundry/bin"
if ! have forge; then
  curl -fsSL https://foundry.paradigm.xyz | bash || fail "foundryup installer"
  "$HOME/.foundry/bin/foundryup" || fail "foundryup"
fi
have forge && ok "$(forge --version | head -1)"

# =============================================================================
log "[7/16] Slither (static analysis)"
# =============================================================================
have slither || pipx install slither-analyzer || fail "slither"
have slither && ok "slither $(slither --version 2>/dev/null)"

# =============================================================================
log "[8/16] crytic-compile (standalone compilation driver)"
# =============================================================================
have crytic-compile || pipx install crytic-compile || fail "crytic-compile"
have crytic-compile && ok "crytic-compile $(crytic-compile --version 2>/dev/null | head -1)"

# =============================================================================
log "[9/16] Mythril (symbolic execution)"
# =============================================================================
if ! have myth; then
  # mythril's deps are picky: resolve a REAL python (pyenv shims can dangle), then
  # pin setuptools<81 so pkg_resources (removed from setuptools 81, needed by py-evm) exists on Python 3.12+.
  MYTH_PY="$( { command -v pyenv >/dev/null 2>&1 && pyenv which python3.12 2>/dev/null; } \
             || ls "$HOME"/.pyenv/versions/3.12.*/bin/python 2>/dev/null | head -1 \
             || command -v python3.12 || command -v python3.11 || command -v python3.10 || command -v python3 )"
  if pipx install --python "$MYTH_PY" mythril --force; then
    pipx inject mythril "setuptools<81" --force >/dev/null 2>&1 || true
  else
    fail "mythril (pipx)"; warn "fallback: docker run -v \"\$PWD\":/tmp mythril/myth analyze /tmp/Contract.sol"
  fi
fi
have myth && ok "mythril $(myth version 2>/dev/null | head -1)"

# =============================================================================
log "[10/16] Semgrep + Decurity smart-contract rules"
# =============================================================================
have semgrep || pipx install semgrep || fail "semgrep"
have semgrep && ok "semgrep $(semgrep --version 2>/dev/null)"
RULES_DIR="$AUDIT_HOME/semgrep-smart-contracts"
# PIN the ruleset commit for reproducible audits — a floating `git pull` would silently
# change results between runs. Override with DECURITY_REF=<sha|tag> to bump deliberately.
DECURITY_REF="${DECURITY_REF:-2e878a89ac7bba1f8435e8a68e3ecb7700096cd5}"
if [ ! -d "$RULES_DIR/.git" ]; then
  git clone https://github.com/Decurity/semgrep-smart-contracts "$RULES_DIR" \
    || fail "Decurity semgrep rules (clone)"
fi
if [ -d "$RULES_DIR/.git" ]; then
  git -C "$RULES_DIR" fetch --quiet origin "$DECURITY_REF" 2>/dev/null || git -C "$RULES_DIR" fetch --quiet --all 2>/dev/null || true
  if git -C "$RULES_DIR" checkout --quiet "$DECURITY_REF" 2>/dev/null; then
    ok "Decurity rules pinned @ ${DECURITY_REF:0:12} -> $RULES_DIR"
  else
    warn "Decurity rules: could not check out $DECURITY_REF (using whatever is checked out)"
  fi
fi
# TRON/TVM-native ruleset ships in-repo (no install); validate it if present.
TRON_RULES="$(cd "$(dirname "$0")" && pwd)/semgrep-tron"
if [ -d "$TRON_RULES" ]; then
  semgrep --validate --config "$TRON_RULES" >/dev/null 2>&1 \
    && ok "TRON semgrep rules valid -> $TRON_RULES (use: semgrep --config tooling/semgrep-tron/)" \
    || warn "TRON semgrep rules present but --validate failed"
fi

# =============================================================================
log "[11/16] Aderyn via cyfrinup"
# =============================================================================
path_add "$HOME/.cyfrin/bin"
if ! have aderyn; then
  have cyfrinup || curl -fsSL https://raw.githubusercontent.com/Cyfrin/up/main/install | bash || fail "cyfrinup installer"
  CYFRINUP_BIN="$(command -v cyfrinup || echo "$HOME/.cyfrin/bin/cyfrinup")"
  [ -x "$CYFRINUP_BIN" ] && { "$CYFRINUP_BIN" || fail "cyfrinup run"; }
fi
have aderyn && ok "aderyn $(aderyn --version 2>/dev/null)"

# =============================================================================
log "[12/16] heimdall-rs via bifrost  ** decompiler for UNVERIFIED contracts **"
# =============================================================================
path_add "$HOME/.bifrost/bin"
if ! have heimdall; then
  curl -fsSL https://raw.githubusercontent.com/Jon-Becker/heimdall-rs/main/bifrost/install | bash \
    || fail "bifrost installer"
  BIFROST_BIN="$(command -v bifrost || echo "$HOME/.bifrost/bin/bifrost")"
  # bifrost compiles heimdall from source (needs cargo); can take several minutes
  [ -x "$BIFROST_BIN" ] && { "$BIFROST_BIN" || fail "bifrost build of heimdall"; }
fi
have heimdall && ok "heimdall $(heimdall --version 2>/dev/null | head -1)"

# =============================================================================
log "[13/16] panoramix (fallback decompiler)"
# =============================================================================
have panoramix || pipx install panoramix-decompiler || fail "panoramix"
have panoramix && ok "panoramix installed (set WEB3_PROVIDER_URI to decompile by address)"

# =============================================================================
log "[14/16] TronBox (TRON dev/compile framework)"
# =============================================================================
if ! have tronbox; then
  have npm && npm install -g tronbox || fail "tronbox"
fi
have tronbox && ok "tronbox $(tronbox version 2>/dev/null | head -1)"

# =============================================================================
log "[15/16] Echidna + Medusa (property fuzzers) + Halmos (symbolic testing)"
# =============================================================================
if ! have echidna; then
  if [ "$PLATFORM" = macos ] && have brew; then
    brew install echidna || fail "echidna"
  else
    case "$ARCH" in x86_64) ep="x86_64-linux" ;; aarch64|arm64) ep="aarch64-linux" ;; esac
    url="$(github_latest_asset_url crytic/echidna "$ep.tar.gz")"
    if [ -n "${url:-}" ]; then
      curl -fL "$url" | tar -xz -C "$LOCAL_BIN" echidna && chmod +x "$LOCAL_BIN/echidna" || fail "echidna extract"
    else fail "echidna (no release asset for $ARCH)"; fi
  fi
fi
have echidna && ok "echidna $(echidna --version 2>/dev/null | head -1)"

if ! have medusa; then
  if [ "$PLATFORM" = macos ] && have brew; then
    brew install medusa || fail "medusa"
  elif have go; then
    go install github.com/crytic/medusa@latest && path_add "$(go env GOPATH)/bin" || fail "medusa (go install)"
  elif [ "$ARCH" = x86_64 ]; then
    url="$(github_latest_asset_url crytic/medusa "linux-x64.tar.gz")"
    [ -n "${url:-}" ] && curl -fL "$url" | tar -xz -C "$LOCAL_BIN" medusa && chmod +x "$LOCAL_BIN/medusa" || fail "medusa"
  else
    fail "medusa (install Go, then: go install github.com/crytic/medusa@latest)"
  fi
fi
have medusa && ok "medusa $(medusa --version 2>/dev/null | head -1)"

# Halmos — symbolic-execution unit tester (the skill's gate 7 accepts a symbolic counterexample as proof)
if ! have halmos; then
  { have pipx && pipx install halmos >/dev/null 2>&1; } || pip install --user halmos >/dev/null 2>&1 || warn "halmos (retry: pipx install halmos)"
fi
have halmos && ok "halmos $(halmos --version 2>/dev/null | head -1)"

# =============================================================================
log "[16/16] TronGrid / Tronscan API keys (read-only rate-limit relief)"
# =============================================================================
if [ ! -f "$ENV_FILE" ]; then
  # prefer the committed template (single source of truth); fall back to inline
  EXAMPLE="$(cd "$(dirname "$0")/.." 2>/dev/null && pwd)/audit.env.example"
  if [ -f "$EXAMPLE" ]; then
    cp "$EXAMPLE" "$ENV_FILE"
  else
    cat > "$ENV_FILE" <<'EOF'
# reviewing-smart-contracts — API keys (read-only usage; NEVER commit this file)
# TronGrid: https://www.trongrid.io -> Dashboard -> API Keys.  Header: TRON-PRO-API-KEY
export TRONGRID_API_KEY=""
# TronScan: https://tronscan.org/#/myaccount/apiKeys  (verified-source fetch; keyless is stripped since 2025-08)
export TRONSCAN_API_KEY=""
export TRONGRID_MAINNET="https://api.trongrid.io"
export TRONGRID_NILE="https://nile.trongrid.io"
export TRONGRID_SHASTA="https://api.shasta.trongrid.io"
export TRONSCAN_API="https://apilist.tronscanapi.com"
export WEB3_PROVIDER_URI=""
EOF
  fi
  chmod 600 "$ENV_FILE"
  ok "wrote $ENV_FILE (fill in your keys, chmod 600 applied)"
else
  ok "$ENV_FILE already exists — left untouched"
fi
ensure_profile_line "[ -f \"$ENV_FILE\" ] && . \"$ENV_FILE\""

# =============================================================================
log "Verification summary"
# =============================================================================
verify() { # name command...
  local name="$1"; shift
  if out="$("$@" 2>&1 | head -1)"; then printf '  %-18s PASS  %s\n' "$name" "$out"
  else printf '  %-18s FAIL\n' "$name"; FAILURES+=("verify:$name"); fi
}
verify "solc-select"    solc-select versions
verify "solc"           solc --version
verify "tron-solc"      "$LOCAL_BIN/tron-solc" --version
verify "forge"          forge --version
verify "cast"           cast --version
verify "anvil"          anvil --version
verify "slither"        slither --version
verify "crytic-compile" crytic-compile --version
verify "myth"           myth version
verify "semgrep"        semgrep --version
verify "aderyn"         aderyn --version
verify "heimdall"       heimdall --version
verify "panoramix"      panoramix --help
verify "tronbox"        tronbox version
verify "echidna"        echidna --version
verify "medusa"         medusa --version

echo
if [ "${#FAILURES[@]}" -gt 0 ]; then
  printf '%s\n' "${BOLD}Completed with ${#FAILURES[@]} failure(s):${RESET}"
  printf '  - %s\n' "${FAILURES[@]}"
  echo "Re-run this script after fixing; all steps are idempotent."
  exit 1
fi
log "All tools installed. Open a NEW shell (or: source $PROFILE) and fill in $ENV_FILE."