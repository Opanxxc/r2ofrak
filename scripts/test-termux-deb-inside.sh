#!/data/data/com.termux/files/usr/bin/env bash
# ==============================================================
#  R2OFRAK Termux .deb auto-test
#  Runs INSIDE termux/termux-docker:aarch64
#  Host mounts repo at /work
# ==============================================================
set -uo pipefail

PREFIX="/data/data/com.termux/files/usr"
PASS=0 FAIL=0 WARN=0

ok()   { echo -e "\033[0;32m[PASS]\033[0m $*"; PASS=$((PASS+1)); }
bad()  { echo -e "\033[0;31m[FAIL]\033[0m $*"; FAIL=$((FAIL+1)); }
warn() { echo -e "\033[0;33m[WARN]\033[0m $*"; WARN=$((WARN+1)); }
check(){ if eval "$2" >/dev/null 2>&1; then ok "$1"; else bad "$1"; echo "  error:"; eval "$2" 2>&1 | head -5; fi }

echo ""
echo "============================================"
echo "  R2OFRAK Termux Auto-Test"
echo "============================================"

# ── Setup ──────────────────────────────────────────────────────────
export TERMUX_PKG_NO_MIRROR_PICKER=1
pkg update -y 2>/dev/null || apt update -y 2>/dev/null || true
pkg install -y python python-pip git radare2 dpkg 2>/dev/null || \
    apt-get install -y python python-pip git radare2 dpkg 2>/dev/null || true

# Find and install the .deb
DEB=$(find /work /data/data/com.termux/files/home -maxdepth 2 -name "panxcz-tools_*_aarch64.deb" 2>/dev/null | head -1)
if [ -z "$DEB" ]; then
    DEB=$(find /work /data/data/com.termux/files/home -maxdepth 2 -name "*.deb" 2>/dev/null | head -1)
fi

if [ -z "$DEB" ]; then
    bad "No .deb found in /work or ~"
    echo "  Files in /work: $(ls /work/*.deb 2>/dev/null || echo 'none')"
    echo "  Files in ~: $(ls ~/panxcz-tools_*_aarch64.deb 2>/dev/null || echo 'none')"
    exit 1
fi

echo "[*] Installing: $DEB"
apt install -y "$DEB" 2>/dev/null || dpkg --force-all -i "$DEB" 2>/dev/null || {
    bad "Failed to install .deb"
    exit 1
}

# ── Tests ──────────────────────────────────────────────────────────
echo ""
echo "=== Core Tests ==="

check "panxcz-tools binary in PATH" \
    "command -v panxcz-tools"

check "panxcz-tools-tui binary in PATH" \
    "command -v panxcz-tools-tui"

check "python can import panxcz_tools" \
    "python3 -c 'import panxcz_tools; print(panxcz-tools.__version__)'"

check "panxcz-tools --version works" \
    "panxcz-tools --version"

check "panxcz-tools --help works" \
    "panxcz-tools --help"

check "panxcz-tools-tui --help works" \
    "panxcz-tools-tui --help"

check "radare2 binary available" \
    "command -v r2"

echo ""
echo "=== CLI Tests ==="

# Test analyze on a binary
if [ -f "$PREFIX/bin/ls" ]; then
    check "panxcz-tools analyze works" \
        "panxcz-tools analyze '$PREFIX/bin/ls' --json 2>/dev/null | python3 -c 'import sys,json; d=json.load(sys.stdin); assert \"file\" in d'"
else
    warn "Skipping analyze test (no /bin/ls)"
fi

if [ -f "$PREFIX/bin/ls" ]; then
    check "panxcz-tools strings works" \
        "panxcz-tools strings '$PREFIX/bin/ls' --json 2>/dev/null | python3 -c 'import sys,json; d=json.load(sys.stdin); assert isinstance(d, list)'"
else
    warn "Skipping strings test"
fi

if [ -f "$PREFIX/bin/ls" ]; then
    check "panxcz-tools imports works" \
        "panxcz-tools imports '$PREFIX/bin/ls' --json 2>/dev/null | python3 -c 'import sys,json; d=json.load(sys.stdin); assert isinstance(d, list)'"
else
    warn "Skipping imports test"
fi

echo ""
echo "=== Extended Tests (warnings if fail) ==="

check "panxcz-tools functions works" \
    "panxcz-tools functions '$PREFIX/bin/ls' --json 2>/dev/null | python3 -c 'import sys,json; d=json.load(sys.stdin); assert isinstance(d, list)'" || true

check "panxcz-tools entropy works" \
    "panxcz-tools entropy '$PREFIX/bin/ls' 2>/dev/null" || true

echo ""
echo "============================================"
echo "  Results: ${PASS} passed, ${FAIL} failed, ${WARN} warnings"
echo "============================================"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
