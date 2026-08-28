#!/usr/bin/env bash
# ============================================================
#  R2OFRAK Termux .deb builder (cross-compiled)
#  Builds a pure-Python arch-independent .deb on x86_64 CI
#  Works on any architecture (aarch64, arm, x86_64)
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
DEB_VERSION="${DEB_VERSION:-0.2.0}"
PKG_NAME="panxcz-tools"

echo "============================================"
echo "  Building R2OFRAK Termux .deb v${DEB_VERSION}"
echo "  (pure Python, arch-independent)"
echo "============================================"

cd "$REPO_DIR"

# ── 1. Create .deb structure ──────────────────────────────────────
STAGE="/tmp/panxcz-tools-termux-deb"
rm -rf "$STAGE"
PREFIX="/data/data/com.termux/files/usr"
mkdir -p "$STAGE/DEBIAN"
mkdir -p "$STAGE$PREFIX/lib/python3.12/site-packages"
mkdir -p "$STAGE$PREFIX/bin"

# ── 2. Copy Python package ────────────────────────────────────────
cp -r src/panxcz_tools "$STAGE$PREFIX/lib/python3.12/site-packages/"

# ── 3. Create entry point scripts ────────────────────────────────
PY_SITE="$PREFIX/lib/python3.12/site-packages"

cat > "$STAGE$PREFIX/bin/panxcz-tools" << WRAPPER
#!/data/data/com.termux/files/usr/bin/env python3
import sys, os
sys.path.insert(0, '${PY_SITE}')
from panxcz_tools.cli import main
main()
WRAPPER
chmod 755 "$STAGE$PREFIX/bin/panxcz-tools"

cat > "$STAGE$PREFIX/bin/panxcz-tools-tui" << WRAPPER
#!/data/data/com.termux/files/usr/bin/env python3
import sys, os
sys.path.insert(0, '${PY_SITE}')
from panxcz_tools.tui import main
main()
WRAPPER
chmod 755 "$STAGE$PREFIX/bin/panxcz-tools-tui"

# ── 4. Install deps via postinst ─────────────────────────────────
cat > "$STAGE/DEBIAN/postinst" << 'POSTINST'
#!/data/data/com.termux/files/usr/bin/env bash
echo "[*] Installing R2OFRAK dependencies..."
export TERMUX_PKG_NO_MIRROR_PICKER=1
yes | pkg update 2>/dev/null || true
pkg install -y python python-pip radare2 2>/dev/null || \
    apt-get install -y python python-pip radare2 2>/dev/null || true
pip install --no-cache-dir textual rich r2pipe 2>/dev/null || true
echo "[+] R2OFRAK installed! Run: panxcz-tools-tui"
POSTINST
chmod 755 "$STAGE/DEBIAN/postinst"

# ── 5. Control file ──────────────────────────────────────────────
cat > "$STAGE/DEBIAN/control" << EOF
Package: $PKG_NAME
Version: $DEB_VERSION
Section: devel
Priority: optional
Architecture: all
Maintainer: Opanxxc <opanxxc@users.noreply.github.com>
Depends: python (>= 3.9), radare2
Homepage: https://github.com/Opanxxc/panxcz-tools
Description: R2OFRAK - Unified Reverse Engineering for Termux
 Combines radare2 + OFRAK into one tool for Android/Termux.
 Features: TUI, disassembler, string extraction, hex viewer,
 import/export analysis, vulnerability scanning, binary patching.
 .
 Run 'panxcz-tools-tui' for interactive mode.
 .
 Install dependencies: pkg install python radare2
EOF

# ── 6. Build .deb ────────────────────────────────────────────────
cd /tmp
fakeroot dpkg-deb --build "$STAGE" "${PKG_NAME}_${DEB_VERSION}_all.deb" 2>/dev/null || \
    dpkg-deb --root-owner-group --build "$STAGE" "${PKG_NAME}_${DEB_VERSION}_all.deb" 2>/dev/null || \
    dpkg-deb --build "$STAGE" "${PKG_NAME}_${DEB_VERSION}_all.deb"

# Copy to repo dir for CI artifact
cp "/tmp/${PKG_NAME}_${DEB_VERSION}_all.deb" "$REPO_DIR/" 2>/dev/null || true

ls -lh "/tmp/${PKG_NAME}_${DEB_VERSION}_all.deb"
echo "[+] Termux .deb (all arch) built!"
