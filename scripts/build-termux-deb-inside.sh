#!/data/data/com.termux/files/usr/bin/env bash
# ==============================================================
#  R2OFRAK Termux .deb builder
#  Runs INSIDE termux/termux-docker:aarch64 container
#  Host mounts repo at /work, deb written to /work
# ==============================================================
set -euo pipefail

DEB_VERSION="${R2OFRAK_DEB_VERSION:-0.1.0}"
PKG_NAME="r2ofrak"
PREFIX="/data/data/com.termux/files/usr"
PYVER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "3.12")

echo "============================================"
echo "  Building R2OFRAK Termux .deb v${DEB_VERSION}"
echo "  Python: ${PYVER}"
echo "============================================"

# ── 1. Fix mirror + install build deps ─────────────────────────────
export TERMUX_PKG_NO_MIRROR_PICKER=1
yes | pkg update 2>/dev/null || yes | apt update 2>/dev/null || true
pkg install -y python python-pip build-essential cmake ninja \
    git radare2 dpkg fakeroot libffi openssl 2>/dev/null || \
apt-get install -y python python-pip build-essential cmake ninja \
    git radare2 dpkg fakeroot libffi openssl 2>/dev/null || true

# ── 2. Copy source to writable location ───────────────────────────
WORK="$HOME/r2ofrak-build"
rm -rf "$WORK"
mkdir -p "$WORK"
cp -r /work/. "$WORK/" 2>/dev/null || cp -r /work/* "$WORK/" 2>/dev/null || true
cd "$WORK"

# ── 3. Install Python package ─────────────────────────────────────
echo "[*] Installing R2OFRAK..."
pip install --no-cache-dir . 2>/dev/null || {
    echo "[*] Fallback: manual install..."
    pip install --no-cache-dir textual rich r2pipe 2>/dev/null || true
    mkdir -p "$PREFIX/lib/python${PYVER}/site-packages"
    cp -r src/r2ofrak "$PREFIX/lib/python${PYVER}/site-packages/"
}

# Verify
python3 -c "import r2ofrak; print(f'R2OFRAK v{r2ofrak.__version__} imported OK')" 2>/dev/null || \
    echo "[!] Import check failed (non-fatal)"

# ── 4. Check r2 ───────────────────────────────────────────────────
which r2 >/dev/null 2>&1 && echo "[+] radare2: $(r2 -v 2>&1 | head -1)" || \
    echo "[!] radare2 not found"

# ── 5. Create .deb ────────────────────────────────────────────────
echo "[*] Building .deb package..."
STAGE="$HOME/r2ofrak-deb"
rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN"
mkdir -p "$STAGE/usr/bin"

# Copy installed package files
PY_SITE="$PREFIX/lib/python${PYVER}/site-packages"
if [ -d "$PY_SITE/r2ofrak" ]; then
    mkdir -p "$STAGE$PY_SITE"
    cp -r "$PY_SITE/r2ofrak" "$STAGE$PY_SITE/"
else
    mkdir -p "$STAGE$PY_SITE"
    cp -r "$WORK/src/r2ofrak" "$STAGE$PY_SITE/"
fi

# Create entry points
cat > "$STAGE/usr/bin/r2ofrak" << WRAPPER
#!/usr/bin/env python3
import sys, os
sys.path.insert(0, '$PY_SITE')
from r2ofrak.cli import main
main()
WRAPPER
chmod 755 "$STAGE/usr/bin/r2ofrak"

cat > "$STAGE/usr/bin/r2ofrak-tui" << WRAPPER
#!/usr/bin/env python3
import sys, os
sys.path.insert(0, '$PY_SITE')
from r2ofrak.tui import main
main()
WRAPPER
chmod 755 "$STAGE/usr/bin/r2ofrak-tui"

# Control
cat > "$STAGE/DEBIAN/control" << EOF
Package: $PKG_NAME
Version: $DEB_VERSION
Section: devel
Priority: optional
Architecture: aarch64
Maintainer: Opanxxc <opanxxc@users.noreply.github.com>
Depends: python (>= 3.9), python-pip, radare2, libffi, openssl
Homepage: https://github.com/Opanxxc/r2ofrak
Description: R2OFRAK - Unified Reverse Engineering for Termux
 Combines radare2 + OFRAK into one tool for Android/Termux.
 Run 'r2ofrak-tui' for interactive mode.
EOF

# Build
DEB_OUT="$HOME/${PKG_NAME}_${DEB_VERSION}_aarch64.deb"
cd "$HOME"
fakeroot dpkg-deb --build "$STAGE" "$DEB_OUT" 2>/dev/null || \
    dpkg-deb --root-owner-group --build "$STAGE" "$DEB_OUT" 2>/dev/null || \
    dpkg-deb --build "$STAGE" "$DEB_OUT"

ls -lh "$DEB_OUT"

# ── 6. Copy to /work so host can access ────────────────────────────
cp "$DEB_OUT" /work/ 2>/dev/null && echo "[+] Copied .deb to /work" || \
    echo "[!] Could not copy to /work (will need docker cp)"

echo "[+] Termux .deb built successfully!"
