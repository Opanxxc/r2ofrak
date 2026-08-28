#!/usr/bin/env bash
# ============================================================
#  R2OFRAK Desktop .deb builder
#  Builds a Debian package with Python + radare2 + r2ofrak
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
DEB_VERSION="${R2OFRAK_DEB_VERSION:-0.1.0}"
PKG_NAME="r2ofrak"
ARCH="amd64"

echo "============================================"
echo "  Building R2OFRAK .deb v${DEB_VERSION}"
echo "============================================"

# ── 1. Build Python wheel ──────────────────────────────────────────
cd "$REPO_DIR"
python3 -m pip install build 2>/dev/null || pip install build 2>/dev/null || true
python3 -m build --wheel --outdir /tmp/r2ofrak-wheels/ 2>/dev/null || {
    # Fallback: manual wheel
    mkdir -p /tmp/r2ofrak-wheels
    python3 -c "
import zipfile, os, glob
whl = f'/tmp/r2ofrak-wheels/${PKG_NAME}-${DEB_VERSION}-py3-none-any.whl'
with zipfile.ZipFile(whl, 'w') as z:
    for root, dirs, files in os.walk('src'):
        for f in files:
            if f.endswith('.py'):
                arc = os.path.join(root, f).replace('src/', f'${PKG_NAME.replace('-','_').replace('r2ofrak','r2ofrak')}/')
                z.write(os.path.join(root, f), arc)
    z.write('pyproject.toml', 'r2ofrak-0.1.0.dist-info/METADATA')
    z.write('pyproject.toml', 'r2ofrak-0.1.0.dist-info/WHEEL')
    with open('/tmp/entry_points.txt', 'w') as ep:
        ep.write('[console_scripts]\nr2ofrak = r2ofrak.cli:main\nr2ofrak-tui = r2ofrak.tui:main\n')
    z.write('/tmp/entry_points.txt', 'r2ofrak-0.1.0.dist-info/entry_points.txt')
    with open('/tmp/top_level.txt', 'w') as tl:
        tl.write('r2ofrak\n')
    z.write('/tmp/top_level.txt', 'r2ofrak-0.1.0.dist-info/top_level.txt')
"
}
echo "[+] Wheel built: $(ls /tmp/r2ofrak-wheels/*.whl 2>/dev/null)"

# ── 2. Create .deb structure ───────────────────────────────────────
STAGE="/tmp/r2ofrak-deb"
rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN"
mkdir -p "$STAGE/usr/lib/python3/dist-packages"
mkdir -p "$STAGE/usr/bin"

# Install wheel into staging
python3 -m pip install --target="$STAGE/usr/lib/python3/dist-packages" \
    /tmp/r2ofrak-wheels/*.whl --no-deps 2>/dev/null || true

# If wheel install failed, copy manually
if [ ! -d "$STAGE/usr/lib/python3/dist-packages/r2ofrak" ]; then
    cp -r "$REPO_DIR/src/r2ofrak" "$STAGE/usr/lib/python3/dist-packages/"
fi

# Create wrapper scripts
cat > "$STAGE/usr/bin/r2ofrak" << 'WRAPPER'
#!/usr/bin/env python3
from r2ofrak.cli import main
if __name__ == "__main__":
    main()
WRAPPER
chmod 755 "$STAGE/usr/bin/r2ofrak"

cat > "$STAGE/usr/bin/r2ofrak-tui" << 'WRAPPER'
#!/usr/bin/env python3
from r2ofrak.tui import main
if __name__ == "__main__":
    main()
WRAPPER
chmod 755 "$STAGE/usr/bin/r2ofrak-tui"

# ── 3. Control file ────────────────────────────────────────────────
cat > "$STAGE/DEBIAN/control" << EOF
Package: $PKG_NAME
Version: $DEB_VERSION
Section: devel
Priority: optional
Architecture: $ARCH
Maintainer: Opanxxc <opanxxc@users.noreply.github.com>
Depends: python3 (>= 3.9), python3-pip, radare2, libradare2-dev
Recommends: radare2 (>= 5.9)
Homepage: https://github.com/Opanxxc/r2ofrak
Description: R2OFRAK — Unified Reverse Engineering Platform
 Combines radare2 (disassembly/analysis/debugging) with OFRAK
 (unpacking/modification/repacking) into one powerful tool.
 Features: TUI interface, hex viewer, disassembler, string extraction,
 import/export analysis, vulnerability scanning, binary patching,
 ELF/PE/Mach-O/APK support, firmware unpacking, and more.
 .
 Run 'r2ofrak-tui' for interactive mode or 'r2ofrak --help' for CLI.
EOF

# ── 4. Build .deb ──────────────────────────────────────────────────
cd /tmp
fakeroot dpkg-deb --build "$STAGE" "${PKG_NAME}_${DEB_VERSION}_${ARCH}.deb" 2>/dev/null || \
    dpkg-deb --root-owner-group --build "$STAGE" "${PKG_NAME}_${DEB_VERSION}_${ARCH}.deb" 2>/dev/null || \
    dpkg-deb --build "$STAGE" "${PKG_NAME}_${DEB_VERSION}_${ARCH}.deb"

ls -lh "/tmp/${PKG_NAME}_${DEB_VERSION}_${ARCH}.deb"
echo "[+] Desktop .deb built successfully!"
