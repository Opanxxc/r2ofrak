#!/usr/bin/env bash
# ============================================================
#  R2OFRAK Desktop .deb builder
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

# ── 1. Install build deps ─────────────────────────────────────────
pip install build 2>/dev/null || python3 -m pip install build 2>/dev/null || true

# ── 2. Create wheel manually (most reliable) ──────────────────────
cd "$REPO_DIR"
WHEELS="/tmp/r2ofrak-wheels"
mkdir -p "$WHEELS"

python3 << 'PYEOF'
import zipfile, os, hashlib

whl_name = "r2ofrak-0.1.0-py3-none-any.whl"
whl = f"/tmp/r2ofrak-wheels/{whl_name}"
src = "src/r2ofrak"

with zipfile.ZipFile(whl, "w", zipfile.ZIP_DEFLATED) as z:
    for root, dirs, files in os.walk(src):
        for f in files:
            if f.endswith(".py"):
                arc = os.path.join(root, f).replace("src/", "r2ofrak/")
                z.write(os.path.join(root, f), arc)
    
    di = "r2ofrak-0.1.0.dist-info"
    z.writestr(f"{di}/METADATA", """Metadata-Version: 2.1
Name: r2ofrak
Version: 0.1.0
Summary: Unified Reverse Engineering Platform
Author: Opanxxc
License: AGPL-3.0
Requires-Python: >=3.9
Requires-Dist: r2pipe>=1.8.0
Requires-Dist: textual>=0.40.0
Requires-Dist: rich>=13.0.0
""")
    z.writestr(f"{di}/WHEEL", "Wheel-Version: 1.0\nGenerator: r2ofrak-build\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
    z.writestr(f"{di}/entry_points.txt", "[console_scripts]\nr2ofrak = r2ofrak.cli:main\nr2ofrak-tui = r2ofrak.tui:main\n")
    z.writestr(f"{di}/top_level.txt", "r2ofrak\n")

print(f"Wheel: {whl}")
PYEOF

# ── 3. Create .deb ────────────────────────────────────────────────
STAGE="/tmp/r2ofrak-deb"
rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN"
mkdir -p "$STAGE/usr/lib/python3/dist-packages"
mkdir -p "$STAGE/usr/bin"

# Install wheel
python3 -m pip install --target="$STAGE/usr/lib/python3/dist-packages" \
    "$WHEELS"/*.whl --no-deps 2>/dev/null || true

# Fallback: copy source directly
if [ ! -d "$STAGE/usr/lib/python3/dist-packages/r2ofrak" ]; then
    cp -r "$REPO_DIR/src/r2ofrak" "$STAGE/usr/lib/python3/dist-packages/"
fi

# Wrapper scripts
cat > "$STAGE/usr/bin/r2ofrak" << 'W'
#!/usr/bin/env python3
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lib/python3/dist-packages"))
from r2ofrak.cli import main
main()
W
chmod 755 "$STAGE/usr/bin/r2ofrak"

cat > "$STAGE/usr/bin/r2ofrak-tui" << 'W'
#!/usr/bin/env python3
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lib/python3/dist-packages"))
from r2ofrak.tui import main
main()
W
chmod 755 "$STAGE/usr/bin/r2ofrak-tui"

# Control
cat > "$STAGE/DEBIAN/control" << EOF
Package: $PKG_NAME
Version: $DEB_VERSION
Section: devel
Priority: optional
Architecture: $ARCH
Maintainer: Opanxxc <opanxxc@users.noreply.github.com>
Depends: python3 (>= 3.9), python3-pip, radare2
Homepage: https://github.com/Opanxxc/r2ofrak
Description: R2OFRAK - Unified Reverse Engineering Platform
 Combines radare2 + OFRAK into one tool.
 Run 'r2ofrak-tui' for interactive mode or 'r2ofrak --help' for CLI.
EOF

# Build deb in REPO dir (so CI can find it)
cd "$REPO_DIR"
fakeroot dpkg-deb --build "$STAGE" "${PKG_NAME}_${DEB_VERSION}_${ARCH}.deb" 2>/dev/null || \
    dpkg-deb --root-owner-group --build "$STAGE" "${PKG_NAME}_${DEB_VERSION}_${ARCH}.deb" 2>/dev/null || \
    dpkg-deb --build "$STAGE" "${PKG_NAME}_${DEB_VERSION}_${ARCH}.deb"

ls -lh "$REPO_DIR/${PKG_NAME}_${DEB_VERSION}_${ARCH}.deb"
echo "[+] Desktop .deb built!"
