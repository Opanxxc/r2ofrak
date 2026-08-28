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

# ── 1. Install build deps ─────────────────────────────────────────
pip install build 2>/dev/null || python3 -m pip install build 2>/dev/null || true

# ── 2. Build Python wheel ──────────────────────────────────────────
cd "$REPO_DIR"
mkdir -p /tmp/r2ofrak-wheels
python3 -m build --wheel --outdir /tmp/r2ofrak-wheels/ 2>/dev/null || {
    # Fallback: create wheel manually
    echo "[*] Fallback wheel creation..."
    WHL="/tmp/r2ofrak-wheels/r2ofrak-${DEB_VERSION}-py3-none-any.whl"
    python3 << 'PYEOF'
import zipfile, os, hashlib, time

whl = "/tmp/r2ofrak-wheels/r2ofrak-0.1.0-py3-none-any.whl"
src = "src/r2ofrak"

with zipfile.ZipFile(whl, "w", zipfile.ZIP_DEFLATED) as z:
    # Copy all .py files
    for root, dirs, files in os.walk(src):
        for f in files:
            if f.endswith(".py"):
                arcpath = os.path.join(root, f).replace("src/", "r2ofrak/")
                z.write(os.path.join(root, f), arcpath)
    
    # Create dist-info
    dist_info = "r2ofrak-0.1.0.dist-info"
    
    # METADATA
    metadata = """Metadata-Version: 2.1
Name: r2ofrak
Version: 0.1.0
Summary: Unified Reverse Engineering Platform
Author: Opanxxc
License: AGPL-3.0
Requires-Python: >=3.9
Requires-Dist: r2pipe>=1.8.0
Requires-Dist: textual>=0.40.0
Requires-Dist: rich>=13.0.0
"""
    z.writestr(f"{dist_info}/METADATA", metadata)
    
    # WHEEL
    wheel = """Wheel-Version: 1.0
Generator: r2ofrak-build
Root-Is-Purelib: true
Tag: py3-none-any
"""
    z.writestr(f"{dist_info}/WHEEL", wheel)
    
    # RECORD
    record_lines = []
    for info in z.infolist():
        record_lines.append(f"{info.filename},sha256={hashlib.sha256(z.read(info.filename)).hexdigest()},{len(z.read(info.filename))}")
    record_lines.append(f"{dist_info}/RECORD,,")
    z.writestr(f"{dist_info}/RECORD", "\n".join(record_lines))
    
    # entry_points.txt
    eps = """[console_scripts]
r2ofrak = r2ofrak.cli:main
r2ofrak-tui = r2ofrak.tui:main
"""
    z.writestr(f"{dist_info}/entry_points.txt", eps)
    
    # top_level.txt
    z.writestr(f"{dist_info}/top_level.txt", "r2ofrak\n")

print(f"Wheel created: {whl}")
PYEOF
}
echo "[+] Wheel: $(ls /tmp/r2ofrak-wheels/*.whl 2>/dev/null)"

# ── 3. Create .deb structure ───────────────────────────────────────
STAGE="/tmp/r2ofrak-deb"
rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN"
mkdir -p "$STAGE/usr/lib/python3/dist-packages"
mkdir -p "$STAGE/usr/bin"

# Install wheel into staging
python3 -m pip install --target="$STAGE/usr/lib/python3/dist-packages" \
    /tmp/r2ofrak-wheels/*.whl --no-deps 2>/dev/null || true

# If wheel install failed, copy source directly
if [ ! -d "$STAGE/usr/lib/python3/dist-packages/r2ofrak" ]; then
    echo "[*] Fallback: copying source directly..."
    cp -r "$REPO_DIR/src/r2ofrak" "$STAGE/usr/lib/python3/dist-packages/"
fi

# Create CLI wrapper
cat > "$STAGE/usr/bin/r2ofrak" << 'WRAPPER'
#!/usr/bin/env python3
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lib/python3/dist-packages"))
from r2ofrak.cli import main
main()
WRAPPER
chmod 755 "$STAGE/usr/bin/r2ofrak"

# Create TUI wrapper
cat > "$STAGE/usr/bin/r2ofrak-tui" << 'WRAPPER'
#!/usr/bin/env python3
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lib/python3/dist-packages"))
from r2ofrak.tui import main
main()
WRAPPER
chmod 755 "$STAGE/usr/bin/r2ofrak-tui"

# ── 4. Control file ────────────────────────────────────────────────
cat > "$STAGE/DEBIAN/control" << EOF
Package: $PKG_NAME
Version: $DEB_VERSION
Section: devel
Priority: optional
Architecture: $ARCH
Maintainer: Opanxxc <opanxxc@users.noreply.github.com>
Depends: python3 (>= 3.9), python3-pip, radare2
Recommends: radare2 (>= 5.9)
Homepage: https://github.com/Opanxxc/r2ofrak
Description: R2OFRAK - Unified Reverse Engineering Platform
 Combines radare2 (disassembly/analysis/debugging) with OFRAK
 (unpacking/modification/repacking) into one powerful tool.
 Features: TUI interface, hex viewer, disassembler, string extraction,
 import/export analysis, vulnerability scanning, binary patching,
 ELF/PE/Mach-O/APK support, firmware unpacking, and more.
 .
 Run 'r2ofrak-tui' for interactive mode or 'r2ofrak --help' for CLI.
EOF

# ── 5. Build .deb ──────────────────────────────────────────────────
cd /tmp
fakeroot dpkg-deb --build "$STAGE" "${PKG_NAME}_${DEB_VERSION}_${ARCH}.deb" 2>/dev/null || \
    dpkg-deb --root-owner-group --build "$STAGE" "${PKG_NAME}_${DEB_VERSION}_${ARCH}.deb" 2>/dev/null || \
    dpkg-deb --build "$STAGE" "${PKG_NAME}_${DEB_VERSION}_${ARCH}.deb"

ls -lh "/tmp/${PKG_NAME}_${DEB_VERSION}_${ARCH}.deb"
echo "[+] Desktop .deb built successfully!"
