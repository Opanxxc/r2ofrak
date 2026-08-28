#!/usr/bin/env bash
# ============================================================
#  Panxcz Tools Desktop .deb builder
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
DEB_VERSION="${DEB_VERSION:-${R2OFRAK_DEB_VERSION:-0.2.0}}"
PKG_NAME="panxcz-tools"
ARCH="amd64"

echo "============================================"
echo "  Building Panxcz Tools .deb v${DEB_VERSION}"
echo "============================================"

# ── 1. Install build deps ─────────────────────────────────────────
pip install build 2>/dev/null || python3 -m pip install build 2>/dev/null || true

# ── 2. Create wheel manually ──────────────────────────────────────
cd "$REPO_DIR"
WHEELS="/tmp/panxcz-tools-wheels"
mkdir -p "$WHEELS"

python3 << PYEOF
import zipfile, os

whl_name = "panxcz_tools-${DEB_VERSION}-py3-none-any.whl"
whl = f"/tmp/panxcz-tools-wheels/{whl_name}"
src = "src/panxcz_tools"

with zipfile.ZipFile(whl, "w", zipfile.ZIP_DEFLATED) as z:
    for root, dirs, files in os.walk(src):
        for f in files:
            if f.endswith(".py"):
                arc = os.path.join(root, f).replace("src/", "panxcz_tools/")
                z.write(os.path.join(root, f), arc)

    di = "panxcz_tools-${DEB_VERSION}.dist-info"
    z.writestr(f"{di}/METADATA", f"""Metadata-Version: 2.1
Name: panxcz-tools
Version: ${DEB_VERSION}
Summary: Unified Reverse Engineering Platform
Author: Opanxxc
License: AGPL-3.0
Requires-Python: >=3.9
Requires-Dist: r2pipe>=1.8.0
Requires-Dist: textual>=0.40.0
Requires-Dist: rich>=13.0.0
""")
    z.writestr(f"{di}/WHEEL", "Wheel-Version: 1.0\nGenerator: panxcz-tools-build\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
    z.writestr(f"{di}/entry_points.txt", "[console_scripts]\npanxcz = panxcz_tools.cli:main\npanxcz-tui = panxcz_tools.tui:main\npanxcz-gui = panxcz_tools.gui.app:main\n")
    z.writestr(f"{di}/top_level.txt", "panxcz_tools\n")

print(f"Wheel: {whl}")
PYEOF

# ── 3. Create .deb structure ──────────────────────────────────────
STAGE="/tmp/panxcz-tools-deb"
rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN"
mkdir -p "$STAGE/usr/lib/python3/dist-packages"
mkdir -p "$STAGE/usr/bin"

# Install wheel
python3 -m pip install --target="$STAGE/usr/lib/python3/dist-packages" \
    "$WHEELS"/*.whl --no-deps 2>/dev/null || true

# Fallback: copy source directly
if [ ! -d "$STAGE/usr/lib/python3/dist-packages/panxcz_tools" ]; then
    cp -r "$REPO_DIR/src/panxcz_tools" "$STAGE/usr/lib/python3/dist-packages/"
fi

# ── 4. CLI wrapper ────────────────────────────────────────────────
cat > "$STAGE/usr/bin/panxcz" << 'W'
#!/usr/bin/env python3
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lib/python3/dist-packages"))
from panxcz_tools.cli import main
main()
W
chmod 755 "$STAGE/usr/bin/panxcz"

# ── 5. TUI wrapper ────────────────────────────────────────────────
cat > "$STAGE/usr/bin/panxcz-tui" << 'W'
#!/usr/bin/env python3
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lib/python3/dist-packages"))
from panxcz_tools.tui import main
main()
W
chmod 755 "$STAGE/usr/bin/panxcz-tui"

# ── 6. GUI wrapper ────────────────────────────────────────────────
cat > "$STAGE/usr/bin/panxcz-gui" << 'W'
#!/usr/bin/env python3
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lib/python3/dist-packages"))
from panxcz_tools.gui.app import main
main()
W
chmod 755 "$STAGE/usr/bin/panxcz-gui"

# ── 7. Control file ───────────────────────────────────────────────
cat > "$STAGE/DEBIAN/control" << EOF
Package: $PKG_NAME
Version: $DEB_VERSION
Section: devel
Priority: optional
Architecture: $ARCH
Maintainer: Opanxxc <opanxxc@users.noreply.github.com>
Depends: python3 (>= 3.9), python3-pip, radare2
Homepage: https://github.com/Opanxxc/panxcz-tools
Description: Panxcz Tools - Unified Reverse Engineering Platform
 Combines radare2 + OFRAK into one tool for binary analysis.
 Features: TUI, disassembler, string extraction, hex viewer,
 import/export analysis, vulnerability scanning, binary patching.
 Run 'panxcz-tui' for interactive mode or 'panxcz --help' for CLI.
EOF

# ── 8. Build .deb ─────────────────────────────────────────────────
cd "$REPO_DIR"
fakeroot dpkg-deb --build "$STAGE" "${PKG_NAME}_${DEB_VERSION}_${ARCH}.deb" 2>/dev/null || \
    dpkg-deb --root-owner-group --build "$STAGE" "${PKG_NAME}_${DEB_VERSION}_${ARCH}.deb" 2>/dev/null || \
    dpkg-deb --build "$STAGE" "${PKG_NAME}_${DEB_VERSION}_${ARCH}.deb"

ls -lh "$REPO_DIR/${PKG_NAME}_${DEB_VERSION}_${ARCH}.deb"
echo "[+] Desktop .deb built!"
