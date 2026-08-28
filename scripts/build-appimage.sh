#!/usr/bin/env bash
# ============================================================
#  R2OFRAK .AppImage builder
#  Universal Linux binary with embedded Python + radare2 bindings
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
APP_VERSION="${R2OFRAK_DEB_VERSION:-0.1.0}"
APP_NAME="R2OFRAK"

echo "============================================"
echo "  Building ${APP_NAME} .AppImage v${APP_VERSION}"
echo "============================================"

# ── 1. Setup AppDir structure ──────────────────────────────────────
APPDIR="/tmp/R2OFRAK.AppDir"
rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin"
mkdir -p "$APPDIR/usr/lib/python3/dist-packages"
mkdir -p "$APPDIR/usr/share/applications"
mkdir -p "$APPDIR/usr/share/icons/hicolor/256x256/apps"

# ── 2. Install Python package ──────────────────────────────────────
cd "$REPO_DIR"
python3 -m pip install --target="$APPDIR/usr/lib/python3/dist-packages" \
    . --no-deps 2>/dev/null || {
    # Manual copy
    cp -r src/r2ofrak "$APPDIR/usr/lib/python3/dist-packages/"
}

# Also install dependencies
python3 -m pip install --target="$APPDIR/usr/lib/python3/dist-packages" \
    textual rich r2pipe 2>/dev/null || true

# ── 3. Create launcher script ─────────────────────────────────────
cat > "$APPDIR/usr/bin/r2ofrak-launcher" << 'LAUNCHER'
#!/usr/bin/env python3
"""R2OFRAK AppImage launcher."""
import sys
import os

# Add our lib path
APPDIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(APPDIR, "usr/lib/python3/dist-packages"))

# Prefer our textual/rich over system ones
sys.path = [p for p in sys.path if "dist-packages" in p or APPDIR in p] + sys.argv[1:]

from r2ofrak.cli import main
if __name__ == "__main__":
    main()
LAUNCHER
chmod 755 "$APPDIR/usr/bin/r2ofrak-launcher"

# Symlink for AppRun
ln -sf usr/bin/r2ofrak-launcher "$APPDIR/AppRun"

# ── 4. Desktop entry ──────────────────────────────────────────────
cat > "$APPDIR/r2ofrak.desktop" << EOF
[Desktop Entry]
Type=Application
Name=R2OFRAK
GenericName=Reverse Engineering Tool
Comment=Unified reverse engineering platform (radare2 + OFRAK)
Exec=r2ofrak-launcher %f
Icon=r2ofrak
Terminal=true
Categories=Development;Security;Utility;
MimeType=application/x-executable;application/x-sharedlib;application/x-object;
Keywords=reverse-engineering;disassembler;binary-analysis;radare2;ofrak;
EOF

# ── 5. Icon (placeholder) ─────────────────────────────────────────
# Create a simple SVG icon
cat > "$APPDIR/usr/share/icons/hicolor/256x256/apps/r2ofrak.svg" << 'SVG'
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256">
  <rect width="256" height="256" rx="32" fill="#1a1a2e"/>
  <text x="128" y="110" text-anchor="middle" font-family="monospace" font-size="48" font-weight="bold" fill="#00d4ff">R2</text>
  <text x="128" y="170" text-anchor="middle" font-family="monospace" font-size="36" font-weight="bold" fill="#ff6b6b">OFRAK</text>
  <line x1="40" y1="190" x2="216" y2="190" stroke="#ffd93d" stroke-width="4"/>
  <text x="128" y="220" text-anchor="middle" font-family="monospace" font-size="18" fill="#6bcf7f">unified RE</text>
</svg>
SVG
cp "$APPDIR/usr/share/icons/hicolor/256x256/apps/r2ofrak.svg" "$APPDIR/r2ofrak.svg"

# ── 6. Download appimagetool ──────────────────────────────────────
if ! command -v appimagetool &>/dev/null; then
    echo "[*] Downloading appimagetool..."
    curl -sSL -o /tmp/appimagetool \
        "https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage" 2>/dev/null || \
    curl -sSL -o /tmp/appimagetool \
        "https://github.com/AppImage/type2-squashfs-static/releases/download/v1.0.0/appimagetool-x86_64.AppImage" 2>/dev/null || true
    chmod +x /tmp/appimagetool 2>/dev/null || true
fi

# ── 7. Build AppImage ─────────────────────────────────────────────
cd /tmp

if [ -x /tmp/appimagetool ]; then
    ARCH=x86_64 /tmp/appimagetool "$APPDIR" \
        "${APP_NAME}-${APP_VERSION}-x86_64.AppImage" 2>&1 || {
        echo "[!] appimagetool failed, creating tar.gz fallback..."
        tar czf "${APP_NAME}-${APP_VERSION}-x86_64.AppImage.tar.gz" -C /tmp R2OFRAK.AppDir
    }
else
    echo "[!] appimagetool not available, creating tar.gz..."
    tar czf "${APP_NAME}-${APP_VERSION}-x86_64.AppImage.tar.gz" -C /tmp R2OFRAK.AppDir
fi

ls -lh /tmp/${APP_NAME}-* 2>/dev/null
echo "[+] AppImage built successfully!"
