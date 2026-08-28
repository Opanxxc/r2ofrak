#!/usr/bin/env bash
# ============================================================
#  Panxcz Tools portable builder
#  Creates a portable package with Python + panxcz-tools
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
APP_VERSION="${DEB_VERSION:-0.2.0}"
APP_NAME="PanxczTools"

echo "============================================"
echo "  Building ${APP_NAME} package v${APP_VERSION}"
echo "============================================"

# ── 1. Setup AppDir structure ──────────────────────────────────────
APPDIR="/tmp/${APP_NAME}.AppDir"
rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin"
mkdir -p "$APPDIR/usr/lib/python3/dist-packages"
mkdir -p "$APPDIR/usr/share/applications"
mkdir -p "$APPDIR/usr/share/icons/hicolor/256x256/apps"

# ── 2. Install Python package ──────────────────────────────────────
cd "$REPO_DIR"

# Install wheel + deps into AppDir
pip install --target="$APPDIR/usr/lib/python3/dist-packages" \
    textual rich r2pipe 2>/dev/null || true

# Copy source
cp -r src/panxcz_tools "$APPDIR/usr/lib/python3/dist-packages/"

# ── 3. Create launcher script ─────────────────────────────────────
cat > "$APPDIR/usr/bin/panxcz-tools-launcher" << 'LAUNCHER'
#!/usr/bin/env python3
"""Panxcz Tools AppImage launcher."""
import sys, os

APPDIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(APPDIR, "usr/lib/python3/dist-packages"))

# Parse args
target = None
cli_mode = False
gui_mode = False
args = sys.argv[1:]
if "--cli" in args:
    cli_mode = True
    args.remove("--cli")
if "--gui" in args:
    gui_mode = True
    args.remove("--gui")
if args and not args[0].startswith("-"):
    target = args[0]

if cli_mode:
    from panxcz_tools.cli import main
    sys.argv = [sys.argv[0]] + args
    main()
elif gui_mode:
    from panxcz_tools.gui.app import main
    sys.argv = [sys.argv[0]] + args
    main()
else:
    from panxcz_tools.tui import R2OFRAKApp
    app = R2OFRAKApp(target=target)
    app.run()
LAUNCHER
chmod 755 "$APPDIR/usr/bin/panxcz-tools-launcher"

# Symlink for AppRun
ln -sf usr/bin/panxcz-tools-launcher "$APPDIR/AppRun"

# ── 4. Desktop entry ──────────────────────────────────────────────
cat > "$APPDIR/panxcz-tools.desktop" << EOF
[Desktop Entry]
Type=Application
Name=Panxcz Tools
GenericName=Reverse Engineering Tool
Comment=Unified reverse engineering platform (radare2 + OFRAK)
Exec=panxcz-tools-launcher %f
Icon=panxcz-tools
Terminal=true
Categories=Development;Security;Utility;
MimeType=application/x-executable;application/x-sharedlib;application/x-object;
EOF

# ── 5. Icon ───────────────────────────────────────────────────────
cat > "$APPDIR/panxcz-tools.svg" << 'SVG'
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256">
  <rect width="256" height="256" rx="32" fill="#1a1a2e"/>
  <text x="128" y="110" text-anchor="middle" font-family="monospace" font-size="48" font-weight="bold" fill="#00d4ff">R2</text>
  <text x="128" y="170" text-anchor="middle" font-family="monospace" font-size="36" font-weight="bold" fill="#ff6b6b">OFRAK</text>
  <line x1="40" y1="190" x2="216" y2="190" stroke="#ffd93d" stroke-width="4"/>
  <text x="128" y="220" text-anchor="middle" font-family="monospace" font-size="18" fill="#6bcf7f">unified RE</text>
</svg>
SVG

# ── 6. Create portable tar.gz (universal format) ──────────────────
TARBALL="${REPO_DIR}/${APP_NAME}-${APP_VERSION}-x86_64.tar.gz"
cd /tmp
tar czf "$TARBALL" -C /tmp "${APP_NAME}.AppDir"

# ── 7. Also create a .run self-extracting script ──────────────────
APPIMAGE="${REPO_DIR}/${APP_NAME}-${APP_VERSION}-x86_64.AppImage"
cat > "$APPIMAGE" << 'RUNSCRIPT'
#!/usr/bin/env bash
# Panxcz Tools AppImage (self-extracting)
set -e
TMPDIR=$(mktemp -d)
ARCHIVE=$(awk 'BEGIN{lines=0} /^__ARCHIVE__$/{exit} {lines++} END{print NR}' "$0")
tail -n +$((ARCHIVE+1)) "$0" | tar xzf - -C "$TMPDIR"
exec "$TMPDIR/PanxczTools.AppDir/AppRun" "$@"
__ARCHIVE__
RUNSCRIPT

# Append the tarball
cat "$TARBALL" >> "$APPIMAGE"
chmod +x "$APPIMAGE"

echo ""
ls -lh "${REPO_DIR}/${APP_NAME}-${APP_VERSION}-x86_64."*
echo "[+] AppImage + tar.gz built!"
