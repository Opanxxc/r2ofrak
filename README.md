# R2OFRAK

**Unified Reverse Engineering Platform — radare2 + OFRAK**

[![Build R2OFRAK Packages](https://github.com/Opanxxc/r2ofrak/actions/workflows/build-packages.yml/badge.svg)](https://github.com/Opanxxc/r2ofrak/actions)

<p align="center">
  <b>Disassemble • Analyze • Unpack • Patch • Repack — All in One Tool</b>
</p>

---

## What is R2OFRAK?

R2OFRAK combines the power of two legendary reverse engineering tools into one unified platform:

| Tool | What it does |
|------|-------------|
| **radare2** | Disassembly, analysis, debugging, patching, hex editing |
| **OFRAK** | Binary unpacking, modification, repacking (ELF, PE, APK, firmware) |

**R2OFRAK** = `radare2` + `OFRAK` + interactive **TUI** + powerful **CLI**

### Features

- 🖥️ **Interactive TUI** — Tabbed interface with Hex view, Disasm, Strings, Imports, Functions, Patches, OFRAK ops, Vulnerability scanner, and built-in r2 Terminal
- ⌨️ **CLI mode** — Scriptable commands for automation and CI/CD
- 🔍 **Full analysis** — Combined radare2 + OFRAK analysis in one click
- 📦 **Unpack/Repack** — OFRAK-powered unpacking of ELF, PE, Mach-O, APK, firmware, compressed archives
- 🔧 **Patching** — NOP patches, byte patches, jump modifications
- 🔐 **Vulnerability scanning** — Dangerous function detection, RWX segments, format strings
- 📊 **Entropy analysis** — Detect packed/encrypted sections
- 📱 **Termux support** — Full Android/Termux support via .deb package

---

## Quick Start

### Option A: One-liner install (Termux)

```bash
pkg install git radare2 && git clone https://github.com/Opanxxc/r2ofrak.git && cd r2ofrak && apt install ./scripts/*.deb || bash scripts/build-termux-deb-inside.sh
```

### Option B: Manual install

#### Termux (Android)

```bash
# Install dependencies
pkg update && pkg install git radare2 python

# Download .deb from releases
wget https://github.com/Opanxxc/r2ofrak/releases/download/continuous/r2ofrak_0.1.0_aarch64.deb

# Install
apt install ./r2ofrak_0.1.0_aarch64.deb

# Launch TUI
r2ofrak-tui /path/to/binary

# Or use CLI
r2ofrak analyze /path/to/binary
```

#### Desktop (Debian/Ubuntu)

```bash
# Install dependencies
sudo apt update && sudo apt install radare2

# Download .deb from releases
wget https://github.com/Opanxxc/r2ofrak/releases/download/continuous/r2ofrak_0.1.0_amd64.deb

# Install
sudo apt install ./r2ofrak_0.1.0_amd64.deb

# Launch TUI
r2ofrak-tui /path/to/binary

# Or use CLI
r2ofrak analyze /path/to/binary
```

#### AppImage (any distro)

```bash
# Download from releases
wget https://github.com/Opanxxc/r2ofrak/releases/download/continuous/R2OFRAK-0.1.0-x86_64.AppImage

# Make executable and run
chmod +x R2OFRAK-0.1.0-x86_64.AppImage
./R2OFRAK-0.1.0-x86_64.AppImage tui /path/to/binary
```

#### From source (pip)

```bash
git clone https://github.com/Opanxxc/r2ofrak.git
cd r2ofrak
pip install .

# Launch
r2ofrak-tui /path/to/binary
r2ofrak analyze /path/to/binary
```

---

## Usage

### TUI Mode (Interactive)

```bash
r2ofrak-tui                          # Open file picker
r2ofrak-tui /path/to/binary          # Open directly
r2ofrak                              # Also launches TUI (default)
```

**Keyboard shortcuts:**

| Key | Action |
|-----|--------|
| `Ctrl+O` | Open file |
| `Ctrl+A` | Full analysis |
| `Ctrl+D` | Disassemble |
| `Ctrl+S` | Dump strings |
| `Ctrl+P` | Patch mode |
| `Ctrl+F` | Run r2 command |
| `Ctrl+Q` | Quit |
| `F1-F8` | Switch tabs |

**TUI Tabs:**
- **Overview** — File info, architecture, analysis summary
- **Disasm** — Full disassembly with function navigation
- **Strings** — Extracted strings with filter
- **Imports** — Import table (API calls, libraries)
- **Exports** — Export table
- **Functions** — Function list with sizes
- **Segments** — ELF/PE sections with permissions
- **Hex** — Hex editor view
- **Patches** — Apply byte patches
- **OFRAK** — Unpack/repack operations
- **Vulns** — Vulnerability pattern scanning
- **Terminal** — Direct radare2 command execution

### CLI Mode

```bash
# Full analysis
r2ofrak analyze /path/to/binary

# Disassemble
r2ofrak disasm /path/to/binary
r2ofrak disasm /path/to/binary --mode function --addr main

# Extract strings
r2ofrak strings /path/to/binary --min-length 8
r2ofrak strings /path/to/binary --json

# List imports/exports
r2ofrak imports /path/to/binary
r2ofrak exports /path/to/binary

# List functions
r2ofrak functions /path/to/binary

# List segments
r2ofrak segments /path/to/binary

# Entropy analysis (detect packing)
r2ofrak entropy /path/to/binary

# Vulnerability scan
r2ofrak vulns /path/to/binary

# Patch binary
r2ofrak patch /path/to/binary --offset 0x1000 --hex-data 90909090
r2ofrak nop /path/to/binary --offset 0x1000 --size 10

# OFRAK unpack/repack
r2ofrak unpack firmware.bin
r2ofrak repack firmware.bin

# Export full report
r2ofrak export /path/to/binary -o report.json

# JSON output
r2ofrak analyze /path/to/binary --json
```

### Python API

```python
from r2ofrak import R2OFRAKContext

# Full analysis
with R2OFRAKContext("/path/to/binary") as ctx:
    report = ctx.analyze()
    strings = ctx.dump_strings(min_length=8)
    imports = ctx.dump_imports()
    vulns = ctx.find_vulnerabilities()
    
    # Patch
    ctx.patch(0x1000, bytes.fromhex("90909090"))
    ctx.repack()
    
    # Export
    ctx.export("report.json")
```

---

## Supported Formats

| Format | Unpack | Analyze | Patch | Repack |
|--------|--------|---------|-------|--------|
| ELF | ✅ | ✅ | ✅ | ✅ |
| PE/EXE | ✅ | ✅ | ✅ | ✅ |
| Mach-O | ✅ | ✅ | ✅ | ✅ |
| APK/DEX | ✅ | ✅ | ✅ | ✅ |
| ZIP/GZIP | ✅ | ✅ | — | ✅ |
| TAR | ✅ | ✅ | — | ✅ |
| Firmware | ✅ | ✅ | ✅ | ✅ |
| .so/.dll | ✅ | ✅ | ✅ | ✅ |

---

## Build from Source

### Build .deb (Desktop)
```bash
bash scripts/build-desktop-deb.sh
```

### Build .AppImage
```bash
bash scripts/build-appimage.sh
```

### Build Termux .deb
```bash
docker run --rm -v "$(pwd):/work" termux/termux-docker:aarch64 bash /work/scripts/build-termux-deb-inside.sh
```

---

## Requirements

- **Python** >= 3.9
- **radare2** >= 5.9 (`pkg install radare2` / `apt install radare2`)
- **textual** >= 0.40 (TUI framework)
- **r2pipe** >= 1.8 (radare2 Python bindings)
- Optional: **OFRAK** >= 3.0 (for full unpack/repack features)

---

## Credits

- **radare2** — [radareorg/radare2](https://github.com/radareorg/radare2) — UNIX-like reverse engineering framework
- **OFRAK** — [redballoonsecurity/ofrak](https://github.com/redballoonsecurity/ofrak) — Open Firmware Reverse Analysis Konsole
- **Textual** — [Textualize/textual](https://github.com/Textualize/textual) — Modern Python TUI framework
- Built by **Opanxxc** — contribution by **Panxcz** and **freebuff**

---

## License

AGPL-3.0 — See [LICENSE](LICENSE)
