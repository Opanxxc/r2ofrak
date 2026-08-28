# 🔬 Panxcz Tools

**Unified Reverse Engineering Platform — radare2 + OFRAK + Web GUI**

[![Build](https://github.com/Opanxxc/r2ofrak/actions/workflows/build-packages.yml/badge.svg)](https://github.com/Opanxxc/r2ofrak/actions)

<p align="center">
  <b>Web GUI • TUI • CLI — Analyze, Disassemble, Patch, Unpack, Security Scan</b>
</p>

---

## What is Panxcz Tools?

Panxcz Tools combines the power of **radare2** and **OFRAK** into one unified platform with three interfaces:

| Interface | Description |
|-----------|-------------|
| 🖥️ **Web GUI** | iaito-style dark theme, disasm view, hex editor, function browser, security panel |
| 💻 **TUI** | Interactive terminal with 16 tabs |
| ⌨️ **CLI** | Scriptable commands for automation |

---

## Quick Start

### Web GUI (Recommended)
```bash
# Install
sudo apt install radare2
sudo dpkg -i panxcz-tools_0.0.1_amd64.deb

# Launch GUI
panxcz-gui /path/to/binary
# Opens http://localhost:8888
```

### Termux (Android)
```bash
# One-liner install
pkg install -y git radare2 && \
  wget -qO /tmp/panxcz.deb https://github.com/Opanxxc/r2ofrak/releases/download/continuous/panxcz-tools_0.0.1_all.deb && \
  apt install -y /tmp/panxcz.deb && \
  panxcz-tui

# Or install manually
pkg install git radare2
wget https://github.com/Opanxxc/r2ofrak/releases/download/continuous/panxcz-tools_0.0.1_all.deb
apt install -y ./panxcz-tools_0.0.1_all.deb
panxcz-tui /path/to/binary
```

### TUI
```bash
panxcz-tui /path/to/binary
```

### CLI
```bash
panxcz analyze /path/to/binary
panxcz security /path/to/binary
panxcz disasm /path/to/binary --function main
```

---

## Features

### 🖥️ Web GUI (iaito-style)
- **Dark theme** — Professional reverse engineering interface
- **Disassembly view** — Syntax-highlighted, jump to function/entry point
- **Hex editor** — Offset navigation, hex/ASCII search
- **Function browser** — Click to disassemble, search/filter
- **String extraction** — With filtering
- **Section viewer** — ELF/PE segments with permissions
- **Security panel** — Anti-debug, crypto, protections
- **Vulnerability scanner** — Dangerous functions, shellcode
- **Binary patching** — Write hex bytes at offset
- **Terminal** — Direct r2 command execution

### 💻 TUI (16 tabs)
Overview • Disasm • Strings • Imports • Exports • Functions • Segments • Hex • Patches • OFRAK • Vulns • Security • APK/FW • Compare • Record • Terminal

### ⌨️ CLI (10+ commands)
`analyze` `disasm` `strings` `imports` `functions` `security` `hex` `vulns` `gui` `tui`

### 🔍 Security Analysis
- Anti-debug detection (Frida, Xposed, ptrace, debugger checks)
- Crypto detection (AES, RSA, MD5, SHA256, HMAC...)
- Binary protections (NX, PIE, canary, FORTIFY, RELRO)
- Vulnerability pattern scanning

### 📱 APK/DEX Analyzer
- DEX file detection, native library extraction
- Permission analysis, security checks

### 🔧 Firmware Analyzer
- Squashfs, CPIO, JFFS2, UBI detection + unpacking
- Credential/URL extraction

### ⚖️ Binary Comparator
- Diff blocks, string diffs, entropy comparison

### 🎬 Script Recorder
- Record RE workflows → generates Python replay scripts

---

## Download

### 📦 Packages

| Package | File | Platform |
|---------|------|----------|
| Desktop .deb | `panxcz-tools_0.0.1_amd64.deb` | Debian/Ubuntu |
| Termux .deb | `panxcz-tools_0.0.1_all.deb` | Android/Termux |
| Portable | `PanxczTools-0.0.1-x86_64.tar.gz` | Any Linux |

**Download from:** https://github.com/Opanxxc/panxcz-tools/releases/tag/continuous

---

## Build from Source

```bash
git clone https://github.com/Opanxxc/panxcz-tools.git
cd panxcz-tools
pip install .
panxcz-gui /path/to/binary
```

---

## Requirements

- **Python** >= 3.9
- **radare2** >= 5.9
- **fastapi** + **uvicorn** (for Web GUI)
- **textual** + **rich** (for TUI)
- **r2pipe** (radare2 Python bindings)

---

## Credits

- **radare2** — [radareorg/radare2](https://github.com/radareorg/radare2)
- **OFRAK** — [redballoonsecurity/ofrak](https://github.com/redballoonsecurity/ofrak)
- **iaito** — [radareorg/iaito](https://github.com/radareorg/iaito) — inspiration for Web GUI
- Built by **Panxcz** — contribution by **freebuff**

---

## License

AGPL-3.0
