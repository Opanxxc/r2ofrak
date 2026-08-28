"""
Panxcz Tools TUI — Textual-based reverse engineering interface.
14 panels: Overview, Disasm, Strings, Imports, Exports, Functions,
           Segments, Hex, Patches, Security, Vulns, Unpacker, XRefs, Terminal.
"""

import sys
import time
from pathlib import Path

try:
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal, Vertical, ScrollableContainer
    from textual.widgets import (
        Header, Footer, Static, DataTable, Input, RichLog,
        Label, Button, ProgressBar, Select,
    )
    HAS_TEXTUAL = True
except ImportError:
    HAS_TEXTUAL = False


__version__ = "0.0.1"


if HAS_TEXTUAL:

    # ═══════════════════════════════════════════════════════════════
    #  OVERVIEW PANEL
    # ═══════════════════════════════════════════════════════════════

    class OverviewPanel(Static):
        def __init__(self, target=None, **kw):
            super().__init__(**kw)
            self.target = target

        def compose(self) -> ComposeResult:
            yield RichLog(id="overview-log", auto_scroll=False)

        def on_mount(self):
            if not self.target:
                self.query_one("#overview-log").write("[dim]No file loaded. Use: panxcz-tui <binary>[/dim]")
                return
            try:
                from panxcz_tools.core.r2_engine import R2Engine
                engine = R2Engine(self.target)
                info = engine.info()
                log = self.query_one("#overview-log")
                bi = info.get("bin", {})
                fi = info.get("core", {})
                funcs = engine.functions()
                imports = engine.imports()
                sections = engine.sections()
                strings = engine.strings(min_len=6)

                lines = [
                    f"[bold cyan]═══════════════════════════════════════════════════════[/bold cyan]",
                    f"[bold cyan]  Panxcz Tools v{__version__} — Binary Overview[/bold cyan]",
                    f"[bold cyan]═══════════════════════════════════════════════════════[/bold cyan]",
                    "",
                    f"  [bold]File:[/bold]     [green]{self.target}[/green]",
                    f"  [bold]Arch:[/bold]     {bi.get('arch', '?')}",
                    f"  [bold]Bits:[/bold]     {bi.get('bits', '?')}",
                    f"  [bold]OS:[/bold]       {bi.get('os', '?')}",
                    f"  [bold]Endian:[/bold]   {bi.get('endian', '?')}",
                    f"  [bold]Type:[/bold]     {bi.get('class', '?')}",
                    f"  [bold]Compiler:[/bold] {bi.get('compiler', 'unknown')}",
                    f"  [bold]Stripped:[/bold] {bi.get('stripped', '?')}",
                    f"  [bold]Relocs:[/bold]   {bi.get('relocs', '?')}",
                    f"  [bold]Size:[/bold]     {fi.get('size', '?'):,} bytes",
                    "",
                    f"  [bold yellow]─── Statistics ───[/bold yellow]",
                    f"  Functions:  [cyan]{len(funcs)}[/cyan]",
                    f"  Imports:    [cyan]{len(imports)}[/cyan]",
                    f"  Sections:   [cyan]{len(sections)}[/cyan]",
                    f"  Strings:    [cyan]{len(strings)}[/cyan]",
                ]

                # Protection flags
                try:
                    from panxcz_tools.core.security import SecurityAnalyzer
                    sa = SecurityAnalyzer(self.target)
                    prots = sa.protections()
                    lines.append("")
                    lines.append("  [bold yellow]─── Protections ───[/bold yellow]")
                    for k, v in prots.items():
                        icon = "✅" if v else "❌"
                        lines.append(f"  {icon} {k}")
                except Exception:
                    pass

                log.write("\n".join(lines))
            except Exception as e:
                self.query_one("#overview-log").write(f"[red]Error: {e}[/red]")

    # ═══════════════════════════════════════════════════════════════
    #  DISASM PANEL
    # ═══════════════════════════════════════════════════════════════

    class DisasmPanel(Static):
        def __init__(self, target=None, **kw):
            super().__init__(**kw)
            self.target = target

        def compose(self) -> ComposeResult:
            with Horizontal():
                yield Input(placeholder="Address (e.g. entry0, main, 0x401000)", id="disasm-addr")
                yield Input(placeholder="Count", id="disasm-count", value="200")
                yield Button("Disasm", id="disasm-btn", variant="primary")
            yield RichLog(id="disasm-log", auto_scroll=False)

        def on_button_pressed(self, event):
            if event.button.id == "disasm-btn":
                addr = self.query_one("#disasm-addr").value or "entry0"
                count = int(self.query_one("#disasm-count").value or "200")
                self._disassemble(addr, count)

        def on_mount(self):
            if self.target:
                self._disassemble("entry0", 200)

        def _disassemble(self, addr, count):
            try:
                from panxcz_tools.core.r2_engine import R2Engine
                engine = R2Engine(self.target)
                engine.cmd("aaa")
                output = engine.cmd(f"pd {count} @ {addr}")
                log = self.query_one("#disasm-log")
                log.clear()
                for line in output.split("\n"):
                    if not line.strip():
                        log.write(line)
                    elif any(k in line for k in ["sym.", "fcn.", "sub.", "entry"]):
                        log.write(f"[bold yellow]{line}[/bold yellow]")
                    elif any(k in line for k in ["jnz", "je ", "jne", "jmp", "call"]):
                        log.write(f"[bold red]{line}[/bold red]")
                    elif any(k in line for k in ["mov", "push", "pop", "lea"]):
                        log.write(f"[cyan]{line}[/cyan]")
                    elif "NOP" in line or "nop" in line:
                        log.write(f"[dim]{line}[/dim]")
                    else:
                        log.write(line)
            except Exception as e:
                self.query_one("#disasm-log").write(f"[red]Error: {e}[/red]")

    # ═══════════════════════════════════════════════════════════════
    #  STRINGS PANEL
    # ═══════════════════════════════════════════════════════════════

    class StringsPanel(Static):
        def __init__(self, target=None, **kw):
            super().__init__(**kw)
            self.target = target

        def compose(self) -> ComposeResult:
            with Horizontal():
                yield Input(placeholder="Filter...", id="str-filter")
                yield Input(placeholder="Min len", id="str-minlen", value="6")
                yield Button("Extract", id="str-btn", variant="primary")
            yield DataTable(id="strings-table")

        def on_button_pressed(self, event):
            if event.button.id == "str-btn":
                self._extract()

        def on_mount(self):
            if self.target:
                table = self.query_one("#strings-table")
                table.add_columns("Offset", "VAddr", "Type", "Len", "String")
                self._extract()

        def _extract(self):
            try:
                from panxcz_tools.core.r2_engine import R2Engine
                engine = R2Engine(self.target)
                min_len = int(self.query_one("#str-minlen").value or "6")
                filter_text = self.query_one("#str-filter").value.lower()
                strings = engine.strings(min_len=min_len)
                table = self.query_one("#strings-table")
                table.clear()
                count = 0
                for s in strings:
                    val = s.get("string", "")
                    if filter_text and filter_text not in val.lower():
                        continue
                    table.add_row(
                        s.get("offset", "0x0"),
                        s.get("vaddr", "0x0"),
                        s.get("type", "?"),
                        str(len(val)),
                        val[:120],
                    )
                    count += 1
                    if count > 1000:
                        break
            except Exception as e:
                self.query_one("#strings-table").add_row("Error", "", "", "", str(e))

    # ═══════════════════════════════════════════════════════════════
    #  IMPORTS PANEL
    # ═══════════════════════════════════════════════════════════════

    class ImportsPanel(Static):
        def __init__(self, target=None, **kw):
            super().__init__(**kw)
            self.target = target

        def compose(self) -> ComposeResult:
            yield DataTable(id="imports-table")

        def on_mount(self):
            if not self.target:
                return
            table = self.query_one("#imports-table")
            table.add_columns("PLT", "Name", "Library")
            try:
                from panxcz_tools.core.r2_engine import R2Engine
                engine = R2Engine(self.target)
                engine.cmd("aaa")
                imports = engine.imports()
                for imp in imports:
                    if isinstance(imp, dict):
                        table.add_row(
                            str(imp.get("plt", "?")),
                            imp.get("name", "?"),
                            imp.get("libname", ""),
                        )
            except Exception as e:
                table.add_row("Error", str(e), "")

    # ═══════════════════════════════════════════════════════════════
    #  EXPORTS PANEL
    # ═══════════════════════════════════════════════════════════════

    class ExportsPanel(Static):
        def __init__(self, target=None, **kw):
            super().__init__(**kw)
            self.target = target

        def compose(self) -> ComposeResult:
            yield DataTable(id="exports-table")

        def on_mount(self):
            if not self.target:
                return
            table = self.query_one("#exports-table")
            table.add_columns("VAddr", "Name", "Type")
            try:
                from panxcz_tools.core.r2_engine import R2Engine
                engine = R2Engine(self.target)
                engine.cmd("aaa")
                exports = engine.exports()
                for exp in exports:
                    if isinstance(exp, dict):
                        table.add_row(
                            str(exp.get("vaddr", "?")),
                            exp.get("name", "?"),
                            exp.get("type", ""),
                        )
            except Exception as e:
                table.add_row("Error", str(e), "")

    # ═══════════════════════════════════════════════════════════════
    #  FUNCTIONS PANEL
    # ═══════════════════════════════════════════════════════════════

    class FunctionsPanel(Static):
        def __init__(self, target=None, **kw):
            super().__init__(**kw)
            self.target = target

        def compose(self) -> ComposeResult:
            yield DataTable(id="funcs-table")

        def on_mount(self):
            if not self.target:
                return
            table = self.query_one("#funcs-table")
            table.add_columns("Offset", "Name", "Size", "Calls")
            try:
                from panxcz_tools.core.r2_engine import R2Engine
                engine = R2Engine(self.target)
                engine.cmd("aaa")
                funcs = engine.functions()
                for f in funcs:
                    if isinstance(f, dict):
                        table.add_row(
                            f"0x{f.get('offset', 0):x}",
                            f.get("name", "?"),
                            str(f.get("size", 0)),
                            str(f.get("cc", "?")),
                        )
            except Exception as e:
                table.add_row("Error", str(e), "", "")

    # ═══════════════════════════════════════════════════════════════
    #  SEGMENTS PANEL
    # ═══════════════════════════════════════════════════════════════

    class SegmentsPanel(Static):
        def __init__(self, target=None, **kw):
            super().__init__(**kw)
            self.target = target

        def compose(self) -> ComposeResult:
            yield DataTable(id="segments-table")

        def on_mount(self):
            if not self.target:
                return
            table = self.query_one("#segments-table")
            table.add_columns("Name", "VAddr", "Size", "Type", "Perm")
            try:
                from panxcz_tools.core.r2_engine import R2Engine
                engine = R2Engine(self.target)
                sections = engine.sections()
                for sec in sections:
                    if isinstance(sec, dict):
                        table.add_row(
                            sec.get("name", "?"),
                            f"0x{sec.get('vaddr', 0):x}",
                            str(sec.get("size", 0)),
                            sec.get("type", "?"),
                            sec.get("perm", "?"),
                        )
            except Exception as e:
                table.add_row("Error", str(e), "", "", "")

    # ═══════════════════════════════════════════════════════════════
    #  HEX PANEL
    # ═══════════════════════════════════════════════════════════════

    class HexPanel(Static):
        def __init__(self, target=None, **kw):
            super().__init__(**kw)
            self.target = target

        def compose(self) -> ComposeResult:
            with Horizontal():
                yield Input(placeholder="Offset (hex)", id="hex-offset", value="0x0")
                yield Input(placeholder="Size", id="hex-size", value="512")
                yield Button("View", id="hex-btn", variant="primary")
            yield RichLog(id="hex-log", auto_scroll=False)

        def on_button_pressed(self, event):
            if event.button.id == "hex-btn":
                self._view()

        def on_mount(self):
            if self.target:
                self._view()

        def _view(self):
            try:
                from panxcz_tools.core.r2_engine import R2Engine
                engine = R2Engine(self.target)
                offset_str = self.query_one("#hex-offset").value or "0x0"
                size_str = self.query_one("#hex-size").value or "512"
                offset = int(offset_str, 16) if offset_str.startswith("0x") else int(offset_str)
                size = int(size_str)
                output = engine.hexdump(offset=offset, size=min(size, 4096))
                log = self.query_one("#hex-log")
                log.clear()
                log.write(output)
            except Exception as e:
                self.query_one("#hex-log").write(f"[red]Error: {e}[/red]")

    # ═══════════════════════════════════════════════════════════════
    #  PATCHES PANEL
    # ═══════════════════════════════════════════════════════════════

    class PatchesPanel(Static):
        def __init__(self, target=None, **kw):
            super().__init__(**kw)
            self.target = target

        def compose(self) -> ComposeResult:
            with Horizontal():
                yield Input(placeholder="Offset (hex)", id="patch-offset")
                yield Input(placeholder="Hex bytes (e.g. 9090)", id="patch-data")
                yield Button("Patch", id="patch-btn", variant="warning")
                yield Button("NOP", id="nop-btn", variant="error")
            yield RichLog(id="patch-log", auto_scroll=False)

        def on_button_pressed(self, event):
            if event.button.id == "patch-btn":
                self._patch()
            elif event.button.id == "nop-btn":
                self._nop()

        def _patch(self):
            try:
                from panxcz_tools.core.r2_engine import R2Engine
                engine = R2Engine(self.target)
                offset = int(self.query_one("#patch-offset").value, 16)
                data = self.query_one("#patch-data").value
                engine.patch(offset, data)
                self.query_one("#patch-log").write(
                    f"[green]✓ Patched {len(data)//2} bytes at 0x{offset:x}[/green]"
                )
            except Exception as e:
                self.query_one("#patch-log").write(f"[red]Error: {e}[/red]")

        def _nop(self):
            try:
                from panxcz_tools.core.r2_engine import R2Engine
                engine = R2Engine(self.target)
                offset = int(self.query_one("#patch-offset").value, 16)
                size = int(self.query_one("#patch-data").value or "1")
                engine.nop(offset, size)
                self.query_one("#patch-log").write(
                    f"[green]✓ NOP'd {size} bytes at 0x{offset:x}[/green]"
                )
            except Exception as e:
                self.query_one("#patch-log").write(f"[red]Error: {e}[/red]")

    # ═══════════════════════════════════════════════════════════════
    #  SECURITY PANEL
    # ═══════════════════════════════════════════════════════════════

    class SecurityPanel(Static):
        def __init__(self, target=None, **kw):
            super().__init__(**kw)
            self.target = target

        def compose(self) -> ComposeResult:
            yield RichLog(id="security-log", auto_scroll=False)

        def on_mount(self):
            if not self.target:
                return
            try:
                from panxcz_tools.core.security import SecurityAnalyzer
                sa = SecurityAnalyzer(self.target)
                data = sa.full()
                log = self.query_one("#security-log")
                log.write("[bold cyan]═══════════════════════════════════════[/bold cyan]")
                log.write("[bold cyan]  Security Analysis Report[/bold cyan]")
                log.write("[bold cyan]═══════════════════════════════════════[/bold cyan]")

                h = data.get("hashes", {})
                log.write(f"\n  [bold]SHA256:[/bold] {h.get('sha256', '?')[:64]}")

                # Protections
                prot = data.get("protections", {})
                log.write(f"\n  [bold yellow]─── Protections ───[/bold yellow]")
                for k, v in prot.items():
                    icon = "✅" if v else "❌"
                    log.write(f"  {icon} {k}")

                # Anti-debug
                ad = data.get("anti_debug", [])
                if ad:
                    log.write(f"\n  [bold red]─── Anti-Debug ({len(ad)}) ───[/bold red]")
                    for a in ad[:15]:
                        log.write(f"  ⚠ {a.get('description', '?')} @ {a.get('offset', '?')}")

                # Anti-root
                ar = data.get("anti_root", [])
                if ar:
                    log.write(f"\n  [bold red]─── Anti-Root ({len(ar)}) ───[/bold red]")
                    for a in ar[:10]:
                        log.write(f"  🔒 {a.get('description', '?')} @ {a.get('offset', '?')}")

                # Anti-emulator
                ae = data.get("anti_emulator", [])
                if ae:
                    log.write(f"\n  [bold red]─── Anti-Emulator ({len(ae)}) ───[/bold red]")
                    for a in ae[:10]:
                        log.write(f"  📱 {a.get('description', '?')} @ {a.get('offset', '?')}")

                # Frida
                fr = data.get("frida_hooks", [])
                if fr:
                    log.write(f"\n  [bold red]─── Frida Detection ({len(fr)}) ───[/bold red]")
                    for f in fr[:10]:
                        log.write(f"  🕵 {f.get('description', '?')} @ {f.get('offset', '?')}")

                # SSL Pinning
                ssl = data.get("ssl_pinning", [])
                if ssl:
                    log.write(f"\n  [bold yellow]─── SSL Pinning ({len(ssl)}) ───[/bold yellow]")
                    for s in ssl[:10]:
                        log.write(f"  🔐 {s.get('description', '?')} @ {s.get('offset', '?')}")

                # Crypto
                cr = data.get("crypto", [])
                if cr:
                    log.write(f"\n  [bold]─── Crypto ({len(cr)}) ───[/bold]")
                    for c in cr[:10]:
                        log.write(f"  🔑 {c.get('description', '?')} @ {c.get('offset', '?')}")

                # Permissions
                perms = data.get("permissions", [])
                if perms:
                    log.write(f"\n  [bold]─── Permissions ({len(perms)}) ───[/bold]")
                    for p in perms:
                        log.write(f"  📋 {p}")

                # Signing
                signing = data.get("code_signing", {})
                if signing.get("signed"):
                    log.write(f"\n  [bold green]─── Code Signing ───[/bold green]")
                    log.write(f"  ✅ Signed ({signing.get('type', '?')})")
                    for d in signing.get("details", []):
                        log.write(f"    • {d}")

            except Exception as e:
                self.query_one("#security-log").write(f"[red]Error: {e}[/red]")

    # ═══════════════════════════════════════════════════════════════
    #  VULNS PANEL
    # ═══════════════════════════════════════════════════════════════

    class VulnsPanel(Static):
        def __init__(self, target=None, **kw):
            super().__init__(**kw)
            self.target = target

        def compose(self) -> ComposeResult:
            yield RichLog(id="vulns-log", auto_scroll=False)

        def on_mount(self):
            if not self.target:
                return
            try:
                from panxcz_tools.core.r2_engine import R2Engine
                from panxcz_tools.core.security import SecurityAnalyzer

                engine = R2Engine(self.target)
                vulns = engine.vulnerabilities()
                sa = SecurityAnalyzer(self.target)
                data = sa.full()
                sus = data.get("suspicious_strings", [])
                vulns2 = data.get("vulnerabilities", [])

                log = self.query_one("#vulns-log")
                total = len(vulns) + len(vulns2)
                if total == 0:
                    log.write("[green]✅ No known vulnerabilities found.[/green]")
                    return

                log.write(f"[bold red]Found {total} potential issues:[/bold red]")

                if vulns:
                    log.write(f"\n[bold]─── Import-based ({len(vulns)}) ───[/bold]")
                    for v in vulns:
                        sev = v.get("severity", "?")
                        color = "red" if sev in ("critical", "high") else "yellow" if sev == "medium" else "dim"
                        log.write(f"  [{color}][{sev.upper()}][/{color}] {v.get('description', '?')} @ {v.get('address', '?')}")

                if vulns2:
                    log.write(f"\n[bold]─── String-based ({len(vulns2)}) ───[/bold]")
                    for v in vulns2:
                        sev = v.get("severity", "?")
                        color = "red" if sev in ("critical", "high") else "yellow"
                        log.write(f"  [{color}][{sev.upper()}][/{color}] {v.get('description', '?')} @ {v.get('offset', '?')}")

                if sus:
                    log.write(f"\n[bold]─── Suspicious Strings ({len(sus)}) ───[/bold]")
                    for s in sus[:20]:
                        log.write(f"  ⚠ {s.get('description', '?')} @ {s.get('offset', '?')}")

            except Exception as e:
                self.query_one("#vulns-log").write(f"[red]Error: {e}[/red]")

    # ═══════════════════════════════════════════════════════════════
    #  UNPACKER PANEL
    # ═══════════════════════════════════════════════════════════════

    class UnpackerPanel(Static):
        def __init__(self, target=None, **kw):
            super().__init__(**kw)
            self.target = target

        def compose(self) -> ComposeResult:
            with Horizontal():
                yield Button("Unpack", id="unpack-btn", variant="primary")
                yield Button("Detect Type", id="detect-btn", variant="secondary")
            yield RichLog(id="unpack-log", auto_scroll=False)

        def on_button_pressed(self, event):
            if event.button.id == "unpack-btn":
                self._unpack()
            elif event.button.id == "detect-btn":
                self._detect()

        def _detect(self):
            if not self.target:
                return
            try:
                from panxcz_tools.unpacker import Unpacker
                u = Unpacker(self.target)
                ftype = u.detect_type()
                log = self.query_one("#unpack-log")
                log.clear()
                log.write(f"[bold]Detected type:[/bold] [cyan]{ftype}[/cyan]")
            except Exception as e:
                self.query_one("#unpack-log").write(f"[red]Error: {e}[/red]")

        def _unpack(self):
            if not self.target:
                return
            log = self.query_one("#unpack-log")
            log.clear()
            log.write("[bold]Unpacking...[/bold]")
            try:
                from panxcz_tools.unpacker import Unpacker
                t0 = time.time()
                u = Unpacker(self.target)
                result = u.unpack()
                elapsed = int((time.time() - t0) * 1000)

                log.write(f"[bold green]✅ Unpack complete![/bold green]")
                log.write(f"  Type:       {result.file_type}")
                log.write(f"  Files:      {result.file_count}")
                log.write(f"  Total size: {result.total_size:,} bytes")
                log.write(f"  Output:     {result.output_dir}")
                log.write(f"  Time:       {elapsed}ms")

                if result.metadata:
                    log.write(f"\n[bold]─── Metadata ───[/bold]")
                    for k, v in result.metadata.items():
                        if isinstance(v, list) and len(v) > 10:
                            log.write(f"  {k}: [{len(v)} items] {v[:5]}...")
                        else:
                            log.write(f"  {k}: {v}")

                if result.errors:
                    log.write(f"\n[bold red]Errors:[/bold red]")
                    for e in result.errors:
                        log.write(f"  ⚠ {e}")

            except Exception as e:
                log.write(f"[red]Error: {e}[/red]")

    # ═══════════════════════════════════════════════════════════════
    #  XREFS PANEL
    # ═══════════════════════════════════════════════════════════════

    class XRefsPanel(Static):
        def __init__(self, target=None, **kw):
            super().__init__(**kw)
            self.target = target

        def compose(self) -> ComposeResult:
            with Horizontal():
                yield Input(placeholder="Address or symbol (e.g. main, printf)", id="xref-addr")
                yield Button("To", id="xref-to-btn", variant="primary")
                yield Button("From", id="xref-from-btn", variant="secondary")
            yield RichLog(id="xref-log", auto_scroll=False)

        def on_button_pressed(self, event):
            addr = self.query_one("#xref-addr").value
            if not addr:
                return
            if event.button.id == "xref-to-btn":
                self._xrefs_to(addr)
            elif event.button.id == "xref-from-btn":
                self._xrefs_from(addr)

        def _xrefs_to(self, addr):
            try:
                from panxcz_tools.core.r2_engine import R2Engine
                engine = R2Engine(self.target)
                xrefs = engine.xrefs_to(addr)
                log = self.query_one("#xref-log")
                log.clear()
                log.write(f"[bold]Cross-references TO {addr} ({len(xrefs)}):[/bold]")
                for x in xrefs:
                    if isinstance(x, dict):
                        log.write(f"  0x{x.get('from', 0):x} → {x.get('type', '?')} {x.get('name', addr)}")
            except Exception as e:
                self.query_one("#xref-log").write(f"[red]Error: {e}[/red]")

        def _xrefs_from(self, addr):
            try:
                from panxcz_tools.core.r2_engine import R2Engine
                engine = R2Engine(self.target)
                xrefs = engine.xrefs_from(addr)
                log = self.query_one("#xref-log")
                log.clear()
                log.write(f"[bold]Cross-references FROM {addr} ({len(xrefs)}):[/bold]")
                for x in xrefs:
                    if isinstance(x, dict):
                        log.write(f"  {addr} → 0x{x.get('to', 0):x} ({x.get('type', '?')})")
            except Exception as e:
                self.query_one("#xref-log").write(f"[red]Error: {e}[/red]")

    # ═══════════════════════════════════════════════════════════════
    #  TERMINAL PANEL
    # ═══════════════════════════════════════════════════════════════

    class TerminalPanel(Static):
        def __init__(self, target=None, **kw):
            super().__init__(**kw)
            self.target = target
            self._engine = None

        def compose(self) -> ComposeResult:
            with Horizontal():
                yield Input(placeholder="r2 command (e.g. afl, pdf @ main, iz)", id="r2-cmd")
                yield Button("Run", id="r2-run", variant="primary")
            yield RichLog(id="r2-log", auto_scroll=True)

        def on_button_pressed(self, event):
            if event.button.id == "r2-run":
                self._run_cmd()

        def on_input_submitted(self, event):
            if event.input.id == "r2-cmd":
                self._run_cmd()

        def _run_cmd(self):
            if not self.target:
                return
            cmd_text = self.query_one("#r2-cmd").value
            if not cmd_text:
                return
            try:
                if not self._engine:
                    from panxcz_tools.core.r2_engine import R2Engine
                    self._engine = R2Engine(self.target)
                    self._engine.cmd("aaa")
                output = self._engine.r2cmd(cmd_text)
                log = self.query_one("#r2-log")
                log.write(f"[dim]$ {cmd_text}[/dim]")
                if output.strip():
                    log.write(output)
            except Exception as e:
                self.query_one("#r2-log").write(f"[red]Error: {e}[/red]")

    # ═══════════════════════════════════════════════════════════════
    #  MAIN APP
    # ═══════════════════════════════════════════════════════════════

    class R2OFRAKApp(App):
        """Panxcz Tools TUI — 14-panel reverse engineering interface."""

        CSS = """
        Screen { background: $surface; }
        #sidebar {
            width: 24;
            dock: left;
            background: $surface-darken-1;
            padding: 1;
            overflow-y: auto;
        }
        #sidebar Button {
            width: 100%;
            margin: 0 0 1 0;
            text-align: left;
        }
        #sidebar Button.selected {
            background: $primary-background-lighten-1;
            text-style: bold;
            border-left: tall $primary;
        }
        #content { height: 1fr; }
        #target-info {
            dock: bottom;
            padding: 1;
            background: $surface-darken-2;
            color: $text-muted;
            text-style: italic;
        }
        .hidden { display: none; }
        DataTable { height: 1fr; }
        RichLog { height: 1fr; }
        Input { margin: 0 0 0 0; width: 1fr; }
        Button { margin: 0 1; }
        Horizontal { height: auto; }
        """

        BINDINGS = [
            # Number keys — work everywhere including Termux
            Binding("1", "show_tab('overview')", "Overview"),
            Binding("2", "show_tab('disasm')", "Disasm"),
            Binding("3", "show_tab('strings')", "Strings"),
            Binding("4", "show_tab('imports')", "Imports"),
            Binding("5", "show_tab('exports')", "Exports"),
            Binding("6", "show_tab('functions')", "Functions"),
            Binding("7", "show_tab('segments')", "Segments"),
            Binding("8", "show_tab('hex')", "Hex"),
            Binding("9", "show_tab('patches')", "Patches"),
            Binding("0", "show_tab('security')", "Security"),
            # Letter keys for extra panels
            Binding("v", "show_tab('vulns')", "Vulns"),
            Binding("u", "show_tab('unpacker')", "Unpack"),
            Binding("x", "show_tab('xrefs')", "XRefs"),
            Binding("t", "show_tab('terminal')", "Terminal"),
            Binding("q", "quit", "Quit"),
        ]

        TITLE = "Panxcz Tools"

        TABS = [
            ("overview", "📁 Overview", "1"),
            ("disasm", "🔍 Disasm", "2"),
            ("strings", "📝 Strings", "3"),
            ("imports", "📥 Imports", "4"),
            ("exports", "📤 Exports", "5"),
            ("functions", "⚡ Functions", "6"),
            ("segments", "📦 Segments", "7"),
            ("hex", "🔢 Hex", "8"),
            ("patches", "🩹 Patches", "9"),
            ("security", "🛡️ Security", "0"),
            ("vulns", "⚠️ Vulns", "V"),
            ("unpacker", "📂 Unpack", "U"),
            ("xrefs", "🔗 XRefs", "X"),
            ("terminal", "💻 Terminal", "T"),
        ]

        def __init__(self, target=None, output_dir=None, **kw):
            super().__init__(**kw)
            self.target = target
            self.output_dir = output_dir
            self._current_panel = "overview"

        def compose(self) -> ComposeResult:
            yield Header()
            with Horizontal(id="main-layout"):
                with Vertical(id="sidebar"):
                    for tab_id, label, key in self.TABS:
                        yield Button(f"{label} [{key}]", id=f"btn-{tab_id}")
                    yield Static(
                        f"\n[dim]Target:[/dim]\n{self.target or 'None'}",
                        id="target-info",
                    )
                with Vertical(id="content"):
                    yield OverviewPanel(target=self.target, id="panel-overview")
                    yield DisasmPanel(target=self.target, id="panel-disasm", classes="hidden")
                    yield StringsPanel(target=self.target, id="panel-strings", classes="hidden")
                    yield ImportsPanel(target=self.target, id="panel-imports", classes="hidden")
                    yield ExportsPanel(target=self.target, id="panel-exports", classes="hidden")
                    yield FunctionsPanel(target=self.target, id="panel-functions", classes="hidden")
                    yield SegmentsPanel(target=self.target, id="panel-segments", classes="hidden")
                    yield HexPanel(target=self.target, id="panel-hex", classes="hidden")
                    yield PatchesPanel(target=self.target, id="panel-patches", classes="hidden")
                    yield SecurityPanel(target=self.target, id="panel-security", classes="hidden")
                    yield VulnsPanel(target=self.target, id="panel-vulns", classes="hidden")
                    yield UnpackerPanel(target=self.target, id="panel-unpacker", classes="hidden")
                    yield XRefsPanel(target=self.target, id="panel-xrefs", classes="hidden")
                    yield TerminalPanel(target=self.target, id="panel-terminal", classes="hidden")
            yield Footer()

        def on_button_pressed(self, event):
            if event.button.id.startswith("btn-"):
                tab_id = event.button.id[4:]
                self.action_show_tab(tab_id)

        def action_show_tab(self, tab_name: str):
            self._current_panel = tab_name
            tab_ids = [t[0] for t in self.TABS]
            for tid in tab_ids:
                widget = self.query(f"#panel-{tid}")
                btn = self.query(f"#btn-{tid}")
                if widget:
                    if tid == tab_name:
                        widget.remove_class("hidden")
                        if btn:
                            btn.add_class("selected")
                    else:
                        widget.add_class("hidden")
                        if btn:
                            btn.remove_class("selected")


def main():
    """Entry point for panxcz-tui."""
    if not HAS_TEXTUAL:
        print("Error: textual not installed. Run: pip install textual", file=sys.stderr)
        sys.exit(1)

    import argparse
    parser = argparse.ArgumentParser(description="Panxcz Tools TUI")
    parser.add_argument("target", nargs="?", help="Binary file to analyze")
    parser.add_argument("-o", "--output", help="Output directory")
    args = parser.parse_args()

    app = R2OFRAKApp(target=args.target, output_dir=args.output)
    app.run()


if __name__ == "__main__":
    main()
