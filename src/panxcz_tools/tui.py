"""
Panxcz Tools TUI — Textual-based reverse engineering interface.
14 panels: Overview, Disasm, Strings, Imports, Exports, Functions,
           Segments, Hex, Patches, Security, Vulns, Unpacker, XRefs, Terminal.

Termux-compatible: uses number keys (1-9,0) + letter keys (V,U,X,T,Q).
No F-keys, no expand=, no width= on Input.
"""

import sys
import time
from pathlib import Path

try:
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal, Vertical
    from textual.widgets import (
        Header, Footer, Static, DataTable, Input, RichLog,
        Button, Label,
    )
    HAS_TEXTUAL = True
except ImportError:
    HAS_TEXTUAL = False

__version__ = "0.0.1"


if HAS_TEXTUAL:

    def safe_log(log, msg):
        """Write to RichLog, ignore errors."""
        try:
            log.write(msg)
        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════════
    #  PANELS — lazy load, no crash on mount
    # ═══════════════════════════════════════════════════════════════

    class OverviewPanel(Static):
        def __init__(self, target=None, **kw):
            super().__init__(**kw)
            self.target = target
            self._loaded = False

        def compose(self) -> ComposeResult:
            yield RichLog(id="overview-log")

        def on_mount(self):
            log = self.query_one("#overview-log")
            if not self.target:
                safe_log(log, "[dim]No file loaded. Use: panxcz-tui <binary>[/dim]")
                return
            safe_log(log, f"[cyan]Loading: {self.target}...[/cyan]")
            try:
                from panxcz_tools.core.r2_engine import R2Engine
                engine = R2Engine(self.target)
                info = engine.info()
                bi = info.get("bin", {})
                fi = info.get("core", {})
                funcs = engine.functions()
                imports = engine.imports()
                log.clear()
                lines = [
                    f"[bold cyan]═══ Panxcz Tools v{__version__} ═══[/bold cyan]",
                    f"",
                    f"  File:      [green]{self.target}[/green]",
                    f"  Arch:      {bi.get('arch', '?')}",
                    f"  Bits:      {bi.get('bits', '?')}",
                    f"  OS:        {bi.get('os', '?')}",
                    f"  Endian:    {bi.get('endian', '?')}",
                    f"  Type:      {bi.get('class', '?')}",
                    f"  Stripped:  {bi.get('stripped', '?')}",
                    f"  Size:      {fi.get('size', '?'):,} bytes",
                    f"",
                    f"  Functions: {len(funcs)}",
                    f"  Imports:   {len(imports)}",
                ]
                # Protections
                try:
                    from panxcz_tools.core.security import SecurityAnalyzer
                    sa = SecurityAnalyzer(self.target)
                    prots = sa.protections()
                    lines.append("")
                    lines.append("  [bold]Protections:[/bold]")
                    for k, v in prots.items():
                        icon = "Y" if v else "N"
                        lines.append(f"    {icon} {k}")
                except Exception:
                    pass
                safe_log(log, "\n".join(lines))
                self._loaded = True
            except Exception as e:
                safe_log(log, f"[red]Error loading: {e}[/red]")

    class DisasmPanel(Static):
        def __init__(self, target=None, **kw):
            super().__init__(**kw)
            self.target = target

        def compose(self) -> ComposeResult:
            with Horizontal():
                yield Input(placeholder="Address (entry0, main, 0x401000)", id="disasm-addr")
                yield Input(placeholder="Count", id="disasm-count")
                yield Button("Go", id="disasm-btn")
            yield RichLog(id="disasm-log")

        def on_button_pressed(self, event):
            if event.button.id == "disasm-btn":
                self._do()

        def on_mount(self):
            if self.target:
                self._do()

        def _do(self):
            log = self.query_one("#disasm-log")
            addr = self.query_one("#disasm-addr").value or "entry0"
            count = self.query_one("#disasm-count").value or "200"
            try:
                from panxcz_tools.core.r2_engine import R2Engine
                engine = R2Engine(self.target)
                engine.cmd("aaa")
                output = engine.cmd(f"pd {count} @ {addr}")
                log.clear()
                for line in output.split("\n"):
                    if not line.strip():
                        continue
                    if any(k in line for k in ["sym.", "fcn.", "sub."]):
                        log.write(f"[yellow]{line}[/yellow]")
                    elif any(k in line for k in ["jnz", "je ", "jne", "jmp", "call"]):
                        log.write(f"[red]{line}[/red]")
                    else:
                        log.write(line)
            except Exception as e:
                safe_log(log, f"[red]Error: {e}[/red]")

    class StringsPanel(Static):
        def __init__(self, target=None, **kw):
            super().__init__(**kw)
            self.target = target

        def compose(self) -> ComposeResult:
            with Horizontal():
                yield Input(placeholder="Filter...", id="str-filter")
                yield Button("Extract", id="str-btn")
            yield DataTable(id="strings-table")

        def on_button_pressed(self, event):
            if event.button.id == "str-btn":
                self._do()

        def on_mount(self):
            if self.target:
                table = self.query_one("#strings-table")
                table.add_columns("Offset", "Type", "String")
                self._do()

        def _do(self):
            try:
                from panxcz_tools.core.r2_engine import R2Engine
                engine = R2Engine(self.target)
                flt = self.query_one("#str-filter").value.lower()
                strings = engine.strings(min_len=6)
                table = self.query_one("#strings-table")
                table.clear()
                n = 0
                for s in strings:
                    val = s.get("string", "")
                    if flt and flt not in val.lower():
                        continue
                    table.add_row(s.get("offset", "?"), s.get("type", "?"), val[:100])
                    n += 1
                    if n > 500:
                        break
            except Exception as e:
                self.query_one("#strings-table").add_row("Error", "", str(e))

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
            table.add_columns("PLT", "Name")
            try:
                from panxcz_tools.core.r2_engine import R2Engine
                engine = R2Engine(self.target)
                engine.cmd("aaa")
                for imp in engine.imports():
                    if isinstance(imp, dict):
                        table.add_row(str(imp.get("plt", "?")), imp.get("name", "?"))
            except Exception as e:
                table.add_row("Error", str(e))

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
            table.add_columns("VAddr", "Name")
            try:
                from panxcz_tools.core.r2_engine import R2Engine
                engine = R2Engine(self.target)
                engine.cmd("aaa")
                for exp in engine.exports():
                    if isinstance(exp, dict):
                        table.add_row(str(exp.get("vaddr", "?")), exp.get("name", "?"))
            except Exception as e:
                table.add_row("Error", str(e))

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
            table.add_columns("Offset", "Name", "Size")
            try:
                from panxcz_tools.core.r2_engine import R2Engine
                engine = R2Engine(self.target)
                engine.cmd("aaa")
                for f in engine.functions():
                    if isinstance(f, dict):
                        table.add_row(f"0x{f.get('offset', 0):x}", f.get("name", "?"), str(f.get("size", 0)))
            except Exception as e:
                table.add_row("Error", str(e), "")

    class SegmentsPanel(Static):
        def __init__(self, target=None, **kw):
            super().__init__(**kw)
            self.target = target

        def compose(self) -> ComposeResult:
            yield DataTable(id="seg-table")

        def on_mount(self):
            if not self.target:
                return
            table = self.query_one("#seg-table")
            table.add_columns("Name", "VAddr", "Size", "Perm")
            try:
                from panxcz_tools.core.r2_engine import R2Engine
                engine = R2Engine(self.target)
                for sec in engine.sections():
                    if isinstance(sec, dict):
                        table.add_row(
                            sec.get("name", "?"),
                            f"0x{sec.get('vaddr', 0):x}",
                            str(sec.get("size", 0)),
                            sec.get("perm", "?"),
                        )
            except Exception as e:
                table.add_row("Error", "", "", str(e))

    class HexPanel(Static):
        def __init__(self, target=None, **kw):
            super().__init__(**kw)
            self.target = target

        def compose(self) -> ComposeResult:
            with Horizontal():
                yield Input(placeholder="Offset hex", id="hex-addr")
                yield Input(placeholder="Size", id="hex-size")
                yield Button("View", id="hex-btn")
            yield RichLog(id="hex-log")

        def on_button_pressed(self, event):
            if event.button.id == "hex-btn":
                self._do()

        def on_mount(self):
            if self.target:
                self._do()

        def _do(self):
            log = self.query_one("#hex-log")
            try:
                from panxcz_tools.core.r2_engine import R2Engine
                engine = R2Engine(self.target)
                addr = self.query_one("#hex-addr").value or "0x0"
                sz = self.query_one("#hex-size").value or "256"
                offset = int(addr, 16) if addr.startswith("0x") else int(addr)
                size = int(sz)
                log.clear()
                log.write(engine.hexdump(offset=offset, size=min(size, 2048)))
            except Exception as e:
                safe_log(log, f"[red]Error: {e}[/red]")

    class PatchesPanel(Static):
        def __init__(self, target=None, **kw):
            super().__init__(**kw)
            self.target = target

        def compose(self) -> ComposeResult:
            with Horizontal():
                yield Input(placeholder="Offset hex", id="patch-addr")
                yield Input(placeholder="Hex bytes (9090)", id="patch-data")
                yield Button("Patch", id="patch-btn")
                yield Button("NOP", id="nop-btn")
            yield RichLog(id="patch-log")

        def on_button_pressed(self, event):
            log = self.query_one("#patch-log")
            try:
                from panxcz_tools.core.r2_engine import R2Engine
                engine = R2Engine(self.target)
                offset = int(self.query_one("#patch-addr").value, 16)
                if event.button.id == "patch-btn":
                    data = self.query_one("#patch-data").value
                    engine.patch(offset, data)
                    safe_log(log, f"[green]Patched {len(data)//2} bytes at 0x{offset:x}[/green]")
                elif event.button.id == "nop-btn":
                    size = int(self.query_one("#patch-data").value or "1")
                    engine.nop(offset, size)
                    safe_log(log, f"[green]NOP {size} bytes at 0x{offset:x}[/green]")
            except Exception as e:
                safe_log(log, f"[red]Error: {e}[/red]")

    class SecurityPanel(Static):
        def __init__(self, target=None, **kw):
            super().__init__(**kw)
            self.target = target
            self._loaded = False

        def compose(self) -> ComposeResult:
            yield RichLog(id="sec-log")

        def on_mount(self):
            if self._loaded or not self.target:
                return
            log = self.query_one("#sec-log")
            safe_log(log, "[cyan]Running security analysis...[/cyan]")
            try:
                from panxcz_tools.core.security import SecurityAnalyzer
                sa = SecurityAnalyzer(self.target)
                data = sa.full()
                log.clear()
                safe_log(log, "[bold cyan]═══ Security Report ═══[/bold cyan]")

                # Protections
                prot = data.get("protections", {})
                safe_log(log, "\n  [bold]Protections:[/bold]")
                for k, v in prot.items():
                    safe_log(log, f"    {'Y' if v else 'N'} {k}")

                # Anti-debug
                ad = data.get("anti_debug", [])
                if ad:
                    safe_log(log, f"\n  [bold red]Anti-Debug ({len(ad)}):[/bold red]")
                    for a in ad[:10]:
                        safe_log(log, f"    ! {a.get('description', '?')}")

                # Anti-root
                ar = data.get("anti_root", [])
                if ar:
                    safe_log(log, f"\n  [bold red]Anti-Root ({len(ar)}):[/bold red]")
                    for a in ar[:5]:
                        safe_log(log, f"    ! {a.get('description', '?')}")

                # Anti-emulator
                ae = data.get("anti_emulator", [])
                if ae:
                    safe_log(log, f"\n  [bold red]Anti-Emulator ({len(ae)}):[/bold red]")
                    for a in ae[:5]:
                        safe_log(log, f"    ! {a.get('description', '?')}")

                # Frida
                fr = data.get("frida_hooks", [])
                if fr:
                    safe_log(log, f"\n  [bold red]Frida ({len(fr)}):[/bold red]")
                    for f in fr[:5]:
                        safe_log(log, f"    ! {f.get('description', '?')}")

                # SSL
                ssl = data.get("ssl_pinning", [])
                if ssl:
                    safe_log(log, f"\n  [bold yellow]SSL Pinning ({len(ssl)}):[/bold yellow]")
                    for s in ssl[:5]:
                        safe_log(log, f"    ! {s.get('description', '?')}")

                # Crypto
                cr = data.get("crypto", [])
                if cr:
                    safe_log(log, f"\n  Crypto ({len(cr)}):")
                    for c in cr[:5]:
                        safe_log(log, f"    {c.get('description', '?')}")

                # Permissions
                perms = data.get("permissions", [])
                if perms:
                    safe_log(log, f"\n  Permissions ({len(perms)}):")
                    for p in perms:
                        safe_log(log, f"    {p}")

                self._loaded = True
            except Exception as e:
                safe_log(log, f"[red]Error: {e}[/red]")

    class VulnsPanel(Static):
        def __init__(self, target=None, **kw):
            super().__init__(**kw)
            self.target = target

        def compose(self) -> ComposeResult:
            yield RichLog(id="vulns-log")

        def on_mount(self):
            if not self.target:
                return
            log = self.query_one("#vulns-log")
            try:
                from panxcz_tools.core.r2_engine import R2Engine
                from panxcz_tools.core.security import SecurityAnalyzer
                engine = R2Engine(self.target)
                vulns = engine.vulnerabilities()
                sa = SecurityAnalyzer(self.target)
                data = sa.full()
                vulns2 = data.get("vulnerabilities", [])
                total = vulns + vulns2
                if not total:
                    safe_log(log, "[green]No known vulnerabilities.[/green]")
                    return
                safe_log(log, f"[bold red]Found {len(total)} issues:[/bold red]")
                for v in total:
                    sev = v.get("severity", "?")
                    safe_log(log, f"  [{sev.upper()}] {v.get('description', '?')} @ {v.get('address', v.get('offset', '?'))}")
            except Exception as e:
                safe_log(log, f"[red]Error: {e}[/red]")

    class UnpackerPanel(Static):
        def __init__(self, target=None, **kw):
            super().__init__(**kw)
            self.target = target

        def compose(self) -> ComposeResult:
            with Horizontal():
                yield Button("Unpack", id="unpack-btn")
                yield Button("Detect", id="detect-btn")
            yield RichLog(id="unpack-log")

        def on_button_pressed(self, event):
            log = self.query_one("#unpack-log")
            if not self.target:
                return
            try:
                from panxcz_tools.unpacker import Unpacker
                u = Unpacker(self.target)
                if event.button.id == "detect-btn":
                    log.clear()
                    safe_log(log, f"Type: [cyan]{u.detect_type()}[/cyan]")
                elif event.button.id == "unpack-btn":
                    log.clear()
                    safe_log(log, "[cyan]Unpacking...[/cyan]")
                    t0 = time.time()
                    result = u.unpack()
                    ms = int((time.time() - t0) * 1000)
                    log.clear()
                    safe_log(log, f"[green]Done![/green] {result.file_count} files, {result.total_size:,} bytes, {ms}ms")
                    safe_log(log, f"Output: {result.output_dir}")
                    if result.errors:
                        for e in result.errors:
                            safe_log(log, f"[red]  {e}[/red]")
            except Exception as e:
                safe_log(log, f"[red]Error: {e}[/red]")

    class XRefsPanel(Static):
        def __init__(self, target=None, **kw):
            super().__init__(**kw)
            self.target = target

        def compose(self) -> ComposeResult:
            with Horizontal():
                yield Input(placeholder="Address/symbol", id="xref-addr")
                yield Button("To", id="xref-to")
                yield Button("From", id="xref-from")
            yield RichLog(id="xref-log")

        def on_button_pressed(self, event):
            log = self.query_one("#xref-log")
            addr = self.query_one("#xref-addr").value
            if not addr or not self.target:
                return
            try:
                from panxcz_tools.core.r2_engine import R2Engine
                engine = R2Engine(self.target)
                log.clear()
                if event.button.id == "xref-to":
                    data = engine.xrefs_to(addr)
                    safe_log(log, f"[bold]XRefs TO {addr} ({len(data)}):[/bold]")
                    for x in data:
                        if isinstance(x, dict):
                            safe_log(log, f"  0x{x.get('from', 0):x} -> {x.get('name', addr)}")
                elif event.button.id == "xref-from":
                    data = engine.xrefs_from(addr)
                    safe_log(log, f"[bold]XRefs FROM {addr} ({len(data)}):[/bold]")
                    for x in data:
                        if isinstance(x, dict):
                            safe_log(log, f"  -> 0x{x.get('to', 0):x}")
            except Exception as e:
                safe_log(log, f"[red]Error: {e}[/red]")

    class TerminalPanel(Static):
        def __init__(self, target=None, **kw):
            super().__init__(**kw)
            self.target = target
            self._engine = None

        def compose(self) -> ComposeResult:
            with Horizontal():
                yield Input(placeholder="r2 command (afl, pdf @ main, iz)", id="r2-cmd")
                yield Button("Run", id="r2-run")
            yield RichLog(id="r2-log")

        def on_button_pressed(self, event):
            if event.button.id == "r2-run":
                self._run()

        def on_input_submitted(self, event):
            if event.input.id == "r2-cmd":
                self._run()

        def _run(self):
            if not self.target:
                return
            cmd_text = self.query_one("#r2-cmd").value
            if not cmd_text:
                return
            log = self.query_one("#r2-log")
            try:
                if not self._engine:
                    from panxcz_tools.core.r2_engine import R2Engine
                    self._engine = R2Engine(self.target)
                    self._engine.cmd("aaa")
                output = self._engine.r2cmd(cmd_text)
                safe_log(log, f"[dim]$ {cmd_text}[/dim]")
                if output.strip():
                    safe_log(log, output)
            except Exception as e:
                safe_log(log, f"[red]Error: {e}[/red]")

    # ═══════════════════════════════════════════════════════════════
    #  MAIN APP
    # ═══════════════════════════════════════════════════════════════

    class R2OFRAKApp(App):
        """Panxcz Tools TUI — 14-panel reverse engineering interface."""

        CSS = """
        Screen { background: $surface; }
        #sidebar {
            width: 22;
            dock: left;
            background: $surface-darken-1;
            padding: 1;
        }
        #sidebar Button { width: 100%; margin: 0 0 1 0; text-align: left; }
        #sidebar Button.selected { background: $primary; color: $text; text-style: bold; }
        #content { height: 1fr; }
        #info { dock: bottom; padding: 1; background: $surface-darken-2; color: $text-muted; }
        .hidden { display: none; }
        DataTable { height: 1fr; }
        RichLog { height: 1fr; }
        Horizontal { height: auto; }
        Input { width: 1fr; }
        """

        BINDINGS = [
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
            Binding("v", "show_tab('vulns')", "Vulns"),
            Binding("u", "show_tab('unpacker')", "Unpack"),
            Binding("x", "show_tab('xrefs')", "XRefs"),
            Binding("t", "show_tab('terminal')", "Terminal"),
            Binding("q", "quit", "Quit"),
        ]

        TITLE = "Panxcz Tools"

        TABS = [
            ("overview", "1 Overview"),
            ("disasm", "2 Disasm"),
            ("strings", "3 Strings"),
            ("imports", "4 Imports"),
            ("exports", "5 Exports"),
            ("functions", "6 Functions"),
            ("segments", "7 Segments"),
            ("hex", "8 Hex"),
            ("patches", "9 Patches"),
            ("security", "0 Security"),
            ("vulns", "V Vulns"),
            ("unpacker", "U Unpack"),
            ("xrefs", "X XRefs"),
            ("terminal", "T Terminal"),
        ]

        def __init__(self, target=None, output_dir=None, **kw):
            super().__init__(**kw)
            self.target = target
            self.output_dir = output_dir

        def compose(self) -> ComposeResult:
            yield Header()
            with Horizontal(id="main-layout"):
                with Vertical(id="sidebar"):
                    for tid, label in self.TABS:
                        yield Button(label, id=f"btn-{tid}")
                    t = self.target or "None"
                    yield Static(f"\nTarget:\n{t}", id="info")
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
                self.action_show_tab(event.button.id[4:])

        def action_show_tab(self, tab_name):
            tab_ids = [t[0] for t in self.TABS]
            for tid in tab_ids:
                w = self.query(f"#panel-{tid}")
                b = self.query(f"#btn-{tid}")
                if w:
                    if tid == tab_name:
                        w.remove_class("hidden")
                        if b:
                            try:
                                b.add_class("selected")
                            except Exception:
                                pass
                    else:
                        w.add_class("hidden")
                        if b:
                            try:
                                b.remove_class("selected")
                            except Exception:
                                pass


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
