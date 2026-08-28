"""
Panxcz Tools TUI — Textual-based reverse engineering interface.
Tabs: Overview, Disasm, Strings, Imports, Functions, Segments,
      Hex, Patches, Security, Vulns, Terminal
"""

import sys
from pathlib import Path

try:
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal, Vertical, ScrollableContainer
    from textual.widgets import (
        Header, Footer, Static, DataTable, Input, RichLog,
        Label, Tabs, Tab, Button, Select, OptionList, Markdown,
    )
    from textual.reactive import reactive
    HAS_TEXTUAL = True
except ImportError:
    HAS_TEXTUAL = False


__version__ = "1.0.0"


if HAS_TEXTUAL:
    class OverviewPanel(Static):
        """Binary overview panel."""
        def __init__(self, target=None, **kw):
            super().__init__(**kw)
            self.target = target
            self._data = None

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
                lines = [
                    f"[bold cyan]═══ Panxcz Tools v{__version__} ═══[/bold cyan]",
                    f"File:      [green]{self.target}[/green]",
                    f"Arch:      {bi.get('arch', '?')}",
                    f"Bits:      {bi.get('bits', '?')}",
                    f"OS:        {bi.get('os', '?')}",
                    f"Endian:    {bi.get('endian', '?')}",
                    f"Type:      {bi.get('class', '?')}",
                    f"Compiler:  {bi.get('compiler', 'unknown')}",
                    f"Stripped:  {bi.get('stripped', '?')}",
                    f"Relocs:    {bi.get('relocs', '?')}",
                    f"Size:      {fi.get('size', '?')} bytes",
                    f"MD5:       {fi.get('md5', '?')[:32]}",
                ]
                log.write("\n".join(lines))
            except Exception as e:
                self.query_one("#overview-log").write(f"[red]Error: {e}[/red]")

    class DisasmPanel(Static):
        """Disassembly panel."""
        def __init__(self, target=None, **kw):
            super().__init__(**kw)
            self.target = target

        def compose(self) -> ComposeResult:
            with Vertical():
                yield Input(placeholder="Address (e.g. entry0, main, 0x401000)", id="disasm-addr")
                yield Button("Disassemble", id="disasm-btn", variant="primary")
                yield RichLog(id="disasm-log", auto_scroll=False)

        def on_button_pressed(self, event):
            if event.button.id == "disasm-btn":
                addr = self.query_one("#disasm-addr").value or "entry0"
                self._disassemble(addr)

        def on_mount(self):
            if self.target:
                self._disassemble("entry0")

        def _disassemble(self, addr):
            try:
                from panxcz_tools.core.r2_engine import R2Engine
                engine = R2Engine(self.target)
                engine.cmd("aaa")
                output = engine.cmd(f"pd 200 @ {addr}")
                log = self.query_one("#disasm-log")
                log.clear()
                for line in output.split("\n"):
                    if "sym." in line or "fcn." in line or "sub." in line:
                        log.write(f"[bold yellow]{line}[/bold yellow]")
                    elif "jnz" in line or "je" in line or "jmp" in line:
                        log.write(f"[bold red]{line}[/bold red]")
                    elif "mov" in line or "push" in line:
                        log.write(f"[cyan]{line}[/cyan]")
                    else:
                        log.write(line)
            except Exception as e:
                self.query_one("#disasm-log").write(f"[red]Error: {e}[/red]")

    class StringsPanel(Static):
        """String extraction panel."""
        def __init__(self, target=None, **kw):
            super().__init__(**kw)
            self.target = target

        def compose(self) -> ComposeResult:
            with Horizontal():
                yield Input(placeholder="Filter strings...", id="str-filter", expand=True)
                yield Button("Extract", id="str-btn", variant="primary")
            yield DataTable(id="strings-table")

        def on_button_pressed(self, event):
            if event.button.id == "str-btn":
                self._extract()

        def on_mount(self):
            if self.target:
                table = self.query_one("#strings-table")
                table.add_columns("Offset", "VAddr", "Type", "String")
                self._extract()

        def _extract(self):
            try:
                from panxcz_tools.core.r2_engine import R2Engine
                engine = R2Engine(self.target)
                filter_text = self.query_one("#str-filter").value.lower()
                strings = engine.strings(min_len=4)
                table = self.query_one("#strings-table")
                table.clear()
                count = 0
                for s in strings:
                    if filter_text and filter_text not in s.get("string", "").lower():
                        continue
                    table.add_row(
                        s.get("offset", "0x0"),
                        s.get("vaddr", "0x0"),
                        s.get("type", "?"),
                        s.get("string", ""),
                    )
                    count += 1
                    if count > 500:
                        break
            except Exception as e:
                self.query_one("#strings-table").add_row("Error", "", "", str(e))

    class ImportsPanel(Static):
        """Import table panel."""
        def __init__(self, target=None, **kw):
            super().__init__(**kw)
            self.target = target

        def compose(self) -> ComposeResult:
            yield DataTable(id="imports-table")

        def on_mount(self):
            if not self.target:
                return
            table = self.query_one("#imports-table")
            table.add_columns("PLT", "Name", "Type")
            try:
                from panxcz_tools.core.r2_engine import R2Engine
                engine = R2Engine(self.target)
                engine.cmd("aaa")
                imports = engine.imports()
                for imp in imports:
                    if isinstance(imp, dict):
                        name = imp.get("name", "?")
                        table.add_row(
                            str(imp.get("plt", "?")),
                            name,
                            "func",
                        )
            except Exception as e:
                table.add_row("Error", str(e), "")

    class HexPanel(Static):
        """Hex view panel."""
        def __init__(self, target=None, **kw):
            super().__init__(**kw)
            self.target = target

        def compose(self) -> ComposeResult:
            with Horizontal():
                yield Input(placeholder="Offset (hex, e.g. 0x0)", id="hex-offset", value="0x0")
                yield Input(placeholder="Size (bytes)", id="hex-size", value="512")
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
                output = engine.hexdump(offset=offset, size=size)
                log = self.query_one("#hex-log")
                log.clear()
                log.write(output)
            except Exception as e:
                self.query_one("#hex-log").write(f"[red]Error: {e}[/red]")

    class SecurityPanel(Static):
        """Security analysis panel."""
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
                log.write("[bold cyan]═══ Security Analysis ═══[/bold cyan]")
                h = data.get("hashes", {})
                log.write(f"SHA256: {h.get('sha256', '?')[:64]}")
                prot = data.get("protections", {})
                for k, v in prot.items():
                    icon = "✅" if v else "❌"
                    log.write(f"  {icon} {k}")
                ad = data.get("anti_debug", [])
                if ad:
                    log.write(f"\n[bold red]Anti-debug ({len(ad)}):[/bold red]")
                    for a in ad[:10]:
                        log.write(f"  ⚠ {a.get('description', a.get('type', '?'))}")
                cr = data.get("crypto", [])
                if cr:
                    log.write(f"\n[bold yellow]Crypto ({len(cr)}):[/bold yellow]")
                    for c in cr[:10]:
                        log.write(f"  🔐 {c.get('description', c.get('type', '?'))}")
            except Exception as e:
                self.query_one("#security-log").write(f"[red]Error: {e}[/red]")

    class VulnsPanel(Static):
        """Vulnerability scan panel."""
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
                engine = R2Engine(self.target)
                vulns = engine.vulnerabilities()
                log = self.query_one("#vulns-log")
                if not vulns:
                    log.write("[green]No known vulnerabilities found.[/green]")
                    return
                log.write(f"[bold red]Found {len(vulns)} potential issues:[/bold red]")
                for v in vulns:
                    sev = v.get("severity", "?")
                    color = "red" if sev == "high" else "yellow"
                    log.write(f"  [{color}][{sev.upper()}][/{color}] {v.get('description', '?')} @ {v.get('address', '?')}")
            except Exception as e:
                self.query_one("#vulns-log").write(f"[red]Error: {e}[/red]")

    class TerminalPanel(Static):
        """Direct r2 command terminal."""
        def __init__(self, target=None, **kw):
            super().__init__(**kw)
            self.target = target
            self._engine = None

        def compose(self) -> ComposeResult:
            with Horizontal():
                yield Input(placeholder="r2 command (e.g. afl, pdf @ main, iz)", id="r2-cmd", expand=True)
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
                log.write(output)
            except Exception as e:
                self.query_one("#r2-log").write(f"[red]Error: {e}[/red]")

    class R2OFRAKApp(App):
        """Panxcz Tools TUI — Full-featured reverse engineering interface."""

        CSS = """
        Screen { background: $surface }
        #sidebar { width: 22; dock: left; background: $surface-darken-1; padding: 1; }
        #sidebar Button { width: 100%; margin: 1 0; }
        #content { height: 1fr; }
        #status-bar { height: 1; dock: bottom; background: $primary-background-lighten-2; padding: 0 1; }
        DataTable { height: 1fr; }
        RichLog { height: 1fr; }
        Input { margin: 0 0 0 0; }
        Button { margin: 0 1; }
        .hidden { display: none; }
        Button.selected { background: $primary-background-lighten-1; text-style: bold; }
        """

        BINDINGS = [
            Binding("f1", "show_tab('overview')", "Overview"),
            Binding("f2", "show_tab('disasm')", "Disasm"),
            Binding("f3", "show_tab('strings')", "Strings"),
            Binding("f4", "show_tab('imports')", "Imports"),
            Binding("f5", "show_tab('hex')", "Hex"),
            Binding("f6", "show_tab('security')", "Security"),
            Binding("f7", "show_tab('vulns')", "Vulns"),
            Binding("f8", "show_tab('terminal')", "Terminal"),
            Binding("ctrl+q", "quit", "Quit"),
        ]

        TITLE = "Panxcz Tools"

        def __init__(self, target=None, output_dir=None, **kw):
            super().__init__(**kw)
            self.target = target
            self.output_dir = output_dir
            self._current_panel = "overview"

        def compose(self) -> ComposeResult:
            yield Header()
            with Horizontal(id="main-layout"):
                with Vertical(id="sidebar"):
                    yield Button("📁 Overview", id="btn-overview", variant="primary")
                    yield Button("🔍 Disasm", id="btn-disasm")
                    yield Button("📝 Strings", id="btn-strings")
                    yield Button("📥 Imports", id="btn-imports")
                    yield Button("🔢 Hex", id="btn-hex")
                    yield Button("🛡️ Security", id="btn-security")
                    yield Button("⚠️ Vulns", id="btn-vulns")
                    yield Button("💻 Terminal", id="btn-terminal")
                    yield Static(f"\n[target]\n{self.target or 'None'}", id="target-info")
                with Vertical(id="content"):
                    yield OverviewPanel(target=self.target, id="panel-overview")
                    yield DisasmPanel(target=self.target, id="panel-disasm", classes="hidden")
                    yield StringsPanel(target=self.target, id="panel-strings", classes="hidden")
                    yield ImportsPanel(target=self.target, id="panel-imports", classes="hidden")
                    yield HexPanel(target=self.target, id="panel-hex", classes="hidden")
                    yield SecurityPanel(target=self.target, id="panel-security", classes="hidden")
                    yield VulnsPanel(target=self.target, id="panel-vulns", classes="hidden")
                    yield TerminalPanel(target=self.target, id="panel-terminal", classes="hidden")
            yield Footer()

        def on_button_pressed(self, event):
            panel_map = {
                "btn-overview": "overview",
                "btn-disasm": "disasm",
                "btn-strings": "strings",
                "btn-imports": "imports",
                "btn-hex": "hex",
                "btn-security": "security",
                "btn-vulns": "vulns",
                "btn-terminal": "terminal",
            }
            if event.button.id in panel_map:
                self.action_show_tab(panel_map[event.button.id])

        def action_show_tab(self, tab_name: str):
            self._current_panel = tab_name
            panels = [
                "overview", "disasm", "strings", "imports",
                "hex", "security", "vulns", "terminal",
            ]
            for p in panels:
                widget = self.query(f"#panel-{p}")
                if widget:
                    if p == tab_name:
                        widget.remove_class("hidden")
                        self.query(f"#btn-{p}").add_class("selected")
                    else:
                        widget.add_class("hidden")
                        self.query(f"#btn-{p}").remove_class("selected")


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
