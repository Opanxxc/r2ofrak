#!/usr/bin/env python3
"""
R2OFRAK TUI — Terminal User Interface for unified reverse engineering.
Tabs: Overview | Disasm | Strings | Imports | Exports | Functions | Segments | Hex | Patches | OFRAK | Vulns | Terminal
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Label,
    LoadingIndicator,
    RichLog,
    Select,
    Static,
    TabbedContent,
    TabPane,
    TextArea,
)

if TYPE_CHECKING:
    from r2ofrak.core import R2OFRAKContext

# ─── Colours ────────────────────────────────────────────────────────────────
ACCENT = "bold cyan"
HIGHLIGHT = "bold yellow"
ERR = "bold red"
OK = "bold green"
DIM = "dim"


# ─── Helper ─────────────────────────────────────────────────────────────────
def _safe(ctx: "R2OFRAKContext", fn, *a, **kw):
    """Run fn, return result or error dict."""
    try:
        return fn(*a, **kw)
    except Exception as exc:
        return {"error": str(exc)}


# ─── Screens ────────────────────────────────────────────────────────────────
class FileOpenScreen(ModalScreen[Optional[str]]):
    """Modal: type a file path to open."""

    CSS = """
    FileOpenScreen { align: center middle; }
    #dialog {
        width: 70;
        height: auto;
        border: tall $accent;
        padding: 1 2;
        background: $surface;
    }
    #path_input { width: 100%; }
    .buttons { margin-top: 1; }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label("[b]Open Binary[/b]", id="title")
            yield TextArea(id="path_input")
            with Horizontal(classes="buttons"):
                yield Select(
                    [(str(p), str(p)) for p in Path("/usr/bin").iterdir() if p.is_file()][:30],
                    id="quick_pick",
                    prompt="Quick pick…",
                )

    def on_mount(self) -> None:
        self.query_one("#path_input", TextArea).focus()

    @on(TextArea.Changed, "#path_input")
    def on_input_changed(self, event: TextArea.Changed) -> None:
        pass

    @on(Select.Changed, "#quick_pick")
    def on_quick_pick(self, event: Select.Changed) -> None:
        if event.value and event.value is not Select.BLANK:
            self.dismiss(str(event.value))

    def on_key(self, event) -> None:
        if event.key == "enter" and not self.query_one("#path_input").has_focus:
            path = self.query_one("#path_input", TextArea).text.strip()
            if path:
                self.dismiss(path)
        if event.key == "escape":
            self.dismiss(None)


# ─── Main TUI App ──────────────────────────────────────────────────────────
class R2OFRAKApp(App):
    """
    R2OFRAK — Unified Reverse Engineering TUI.
    
    Keyboard:
      Ctrl+O   Open file
      Ctrl+Q   Quit
      Ctrl+A   Full analysis
      Ctrl+D   Disassemble
      Ctrl+S   Dump strings
      Ctrl+P   Patch mode
      Ctrl+F   Run r2 command
      1-9      Switch tabs
    """

    TITLE = "R2OFRAK — radare2 + OFRAK"
    SUB_TITLE = "Unified Reverse Engineering Platform"

    CSS = """
    Screen { background: $surface; }
    
    #sidebar {
        width: 30;
        dock: left;
        border-right: tall $accent;
        background: $surface-darken-1;
    }
    #sidebar DataTable { height: 100%; }
    
    #main { width: 1fr; }
    
    TabbedContent { height: 1fr; }
    TabPane { padding: 1; }
    
    #overview_content { height: auto; }
    #disasm_content { height: 1fr; overflow-y: auto; }
    #strings_content { height: 1fr; }
    #imports_content { height: 1fr; }
    #exports_content { height: 1fr; }
    #functions_content { height: 1fr; }
    #segments_content { height: 1fr; }
    #hex_content { height: 1fr; overflow-y: auto; }
    #patches_content { height: 1fr; }
    #ofrak_content { height: 1fr; }
    #vulns_content { height: 1fr; }
    #terminal_content { height: 1fr; }
    
    DataTable { height: 1fr; }
    RichLog { height: 1fr; }
    TextArea { height: 1fr; }
    
    #info_bar {
        dock: bottom;
        height: 1;
        background: $accent;
        color: $text;
        padding: 0 1;
    }
    
    #search_bar {
        dock: top;
        height: 3;
        display: none;
        padding: 0 1;
        background: $surface-darken-1;
        border-bottom: solid $accent;
    }
    #search_bar.visible { display: block; }
    #search_input { width: 100%; }
    """

    BINDINGS = [
        Binding("ctrl+o", "open_file", "Open file"),
        Binding("ctrl+q", "quit", "Quit"),
        Binding("ctrl+a", "full_analysis", "Full analysis"),
        Binding("ctrl+d", "disassemble", "Disassemble"),
        Binding("ctrl+s", "dump_strings", "Strings"),
        Binding("ctrl+p", "patch_mode", "Patch"),
        Binding("ctrl+f", "r2_command", "r2 command"),
        Binding("ctrl+g", "toggle_search", "Search"),
        Binding("escape", "close_search", "Close search"),
        Binding("f1", "show_overview", "Overview"),
        Binding("f2", "show_disasm", "Disasm"),
        Binding("f3", "show_strings", "Strings"),
        Binding("f4", "show_imports", "Imports"),
        Binding("f5", "show_hex", "Hex"),
        Binding("f6", "show_functions", "Functions"),
        Binding("f7", "show_patches", "Patches"),
        Binding("f8", "show_ofrak", "OFRAK"),
    ]

    def __init__(self, target: Optional[str] = None, output_dir: Optional[str] = None):
        super().__init__()
        self.target_path = target
        self.output_dir = output_dir
        self.ctx: Optional["R2OFRAKContext"] = None
        self._data_cache: dict = {}

    def compose(self) -> ComposeResult:
        yield Header()
        
        with Horizontal(id="main_area"):
            # Sidebar
            with Vertical(id="sidebar"):
                yield Static("[b]File Info[/b]", id="sidebar_title")
                yield DataTable(id="file_info_table")
            
            # Main content with tabs
            with TabbedContent(id="tabs", initial="tab_overview"):
                with TabPane("Overview (F1)", id="tab_overview"):
                    with VerticalScroll(id="overview_content"):
                        yield Static("Open a file to start analysis… (Ctrl+O)", id="overview_text")
                
                with TabPane("Disasm (F2)", id="tab_disasm"):
                    yield TextArea(id="disasm_content", read_only=True)
                
                with TabPane("Strings (F3)", id="tab_strings"):
                    with Vertical():
                        yield TextArea(id="strings_filter", placeholder="Filter strings…", height=3)
                        yield DataTable(id="strings_table")
                
                with TabPane("Imports (F4)", id="tab_imports"):
                    yield DataTable(id="imports_table")
                
                with TabPane("Exports", id="tab_exports"):
                    yield DataTable(id="exports_table")
                
                with TabPane("Functions (F6)", id="tab_functions"):
                    yield DataTable(id="functions_table")
                
                with TabPane("Segments", id="tab_segments"):
                    yield DataTable(id="segments_table")
                
                with TabPane("Hex (F5)", id="tab_hex"):
                    yield TextArea(id="hex_content", read_only=True)
                
                with TabPane("Patches (F7)", id="tab_patches"):
                    with Vertical():
                        yield TextArea(
                            id="patch_input",
                            placeholder="Offset: 0x1000\nHex: 90909090",
                            height=4,
                        )
                        yield Static("[ Ctrl+Enter: Apply patch ]", id="patch_hint")
                        yield DataTable(id="patches_table")
                
                with TabPane("OFRAK (F8)", id="tab_ofrak"):
                    with Vertical():
                        yield Static("[b]OFRAK Operations[/b]")
                        yield Static("  [Ctrl+U] Unpack  |  [Ctrl+R] Repack")
                        yield DataTable(id="ofrak_table")
                        yield RichLog(id="ofrak_log")
                
                with TabPane("Vulns", id="tab_vulns"):
                    yield DataTable(id="vulns_table")
                
                with TabPane("Terminal", id="tab_terminal"):
                    yield TextArea(id="terminal_input", placeholder="Type r2 command here…", height=3)
                    yield RichLog(id="terminal_output", markup=True)
        
        # Bottom bar
        yield Static("", id="info_bar")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "R2OFRAK"
        self.sub_title = "radare2 + OFRAK | Ctrl+O to open"
        self._update_info_bar("Ready. Press Ctrl+O to open a file.")
        
        # Setup sidebar table
        table = self.query_one("#file_info_table", DataTable)
        table.add_columns("Key", "Value")
        
        # Setup strings filter
        self.query_one("#strings_filter", TextArea).display = False

    # ─── Actions ────────────────────────────────────────────────────────────
    def action_open_file(self) -> None:
        self.push_screen(FileOpenScreen(), self._on_file_selected)

    def action_quit(self) -> None:
        if self.ctx:
            self.ctx.close()
        self.exit()

    def action_full_analysis(self) -> None:
        if not self._ensure_loaded():
            return
        self._update_info_bar("Running full analysis…")
        self._run_analysis()

    def action_disassemble(self) -> None:
        if not self._ensure_loaded():
            return
        self._show_tab("tab_disasm")
        self._run_disasm()

    def action_dump_strings(self) -> None:
        if not self._ensure_loaded():
            return
        self._show_tab("tab_strings")
        self._run_strings()

    def action_patch_mode(self) -> None:
        if not self._ensure_loaded():
            return
        self._show_tab("tab_patches")
        self.query_one("#patch_input", TextArea).focus()

    def action_r2_command(self) -> None:
        if not self._ensure_loaded():
            return
        self._show_tab("tab_terminal")
        self.query_one("#terminal_input", TextArea).focus()

    def action_toggle_search(self) -> None:
        bar = self.query_one("#search_bar")
        bar.visible = not bar.visible
        if bar.visible:
            self.query_one("#search_input", TextArea).focus()

    def action_close_search(self) -> None:
        self.query_one("#search_bar").visible = False

    def action_show_overview(self) -> None:
        self._show_tab("tab_overview")

    def action_show_disasm(self) -> None:
        self._show_tab("tab_disasm")

    def action_show_strings(self) -> None:
        self._show_tab("tab_strings")

    def action_show_imports(self) -> None:
        self._show_tab("tab_imports")

    def action_show_hex(self) -> None:
        self._show_tab("tab_hex")

    def action_show_functions(self) -> None:
        self._show_tab("tab_functions")

    def action_show_patches(self) -> None:
        self._show_tab("tab_patches")

    def action_show_ofrak(self) -> None:
        self._show_tab("tab_ofrak")

    # ─── Helpers ────────────────────────────────────────────────────────────
    def _show_tab(self, tab_id: str) -> None:
        self.query_one("#tabs", TabbedContent).active = tab_id

    def _ensure_loaded(self) -> bool:
        if self.ctx is None:
            self._update_info_bar("⚠ No file loaded. Press Ctrl+O to open.")
            return False
        return True

    def _update_info_bar(self, text: str) -> None:
        self.query_one("#info_bar", Static).update(text)

    def _on_file_selected(self, path: Optional[str]) -> None:
        if not path:
            return
        self.target_path = path
        self._init_context(path)

    def _init_context(self, path: str) -> None:
        from r2ofrak.core import R2OFRAKContext
        
        self._update_info_bar(f"Loading {Path(path).name}…")
        self.ctx = R2OFRAKContext(
            path,
            output_dir=self.output_dir,
            verbose=True,
        )
        self.sub_title = f"{Path(path).name} ({Path(path).stat().st_size:,} bytes)"
        self._update_info_bar(f"Loaded: {Path(path).name} — Ctrl+A for analysis")
        
        # Fill sidebar
        self._fill_sidebar()
        
        # Auto-run overview
        self._run_overview()

    def _fill_sidebar(self) -> None:
        table = self.query_one("#file_info_table", DataTable)
        table.clear()
        if not self.ctx:
            return
        
        p = self.ctx.target
        table.add_row("Name", p.name)
        table.add_row("Size", f"{p.stat().st_size:,}")
        table.add_row("Path", str(p.parent))
        table.add_row("Type", p.suffix or "N/A")
        
        # Quick r2 info
        try:
            info = self.ctx.r2.get_binary_info()
            bin_info = info.get("bin", {})
            table.add_row("Arch", bin_info.get("arch", "?"))
            table.add_row("Bits", str(bin_info.get("bits", "?")))
            table.add_row("Endian", bin_info.get("endian", "?"))
            table.add_row("OS", bin_info.get("os", "?"))
        except Exception:
            pass

    # ─── Background Tasks ───────────────────────────────────────────────────
    @work(exclusive=True, group="analysis")
    def _run_analysis(self) -> None:
        report = _safe(self.ctx, self.ctx.analyze)
        self.call_from_thread(self._render_overview, report)

    @work(exclusive=True, group="analysis")
    def _run_overview(self) -> None:
        """Quick overview without full analysis."""
        data = {}
        try:
            data["file_info"] = self.ctx.r2.get_binary_info()
        except Exception:
            pass
        try:
            data["imports"] = len(self.ctx.r2.get_imports())
        except Exception:
            pass
        try:
            data["strings_count"] = len(self.ctx.r2.extract_strings())
        except Exception:
            pass
        self.call_from_thread(self._render_overview, data)

    @work(exclusive=True, group="disasm")
    def _run_disasm(self, addr: str = None) -> None:
        output = _safe(self.ctx, self.ctx.disassemble, mode="full", addr=addr, count=200)
        self.call_from_thread(self._render_disasm, output)

    @work(exclusive=True, group="strings")
    def _run_strings(self) -> None:
        strings = _safe(self.ctx, self.ctx.dump_strings, min_length=4)
        self._data_cache["strings"] = strings if isinstance(strings, list) else []
        self.call_from_thread(self._render_strings)

    @work(exclusive=True, group="imports")
    def _run_imports(self) -> None:
        imports = _safe(self.ctx, self.ctx.dump_imports)
        self.call_from_thread(self._render_table, "#imports_table", imports, ["Name", "Address"])

    @work(exclusive=True, group="exports")
    def _run_exports(self) -> None:
        exports = _safe(self.ctx, self.ctx.dump_exports)
        self.call_from_thread(self._render_table, "#exports_table", exports, ["Name", "Address"])

    @work(exclusive=True, group="functions")
    def _run_functions(self) -> None:
        funcs = _safe(self.ctx, self.ctx.dump_functions)
        self.call_from_thread(self._render_table, "#functions_table", funcs, ["Name", "Offset", "Size"])

    @work(exclusive=True, group="segments")
    def _run_segments(self) -> None:
        segs = _safe(self.ctx, self.ctx.extract_segments)
        self.call_from_thread(self._render_table, "#segments_table", segs, ["Name", "Address", "Size", "Perms"])

    @work(exclusive=True, group="hex")
    def _run_hex(self) -> None:
        try:
            with open(self.ctx.target, "rb") as f:
                data = f.read(4096)  # First 4KB
            lines = []
            for i in range(0, len(data), 16):
                chunk = data[i:i+16]
                hex_part = " ".join(f"{b:02x}" for b in chunk)
                ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                lines.append(f"{i:08x}  {hex_part:<48s}  {ascii_part}")
            output = "\n".join(lines)
        except Exception as e:
            output = f"Error: {e}"
        self.call_from_thread(self._render_hex, output)

    @work(exclusive=True, group="vulns")
    def _run_vulns(self) -> None:
        vulns = _safe(self.ctx, self.ctx.find_vulnerabilities)
        self.call_from_thread(self._render_table, "#vulns_table", vulns, ["Type", "Severity", "Description"])

    @work(exclusive=True, group="r2cmd")
    def _run_r2cmd(self, cmd: str) -> None:
        output = _safe(self.ctx, self.ctx.r2._cmd, cmd)
        self.call_from_thread(self._render_terminal, cmd, output if isinstance(output, str) else str(output))

    @work(exclusive=True, group="patch")
    def _apply_patch(self, offset: int, data: bytes) -> None:
        result = _safe(self.ctx, self.ctx.patch, offset, data)
        self.call_from_thread(self._update_info_bar, f"Patch applied at 0x{offset:08x}")

    @work(exclusive=True, group="ofrak_unpack")
    def _run_unpack(self) -> None:
        result = _safe(self.ctx, self.ctx.unpack)
        self.call_from_thread(self._render_ofrak_result, "Unpack", result)

    @work(exclusive=True, group="ofrak_repack")
    def _run_repack(self) -> None:
        result = _safe(self.ctx, self.ctx.repack)
        self.call_from_thread(self._render_ofrak_result, "Repack", result)

    # ─── Renderers ──────────────────────────────────────────────────────────
    def _render_overview(self, data: dict) -> None:
        lines = ["[b]═══ Analysis Overview ═══[/b]\n"]
        
        if "file" in data:
            lines.append(f"[b]File:[/b] {data['file']}")
            lines.append(f"[b]Size:[/b] {data.get('size', 0):,} bytes")
        
        r2 = data.get("r2", data.get("file_info", {}))
        if isinstance(r2, dict) and "error" not in r2:
            fi = r2.get("file_info", r2)
            bin_info = fi.get("bin", fi) if isinstance(fi, dict) else {}
            lines.append(f"\n[bold cyan]radare2:[/]")
            lines.append(f"  Arch:   {bin_info.get('arch', '?')}")
            lines.append(f"  Bits:   {bin_info.get('bits', '?')}")
            lines.append(f"  OS:     {bin_info.get('os', '?')}")
            lines.append(f"  Format: {bin_info.get('machine', '?')}")
            if "functions" in r2:
                lines.append(f"  Functions: {r2['functions']}")
            if "imports" in r2:
                lines.append(f"  Imports:   {r2['imports']}")
            if "exports" in r2:
                lines.append(f"  Exports:   {r2['exports']}")
            if "strings" in r2:
                lines.append(f"  Strings:   {r2['strings']}")
        
        imports = data.get("imports", 0)
        if isinstance(imports, int) and imports > 0:
            lines.append(f"\n[bold cyan]Summary:[/]")
            lines.append(f"  Total imports: {imports}")
        
        sc = data.get("strings_count", 0)
        if isinstance(sc, int) and sc > 0:
            lines.append(f"  Total strings: {sc}")
        
        self.query_one("#overview_text", Static).update("\n".join(lines))
        self._update_info_bar(f"Overview loaded — {self.ctx.target.name}")

    def _render_disasm(self, output) -> None:
        text = self.query_one("#disasm_content", TextArea)
        if isinstance(output, str):
            text.load_text(output)
        else:
            text.load_text(str(output))
        self._update_info_bar("Disassembly loaded")

    def _render_strings(self) -> None:
        strings = self._data_cache.get("strings", [])
        table = self.query_one("#strings_table", DataTable)
        table.clear()
        table.add_columns("Offset", "Type", "String")
        for s in strings[:500]:  # Limit to 500
            if isinstance(s, dict):
                table.add_row(
                    s.get("offset", "?"),
                    s.get("type", "?"),
                    s.get("string", "")[:100],
                )
        self._update_info_bar(f"Strings loaded: {len(strings)} found")

    def _render_table(self, selector: str, data, columns: list) -> None:
        table = self.query_one(selector, DataTable)
        table.clear()
        if isinstance(data, list):
            table.add_columns(*columns)
            for item in data[:500]:
                if isinstance(item, dict):
                    row = []
                    for col in columns:
                        key = col.lower()
                        if key == "address" or key == "offset":
                            val = item.get("plt", item.get("paddr", item.get("vaddr", item.get("addr", "?"))))
                        elif key == "size":
                            val = str(item.get("size", "?"))
                        elif key == "perms":
                            val = item.get("perm", "?")
                        elif key == "severity":
                            val = item.get("severity", "?")
                        elif key == "description":
                            val = item.get("description", "?")
                        elif key == "type":
                            val = item.get("type", "?")
                        else:
                            val = item.get(key, item.get("name", "?"))
                        row.append(str(val)[:80])
                    table.add_row(*row)
        elif isinstance(data, dict) and "error" in data:
            table.add_columns("Error")
            table.add_row(data["error"])
        self._update_info_bar(f"{selector.replace('#', '').replace('_', ' ').title()} loaded")

    def _render_hex(self, output: str) -> None:
        text = self.query_one("#hex_content", TextArea)
        text.load_text(output)
        self._update_info_bar("Hex view loaded (first 4KB)")

    def _render_terminal(self, cmd: str, output: str) -> None:
        log = self.query_one("#terminal_output", RichLog)
        log.write(f"[b cyan]$ {cmd}[/]")
        for line in output.split("\n"):
            log.write(line)
        self._update_info_bar(f"r2 command executed")

    def _render_ofrak_result(self, op: str, result) -> None:
        log = self.query_one("#ofrak_log", RichLog)
        log.write(f"[b green]{op} result:[/]")
        log.write(json.dumps(result, indent=2, default=str) if isinstance(result, dict) else str(result))
        self._update_info_bar(f"OFRAK {op} complete")

    # ─── Event Handlers ─────────────────────────────────────────────────────
    @on(TabbedContent.TabActivated)
    def on_tab_changed(self, event: TabbedContent.TabActivated) -> None:
        """Auto-load data when switching tabs."""
        tab = event.tab.id
        if tab == "tab_imports" and "imports" not in self._data_cache:
            self._run_imports()
        elif tab == "tab_exports" and "exports" not in self._data_cache:
            self._run_exports()
        elif tab == "tab_functions" and "functions" not in self._data_cache:
            self._run_functions()
        elif tab == "tab_segments" and "segments" not in self._data_cache:
            self._run_segments()
        elif tab == "tab_hex" and "hex" not in self._data_cache:
            self._run_hex()
            self._data_cache["hex"] = True
        elif tab == "tab_vulns" and "vulns" not in self._data_cache:
            self._run_vulns()

    @on(DataTable.RowSelected)
    def on_row_selected(self, event: DataTable.RowSelected) -> None:
        """On row click, show detail or navigate."""
        table = event.data_table
        try:
            row_data = table.get_row_at(event.row_index)
            # If in functions table, disassemble that function
            if table.id == "functions_table" and len(row_data) >= 2:
                offset = row_data[1]
                if offset and offset != "?":
                    self._show_tab("tab_disasm")
                    self._run_disasm(addr=str(offset))
        except Exception:
            pass

    @on(TextArea.Submitted, "#terminal_input")
    def on_terminal_submit(self, event: TextArea.Submitted) -> None:
        """Execute r2 command from terminal."""
        cmd = event.text_area.text.strip()
        if cmd and self.ctx:
            self._run_r2cmd(cmd)
            event.text_area.clear()

    @on(TextArea.Submitted, "#patch_input")
    def on_patch_submit(self, event: TextArea.Submitted) -> None:
        """Apply patch from patch input."""
        if not self.ctx:
            return
        text = event.text_area.text.strip()
        lines = text.split("\n")
        if len(lines) >= 2:
            try:
                offset = int(lines[0].strip(), 0)
                hex_data = lines[1].strip().replace(" ", "")
                data = bytes.fromhex(hex_data)
                self._apply_patch(offset, data)
                # Refresh patches table
                table = self.query_one("#patches_table", DataTable)
                if not table.columns:
                    table.add_columns("Offset", "Size", "Hex Data")
                table.add_row(f"0x{offset:08x}", str(len(data)), hex_data[:40])
            except Exception as e:
                self._update_info_bar(f"⚠ Patch error: {e}")


# ─── Entry point ────────────────────────────────────────────────────────────
def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        prog="r2ofrak-tui",
        description="R2OFRAK TUI — Interactive reverse engineering",
    )
    parser.add_argument("target", nargs="?", help="Target binary to open")
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("--cli", action="store_true", help="Use CLI mode instead of TUI")
    
    args = parser.parse_args()
    
    if args.cli:
        # Fall back to CLI
        from r2ofrak.cli import main as cli_main
        sys.argv = [sys.argv[0]]
        if args.target:
            sys.argv.append(args.target)
        if args.output:
            sys.argv.extend(["-o", args.output])
        cli_main()
    else:
        app = R2OFRAKApp(target=args.target, output_dir=args.output)
        app.run()


if __name__ == "__main__":
    main()
