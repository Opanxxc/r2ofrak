#!/usr/bin/env python3
"""
R2OFRAK TUI v0.2 — Advanced Terminal User Interface.
16 tabs: Overview | Disasm | Strings | Imports | Exports | Functions |
         Segments | Hex | Patches | OFRAK | Vulns | Security | APK/FW |
         Compare | Record | Terminal
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

def _safe(ctx, fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except Exception as exc:
        return {"error": str(exc)}


# ─── File Open Modal ──────────────────────────────────────────────
class FileOpenScreen(ModalScreen[Optional[str]]):
    CSS = """
    FileOpenScreen { align: center middle; }
    #dialog {
        width: 80;
        height: auto;
        max-height: 30;
        border: tall $accent;
        padding: 1 2;
        background: $surface;
    }
    #path_input { width: 100%; height: 3; }
    .btn { margin: 0 1; min-width: 12; }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label("[b]📂 Open Binary[/b]")
            yield TextArea(id="path_input")
            with Horizontal():
                quick_paths = []
                for p in ["/usr/bin/ls", "/usr/bin/cat", "/bin/sh"]:
                    if Path(p).exists():
                        quick_paths.append((p, p))
                if quick_paths:
                    yield Select(quick_paths, id="quick_pick", prompt="Quick pick…")
                yield Label("[dim]Enter path + Enter, or pick above[/dim]")

    def on_mount(self) -> None:
        self.query_one("#path_input", TextArea).focus()

    @on(Select.Changed, "#quick_pick")
    def on_quick_pick(self, event: Select.Changed) -> None:
        if event.value and event.value is not Select.BLANK:
            self.dismiss(str(event.value))

    def on_key(self, event) -> None:
        if event.key == "escape":
            self.dismiss(None)


# ─── Main App ─────────────────────────────────────────────────────
class R2OFRAKApp(App):
    TITLE = "R2OFRAK v0.2"
    SUB_TITLE = "radare2 + OFRAK | Ctrl+O open"

    CSS = """
    Screen { background: $surface; }

    #sidebar {
        width: 32;
        dock: left;
        border-right: tall $accent;
        background: $surface-darken-1;
    }
    #sidebar_title { text-align: center; padding: 0 0 1 0; }
    #file_info_table { height: 1fr; }
    #hash_table { height: auto; max-height: 6; }

    #main { width: 1fr; }
    TabbedContent { height: 1fr; }
    TabPane { padding: 0; }

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

    #progress_bar {
        dock: bottom;
        height: 1;
        display: none;
        background: $warning;
    }
    #progress_bar.visible { display: block; }

    .section-header {
        text-style: bold;
        color: $accent;
        padding: 1 0 0 0;
    }
    """

    BINDINGS = [
        Binding("ctrl+o", "open_file", "Open"),
        Binding("ctrl+q", "quit", "Quit"),
        Binding("ctrl+a", "full_analysis", "Analyze"),
        Binding("ctrl+d", "disassemble", "Disasm"),
        Binding("ctrl+s", "dump_strings", "Strings"),
        Binding("ctrl+p", "patch_mode", "Patch"),
        Binding("ctrl+f", "r2_command", "r2 cmd"),
        Binding("ctrl+r", "start_record", "Record"),
        Binding("f1", "show_tab('tab_overview')", "Overview"),
        Binding("f2", "show_tab('tab_disasm')", "Disasm"),
        Binding("f3", "show_tab('tab_strings')", "Strings"),
        Binding("f4", "show_tab('tab_imports')", "Imports"),
        Binding("f5", "show_tab('tab_hex')", "Hex"),
        Binding("f6", "show_tab('tab_functions')", "Funcs"),
        Binding("f7", "show_tab('tab_security')", "Security"),
        Binding("f8", "show_tab('tab_apk')", "APK"),
        Binding("f9", "show_tab('tab_terminal')", "Terminal"),
    ]

    def __init__(self, target: Optional[str] = None, output_dir: Optional[str] = None):
        super().__init__()
        self.target_path = target
        self.output_dir = output_dir
        self.ctx: Optional["R2OFRAKContext"] = None
        self._cache: dict = {}
        self._recording = False

    def compose(self) -> ComposeResult:
        yield Header()

        with Horizontal(id="main_area"):
            with Vertical(id="sidebar"):
                yield Static("[b]📋 File Info[/b]", id="sidebar_title")
                yield DataTable(id="file_info_table")
                yield Static("[b]🔐 Hashes[/b]", classes="section-header")
                yield DataTable(id="hash_table")

            with TabbedContent(id="tabs", initial="tab_overview"):
                # ── Overview ──
                with TabPane("Overview F1", id="tab_overview"):
                    with VerticalScroll():
                        yield Static("Open a file to start… (Ctrl+O)", id="overview_text")

                # ── Disasm ──
                with TabPane("Disasm F2", id="tab_disasm"):
                    yield TextArea(id="disasm_content", read_only=True)

                # ── Strings ──
                with TabPane("Strings F3", id="tab_strings"):
                    yield DataTable(id="strings_table")

                # ── Imports ──
                with TabPane("Imports F4", id="tab_imports"):
                    yield DataTable(id="imports_table")

                # ── Exports ──
                with TabPane("Exports", id="tab_exports"):
                    yield DataTable(id="exports_table")

                # ── Functions ──
                with TabPane("Functions F6", id="tab_functions"):
                    yield DataTable(id="functions_table")

                # ── Segments ──
                with TabPane("Segments", id="tab_segments"):
                    yield DataTable(id="segments_table")

                # ── Hex ──
                with TabPane("Hex F5", id="tab_hex"):
                    with Vertical():
                        yield TextArea(id="hex_search", placeholder="Search hex / ASCII…", height=2)
                        yield TextArea(id="hex_content", read_only=True)

                # ── Patches ──
                with TabPane("Patches", id="tab_patches"):
                    with Vertical():
                        yield TextArea(id="patch_input",
                                       placeholder="Offset: 0x1000\nHex: 90909090\n(Ctrl+Enter to apply)",
                                       height=4)
                        yield DataTable(id="patches_table")

                # ── OFRAK ──
                with TabPane("OFRAK", id="tab_ofrak"):
                    with Vertical():
                        yield Static("[b]OFRAK Operations[/b]  |  Ctrl+U: Unpack  |  Ctrl+Shift+R: Repack")
                        yield DataTable(id="ofrak_table")
                        yield RichLog(id="ofrak_log")

                # ── Vulns ──
                with TabPane("Vulns", id="tab_vulns"):
                    yield DataTable(id="vulns_table")

                # ── Security ──
                with TabPane("Security F7", id="tab_security"):
                    with Vertical():
                        yield Static("[b]🛡️ Security Analysis[/b]  |  Ctrl+Shift+S: Full scan")
                        yield DataTable(id="security_table")
                        yield RichLog(id="security_log")

                # ── APK / Firmware ──
                with TabPane("APK/FW F8", id="tab_apk"):
                    with Vertical():
                        yield Static("[b]📱 APK / 🔧 Firmware Analyzer[/b]")
                        yield DataTable(id="apk_table")
                        yield RichLog(id="apk_log")

                # ── Compare ──
                with TabPane("Compare", id="tab_compare"):
                    with Vertical():
                        yield TextArea(id="compare_input",
                                       placeholder="Path to second binary to compare…",
                                       height=2)
                        yield DataTable(id="compare_table")
                        yield RichLog(id="compare_log")

                # ── Record ──
                with TabPane("Record", id="tab_record"):
                    with Vertical():
                        yield Static("[b]🎬 Script Recorder[/b]  |  Ctrl+R: Start/Stop recording")
                        yield DataTable(id="record_table")
                        yield RichLog(id="record_log")

                # ── Terminal ──
                with TabPane("Terminal F9", id="tab_terminal"):
                    yield TextArea(id="terminal_input", placeholder="Type r2 command…", height=3)
                    yield RichLog(id="terminal_output", markup=True)

        yield Static("Ready.", id="info_bar")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "R2OFRAK v0.2"
        self.sub_title = "radare2 + OFRAK | Ctrl+O to open"
        self.query_one("#file_info_table", DataTable).add_columns("Key", "Value")
        self.query_one("#hash_table", DataTable).add_columns("Hash", "Value")

        if self.target_path:
            self._init_context(self.target_path)

    # ─── Actions ────────────────────────────────────────────────────
    def action_open_file(self) -> None:
        self.push_screen(FileOpenScreen(), self._on_file_selected)

    def action_quit(self) -> None:
        if self._recording and self.ctx:
            self.ctx.stop_recording()
        if self.ctx:
            self.ctx.close()
        self.exit()

    def action_full_analysis(self) -> None:
        if not self._ensure(): return
        self._show_progress("Running full analysis…")
        self._run_analysis()

    def action_disassemble(self) -> None:
        if not self._ensure(): return
        self._show_tab("tab_disasm")
        self._run_disasm()

    def action_dump_strings(self) -> None:
        if not self._ensure(): return
        self._show_tab("tab_strings")
        self._run_strings()

    def action_patch_mode(self) -> None:
        if not self._ensure(): return
        self._show_tab("tab_patches")
        self.query_one("#patch_input", TextArea).focus()

    def action_r2_command(self) -> None:
        if not self._ensure(): return
        self._show_tab("tab_terminal")
        self.query_one("#terminal_input", TextArea).focus()

    def action_start_record(self) -> None:
        if not self._ensure(): return
        if self._recording:
            path = self.ctx.stop_recording()
            self._recording = False
            self._info(f"Recording stopped. Script: {path}")
        else:
            self.ctx.start_recording(str(self.output_dir or ".") + "/session.py")
            self._recording = True
            self._info("🔴 Recording started…")
            self._show_tab("tab_record")

    def action_show_tab(self, tab_id: str) -> None:
        self._show_tab(tab_id)

    # ─── Helpers ────────────────────────────────────────────────────
    def _show_tab(self, tab_id: str) -> None:
        self.query_one("#tabs", TabbedContent).active = tab_id

    def _ensure(self) -> bool:
        if self.ctx is None:
            self._info("⚠ No file loaded — Ctrl+O to open")
            return False
        return True

    def _info(self, text: str) -> None:
        self.query_one("#info_bar", Static).update(text)

    def _show_progress(self, text: str) -> None:
        bar = self.query_one("#progress_bar", Static)
        bar.display = True
        bar.update(f"⏳ {text}")

    def _hide_progress(self) -> None:
        self.query_one("#progress_bar", Static).display = False

    def _on_file_selected(self, path: Optional[str]) -> None:
        if not path:
            return
        self.target_path = path
        self._init_context(path)

    def _init_context(self, path: str) -> None:
        from r2ofrak.core import R2OFRAKContext
        self._info(f"Loading {Path(path).name}…")
        self.ctx = R2OFRAKContext(path, output_dir=self.output_dir, verbose=True)
        p = self.ctx.target
        self.sub_title = f"{p.name} ({p.stat().st_size:,} bytes)"
        self._info(f"✅ Loaded: {p.name}")
        self._fill_sidebar()
        self._run_overview()

    def _fill_sidebar(self) -> None:
        ft = self.query_one("#file_info_table", DataTable)
        ft.clear()
        if not self.ctx:
            return
        p = self.ctx.target
        ft.add_row("Name", p.name)
        ft.add_row("Size", f"{p.stat().st_size:,}")
        ft.add_row("Type", p.suffix or "?")
        try:
            info = self.ctx.r2.get_binary_info()
            bi = info.get("bin", {})
            ft.add_row("Arch", bi.get("arch", "?"))
            ft.add_row("Bits", str(bi.get("bits", "?")))
            ft.add_row("Endian", bi.get("endian", "?"))
            ft.add_row("OS", bi.get("os", "?"))
        except Exception:
            pass

        # Hashes
        ht = self.query_one("#hash_table", DataTable)
        ht.clear()
        try:
            h = self.ctx.security_analysis().get("hashes", {})
            ht.add_row("SHA256", h.get("sha256", "?")[:32] + "…")
            ht.add_row("MD5", h.get("md5", "?")[:16] + "…")
        except Exception:
            ht.add_row("SHA256", "N/A")

    # ─── Background Tasks ───────────────────────────────────────────
    @work(exclusive=True, group="analysis")
    def _run_analysis(self) -> None:
        report = _safe(self.ctx, self.ctx.analyze)
        self.call_from_thread(self._render_overview, report)
        self.call_from_thread(self._hide_progress)

    @work(exclusive=True, group="analysis")
    def _run_overview(self) -> None:
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
    def _run_disasm(self, addr=None) -> None:
        out = _safe(self.ctx, self.ctx.disassemble, mode="full", addr=addr, count=300)
        self.call_from_thread(self._render_disasm, out)

    @work(exclusive=True, group="strings")
    def _run_strings(self) -> None:
        s = _safe(self.ctx, self.ctx.dump_strings, min_length=4)
        self._cache["strings"] = s if isinstance(s, list) else []
        self.call_from_thread(self._render_strings)

    @work(exclusive=True, group="imports")
    def _run_imports(self) -> None:
        d = _safe(self.ctx, self.ctx.dump_imports)
        self.call_from_thread(self._render_table, "#imports_table", d, ["Name", "Address"])

    @work(exclusive=True, group="exports")
    def _run_exports(self) -> None:
        d = _safe(self.ctx, self.ctx.dump_exports)
        self.call_from_thread(self._render_table, "#exports_table", d, ["Name", "Address"])

    @work(exclusive=True, group="functions")
    def _run_functions(self) -> None:
        d = _safe(self.ctx, self.ctx.dump_functions)
        self.call_from_thread(self._render_table, "#functions_table", d, ["Name", "Offset", "Size"])

    @work(exclusive=True, group="segments")
    def _run_segments(self) -> None:
        d = _safe(self.ctx, self.ctx.extract_segments)
        self.call_from_thread(self._render_table, "#segments_table", d, ["Name", "Address", "Size", "Perms"])

    @work(exclusive=True, group="hex")
    def _run_hex(self) -> None:
        try:
            with open(self.ctx.target, "rb") as f:
                data = f.read(8192)
            lines = []
            for i in range(0, len(data), 16):
                chunk = data[i:i+16]
                hex_part = " ".join(f"{b:02x}" for b in chunk)
                ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                lines.append(f"{i:08x}  {hex_part:<48s}  │{ascii_part}│")
            output = "\n".join(lines)
        except Exception as e:
            output = f"Error: {e}"
        self.call_from_thread(self._render_hex, output)

    @work(exclusive=True, group="vulns")
    def _run_vulns(self) -> None:
        d = _safe(self.ctx, self.ctx.find_vulnerabilities)
        self.call_from_thread(self._render_table, "#vulns_table", d, ["Type", "Severity", "Description"])

    @work(exclusive=True, group="security")
    def _run_security(self) -> None:
        d = _safe(self.ctx, self.ctx.security_analysis)
        self.call_from_thread(self._render_security, d)

    @work(exclusive=True, group="apk")
    def _run_apk(self) -> None:
        d = _safe(self.ctx, self.ctx.analyze_apk)
        self.call_from_thread(self._render_apk, d)

    @work(exclusive=True, group="r2cmd")
    def _run_r2cmd(self, cmd: str) -> None:
        out = _safe(self.ctx, self.ctx.r2._cmd, cmd)
        self.call_from_thread(self._render_terminal, cmd, out if isinstance(out, str) else str(out))

    @work(exclusive=True, group="patch")
    def _apply_patch(self, offset: int, data: bytes) -> None:
        _safe(self.ctx, self.ctx.patch, offset, data)
        self.call_from_thread(self._info, f"✅ Patch applied at 0x{offset:08x}")

    @work(exclusive=True, group="compare")
    def _run_compare(self, other: str) -> None:
        d = _safe(self.ctx, self.ctx.compare_with, other)
        self.call_from_thread(self._render_compare, d)

    # ─── Renderers ──────────────────────────────────────────────────
    def _render_overview(self, data: dict) -> None:
        lines = ["[b]══════════ Analysis Overview ══════════[/b]\n"]

        if "file" in data:
            lines.append(f"[b]File:[/b]  {data['file']}")
            lines.append(f"[b]Size:[/b]  {data.get('size', 0):,} bytes")

        r2 = data.get("r2", data.get("file_info", {}))
        if isinstance(r2, dict) and "error" not in r2:
            fi = r2.get("file_info", r2)
            bi = fi.get("bin", fi) if isinstance(fi, dict) else {}
            lines.append(f"\n[bold cyan]━━━ radare2 ━━━[/]")
            lines.append(f"  Arch:     {bi.get('arch', '?')}")
            lines.append(f"  Bits:     {bi.get('bits', '?')}")
            lines.append(f"  OS:       {bi.get('os', '?')}")
            lines.append(f"  Format:   {bi.get('machine', '?')}")
            if "functions" in r2:
                lines.append(f"  Functions: {r2['functions']}")
            if "imports" in r2:
                lines.append(f"  Imports:   {r2['imports']}")
            if "exports" in r2:
                lines.append(f"  Exports:   {r2['exports']}")
            if "strings" in r2:
                lines.append(f"  Strings:   {r2['strings']}")

        imports = data.get("imports", 0)
        sc = data.get("strings_count", 0)
        if isinstance(imports, int) or isinstance(sc, int):
            lines.append(f"\n[bold cyan]━━━ Summary ━━━[/]")
            if isinstance(imports, int):
                lines.append(f"  Imports:  {imports}")
            if isinstance(sc, int):
                lines.append(f"  Strings:  {sc}")

        self.query_one("#overview_text", Static).update("\n".join(lines))
        self._info(f"Overview: {self.ctx.target.name}")

    def _render_disasm(self, output) -> None:
        t = self.query_one("#disasm_content", TextArea)
        t.load_text(str(output) if output else "No disassembly available")
        self._info("Disassembly loaded")

    def _render_strings(self) -> None:
        strings = self._cache.get("strings", [])
        table = self.query_one("#strings_table", DataTable)
        table.clear()
        table.add_columns("Offset", "Type", "Length", "String")
        for s in strings[:500]:
            if isinstance(s, dict):
                table.add_row(
                    s.get("offset", "?"),
                    s.get("type", "?"),
                    str(s.get("length", len(s.get("string", "")))),
                    s.get("string", "")[:120],
                )
        self._info(f"Strings: {len(strings)} found")

    def _render_table(self, sel: str, data, columns: list) -> None:
        table = self.query_one(sel, DataTable)
        table.clear()
        if isinstance(data, list):
            table.add_columns(*columns)
            for item in data[:500]:
                if isinstance(item, dict):
                    row = []
                    for col in columns:
                        key = col.lower()
                        if key in ("address", "offset"):
                            val = item.get("plt", item.get("paddr", item.get("vaddr", item.get("addr", "?"))))
                        elif key == "size":
                            val = str(item.get("size", "?"))
                        elif key == "perms":
                            val = item.get("perm", "?")
                        elif key == "severity":
                            val = item.get("severity", "?")
                        elif key == "description":
                            val = item.get("description", "?")[:80]
                        elif key == "type":
                            val = item.get("type", "?")
                        else:
                            val = item.get(key, item.get("name", "?"))
                        row.append(str(val)[:100])
                    table.add_row(*row)
        elif isinstance(data, dict) and "error" in data:
            table.add_columns("Error")
            table.add_row(data["error"])
        self._info(f"{sel.replace('#', '').replace('_', ' ').title()} loaded")

    def _render_hex(self, output: str) -> None:
        self.query_one("#hex_content", TextArea).load_text(output)
        self._info("Hex view (first 8KB)")

    def _render_security(self, data: dict) -> None:
        if not isinstance(data, dict):
            return
        # Table: protections
        table = self.query_one("#security_table", DataTable)
        table.clear()
        table.add_columns("Check", "Status", "Details")

        prot = data.get("protections", {})
        for k, v in prot.items():
            status = "✅" if v else "❌"
            table.add_row(k, status, "")

        # Anti-debug
        for ad in data.get("anti_debug", [])[:20]:
            table.add_row(f"anti-debug: {ad.get('pattern', '')}", "⚠️", ad.get("description", ""))

        # Crypto
        for c in data.get("crypto", [])[:20]:
            table.add_row(f"crypto: {c.get('pattern', '')}", "🔑", c.get("description", ""))

        # Hashes
        log = self.query_one("#security_log", RichLog)
        log.clear()
        h = data.get("hashes", {})
        log.write("[b]File Hashes:[/]")
        for k, v in h.items():
            log.write(f"  {k}: {v}")

        # Vulns
        vulns = data.get("vulnerabilities", [])
        if vulns:
            log.write(f"\n[b]Vulnerabilities: {len(vulns)} found[/]")
            for v in vulns[:10]:
                sev = v.get("severity", "?")
                color = "red" if sev == "critical" else "yellow" if sev == "high" else "cyan"
                log.write(f"  [{color}]{sev.upper()}[/]: {v.get('description', '')}")

        self._info(f"Security: {len(data.get('anti_debug', []))} anti-debug, {len(data.get('crypto', []))} crypto")

    def _render_apk(self, data: dict) -> None:
        if not isinstance(data, dict):
            return
        table = self.query_one("#apk_table", DataTable)
        table.clear()
        table.add_columns("Property", "Value")

        for key in ["type", "size"]:
            if key in data:
                table.add_row(key, str(data[key]))

        dex = data.get("dex_files", [])
        for d in dex:
            table.add_row("DEX", f"{d.get('name', '?')} ({d.get('size', 0):,} bytes)")

        libs = data.get("native_libs", [])
        for lib in libs:
            table.add_row("Native", f"{lib.get('name', '?')} [{lib.get('abi', '?')}]")

        perms = data.get("permissions", [])
        for p in perms[:10]:
            table.add_row("Permission", str(p))

        sec = data.get("security", {})
        for k, v in sec.items():
            table.add_row(f"sec:{k}", "⚠️" if v else "✅")

        log = self.query_one("#apk_log", RichLog)
        log.clear()
        urls = data.get("suspicious_strings", [])
        if urls:
            log.write(f"[b]Suspicious strings: {len(urls)}[/]")
            for u in urls[:20]:
                log.write(f"  ⚠ {u}")

        self._info(f"APK: {data.get('type', 'unknown')}")

    def _render_compare(self, data: dict) -> None:
        if not isinstance(data, dict):
            return
        table = self.query_one("#compare_table", DataTable)
        table.clear()
        table.add_columns("Property", "Value")

        table.add_row("Identical", "✅ Yes" if data.get("identical") else "❌ No")
        table.add_row("Size A", str(data.get("size_a", 0)))
        table.add_row("Size B", str(data.get("size_b", 0)))
        table.add_row("Diff regions", str(len(data.get("diff_regions", []))))

        log = self.query_one("#compare_log", RichLog)
        log.clear()
        sd = data.get("string_diffs", {})
        only_a = sd.get("only_in_a", [])
        only_b = sd.get("only_in_b", [])
        if only_a:
            log.write(f"[b]Only in A ({len(only_a)}):[/]")
            for s in only_a[:10]:
                log.write(f"  + {s}")
        if only_b:
            log.write(f"[b]Only in B ({len(only_b)}):[/]")
            for s in only_b[:10]:
                log.write(f"  + {s}")

        self._info(f"Compare: {'identical' if data.get('identical') else 'differences found'}")

    def _render_terminal(self, cmd: str, output: str) -> None:
        log = self.query_one("#terminal_output", RichLog)
        log.write(f"[b cyan]$ {cmd}[/]")
        for line in output.split("\n"):
            log.write(line)
        self._info("r2 command executed")

    # ─── Event Handlers ─────────────────────────────────────────────
    @on(TabbedContent.TabActivated)
    def on_tab_changed(self, event: TabbedContent.TabActivated) -> None:
        tab = event.tab.id
        lazy = {
            "tab_imports": ("imports", self._run_imports),
            "tab_exports": ("exports", self._run_exports),
            "tab_functions": ("functions", self._run_functions),
            "tab_segments": ("segments", self._run_segments),
            "tab_hex": ("hex", self._run_hex),
            "tab_vulns": ("vulns", self._run_vulns),
            "tab_security": ("security", self._run_security),
            "tab_apk": ("apk", self._run_apk),
        }
        if tab in lazy:
            key, fn = lazy[tab]
            if key not in self._cache:
                self._cache[key] = True
                fn()

    @on(DataTable.RowSelected)
    def on_row_selected(self, event: DataTable.RowSelected) -> None:
        table = event.data_table
        try:
            row = table.get_row_at(event.row_index)
            if table.id == "functions_table" and len(row) >= 2:
                offset = row[1]
                if offset and offset != "?":
                    self._show_tab("tab_disasm")
                    self._run_disasm(addr=str(offset))
        except Exception:
            pass

    @on(TextArea.Submitted, "#terminal_input")
    def on_terminal_submit(self, event: TextArea.Submitted) -> None:
        cmd = event.text_area.text.strip()
        if cmd and self.ctx:
            self._run_r2cmd(cmd)
            event.text_area.clear()

    @on(TextArea.Submitted, "#patch_input")
    def on_patch_submit(self, event: TextArea.Submitted) -> None:
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
                table = self.query_one("#patches_table", DataTable)
                if not table.columns:
                    table.add_columns("Offset", "Size", "Hex")
                table.add_row(f"0x{offset:08x}", str(len(data)), hex_data[:60])
            except Exception as e:
                self._info(f"⚠ Patch error: {e}")

    @on(TextArea.Submitted, "#hex_search")
    def on_hex_search(self, event: TextArea.Submitted) -> None:
        query = event.text_area.text.strip()
        if query and self.ctx:
            try:
                data = self.ctx.target.read_bytes()
                # Try hex
                try:
                    search = bytes.fromhex(query)
                except ValueError:
                    search = query.encode()

                pos = data.find(search)
                if pos >= 0:
                    # Show context around match
                    start = max(0, pos - 64)
                    end = min(len(data), pos + 64)
                    chunk = data[start:end]
                    lines = []
                    for i in range(0, len(chunk), 16):
                        off = start + i
                        c = chunk[i:i+16]
                        h = " ".join(f"{b:02x}" for b in c)
                        a = "".join(chr(b) if 32 <= b < 127 else "." for b in c)
                        marker = " ◄" if start + i <= pos < start + i + 16 else ""
                        lines.append(f"{off:08x}  {h:<48s}  │{a}│{marker}")
                    self.query_one("#hex_content", TextArea).load_text("\n".join(lines))
                    self._info(f"Found at 0x{pos:08x}")
                else:
                    self._info(f"Not found: {query}")
            except Exception as e:
                self._info(f"Search error: {e}")

    @on(TextArea.Submitted, "#compare_input")
    def on_compare_submit(self, event: TextArea.Submitted) -> None:
        other = event.text_area.text.strip()
        if other and self.ctx:
            self._run_compare(other)


def main():
    import argparse
    parser = argparse.ArgumentParser(
        prog="r2ofrak-tui",
        description="R2OFRAK TUI — Interactive reverse engineering",
    )
    parser.add_argument("target", nargs="?", help="Target binary")
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("--cli", action="store_true", help="Use CLI mode")
    args = parser.parse_args()

    if args.cli:
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
