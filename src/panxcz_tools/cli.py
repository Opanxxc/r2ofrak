#!/usr/bin/env python3
"""
Panxcz Tools CLI — Command-line reverse engineering.
"""

import argparse
import json
import sys
from pathlib import Path

__version__ = "0.0.1"


def cmd_analyze(args):
    from panxcz_tools.core.r2_engine import R2Engine
    engine = R2Engine(args.target)
    data = engine.analyze_fast() if args.fast else engine.analyze()
    if args.json:
        print(json.dumps(data, indent=2, default=str))
    else:
        fi = data.get("file_info", {})
        bi = fi.get("bin", {})
        print(f"\n{'='*60}")
        print(f"  Panxcz Tools v{__version__} — {Path(args.target).name}")
        print(f"{'='*60}")
        print(f"  Arch:      {bi.get('arch', '?')}")
        print(f"  Bits:      {bi.get('bits', '?')}")
        print(f"  OS:        {bi.get('os', '?')}")
        print(f"  Functions: {len(data.get('functions', []))}")
        print(f"  Imports:   {len(data.get('imports', []))}")
        print(f"  Strings:   {len(data.get('strings', []))}")
        print(f"  Sections:  {len(data.get('sections', []))}")
        print(f"  Time:      {data.get('elapsed_ms', '?')}ms")


def cmd_disasm(args):
    from panxcz_tools.core.r2_engine import R2Engine
    engine = R2Engine(args.target)
    if args.function:
        print(engine.disasm_function(args.function))
    elif args.graph:
        print(engine.graph_function(args.function or "main"))
    else:
        print(engine.disasm(addr=args.addr, count=args.count))


def cmd_strings(args):
    from panxcz_tools.core.r2_engine import R2Engine
    engine = R2Engine(args.target)
    strings = engine.strings(min_len=args.min_length)
    if args.json:
        print(json.dumps(strings, indent=2))
    else:
        for s in strings:
            print(f"[{s.get('offset','?')}] [{s.get('type','?')}] {s.get('string','')}")


def cmd_imports(args):
    from panxcz_tools.core.r2_engine import R2Engine
    engine = R2Engine(args.target)
    if args.by_library:
        data = engine.imports_by_library()
        if args.json:
            print(json.dumps(data, indent=2))
        else:
            for lib, funcs in data.items():
                print(f"\n[bold]{lib}[/bold] ({len(funcs)})")
                for f in funcs:
                    print(f"  {f}")
    else:
        data = engine.imports()
        if args.json:
            print(json.dumps(data, indent=2))
        else:
            for imp in data:
                if isinstance(imp, dict):
                    print(f"[{imp.get('plt', '?')}] {imp.get('name', '?')}")


def cmd_exports(args):
    from panxcz_tools.core.r2_engine import R2Engine
    engine = R2Engine(args.target)
    data = engine.exports()
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        for exp in data:
            if isinstance(exp, dict):
                print(f"[{exp.get('vaddr', '?')}] {exp.get('name', '?')}")


def cmd_functions(args):
    from panxcz_tools.core.r2_engine import R2Engine
    engine = R2Engine(args.target)
    data = engine.functions()
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        for f in data:
            if isinstance(f, dict):
                print(f"[0x{f.get('offset', 0):x}] {f.get('name', '?')} (size: {f.get('size', 0)}, cc: {f.get('cc', '?')})")


def cmd_xrefs(args):
    from panxcz_tools.core.r2_engine import R2Engine
    engine = R2Engine(args.target)
    if args.from_addr:
        data = engine.xrefs_from(args.address)
        label = "FROM"
    else:
        data = engine.xrefs_to(args.address)
        label = "TO"
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print(f"Cross-references {label} {args.address} ({len(data)}):")
        for x in data:
            if isinstance(x, dict):
                if args.from_addr:
                    print(f"  {args.address} → 0x{x.get('to', 0):x} ({x.get('type', '?')})")
                else:
                    print(f"  0x{x.get('from', 0):x} → {x.get('type', '?')} {x.get('name', args.address)}")


def cmd_security(args):
    from panxcz_tools.core.security import SecurityAnalyzer
    sa = SecurityAnalyzer(args.target)
    data = sa.full()
    if args.json:
        print(json.dumps(data, indent=2, default=str))
    else:
        h = data.get("hashes", {})
        print(f"\n{'='*60}")
        print(f"  Security Analysis — {args.target}")
        print(f"{'='*60}")
        print(f"  SHA256: {h.get('sha256', '?')[:64]}")
        prot = data.get("protections", {})
        print(f"\n  ─── Protections ───")
        for k, v in prot.items():
            print(f"    {'✅' if v else '❌'} {k}")
        for section in ["anti_debug", "anti_root", "anti_emulator", "frida_hooks",
                        "ssl_pinning", "xposed_hooks", "crypto", "vulnerabilities"]:
            items = data.get(section, [])
            if items:
                print(f"\n  ─── {section.replace('_', ' ').title()} ({len(items)}) ───")
                for item in items[:10]:
                    print(f"    {item.get('description', '?')} @ {item.get('offset', '?')}")
        perms = data.get("permissions", [])
        if perms:
            print(f"\n  ─── Permissions ({len(perms)}) ───")
            for p in perms:
                print(f"    {p}")
        signing = data.get("code_signing", {})
        if signing.get("signed"):
            print(f"\n  ─── Code Signing ───")
            print(f"    ✅ {signing.get('type', '?')}")
            for d in signing.get("details", []):
                print(f"      • {d}")


def cmd_hex(args):
    from panxcz_tools.core.r2_engine import R2Engine
    engine = R2Engine(args.target)
    print(engine.hexdump(offset=args.offset, size=args.size))


def cmd_vulns(args):
    from panxcz_tools.core.r2_engine import R2Engine
    from panxcz_tools.core.security import SecurityAnalyzer
    engine = R2Engine(args.target)
    vulns = engine.vulnerabilities()
    sa = SecurityAnalyzer(args.target)
    data = sa.full()
    vulns2 = data.get("vulnerabilities", [])
    total = vulns + vulns2
    if args.json:
        print(json.dumps(total, indent=2))
    else:
        for v in total:
            sev = v.get("severity", "?")
            print(f"[{sev.upper()}] {v.get('description', '?')} @ {v.get('address', v.get('offset', '?'))}")


def cmd_unpack(args):
    from panxcz_tools.unpacker import Unpacker
    import time
    t0 = time.time()
    u = Unpacker(args.target, output_dir=args.output)
    result = u.unpack()
    elapsed = int((time.time() - t0) * 1000)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, default=str))
    else:
        print(f"{'='*60}")
        print(f"  Unpack Result — {args.target}")
        print(f"{'='*60}")
        print(f"  Type:       {result.file_type}")
        print(f"  Success:    {result.success}")
        print(f"  Files:      {result.file_count}")
        print(f"  Size:       {result.total_size:,} bytes")
        print(f"  Output:     {result.output_dir}")
        print(f"  Time:       {elapsed}ms")
        if result.metadata:
            print(f"\n  ─── Metadata ───")
            for k, v in result.metadata.items():
                if isinstance(v, list) and len(v) > 10:
                    print(f"    {k}: [{len(v)} items]")
                else:
                    print(f"    {k}: {v}")
        if result.errors:
            print(f"\n  Errors:")
            for e in result.errors:
                print(f"    ⚠ {e}")


def cmd_graph(args):
    from panxcz_tools.core.r2_engine import R2Engine
    engine = R2Engine(args.target)
    if args.json:
        data = engine.graph_json(args.function or "main")
        print(json.dumps(data, indent=2))
    else:
        print(engine.graph_function(args.function or "main"))


def cmd_entropy(args):
    from panxcz_tools.core.r2_engine import R2Engine
    engine = R2Engine(args.target)
    data = engine.entropy()
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        for sec in data:
            ent = sec.get("entropy", 0)
            bar = "█" * int(ent * 10)
            print(f"  {sec.get('name', '?'):20s}  entropy: {ent:.2f}  {bar}")


def cmd_export(args):
    from panxcz_tools.core.r2_engine import R2Engine
    engine = R2Engine(args.target)
    output = args.output or f"{args.target}.report.json"
    report = engine.export_report(output)
    print(f"Report exported to {output}")
    print(f"  Functions: {len(report.get('analysis', {}).get('functions', []))}")
    print(f"  Imports:   {len(report.get('analysis', {}).get('imports', []))}")
    print(f"  Strings:   {len(report.get('analysis', {}).get('strings', []))}")
    print(f"  Vulns:     {len(report.get('vulnerabilities', []))}")


def cmd_gui(args):
    from panxcz_tools.gui.app import main as gui_main
    sys.argv = ["panxcz-gui"]
    if args.target:
        sys.argv.extend(["--target", args.target])
    if args.port:
        sys.argv.extend(["--port", str(args.port)])
    if args.host:
        sys.argv.extend(["--host", args.host])
    gui_main()


def cmd_tui(args):
    from panxcz_tools.tui import R2OFRAKApp
    app = R2OFRAKApp(target=args.target, output_dir=args.output)
    app.run()


def main():
    parser = argparse.ArgumentParser(
        prog="panxcz",
        description=f"Panxcz Tools v{__version__} — Unified Reverse Engineering Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  panxcz                              Launch TUI (default)
  panxcz gui                          Launch Web GUI (http://localhost:8888)
  panxcz analyze /path/to/binary      Full analysis
  panxcz security /path/to/binary     Security scan
  panxcz unpack /path/to/file         Unpack binary/archive

Examples:
  panxcz analyze /bin/ls
  panxcz analyze /bin/ls --fast
  panxcz security /bin/ls
  panxcz disasm /bin/ls --function main
  panxcz disasm /bin/ls --graph
  panxcz strings /bin/ls --min-length 8
  panxcz xrefs /bin/ls printf
  panxcz unpack firmware.bin
  panxcz unpack app.apk -o /tmp/output
  panxcz export /bin/ls -o report.json
"""
    )

    parser.add_argument("--version", action="version", version=f"panxcz {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("--json", action="store_true", help="JSON output")

    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("analyze", help="Full analysis")
    p.add_argument("target")
    p.add_argument("--fast", action="store_true", help="Fast analysis (skip deep analysis)")
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("disasm", help="Disassemble")
    p.add_argument("target")
    p.add_argument("--function", help="Function name")
    p.add_argument("--addr", help="Address")
    p.add_argument("--count", type=int, default=200)
    p.add_argument("--graph", action="store_true", help="Show control flow graph")
    p.set_defaults(func=cmd_disasm)

    p = sub.add_parser("strings", help="Extract strings")
    p.add_argument("target")
    p.add_argument("--min-length", type=int, default=4)
    p.set_defaults(func=cmd_strings)

    p = sub.add_parser("imports", help="List imports")
    p.add_argument("target")
    p.add_argument("--by-library", action="store_true")
    p.set_defaults(func=cmd_imports)

    p = sub.add_parser("exports", help="List exports")
    p.add_argument("target")
    p.set_defaults(func=cmd_exports)

    p = sub.add_parser("functions", help="List functions")
    p.add_argument("target")
    p.set_defaults(func=cmd_functions)

    p = sub.add_parser("xrefs", help="Cross-references")
    p.add_argument("target")
    p.add_argument("address")
    p.add_argument("--from-addr", action="store_true", help="Xrefs FROM address")
    p.set_defaults(func=cmd_xrefs)

    p = sub.add_parser("security", help="Security analysis")
    p.add_argument("target")
    p.set_defaults(func=cmd_security)

    p = sub.add_parser("hex", help="Hex dump")
    p.add_argument("target")
    p.add_argument("--offset", type=int, default=0)
    p.add_argument("--size", type=int, default=256)
    p.set_defaults(func=cmd_hex)

    p = sub.add_parser("vulns", help="Vulnerability scan")
    p.add_argument("target")
    p.set_defaults(func=cmd_vulns)

    p = sub.add_parser("unpack", help="Unpack binary/archive")
    p.add_argument("target")
    p.add_argument("-o", "--output", help="Output directory")
    p.set_defaults(func=cmd_unpack)

    p = sub.add_parser("graph", help="Control flow graph")
    p.add_argument("target")
    p.add_argument("--function", help="Function name")
    p.set_defaults(func=cmd_graph)

    p = sub.add_parser("entropy", help="Entropy analysis")
    p.add_argument("target")
    p.set_defaults(func=cmd_entropy)

    p = sub.add_parser("export", help="Export analysis report")
    p.add_argument("target")
    p.add_argument("-o", "--output", help="Output file")
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("gui", help="Launch Web GUI")
    p.add_argument("target", nargs="?")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8888)
    p.set_defaults(func=cmd_gui)

    p = sub.add_parser("tui", help="Launch TUI")
    p.add_argument("target", nargs="?")
    p.set_defaults(func=cmd_tui)

    args = parser.parse_args()

    if not args.command:
        cmd_tui(args)
        return

    try:
        args.func(args)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
