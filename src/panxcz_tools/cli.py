#!/usr/bin/env python3
"""
Panxcz Tools CLI — Command-line reverse engineering.
"""

import argparse
import json
import sys
from pathlib import Path

__version__ = "1.0.0"


def cmd_analyze(args):
    from panxcz_tools.core.r2_engine import R2Engine
    engine = R2Engine(args.target)
    data = engine.analyze()
    if args.json:
        print(json.dumps(data, indent=2, default=str))
    else:
        fi = data.get("file_info", {})
        bi = fi.get("bin", {})
        print(f"\n{'='*60}")
        print(f"  Panxcz Tools — {Path(args.target).name}")
        print(f"{'='*60}")
        print(f"  Arch:     {bi.get('arch', '?')}")
        print(f"  Bits:     {bi.get('bits', '?')}")
        print(f"  OS:       {bi.get('os', '?')}")
        print(f"  Functions: {len(data.get('functions', []))}")
        print(f"  Imports:   {len(data.get('imports', []))}")
        print(f"  Strings:   {len(data.get('strings', []))}")


def cmd_disasm(args):
    from panxcz_tools.core.r2_engine import R2Engine
    engine = R2Engine(args.target)
    if args.function:
        print(engine.disasm_function(args.function))
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
            print(f"[{s.get('offset','?')}] {s.get('string','')}")


def cmd_imports(args):
    from panxcz_tools.core.r2_engine import R2Engine
    engine = R2Engine(args.target)
    data = engine.imports()
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        for imp in data:
            if isinstance(imp, dict):
                print(f"[{imp.get('plt', '?')}] {imp.get('name', '?')}")


def cmd_functions(args):
    from panxcz_tools.core.r2_engine import R2Engine
    engine = R2Engine(args.target)
    data = engine.functions()
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        for f in data:
            if isinstance(f, dict):
                print(f"[0x{f.get('offset', 0):x}] {f.get('name', '?')} (size: {f.get('size', 0)})")


def cmd_security(args):
    from panxcz_tools.core.security import SecurityAnalyzer
    sa = SecurityAnalyzer(args.target)
    data = sa.full()
    if args.json:
        print(json.dumps(data, indent=2, default=str))
    else:
        h = data.get("hashes", {})
        print(f"\nSecurity: {args.target}")
        print(f"  SHA256: {h.get('sha256', '?')}")
        prot = data.get("protections", {})
        for k, v in prot.items():
            print(f"  {'✅' if v else '❌'} {k}")
        ad = data.get("anti_debug", [])
        print(f"\n  Anti-debug: {len(ad)}")
        for a in ad[:5]:
            print(f"    ⚠ {a.get('description','')}")
        cr = data.get("crypto", [])
        print(f"  Crypto: {len(cr)}")


def cmd_hex(args):
    from panxcz_tools.core.r2_engine import R2Engine
    engine = R2Engine(args.target)
    print(engine.hexdump(offset=args.offset, size=args.size))


def cmd_vulns(args):
    from panxcz_tools.core.r2_engine import R2Engine
    engine = R2Engine(args.target)
    data = engine.vulnerabilities()
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        for v in data:
            print(f"[{v.get('severity','?').upper()}] {v.get('description','?')}")


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
        description="Panxcz Tools v1.0 — Unified Reverse Engineering Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  panxcz                             Launch TUI (default)
  panxcz gui                         Launch Web GUI (http://localhost:8888)
  panxcz gui /path/to/binary         Launch GUI with file
  panxcz analyze /path/to/binary     Full analysis (CLI)
  panxcz security /path/to/binary    Security scan

Examples:
  panxcz analyze /bin/ls
  panxcz security /bin/ls
  panxcz disasm /bin/ls --function main
  panxcz strings /bin/ls --min-length 8
  panxcz hex /bin/ls --offset 0
  panxcz gui /bin/ls --port 8888
"""
    )

    parser.add_argument("--version", action="version", version=f"panxcz {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("--json", action="store_true")

    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("analyze", help="Full analysis")
    p.add_argument("target")
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("disasm", help="Disassemble")
    p.add_argument("target")
    p.add_argument("--function", help="Function name")
    p.add_argument("--addr", help="Address")
    p.add_argument("--count", type=int, default=200)
    p.set_defaults(func=cmd_disasm)

    p = sub.add_parser("strings", help="Extract strings")
    p.add_argument("target")
    p.add_argument("--min-length", type=int, default=4)
    p.set_defaults(func=cmd_strings)

    p = sub.add_parser("imports", help="List imports")
    p.add_argument("target")
    p.set_defaults(func=cmd_imports)

    p = sub.add_parser("functions", help="List functions")
    p.add_argument("target")
    p.set_defaults(func=cmd_functions)

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
