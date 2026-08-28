#!/usr/bin/env python3
"""
R2OFRAK CLI v0.2 — Powerful command-line reverse engineering.
"""

import argparse
import json
import sys
from pathlib import Path

__version__ = "0.2.0"


def _pp(data, use_json=False):
    if use_json:
        print(json.dumps(data, indent=2, default=str))
    elif isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, list):
                print(f"  {k}: {len(v)} items")
                for item in v[:5]:
                    print(f"    - {item}")
            elif isinstance(v, dict):
                print(f"  {k}:")
                for kk, vv in v.items():
                    print(f"    {kk}: {vv}")
            else:
                print(f"  {k}: {v}")
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                print(json.dumps(item, default=str))
            else:
                print(item)


# ─── Commands ──────────────────────────────────────────────────────

def cmd_analyze(args):
    from r2ofrak.core import R2OFRAKContext
    with R2OFRAKContext(args.target, output_dir=args.output, verbose=args.verbose) as ctx:
        report = ctx.analyze()
        if args.json:
            print(json.dumps(report, indent=2, default=str))
        else:
            print(f"\n{'='*60}")
            print(f"  R2OFRAK Analysis — {Path(args.target).name}")
            print(f"{'='*60}")
            _pp(report, args.json)
            print(f"\n  Output: {ctx.output_dir}")


def cmd_disasm(args):
    from r2ofrak.core import R2OFRAKContext
    with R2OFRAKContext(args.target, output_dir=args.output, verbose=args.verbose) as ctx:
        out = ctx.disassemble(mode=args.mode, addr=args.addr, count=args.count)
        print(out)


def cmd_strings(args):
    from r2ofrak.core import R2OFRAKContext
    with R2OFRAKContext(args.target, output_dir=args.output, verbose=args.verbose) as ctx:
        strings = ctx.dump_strings(min_length=args.min_length)
        if args.json:
            print(json.dumps(strings, indent=2))
        else:
            for s in strings:
                print(f"[{s.get('offset','?')}] {s.get('string','')}")


def cmd_imports(args):
    from r2ofrak.core import R2OFRAKContext
    with R2OFRAKContext(args.target, output_dir=args.output, verbose=args.verbose) as ctx:
        data = ctx.dump_imports()
        if args.json:
            print(json.dumps(data, indent=2))
        else:
            for imp in data:
                if isinstance(imp, dict):
                    print(f"[{imp.get('plt', imp.get('addr', '?'))}] {imp.get('name', '?')}")


def cmd_exports(args):
    from r2ofrak.core import R2OFRAKContext
    with R2OFRAKContext(args.target, output_dir=args.output, verbose=args.verbose) as ctx:
        data = ctx.dump_exports()
        if args.json:
            print(json.dumps(data, indent=2))
        else:
            for exp in data:
                if isinstance(exp, dict):
                    print(f"[{exp.get('paddr', exp.get('vaddr', '?'))}] {exp.get('name', '?')}")


def cmd_functions(args):
    from r2ofrak.core import R2OFRAKContext
    with R2OFRAKContext(args.target, output_dir=args.output, verbose=args.verbose) as ctx:
        data = ctx.dump_functions()
        if args.json:
            print(json.dumps(data, indent=2))
        else:
            for f in data:
                if isinstance(f, dict):
                    print(f"[{f.get('offset', f.get('addr', '?'))}] {f.get('name', '?')} (size: {f.get('size', 0)})")


def cmd_segments(args):
    from r2ofrak.core import R2OFRAKContext
    with R2OFRAKContext(args.target, output_dir=args.output, verbose=args.verbose) as ctx:
        data = ctx.extract_segments()
        if args.json:
            print(json.dumps(data, indent=2))
        else:
            for s in data:
                if isinstance(s, dict):
                    print(f"[{s.get('vaddr', '?')}] {s.get('name', '?')} (size: {s.get('size', 0)}, perm: {s.get('perm', '?')})")


def cmd_entropy(args):
    from r2ofrak.core import R2OFRAKContext
    with R2OFRAKContext(args.target, output_dir=args.output, verbose=args.verbose) as ctx:
        data = ctx.entropy_analysis()
        if args.json:
            print(json.dumps(data, indent=2))
        else:
            for e in data:
                ent = e.get("entropy", 0)
                bar = "█" * int(ent * 5)
                print(f"[{e.get('name','?'):20s}] {ent:.2f} {bar}")


def cmd_vulns(args):
    from r2ofrak.core import R2OFRAKContext
    with R2OFRAKContext(args.target, output_dir=args.output, verbose=args.verbose) as ctx:
        data = ctx.find_vulnerabilities()
        if args.json:
            print(json.dumps(data, indent=2))
        else:
            for v in data:
                print(f"[{v.get('severity','?').upper():8s}] {v.get('description','?')}")


def cmd_security(args):
    from r2ofrak.core import R2OFRAKContext
    with R2OFRAKContext(args.target, output_dir=args.output, verbose=args.verbose) as ctx:
        data = ctx.security_analysis()
        if args.json:
            print(json.dumps(data, indent=2, default=str))
        else:
            print(f"\n{'='*60}")
            print(f"  Security Analysis — {Path(args.target).name}")
            print(f"{'='*60}")
            h = data.get("hashes", {})
            print(f"\n  Hashes:")
            for k, v in h.items():
                print(f"    {k}: {v}")
            prot = data.get("protections", {})
            print(f"\n  Protections:")
            for k, v in prot.items():
                print(f"    {'✅' if v else '❌'} {k}")
            ad = data.get("anti_debug", [])
            print(f"\n  Anti-debug: {len(ad)} detected")
            for a in ad[:10]:
                print(f"    ⚠ {a.get('description','')} @ {a.get('offset','')}")
            cr = data.get("crypto", [])
            print(f"\n  Crypto: {len(cr)} detected")
            for c in cr[:10]:
                print(f"    🔑 {c.get('description','')} @ {c.get('offset','')}")
            vulns = data.get("vulnerabilities", [])
            print(f"\n  Vulnerabilities: {len(vulns)}")
            for v in vulns[:10]:
                print(f"    [{v.get('severity','?').upper()}] {v.get('description','')}")


def cmd_apk(args):
    from r2ofrak.apk_analyzer import APKAnalyzer
    aa = APKAnalyzer(args.target, args.output)
    data = aa.analyze()
    if args.json:
        print(json.dumps(data, indent=2, default=str))
    else:
        print(f"\nAPK Analysis: {args.target}")
        _pp(data)


def cmd_firmware(args):
    from r2ofrak.firmware import FirmwareAnalyzer
    fa = FirmwareAnalyzer(args.target, args.output)
    data = fa.analyze()
    if args.json:
        print(json.dumps(data, indent=2, default=str))
    else:
        print(f"\nFirmware Analysis: {args.target}")
        _pp(data)


def cmd_compare(args):
    from r2ofrak.comparator import BinaryComparator
    comp = BinaryComparator(args.target, args.other)
    data = comp.compare()
    if args.json:
        print(json.dumps(data, indent=2, default=str))
    else:
        print(f"\nComparing: {args.target} vs {args.other}")
        print(f"  Identical: {data.get('identical', False)}")
        print(f"  Diff regions: {len(data.get('diff_regions', []))}")
        sd = data.get("string_diffs", {})
        print(f"  Strings only in A: {len(sd.get('only_in_a', []))}")
        print(f"  Strings only in B: {len(sd.get('only_in_b', []))}")


def cmd_unpack(args):
    from r2ofrak.core import R2OFRAKContext
    with R2OFRAKContext(args.target, output_dir=args.output, verbose=args.verbose) as ctx:
        result = ctx.unpack()
        print(json.dumps(result, indent=2, default=str))


def cmd_patch(args):
    from r2ofrak.core import R2OFRAKContext
    offset = int(args.offset, 0)
    data = bytes.fromhex(args.hex_data)
    with R2OFRAKContext(args.target, output_dir=args.output, verbose=args.verbose) as ctx:
        ctx.patch(offset, data)
        print(f"Patch applied at 0x{offset:08x}: {data.hex()}")


def cmd_nop(args):
    from r2ofrak.core import R2OFRAKContext
    offset = int(args.offset, 0)
    with R2OFRAKContext(args.target, output_dir=args.output, verbose=args.verbose) as ctx:
        ctx.nop_patch(offset, args.size)
        print(f"NOP'd {args.size} bytes at 0x{offset:08x}")


def cmd_repack(args):
    from r2ofrak.core import R2OFRAKContext
    with R2OFRAKContext(args.target, output_dir=args.output, verbose=args.verbose) as ctx:
        output = ctx.repack()
        print(f"Repacked: {output}")


def cmd_export(args):
    from r2ofrak.core import R2OFRAKContext
    with R2OFRAKContext(args.target, output_dir=args.output, verbose=args.verbose) as ctx:
        ctx.analyze()
        out = ctx.export(args.outfile)
        print(f"Report exported: {out}")


def cmd_tui(args):
    from r2ofrak.tui import R2OFRAKApp
    target = getattr(args, 'target', None)
    output = getattr(args, 'output', None)
    app = R2OFRAKApp(target=target, output_dir=output)
    app.run()


def main():
    parser = argparse.ArgumentParser(
        prog="r2ofrak",
        description="R2OFRAK v0.2 — Unified Reverse Engineering Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  r2ofrak                          Launch interactive TUI
  r2ofrak tui /path/to/binary      Launch TUI with file
  r2ofrak analyze /path/to/binary  Full analysis (CLI)

Examples:
  r2ofrak analyze /bin/ls                    Full analysis
  r2ofrak security /bin/ls                  Security scan
  r2ofrak apk app.apk                       Analyze APK
  r2ofrak firmware router.bin               Analyze firmware
  r2ofrak compare a.bin b.bin               Compare binaries
  r2ofrak disasm /bin/ls --mode function    Disassemble
  r2ofrak strings /bin/ls --min-length 8    Extract strings
  r2ofrak patch /bin/ls --offset 0x1000 --hex-data deadbeef
  r2ofrak export /bin/ls -o report.json     Export report
"""
    )

    parser.add_argument("--version", action="version", version=f"r2ofrak {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("--json", action="store_true", help="JSON output")

    sub = parser.add_subparsers(dest="command")

    # Core commands
    for name, help_text, fn in [
        ("analyze", "Full analysis", cmd_analyze),
        ("disasm", "Disassemble", cmd_disasm),
        ("strings", "Extract strings", cmd_strings),
        ("imports", "List imports", cmd_imports),
        ("exports", "List exports", cmd_exports),
        ("functions", "List functions", cmd_functions),
        ("segments", "List segments", cmd_segments),
        ("entropy", "Entropy analysis", cmd_entropy),
        ("vulns", "Vulnerability scan", cmd_vulns),
    ]:
        p = sub.add_parser(name, help=help_text)
        p.add_argument("target", help="Target binary")
        p.set_defaults(func=fn)

    # Security
    p = sub.add_parser("security", help="Full security analysis")
    p.add_argument("target")
    p.set_defaults(func=cmd_security)

    # APK
    p = sub.add_parser("apk", help="Analyze Android APK/DEX")
    p.add_argument("target")
    p.set_defaults(func=cmd_apk)

    # Firmware
    p = sub.add_parser("firmware", help="Analyze firmware image")
    p.add_argument("target")
    p.set_defaults(func=cmd_firmware)

    # Compare
    p = sub.add_parser("compare", help="Compare two binaries")
    p.add_argument("target")
    p.add_argument("other", help="Second binary")
    p.set_defaults(func=cmd_compare)

    # Patch
    p = sub.add_parser("patch", help="Patch binary")
    p.add_argument("target")
    p.add_argument("--offset", required=True)
    p.add_argument("--hex-data", required=True)
    p.set_defaults(func=cmd_patch)

    # NOP
    p = sub.add_parser("nop", help="NOP patch")
    p.add_argument("target")
    p.add_argument("--offset", required=True)
    p.add_argument("--size", type=int, default=4)
    p.set_defaults(func=cmd_nop)

    # Unpack
    p = sub.add_parser("unpack", help="Unpack with OFRAK")
    p.add_argument("target")
    p.set_defaults(func=cmd_unpack)

    # Repack
    p = sub.add_parser("repack", help="Repack with OFRAK")
    p.add_argument("target")
    p.set_defaults(func=cmd_repack)

    # Export
    p = sub.add_parser("export", help="Export full report")
    p.add_argument("target")
    p.add_argument("--outfile", help="Output file")
    p.set_defaults(func=cmd_export)

    # TUI
    p = sub.add_parser("tui", help="Launch interactive TUI")
    p.add_argument("target", nargs="?")
    p.set_defaults(func=cmd_tui)

    # Disasm-specific
    for p_action in [sp for sp in sub._group_actions if hasattr(sp, '_parser_class')]:
        pass
    # Add disasm args
    sub.choices["disasm"].add_argument("--mode", choices=["full", "function", "addr", "range"], default="full")
    sub.choices["disasm"].add_argument("--addr", help="Address")
    sub.choices["disasm"].add_argument("--count", type=int, default=100)
    sub.choices["strings"].add_argument("--min-length", type=int, default=4)

    args = parser.parse_args()

    if not args.command:
        # Default: launch TUI
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
