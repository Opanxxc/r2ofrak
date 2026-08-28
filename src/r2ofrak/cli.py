#!/usr/bin/env python3
"""
R2OFRAK CLI — Unified reverse engineering tool.
Combines radare2 + OFRAK into one powerful command.
"""

import argparse
import json
import sys
import os
from pathlib import Path

__version__ = "0.1.0"


def cmd_analyze(args):
    """Full analysis of binary."""
    from r2ofrak.core import R2OFRAKContext
    
    with R2OFRAKContext(
        args.target,
        output_dir=args.output,
        verbose=args.verbose,
    ) as ctx:
        report = ctx.analyze()
        
        if args.json:
            print(json.dumps(report, indent=2, default=str))
        else:
            print(f"\n{'='*60}")
            print(f"  R2OFRAK Analysis Report")
            print(f"{'='*60}")
            print(f"  File: {report.get('file', 'N/A')}")
            print(f"  Size: {report.get('size', 0):,} bytes")
            
            r2 = report.get("r2", {})
            if "error" not in r2:
                fi = r2.get("file_info", {})
                print(f"\n  radare2:")
                print(f"    Type: {fi.get('core', {}).get('file', 'N/A')}")
                print(f"    Arch: {fi.get('bin', {}).get('arch', 'N/A')}")
                print(f"    Bits: {fi.get('bin', {}).get('bits', 'N/A')}")
                print(f"    OS:   {fi.get('bin', {}).get('os', 'N/A')}")
                print(f"    Functions: {r2.get('functions', 0)}")
                print(f"    Imports:   {r2.get('imports', 0)}")
                print(f"    Exports:   {r2.get('exports', 0)}")
                print(f"    Strings:   {r2.get('strings', 0)}")
            
            ofrak = report.get("ofrak", {})
            if "error" not in ofrak:
                print(f"\n  OFRAK:")
                print(f"    Format: {ofrak.get('format', 'N/A')}")
                print(f"    Tags:   {ofrak.get('tags', [])}")
            
            strings = report.get("strings", {})
            print(f"\n  Strings: {strings.get('count', 0)} found")
            
            print(f"\n  Output: {ctx.output_dir}")
            print(f"{'='*60}\n")


def cmd_disassemble(args):
    """Disassemble binary."""
    from r2ofrak.core import R2OFRAKContext
    
    with R2OFRAKContext(
        args.target,
        output_dir=args.output,
        verbose=args.verbose,
    ) as ctx:
        output = ctx.disassemble(
            mode=args.mode,
            addr=args.addr,
            count=args.count,
        )
        print(output)


def cmd_strings(args):
    """Extract strings."""
    from r2ofrak.core import R2OFRAKContext
    
    with R2OFRAKContext(
        args.target,
        output_dir=args.output,
        verbose=args.verbose,
    ) as ctx:
        strings = ctx.dump_strings(min_length=args.min_length)
        
        if args.json:
            print(json.dumps(strings, indent=2))
        else:
            for s in strings:
                offset = s.get("offset", "?")
                string = s.get("string", "")
                print(f"[{offset}] {string}")


def cmd_imports(args):
    """List imports."""
    from r2ofrak.core import R2OFRAKContext
    
    with R2OFRAKContext(
        args.target,
        output_dir=args.output,
        verbose=args.verbose,
    ) as ctx:
        imports = ctx.dump_imports()
        
        if args.json:
            print(json.dumps(imports, indent=2))
        else:
            for imp in imports:
                if isinstance(imp, dict):
                    name = imp.get("name", "?")
                    addr = imp.get("plt", imp.get("addr", "?"))
                    print(f"[{addr}] {name}")


def cmd_exports(args):
    """List exports."""
    from r2ofrak.core import R2OFRAKContext
    
    with R2OFRAKContext(
        args.target,
        output_dir=args.output,
        verbose=args.verbose,
    ) as ctx:
        exports = ctx.dump_exports()
        
        if args.json:
            print(json.dumps(exports, indent=2))
        else:
            for exp in exports:
                if isinstance(exp, dict):
                    name = exp.get("name", "?")
                    addr = exp.get("paddr", exp.get("vaddr", "?"))
                    print(f"[{addr}] {name}")


def cmd_functions(args):
    """List functions."""
    from r2ofrak.core import R2OFRAKContext
    
    with R2OFRAKContext(
        args.target,
        output_dir=args.output,
        verbose=args.verbose,
    ) as ctx:
        funcs = ctx.dump_functions()
        
        if args.json:
            print(json.dumps(funcs, indent=2))
        else:
            for f in funcs:
                if isinstance(f, dict):
                    name = f.get("name", "?")
                    offset = f.get("offset", f.get("addr", "?"))
                    size = f.get("size", 0)
                    print(f"[{offset}] {name} (size: {size})")


def cmd_segments(args):
    """List segments/sections."""
    from r2ofrak.core import R2OFRAKContext
    
    with R2OFRAKContext(
        args.target,
        output_dir=args.output,
        verbose=args.verbose,
    ) as ctx:
        segs = ctx.extract_segments()
        
        if args.json:
            print(json.dumps(segs, indent=2))
        else:
            for seg in segs:
                if isinstance(seg, dict):
                    name = seg.get("name", "?")
                    addr = seg.get("vaddr", "?")
                    size = seg.get("size", 0)
                    perm = seg.get("perm", "?")
                    print(f"[{addr}] {name} (size: {size}, perm: {perm})")


def cmd_entropy(args):
    """Entropy analysis."""
    from r2ofrak.core import R2OFRAKContext
    
    with R2OFRAKContext(
        args.target,
        output_dir=args.output,
        verbose=args.verbose,
    ) as ctx:
        entropy = ctx.entropy_analysis()
        
        if args.json:
            print(json.dumps(entropy, indent=2))
        else:
            for e in entropy:
                name = e.get("name", "?")
                ent = e.get("entropy", 0)
                size = e.get("size", 0)
                bar = "█" * int(ent * 5)
                print(f"[{name:20s}] entropy={ent:.2f} size={size:8d} {bar}")


def cmd_vulns(args):
    """Scan for vulnerabilities."""
    from r2ofrak.core import R2OFRAKContext
    
    with R2OFRAKContext(
        args.target,
        output_dir=args.output,
        verbose=args.verbose,
    ) as ctx:
        vulns = ctx.find_vulnerabilities()
        
        if args.json:
            print(json.dumps(vulns, indent=2))
        else:
            if not vulns:
                print("No vulnerabilities found.")
            else:
                for v in vulns:
                    vtype = v.get("type", "?")
                    severity = v.get("severity", "?")
                    desc = v.get("description", "?")
                    print(f"[{severity.upper():8s}] {vtype}: {desc}")


def cmd_unpack(args):
    """Unpack binary with OFRAK."""
    from r2ofrak.core import R2OFRAKContext
    
    with R2OFRAKContext(
        args.target,
        output_dir=args.output,
        verbose=args.verbose,
    ) as ctx:
        result = ctx.unpack()
        print(json.dumps(result, indent=2, default=str))


def cmd_patch(args):
    """Patch binary."""
    from r2ofrak.core import R2OFRAKContext
    
    offset = int(args.offset, 0)  # supports hex like 0x1234
    data = bytes.fromhex(args.hex_data)
    
    with R2OFRAKContext(
        args.target,
        output_dir=args.output,
        verbose=args.verbose,
    ) as ctx:
        result = ctx.patch(offset, data)
        print(f"Patch applied at 0x{offset:08x}: {result['data']}")


def cmd_nop(args):
    """NOP patch."""
    from r2ofrak.core import R2OFRAKContext
    
    offset = int(args.offset, 0)
    
    with R2OFRAKContext(
        args.target,
        output_dir=args.output,
        verbose=args.verbose,
    ) as ctx:
        result = ctx.nop_patch(offset, args.size)
        print(f"NOP'd {args.size} bytes at 0x{offset:08x}")


def cmd_repack(args):
    """Repack binary with OFRAK."""
    from r2ofrak.core import R2OFRAKContext
    
    with R2OFRAKContext(
        args.target,
        output_dir=args.output,
        verbose=args.verbose,
    ) as ctx:
        output = ctx.repack()
        print(f"Repacked: {output}")


def cmd_export(args):
    """Export analysis results."""
    from r2ofrak.core import R2OFRAKContext
    
    with R2OFRAKContext(
        args.target,
        output_dir=args.output,
        verbose=args.verbose,
    ) as ctx:
        # Run quick analysis first
        ctx.analyze()
        output = ctx.export(args.outfile)
        print(f"Report exported: {output}")


def cmd_tui(args):
    """Launch interactive TUI."""
    from r2ofrak.tui import R2OFRAKApp
    
    target = getattr(args, 'target', None) or getattr(args, 'output', None)
    output = getattr(args, 'output', None)
    
    app = R2OFRAKApp(target=target, output_dir=output)
    app.run()


def main():
    parser = argparse.ArgumentParser(
        prog="r2ofrak",
        description="R2OFRAK — Unified Reverse Engineering Platform (radare2 + OFRAK)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  r2ofrak analyze /bin/ls                    Full analysis
  r2ofrak disasm /bin/ls                     Disassemble
  r2ofrak disasm /bin/ls --mode function     Disassemble functions
  r2ofrak strings /bin/ls --min-length 8     Extract strings
  r2ofrak imports /bin/ls --json             List imports (JSON)
  r2ofrak exports /bin/ls                    List exports
  r2ofrak functions /bin/ls                  List functions
  r2ofrak segments /bin/ls                   List segments
  r2ofrak entropy /bin/ls                    Entropy analysis
  r2ofrak vulns /bin/ls                      Vulnerability scan
  r2ofrak unpack firmware.bin                Unpack with OFRAK
  r2ofrak patch /bin/ls --offset 0x1000 --hex deadbeef
  r2ofrak nop /bin/ls --offset 0x1000 --size 10
  r2ofrak repack /bin/ls                     Repack with OFRAK
  r2ofrak export /bin/ls -o report.json      Export full report
"""
    )
    
    parser.add_argument("--version", action="version", version=f"r2ofrak {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("--json", action="store_true", help="JSON output")
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # analyze
    p = subparsers.add_parser("analyze", help="Full analysis of binary")
    p.add_argument("target", help="Target binary")
    p.set_defaults(func=cmd_analyze)
    
    # disasm
    p = subparsers.add_parser("disasm", aliases=["disassemble"], help="Disassemble binary")
    p.add_argument("target", help="Target binary")
    p.add_argument("--mode", choices=["full", "function", "addr", "range"], default="full")
    p.add_argument("--addr", help="Address to disassemble from")
    p.add_argument("--count", type=int, default=100, help="Number of instructions")
    p.set_defaults(func=cmd_disassemble)
    
    # strings
    p = subparsers.add_parser("strings", help="Extract strings")
    p.add_argument("target", help="Target binary")
    p.add_argument("--min-length", type=int, default=4, help="Minimum string length")
    p.set_defaults(func=cmd_strings)
    
    # imports
    p = subparsers.add_parser("imports", help="List imports")
    p.add_argument("target", help="Target binary")
    p.set_defaults(func=cmd_imports)
    
    # exports
    p = subparsers.add_parser("exports", help="List exports")
    p.add_argument("target", help="Target binary")
    p.set_defaults(func=cmd_exports)
    
    # functions
    p = subparsers.add_parser("functions", aliases=["funcs"], help="List functions")
    p.add_argument("target", help="Target binary")
    p.set_defaults(func=cmd_functions)
    
    # segments
    p = subparsers.add_parser("segments", help="List segments/sections")
    p.add_argument("target", help="Target binary")
    p.set_defaults(func=cmd_segments)
    
    # entropy
    p = subparsers.add_parser("entropy", help="Entropy analysis")
    p.add_argument("target", help="Target binary")
    p.set_defaults(func=cmd_entropy)
    
    # vulns
    p = subparsers.add_parser("vulns", help="Vulnerability scan")
    p.add_argument("target", help="Target binary")
    p.set_defaults(func=cmd_vulns)
    
    # unpack
    p = subparsers.add_parser("unpack", help="Unpack with OFRAK")
    p.add_argument("target", help="Target binary/archive")
    p.set_defaults(func=cmd_unpack)
    
    # patch
    p = subparsers.add_parser("patch", help="Patch binary")
    p.add_argument("target", help="Target binary")
    p.add_argument("--offset", required=True, help="Offset (hex: 0x1234)")
    p.add_argument("--hex-data", required=True, help="Hex data to write")
    p.set_defaults(func=cmd_patch)
    
    # nop
    p = subparsers.add_parser("nop", help="NOP patch")
    p.add_argument("target", help="Target binary")
    p.add_argument("--offset", required=True, help="Offset (hex: 0x1234)")
    p.add_argument("--size", type=int, default=4, help="Number of NOP bytes")
    p.set_defaults(func=cmd_nop)
    
    # repack
    p = subparsers.add_parser("repack", help="Repack with OFRAK")
    p.add_argument("target", help="Target binary")
    p.set_defaults(func=cmd_repack)
    
    # export
    p = subparsers.add_parser("export", help="Export full report")
    p.add_argument("target", help="Target binary")
    p.add_argument("-o", "--outfile", help="Output file path")
    p.set_defaults(func=cmd_export)
    
    # tui — launch interactive TUI
    p = subparsers.add_parser("tui", help="Launch interactive TUI (default when no command)")
    p.add_argument("target", nargs="?", help="Target binary to open")
    p.set_defaults(func=cmd_tui)
    
    args = parser.parse_args()
    
    if not args.command:
        # No subcommand → launch TUI
        cmd_tui(args)
    
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
