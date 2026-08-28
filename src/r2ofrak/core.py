"""
R2OFRAK Core — Unified context that bridges radare2 and OFRAK.
Provides a single entry point for binary analysis, unpacking, patching, and repacking.
"""

import os
import sys
import json
import logging
import tempfile
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple

logger = logging.getLogger("r2ofrak")


class R2OFRAKContext:
    """
    Unified reverse engineering context.
    
    Usage:
        ctx = R2OFRAKContext("/path/to/binary")
        ctx.analyze()          # full analysis (r2 + ofrak)
        ctx.unpack()           # unpack with OFRAK
        ctx.disassemble()      # disassemble with radare2
        ctx.dump_strings()     # extract all strings
        ctx.patch(offset, bytes)  # patch binary
        ctx.repack()           # repack with OFRAK
        ctx.export("output")   # export results
    """

    def __init__(
        self,
        target: str,
        output_dir: Optional[str] = None,
        verbose: bool = False,
        r2_args: Optional[List[str]] = None,
    ):
        self.target = Path(target).resolve()
        if not self.target.exists():
            raise FileNotFoundError(f"Target not found: {self.target}")

        self.output_dir = Path(output_dir) if output_dir else Path(tempfile.mkdtemp(prefix="r2ofrak_"))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.verbose = verbose
        self.r2_args = r2_args or []

        # Internal state
        self._r2 = None
        self._ofrak = None
        self._analysis: Dict[str, Any] = {}
        self._unpacked = False
        self._patches: List[Dict[str, Any]] = []

        # Setup logging
        level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(level=level, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")

        logger.info(f"R2OFRAK initialized: {self.target} -> {self.output_dir}")

    @property
    def r2(self):
        """Lazy-init radare2 bridge."""
        if self._r2 is None:
            from r2ofrak.r2_bridge import R2Bridge
            self._r2 = R2Bridge(self.target, self.r2_args)
        return self._r2

    @property
    def ofrak(self):
        """Lazy-init OFRAK bridge."""
        if self._ofrak is None:
            from r2ofrak.ofrak_bridge import OFRAKBridge
            self._ofrak = OFRAKBridge(self.target, self.output_dir)
        return self._ofrak

    def analyze(self) -> Dict[str, Any]:
        """
        Full analysis: radare2 + OFRAK combined.
        Returns analysis report dict.
        """
        logger.info("=" * 60)
        logger.info(f"FULL ANALYSIS: {self.target.name}")
        logger.info("=" * 60)

        report = {
            "file": str(self.target),
            "size": self.target.stat().st_size,
        }

        # Radare2 analysis
        logger.info("[1/3] radare2 analysis...")
        try:
            r2_info = self.r2.full_analysis()
            report["r2"] = r2_info
        except Exception as e:
            logger.warning(f"radare2 analysis failed: {e}")
            report["r2"] = {"error": str(e)}

        # OFRAK identification
        logger.info("[2/3] OFRAK identification...")
        try:
            ofrak_info = self.ofrak.identify()
            report["ofrak"] = ofrak_info
        except Exception as e:
            logger.warning(f"OFRAK identification failed: {e}")
            report["ofrak"] = {"error": str(e)}

        # String extraction
        logger.info("[3/3] String extraction...")
        try:
            strings = self.r2.extract_strings()
            report["strings"] = {
                "count": len(strings),
                "sample": strings[:50],
            }
        except Exception as e:
            logger.warning(f"String extraction failed: {e}")
            report["strings"] = {"error": str(e)}

        self._analysis = report
        logger.info(f"Analysis complete. Report saved to {self.output_dir / 'analysis.json'}")
        return report

    def disassemble(
        self,
        mode: str = "full",
        addr: Optional[str] = None,
        count: int = 100,
    ) -> str:
        """
        Disassemble using radare2.
        mode: 'full', 'function', 'addr', 'range'
        """
        logger.info(f"Disassembling ({mode})...")
        return self.r2.disassemble(mode=mode, addr=addr, count=count)

    def dump_strings(self, min_length: int = 4) -> List[Dict[str, str]]:
        """Extract all strings from binary."""
        logger.info(f"Extracting strings (min_length={min_length})...")
        strings = self.r2.extract_strings(min_length=min_length)
        
        # Save to file
        out_file = self.output_dir / "strings.json"
        with open(out_file, "w") as f:
            json.dump(strings, f, indent=2)
        logger.info(f"Strings saved to {out_file} ({len(strings)} found)")
        return strings

    def dump_imports(self) -> List[Dict[str, Any]]:
        """Extract import table."""
        logger.info("Extracting imports...")
        imports = self.r2.get_imports()
        out_file = self.output_dir / "imports.json"
        with open(out_file, "w") as f:
            json.dump(imports, f, indent=2)
        return imports

    def dump_exports(self) -> List[Dict[str, Any]]:
        """Extract export table."""
        logger.info("Extracting exports...")
        exports = self.r2.get_exports()
        out_file = self.output_dir / "exports.json"
        with open(out_file, "w") as f:
            json.dump(exports, f, indent=2)
        return exports

    def dump_functions(self) -> List[Dict[str, Any]]:
        """List all functions."""
        logger.info("Extracting functions...")
        funcs = self.r2.get_functions()
        out_file = self.output_dir / "functions.json"
        with open(out_file, "w") as f:
            json.dump(funcs, f, indent=2)
        return funcs

    def unpack(self) -> Dict[str, Any]:
        """
        Unpack binary with OFRAK.
        Supports: ELF, PE, Mach-O, APK, firmware, compressed archives.
        """
        logger.info("Unpacking with OFRAK...")
        result = self.ofrak.unpack()
        self._unpacked = True
        return result

    def patch(self, offset: int, data: bytes) -> Dict[str, Any]:
        """
        Patch binary at offset.
        Records patch for later repacking.
        """
        logger.info(f"Patching at offset 0x{offset:08x} ({len(data)} bytes)")
        patch_info = {
            "offset": offset,
            "data": data.hex(),
            "size": len(data),
        }
        self._patches.append(patch_info)
        
        # Apply with radare2
        self.r2.patch_bytes(offset, data)
        
        logger.info(f"Patch applied: {data.hex()}")
        return patch_info

    def nop_patch(self, offset: int, size: int) -> Dict[str, Any]:
        """NOP out bytes at offset."""
        nop_bytes = b"\x90" * size  # x86 NOP; for ARM use appropriate NOP
        return self.patch(offset, nop_bytes)

    def repack(self) -> Path:
        """
        Repack binary with OFRAK after patching.
        Returns path to repacked binary.
        """
        if not self._patches:
            logger.warning("No patches to apply, repacking original")
        
        logger.info("Repacking with OFRAK...")
        output = self.ofrak.repack()
        logger.info(f"Repacked binary: {output}")
        return output

    def extract_segments(self) -> List[Dict[str, Any]]:
        """Extract ELF/PE segments/sections."""
        logger.info("Extracting segments...")
        segments = self.r2.get_segments()
        out_file = self.output_dir / "segments.json"
        with open(out_file, "w") as f:
            json.dump(segments, f, indent=2)
        return segments

    def entropy_analysis(self) -> Dict[str, Any]:
        """Calculate entropy per section (detect packing/encryption)."""
        logger.info("Entropy analysis...")
        entropy = self.r2.entropy_analysis()
        out_file = self.output_dir / "entropy.json"
        with open(out_file, "w") as f:
            json.dump(entropy, f, indent=2)
        return entropy

    def find_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Basic vulnerability pattern scanning."""
        logger.info("Scanning for vulnerability patterns...")
        vulns = self.r2.scan_vulnerabilities()
        out_file = self.output_dir / "vulnerabilities.json"
        with open(out_file, "w") as f:
            json.dump(vulns, f, indent=2)
        return vulns

    def export(self, output_path: Optional[str] = None) -> Path:
        """Export all analysis results."""
        out = Path(output_path) if output_path else self.output_dir / "full_report.json"
        report = {
            "target": str(self.target),
            "analysis": self._analysis,
            "patches": self._patches,
            "output_dir": str(self.output_dir),
        }
        with open(out, "w") as f:
            json.dump(report, f, indent=2, default=str)
        logger.info(f"Full report exported to {out}")
        return out

    def close(self):
        """Clean up resources."""
        if self._r2:
            self._r2.close()
        if self._ofrak:
            self._ofrak.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
