"""
R2Engine — radare2 wrapper for Panxcz Tools.
Provides JSON API for the web GUI, TUI, and CLI.
Features: caching, batch commands, xrefs, graph, parallel analysis.
"""

import hashlib
import json
import os
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class R2Engine:
    """radare2 engine with caching, batch, and speed optimization."""

    def __init__(self, target: str, flags: Optional[List[str]] = None):
        self.target = Path(target)
        if not self.target.exists():
            raise FileNotFoundError(f"Not found: {self.target}")

        self.r2_bin = shutil.which("r2") or shutil.which("radare2")
        if not self.r2_bin:
            raise RuntimeError("radare2 not found. Install: apt install radare2")

        self.flags = flags or ["-2", "-q"]
        self._cache: Dict[str, Any] = {}
        self._analyzed = False
        self._r2_proc: Optional[subprocess.Popen] = None
        self._batch_mode = False

    # ─── Low-level r2 interaction ────────────────────────────────────

    def cmd(self, command: str) -> str:
        """Execute r2 command, return stdout."""
        cache_key = hashlib.md5(command.encode()).hexdigest()
        if cache_key in self._cache:
            return self._cache[cache_key]

        cmd = [self.r2_bin] + self.flags + ["-c", command, str(self.target)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        self._cache[cache_key] = result.stdout
        return result.stdout

    def cmd_json(self, command: str) -> Any:
        """Execute r2 command, parse JSON output."""
        output = self.cmd(command)
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            return output

    def batch(self, commands: List[str]) -> List[str]:
        """Execute multiple r2 commands in a single session (much faster)."""
        cache_key = "batch:" + "|".join(commands)
        if cache_key in self._cache:
            return self._cache[cache_key]

        cmd_str = " ; ".join(commands)
        full_cmd = [self.r2_bin] + self.flags + ["-c", cmd_str, str(self.target)]
        result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=300)
        outputs = result.stdout.split("\n===\n")
        # Pad if r2 doesn't separate outputs cleanly
        while len(outputs) < len(commands):
            outputs.append("")

        self._cache[cache_key] = outputs
        return outputs

    def _ensure_analyzed(self):
        """Run basic analysis once."""
        if not self._analyzed:
            self.cmd("aaa")
            self._analyzed = True

    # ─── Analysis (fast) ────────────────────────────────────────────

    def analyze_fast(self) -> Dict[str, Any]:
        """Fast analysis — skip deep analysis, use batch commands."""
        t0 = time.time()
        outputs = self.batch(["ij", "aflj", "iij", "iej", "izj", "iSj", "drrj"])
        result = {
            "file_info": self._parse_json(outputs[0]),
            "functions": self._parse_json(outputs[1]),
            "imports": self._parse_json(outputs[2]),
            "exports": self._parse_json(outputs[3]),
            "strings": self._parse_json(outputs[4]),
            "sections": self._parse_json(outputs[5]),
            "relocs": self._parse_json(outputs[6]),
            "elapsed_ms": int((time.time() - t0) * 1000),
        }
        self._analyzed = True
        return result

    def analyze(self) -> Dict[str, Any]:
        """Full analysis with all features."""
        t0 = time.time()
        self._ensure_analyzed()
        outputs = self.batch(["ij", "aflj", "iij", "iej", "izj", "iSj"])
        result = {
            "file_info": self._parse_json(outputs[0]),
            "functions": self._parse_json(outputs[1]),
            "imports": self._parse_json(outputs[2]),
            "exports": self._parse_json(outputs[3]),
            "strings": self._parse_json(outputs[4]),
            "sections": self._parse_json(outputs[5]),
            "elapsed_ms": int((time.time() - t0) * 1000),
        }
        return result

    def _parse_json(self, text: str) -> Any:
        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return text

    # ─── Info ────────────────────────────────────────────────────────

    def info(self) -> Dict[str, Any]:
        """Binary info."""
        return self.cmd_json("ij") or {}

    def info_json(self) -> Dict[str, Any]:
        """Detailed JSON info."""
        return self.cmd_json("ijj") or {}

    # ─── Functions ───────────────────────────────────────────────────

    def functions(self) -> List[Dict]:
        """List functions."""
        self._ensure_analyzed()
        data = self.cmd_json("aflj")
        return data if isinstance(data, list) else []

    def function_info(self, name: str) -> Dict[str, Any]:
        """Get detailed info about a specific function."""
        self._ensure_analyzed()
        return self.cmd_json(f"afij @ {name}") or {}

    def function_size(self, name: str) -> int:
        """Get function size in bytes."""
        self._ensure_analyzed()
        out = self.cmd(f"afis @ {name}")
        try:
            return int(out.strip().split("\n")[0])
        except Exception:
            return 0

    # ─── Cross-references ───────────────────────────────────────────

    def xrefs_to(self, addr: str) -> List[Dict]:
        """Get cross-references TO an address/symbol."""
        self._ensure_analyzed()
        data = self.cmd_json(f"axtj @ {addr}")
        return data if isinstance(data, list) else []

    def xrefs_from(self, addr: str) -> List[Dict]:
        """Get cross-references FROM an address/symbol."""
        self._ensure_analyzed()
        data = self.cmd_json(f"axfj @ {addr}")
        return data if isinstance(data, list) else []

    def xrefs_all(self) -> List[Dict]:
        """Get all cross-references."""
        self._ensure_analyzed()
        data = self.cmd_json("axtj @ $$")
        return data if isinstance(data, list) else []

    # ─── Disassembly ────────────────────────────────────────────────

    def disasm(self, addr: Optional[str] = None, count: int = 200) -> str:
        """Disassemble."""
        self._ensure_analyzed()
        target_addr = addr or "entry0"
        return self.cmd(f"pd {count} @ {target_addr}")

    def disasm_function(self, name: str = "main") -> str:
        """Disassemble a specific function."""
        self._ensure_analyzed()
        return self.cmd(f"pdf @ {name}")

    def disasm_range(self, start: str, end: str) -> str:
        """Disassemble address range."""
        self._ensure_analyzed()
        return self.cmd(f"pd @ {start} @e:scr.color=0")

    # ─── Graph ──────────────────────────────────────────────────────

    def graph_function(self, name: str = "main", width: int = 80, height: int = 24) -> str:
        """Get ASCII control flow graph for a function."""
        self._ensure_analyzed()
        return self.cmd(f"agf @ {name}")

    def graph_json(self, name: str = "main") -> Any:
        """Get graph in JSON format."""
        self._ensure_analyzed()
        return self.cmd_json(f"agfj @ {name}")

    # ─── Strings ────────────────────────────────────────────────────

    def strings(self, min_len: int = 4) -> List[Dict]:
        """Extract strings."""
        data = self.cmd_json("izj") or []
        result = []
        for s in (data if isinstance(data, list) else []):
            if isinstance(s, dict):
                val = s.get("string", "")
                if len(val) >= min_len:
                    result.append({
                        "offset": s.get("paddr", "0x0"),
                        "vaddr": s.get("vaddr", "0x0"),
                        "string": val,
                        "type": s.get("type", "ascii"),
                        "length": len(val),
                    })
        return result

    def strings_unicode(self, min_len: int = 4) -> List[Dict]:
        """Extract Unicode strings."""
        data = self.cmd_json("izj") or []
        result = []
        for s in (data if isinstance(data, list) else []):
            if isinstance(s, dict):
                val = s.get("string", "")
                if len(val) >= min_len and s.get("type", "") in ("utf16", "unicode"):
                    result.append({
                        "offset": s.get("paddr", "0x0"),
                        "vaddr": s.get("vaddr", "0x0"),
                        "string": val,
                        "type": s.get("type", "utf16"),
                    })
        return result

    # ─── Imports / Exports ──────────────────────────────────────────

    def imports(self) -> List[Dict]:
        """List imports."""
        data = self.cmd_json("iij") or []
        return data if isinstance(data, list) else []

    def exports(self) -> List[Dict]:
        """List exports."""
        data = self.cmd_json("iej") or []
        return data if isinstance(data, list) else []

    def imports_by_library(self) -> Dict[str, List[str]]:
        """Group imports by library."""
        imports = self.imports()
        by_lib: Dict[str, List[str]] = {}
        for imp in imports:
            if isinstance(imp, dict):
                lib = imp.get("libname", "unknown")
                name = imp.get("name", "?")
                if lib not in by_lib:
                    by_lib[lib] = []
                by_lib[lib].append(name)
        return by_lib

    # ─── Sections / Segments ────────────────────────────────────────

    def sections(self) -> List[Dict]:
        """List sections."""
        data = self.cmd_json("iSj") or []
        return data if isinstance(data, list) else []

    def segments(self) -> List[Dict]:
        """List segments."""
        data = self.cmd_json("ikj") or []
        return data if isinstance(data, list) else []

    def section_info(self, name: str) -> Dict[str, Any]:
        """Get section info."""
        return self.cmd_json(f"iSj @ {name}") or {}

    # ─── Hex ─────────────────────────────────────────────────────────

    def hexdump(self, offset: int = 0, size: int = 512) -> str:
        """Hex dump at offset."""
        return self.cmd(f"px {size} @ {offset}")

    def hexdump_json(self, offset: int = 0, size: int = 256) -> Any:
        """Hex dump in JSON."""
        return self.cmd_json(f"pxj {size} @ {offset}")

    def write_hex(self, offset: int, hex_data: str) -> bool:
        """Write hex bytes at offset."""
        self.cmd(f"wx {hex_data} @ {offset}")
        return True

    # ─── Entropy ─────────────────────────────────────────────────────

    def entropy(self) -> List[Dict]:
        """Entropy per section."""
        sections = self.sections()
        result = []
        for sec in sections:
            if isinstance(sec, dict):
                name = sec.get("name", "?")
                vaddr = sec.get("vaddr", 0)
                size = sec.get("size", 0)
                if size > 0:
                    ent = self.cmd_json(f"p=P {size} @ {vaddr}") or 0
                    result.append({
                        "name": name,
                        "offset": hex(vaddr) if isinstance(vaddr, int) else vaddr,
                        "size": size,
                        "entropy": float(ent) if ent else 0.0,
                    })
        return result

    def entropy_map(self, block_size: int = 256) -> List[Dict]:
        """Entropy map across entire binary."""
        info = self.info()
        file_size = info.get("core", {}).get("size", 0)
        if not file_size:
            return []

        result = []
        for offset in range(0, min(file_size, 1_000_000), block_size):
            remaining = min(block_size, file_size - offset)
            ent = self.cmd_json(f"p=P {remaining} @ {offset}")
            result.append({
                "offset": offset,
                "size": remaining,
                "entropy": float(ent) if ent else 0.0,
            })
        return result

    # ─── Vulnerabilities ────────────────────────────────────────────

    def vulnerabilities(self) -> List[Dict]:
        """Scan for vulnerability patterns."""
        vulns = []
        dangerous = {
            "gets": "critical", "system": "high", "execve": "high",
            "strcpy": "high", "strcat": "high", "sprintf": "high",
            "scanf": "medium", "printf": "medium", "malloc": "low",
            "free": "low", "mmap": "low", "dlopen": "low",
            "dlsym": "medium", "fork": "low", "popen": "medium",
            "mktemp": "medium", "tmpnam": "medium",
        }
        for imp in self.imports():
            if isinstance(imp, dict):
                name = imp.get("name", "")
                for d, sev in dangerous.items():
                    if d in name.lower():
                        vulns.append({
                            "type": "dangerous_function",
                            "function": name,
                            "address": imp.get("plt", "0x0"),
                            "severity": sev,
                            "description": f"Use of {d}()",
                        })
                        break
        return vulns

    # ─── Search ──────────────────────────────────────────────────────

    def search(self, query: str) -> List[Dict]:
        """Search in binary."""
        data = self.cmd_json(f"/j {query}") or []
        return data if isinstance(data, list) else []

    def search_hex(self, hex_pattern: str) -> List[Dict]:
        """Search for hex pattern."""
        data = self.cmd_json(f"/xj {hex_pattern}") or []
        return data if isinstance(data, list) else []

    def search_regex(self, pattern: str) -> List[Dict]:
        """Search with regex."""
        data = self.cmd_json(f"/rj {pattern}") or []
        return data if isinstance(data, list) else []

    # ─── Patching ────────────────────────────────────────────────────

    def patch(self, offset: int, hex_data: str) -> bool:
        """Write hex bytes at offset."""
        self.cmd(f"wx {hex_data} @ {offset}")
        return True

    def nop(self, offset: int, count: int = 1) -> bool:
        """Write NOPs at offset."""
        self.cmd(f"wx {'90' * count} @ {offset}")
        return True

    def jmp(self, offset: int, target: int) -> bool:
        """Write JMP instruction."""
        rel = target - offset - 2
        if -128 <= rel <= 127:
            self.cmd(f"wx eb{rel & 0xff:02x} @ {offset}")
        else:
            self.cmd(f"wx e9{rel & 0xffffffff:08x} @ {offset}")
        return True

    # ─── Export ──────────────────────────────────────────────────────

    def export_report(self, output_path: str) -> Dict[str, Any]:
        """Export full analysis report to JSON."""
        analysis = self.analyze()
        vulns = self.vulnerabilities()
        entropy = self.entropy()
        xrefs = self.xrefs_all()

        report = {
            "file": str(self.target),
            "analysis": analysis,
            "vulnerabilities": vulns,
            "entropy": entropy,
            "xref_count": len(xrefs),
            "version": "1.0.0",
        }

        with open(output_path, "w") as f:
            json.dump(report, f, indent=2, default=str)

        return report

    # ─── Parallel analysis ───────────────────────────────────────────

    def analyze_parallel(self, functions: Optional[List[str]] = None) -> Dict[str, Any]:
        """Analyze multiple functions in parallel."""
        if not functions:
            funcs = self.functions()
            functions = [f.get("name", "") for f in funcs if isinstance(f, dict)][:50]

        results = {}

        def _analyze_func(name: str) -> Tuple[str, Dict]:
            try:
                cmd = [self.r2_bin] + self.flags + ["-c", f"afij @ {name}", str(self.target)]
                out = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                data = self._parse_json(out.stdout)
                return (name, data)
            except Exception:
                return (name, {"error": True})

        with ThreadPoolExecutor(max_workers=4) as executor:
            for name, data in executor.map(lambda n: _analyze_func(n), functions):
                results[name] = data

        return results

    # ─── Cleanup ─────────────────────────────────────────────────────

    def clear_cache(self):
        """Clear command cache."""
        self._cache.clear()

    def __del__(self):
        """Clean up r2 process if running."""
        if self._r2_proc:
            try:
                self._r2_proc.kill()
            except Exception:
                pass
