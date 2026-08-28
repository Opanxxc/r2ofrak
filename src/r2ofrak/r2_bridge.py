"""
R2Bridge — radare2 integration layer.
Wraps r2pipe for disassembly, analysis, patching, and string extraction.
"""

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Optional, List, Dict, Any

logger = logging.getLogger("r2ofrak.r2")


class R2Bridge:
    """
    Bridge to radare2 via r2pipe (subprocess mode).
    Falls back to CLI if r2pipe unavailable.
    """

    def __init__(self, target: Path, extra_args: Optional[List[str]] = None):
        self.target = target
        self.extra_args = extra_args or []
        self._r2 = None
        self._r2pipe = None

        # Find radare2 binary
        self.r2_bin = shutil.which("r2") or shutil.which("radare2")
        if not self.r2_bin:
            raise RuntimeError(
                "radare2 not found. Install:\n"
                "  Ubuntu: sudo apt install radare2\n"
                "  Termux: pkg install radare2\n"
                "  macOS:  brew install radare2\n"
                "  Source: git clone https://github.com/radareorg/radare2 && cd radare2 && sys/install.sh"
            )

        # Try r2pipe first, fall back to CLI
        try:
            import r2pipe
            self._r2pipe = r2pipe.open(
                str(target),
                flags=["-2", "-q"] + self.extra_args,
            )
            logger.info(f"r2pipe connected to {target.name}")
        except ImportError:
            logger.info("r2pipe not available, using CLI mode")
        except Exception as e:
            logger.warning(f"r2pipe connection failed: {e}, using CLI mode")

    def _cmd(self, command: str) -> str:
        """Execute r2 command via pipe or CLI."""
        if self._r2pipe:
            return self._r2pipe.cmd(command)
        else:
            return self._cmdline(command)

    def _cmd_json(self, command: str) -> Any:
        """Execute r2 command and parse JSON output."""
        if self._r2pipe:
            return self._r2pipe.cmdj(command)
        else:
            output = self._cmdline(command)
            try:
                return json.loads(output)
            except json.JSONDecodeError:
                return output

    def _cmdline(self, command: str) -> str:
        """Execute r2 command via command line."""
        cmd = [
            self.r2_bin,
            "-2",  # suppress stderr
            "-q",  # quiet mode
            "-c", command,
            str(self.target),
        ]
        cmd.extend(self.extra_args)
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0 and result.stderr:
            logger.debug(f"r2 stderr: {result.stderr[:500]}")
        return result.stdout

    def full_analysis(self) -> Dict[str, Any]:
        """Run full radare2 analysis."""
        info = {}
        
        # File info
        info["file_info"] = self._cmd_json("ij") or {}
        
        # Analyze
        self._cmd("aaa")
        
        # Functions
        funcs = self._cmd_json("aflj") or []
        info["functions"] = len(funcs) if isinstance(funcs, list) else 0
        
        # Imports
        imports = self._cmd_json("iij") or []
        info["imports"] = len(imports) if isinstance(imports, list) else 0
        
        # Exports
        exports = self._cmd_json("iej") or []
        info["exports"] = len(exports) if isinstance(exports, list) else 0
        
        # Strings
        strings = self._cmd_json("izj") or []
        info["strings"] = len(strings) if isinstance(strings, list) else 0
        
        # Sections
        sections = self._cmd_json("iSj") or []
        info["sections"] = sections
        
        # Entrypoints
        info["entrypoints"] = self._cmd_json("iej") or []
        
        return info

    def disassemble(
        self,
        mode: str = "full",
        addr: Optional[str] = None,
        count: int = 100,
    ) -> str:
        """Disassemble binary."""
        if mode == "function":
            self._cmd("aaa")
            return self._cmd(f"pdf @ {addr}" if addr else "afl; pdf @ main")
        elif mode == "addr" and addr:
            return self._cmd(f"pd {count} @ {addr}")
        elif mode == "range" and addr:
            return self._cmd(f"pd {count} @ {addr}")
        else:
            self._cmd("aaa")
            return self._cmd(f"pd {count} @ entry0")

    def extract_strings(self, min_length: int = 4) -> List[Dict[str, str]]:
        """Extract all strings from binary."""
        strings = self._cmd_json(f"izj") or []
        result = []
        
        for s in strings:
            if isinstance(s, dict):
                string_val = s.get("string", "")
                if len(string_val) >= min_length:
                    result.append({
                        "offset": s.get("paddr", "0x0"),
                        "vaddr": s.get("vaddr", "0x0"),
                        "string": string_val,
                        "type": s.get("type", "ascii"),
                        "length": len(string_val),
                    })
            elif isinstance(s, str) and len(s) >= min_length:
                result.append({"string": s, "type": "raw"})
        
        # Also get wide strings
        wide_strings = self._cmd_json("izzj") or []
        for s in wide_strings:
            if isinstance(s, dict):
                string_val = s.get("string", "")
                if len(string_val) >= min_length and string_val not in [r["string"] for r in result]:
                    result.append({
                        "offset": s.get("paddr", "0x0"),
                        "vaddr": s.get("vaddr", "0x0"),
                        "string": string_val,
                        "type": s.get("type", "wide"),
                        "length": len(string_val),
                    })
        
        return result

    def get_imports(self) -> List[Dict[str, Any]]:
        """Get import table."""
        imports = self._cmd_json("iij") or []
        return imports if isinstance(imports, list) else []

    def get_exports(self) -> List[Dict[str, Any]]:
        """Get export table."""
        exports = self._cmd_json("iej") or []
        return exports if isinstance(exports, list) else []

    def get_functions(self) -> List[Dict[str, Any]]:
        """Get all functions."""
        self._cmd("aaa")
        funcs = self._cmd_json("aflj") or []
        return funcs if isinstance(funcs, list) else []

    def get_segments(self) -> List[Dict[str, Any]]:
        """Get ELF/PE segments and sections."""
        sections = self._cmd_json("iSj") or []
        return sections if isinstance(sections, list) else []

    def entropy_analysis(self) -> List[Dict[str, Any]]:
        """Analyze entropy per section."""
        sections = self.get_segments()
        result = []
        for sec in sections:
            if isinstance(sec, dict):
                name = sec.get("name", "unknown")
                vaddr = sec.get("vaddr", 0)
                size = sec.get("size", 0)
                if size > 0:
                    # Get entropy via r2
                    entropy = self._cmd_json(f"p=P {size} @ {vaddr}") or 0
                    result.append({
                        "name": name,
                        "vaddr": hex(vaddr) if isinstance(vaddr, int) else vaddr,
                        "size": size,
                        "entropy": float(entropy) if entropy else 0.0,
                    })
        return result

    def scan_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Basic vulnerability pattern scanning."""
        vulns = []
        
        # Check for dangerous functions
        dangerous = ["strcpy", "strcat", "sprintf", "gets", "scanf", "system", "execve"]
        imports = self.get_imports()
        
        for imp in imports:
            if isinstance(imp, dict):
                name = imp.get("name", "")
                for d in dangerous:
                    if d in name.lower():
                        vulns.append({
                            "type": "dangerous_function",
                            "function": name,
                            "address": imp.get("plt", "0x0"),
                            "severity": "high" if d in ["gets", "system", "execve"] else "medium",
                            "description": f"Use of dangerous function: {d}",
                        })
        
        # Check for RWE segments (self-modifying code potential)
        sections = self.get_segments()
        for sec in sections:
            if isinstance(sec, dict):
                perms = sec.get("perm", "")
                if "x" in perms and "w" in perms:
                    vulns.append({
                        "type": "rwx_segment",
                        "name": sec.get("name", ""),
                        "address": sec.get("vaddr", "0x0"),
                        "severity": "medium",
                        "description": "Read-Write-Execute segment (possible shellcode)",
                    })
        
        return vulns

    def patch_bytes(self, offset: int, data: bytes) -> bool:
        """Write bytes at offset."""
        hex_str = data.hex()
        self._cmd(f"wx {hex_str} @ {offset}")
        return True

    def get_byte_at(self, offset: int) -> int:
        """Read single byte at offset."""
        result = self._cmd(f"px 1 @ {offset}")
        # Parse hex output
        try:
            return int(result.strip().split()[0], 16)
        except (IndexError, ValueError):
            return 0

    def get_binary_info(self) -> Dict[str, Any]:
        """Get basic binary info."""
        return self._cmd_json("ij") or {}

    def close(self):
        """Clean up r2pipe connection."""
        if self._r2pipe:
            try:
                self._r2pipe.quit()
            except Exception:
                pass
            self._r2pipe = None
