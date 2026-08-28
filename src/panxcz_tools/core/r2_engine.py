"""
R2Engine — radare2 wrapper for Panxcz Tools.
Provides JSON API for the web GUI, TUI, and CLI.
"""

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional


class R2Engine:
    """radare2 engine with JSON output support."""

    def __init__(self, target: str, flags: Optional[List[str]] = None):
        self.target = Path(target)
        if not self.target.exists():
            raise FileNotFoundError(f"Not found: {self.target}")

        self.r2_bin = shutil.which("r2") or shutil.which("radare2")
        if not self.r2_bin:
            raise RuntimeError("radare2 not found. Install: apt install radare2")

        self.flags = flags or ["-2", "-q"]
        self._cache: Dict[str, Any] = {}

    def cmd(self, command: str) -> str:
        """Execute r2 command, return stdout."""
        cmd = [self.r2_bin] + self.flags + ["-c", command, str(self.target)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return result.stdout

    def cmd_json(self, command: str) -> Any:
        """Execute r2 command, parse JSON output."""
        output = self.cmd(command)
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            return output

    # ─── Analysis ────────────────────────────────────────────────

    def analyze(self) -> Dict[str, Any]:
        """Full analysis."""
        self.cmd("aaa")
        return {
            "file_info": self.cmd_json("ij"),
            "functions": self.cmd_json("aflj"),
            "imports": self.cmd_json("iij"),
            "exports": self.cmd_json("iej"),
            "strings": self.cmd_json("izj"),
            "sections": self.cmd_json("iSj"),
        }

    def info(self) -> Dict[str, Any]:
        """Binary info."""
        return self.cmd_json("ij") or {}

    def functions(self) -> List[Dict]:
        """List functions."""
        self.cmd("aaa")
        data = self.cmd_json("aflj")
        return data if isinstance(data, list) else []

    def disasm(self, addr: Optional[str] = None, count: int = 200) -> str:
        """Disassemble."""
        if addr:
            return self.cmd(f"pd {count} @ {addr}")
        self.cmd("aaa")
        return self.cmd(f"pd {count} @ entry0")

    def disasm_function(self, name: str = "main") -> str:
        """Disassemble a specific function."""
        self.cmd("aaa")
        return self.cmd(f"pdf @ {name}")

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
                    })
        return result

    def imports(self) -> List[Dict]:
        """List imports."""
        data = self.cmd_json("iij") or []
        return data if isinstance(data, list) else []

    def exports(self) -> List[Dict]:
        """List exports."""
        data = self.cmd_json("iej") or []
        return data if isinstance(data, list) else []

    def sections(self) -> List[Dict]:
        """List sections."""
        data = self.cmd_json("iSj") or []
        return data if isinstance(data, list) else []

    def hexdump(self, offset: int = 0, size: int = 512) -> str:
        """Hex dump at offset."""
        return self.cmd(f"px {size} @ {offset}")

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

    def vulnerabilities(self) -> List[Dict]:
        """Scan for vulnerability patterns."""
        vulns = []
        dangerous = ["strcpy", "strcat", "sprintf", "gets", "scanf", "system", "execve"]
        for imp in self.imports():
            if isinstance(imp, dict):
                name = imp.get("name", "")
                for d in dangerous:
                    if d in name.lower():
                        vulns.append({
                            "type": "dangerous_function",
                            "function": name,
                            "address": imp.get("plt", "0x0"),
                            "severity": "high" if d in ["gets", "system", "execve"] else "medium",
                            "description": f"Use of {d}()",
                        })
        return vulns

    def patch(self, offset: int, hex_data: str) -> bool:
        """Write hex bytes at offset."""
        self.cmd(f"wx {hex_data} @ {offset}")
        return True

    def r2cmd(self, command: str) -> str:
        """Execute arbitrary r2 command."""
        return self.cmd(command)

    def search(self, query: str) -> List[Dict]:
        """Search in binary."""
        data = self.cmd_json(f"/j {query}") or []
        return data if isinstance(data, list) else []
