"""
Security Analyzer — Anti-debug, crypto detection, protections, YARA.
"""

import hashlib
import logging
import math
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger("panxcz.security")


class SecurityAnalyzer:
    """Binary security analysis."""

    def __init__(self, target: str):
        self.target = Path(target)
        self._data: bytes = b""

    def _read(self) -> bytes:
        if not self._data:
            with open(self.target, "rb") as f:
                self._data = f.read()
        return self._data

    def full(self) -> Dict[str, Any]:
        data = self._read()
        return {
            "file": str(self.target),
            "size": len(data),
            "hashes": self.hashes(),
            "anti_debug": self.anti_debug(),
            "crypto": self.crypto(),
            "vulnerabilities": self.vulns(),
            "protections": self.protections(),
        }

    def hashes(self) -> Dict[str, str]:
        data = self._read()
        return {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    def anti_debug(self) -> List[Dict]:
        patterns = [
            (b"ptrace", "ptrace API"),
            (b"PTRACE_TRACEME", "PTRACE_TRACEME"),
            (b"/proc/self/status", "proc status check"),
            (b"TracerPid:", "TracerPid check"),
            (b"IsDebuggerPresent", "Windows debug check"),
            (b"Frida", "Frida detection"),
            (b"frida", "Frida detection"),
            (b"Xposed", "Xposed detection"),
            (b"substrate", "substrate detection"),
            (b"OllyDbg", "OllyDbg detection"),
            (b"x64dbg", "x64dbg detection"),
            (b"IDA Pro", "IDA Pro detection"),
            (b"radare2", "radare2 detection"),
        ]
        data = self._read()
        findings = []
        seen = set()
        for pat, desc in patterns:
            if pat in data and desc not in seen:
                seen.add(desc)
                pos = data.find(pat)
                findings.append({"pattern": pat.decode(), "description": desc, "offset": f"0x{pos:08x}"})
        return findings

    def crypto(self) -> List[Dict]:
        patterns = [
            (b"AES", "AES encryption"), (b"RSA", "RSA encryption"),
            (b"MD5", "MD5 hash"), (b"SHA256", "SHA256 hash"),
            (b"SHA512", "SHA512 hash"), (b"HMAC", "HMAC"),
            (b"PBKDF", "PBKDF key derivation"),
            (b"Base64", "Base64 encoding"), (b"DES", "DES encryption"),
            (b"Blowfish", "Blowfish encryption"),
        ]
        data = self._read()
        findings = []
        seen = set()
        for pat, desc in patterns:
            if pat in data and desc not in seen:
                seen.add(desc)
                pos = data.find(pat)
                findings.append({"pattern": pat.decode(), "description": desc, "offset": f"0x{pos:08x}"})
        return findings

    def vulns(self) -> List[Dict]:
        patterns = [
            (b"gets(", "gets() — buffer overflow", "critical"),
            (b"sprintf(", "sprintf() — format string", "high"),
            (b"strcpy(", "strcpy() — buffer overflow", "high"),
            (b"system(", "system() — command injection", "high"),
            (b"/bin/sh", "shell spawn", "high"),
        ]
        data = self._read()
        findings = []
        for pat, desc, sev in patterns:
            if pat in data:
                pos = data.find(pat)
                findings.append({"pattern": pat.decode(), "description": desc, "severity": sev, "offset": f"0x{pos:08x}"})
        return findings

    def protections(self) -> Dict[str, bool]:
        data = self._read()
        return {
            "strip": b".debug_info" not in data and b".symtab" not in data,
            "nx": b"GNU_STACK" in data,
            "stack_canary": b"__stack_chk_fail" in data,
            "fortify": b"__fortify" in data,
            "relro": b"GNU_RELRO" in data,
            "pie": b"PIE" in data,
        }
