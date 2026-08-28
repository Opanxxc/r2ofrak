"""
Security Analyzer — Anti-debug detection, crypto detection, YARA matching, vulnerability patterns.
"""

import hashlib
import logging
import re
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("r2ofrak.security")


# ─── Anti-debug signatures ─────────────────────────────────────────
ANTI_DEBUG_PATTERNS = [
    # Linux ptrace
    (b"\x0f\x05", "syscall instruction"),
    (b"ptrace", "ptrace API call"),
    (b"PTRACE_TRACEME", "PTRACE_TRACEME"),
    (b"PTRACE_ATTACH", "PTRACE_ATTACH"),
    (b"/proc/self/status", "proc status check"),
    (b"/proc/self/maps", "proc maps check"),
    (b"/proc/%d/status", "proc pid status"),
    (b"TracerPid:", "TracerPid check"),
    (b"WPTEditor", "WPTEditor anti-debug"),
    # Android specific
    (b"libptrace.so", "Android ptrace"),
    (b"anti", "anti-debug reference"),
    (b"debug", "debug reference"),
    (b"trace", "trace reference"),
    # Timing checks
    (b"clock_gettime", "timing check"),
    (b"gettimeofday", "timing check"),
    (b"QueryPerformanceCounter", "Windows timing check"),
    (b"rdtsc", "x86 timing instruction"),
    # Debugger detection
    (b"IsDebuggerPresent", "Windows debug check"),
    (b"CheckRemoteDebuggerPresent", "Remote debug check"),
    (b"NtQueryInformationProcess", "NtQuery debug info"),
    (b"ZwQueryInformationProcess", "ZwQuery debug info"),
    (b"OutputDebugString", "debug output check"),
    (b"FindWindow", "window detection"),
    (b"OllyDbg", "OllyDbg detection"),
    (b"x64dbg", "x64dbg detection"),
    (b"GDB", "GDB detection"),
    (b"IDA", "IDA detection"),
    (b"IDA Pro", "IDA Pro detection"),
    (b"radare2", "radare2 detection"),
    (b"r2 ", "r2 detection"),
    (b"Frida", "Frida detection"),
    (b"frida", "Frida detection"),
    (b"frida-server", "frida-server detection"),
    (b"substrate", "substrate detection"),
    (b"Xposed", "Xposed detection"),
    (b"ShadowHook", "ShadowHook detection"),
]

# ─── Crypto signatures ─────────────────────────────────────────────
CRYPTO_PATTERNS = [
    # Algorithms
    (b"AES", "AES encryption"),
    (b"DES", "DES encryption"),
    (b"RSA", "RSA encryption"),
    (b"ECC", "ECC encryption"),
    (b"Blowfish", "Blowfish encryption"),
    (b"Twofish", "Twofish encryption"),
    (b"ChaCha", "ChaCha encryption"),
    (b"Salsa20", "Salsa20 encryption"),
    (b"RC4", "RC4 encryption"),
    (b"RC5", "RC5 encryption"),
    (b"RC6", "RC6 encryption"),
    (b"SEED", "SEED encryption"),
    (b"Camellia", "Camellia encryption"),
    (b"ARIA", "ARIA encryption"),
    # Hashing
    (b"MD5", "MD5 hash"),
    (b"SHA1", "SHA1 hash"),
    (b"SHA256", "SHA256 hash"),
    (b"SHA512", "SHA512 hash"),
    (b"SHA3", "SHA3 hash"),
    (b"RIPEMD", "RIPEMD hash"),
    (b"HMAC", "HMAC"),
    (b"PBKDF", "PBKDF key derivation"),
    (b"scrypt", "scrypt key derivation"),
    (b"Argon2", "Argon2 key derivation"),
    (b"bcrypt", "bcrypt hashing"),
    # Known constants (S-boxes, IVs)
    (b"\x67\x45\x23\x01", "MD5 initial value"),
    (b"\x5a\x82\x79\x99", "MD5 round constant"),
    (b"\x67\x45\x23\x01\xef\xcd\xab\x89", "MD5 IV"),
    (b"\x01\x23\x45\x67\x89\xab\xcd\xef", "DES parity"),
    # License patterns
    (b"license", "license reference"),
    (b"License", "License reference"),
    (b"LICENSE", "LICENSE reference"),
    (b"serial", "serial reference"),
    (b"Serial", "Serial reference"),
    (b"activation", "activation reference"),
    (b"keygen", "keygen reference"),
    (b"crack", "crack reference"),
    (b"patch", "patch reference"),
]

# ─── Vulnerability patterns ────────────────────────────────────────
VULN_PATTERNS = [
    (b"gets(", "gets() — buffer overflow", "critical"),
    (b"sprintf(", "sprintf() — format string", "high"),
    (b"strcpy(", "strcpy() — buffer overflow", "high"),
    (b"strcat(", "strcat() — buffer overflow", "high"),
    (b"scanf(", "scanf() — format string", "high"),
    (b"system(", "system() — command injection", "high"),
    (b"popen(", "popen() — command injection", "high"),
    (b"exec(", "exec() — command injection", "high"),
    (b"execve(", "execve() — command injection", "high"),
    (b"eval(", "eval() — code injection", "high"),
    (b"execsql", "SQL injection", "high"),
    (b"format", "format string", "medium"),
    (b"%s", "format string", "low"),
    (b"%n", "format string write", "medium"),
    (b"ROP", "ROP chain indicator", "info"),
    (b"shellcode", "shellcode indicator", "info"),
    (b"\x90\x90\x90\x90", "NOP sled", "info"),
    (b"/bin/sh", "shell spawn", "high"),
    (b"/bin/bash", "shell spawn", "high"),
]


class SecurityAnalyzer:
    """Comprehensive security analysis for binaries."""

    def __init__(self, target: str):
        self.target = Path(target)
        self._data: Optional[bytes] = None

    def _read(self) -> bytes:
        if self._data is None:
            with open(self.target, "rb") as f:
                self._data = f.read()
        return self._data

    def full_analysis(self) -> Dict[str, Any]:
        """Run all security checks."""
        return {
            "file": str(self.target),
            "size": self.target.stat().st_size,
            "hashes": self.compute_hashes(),
            "anti_debug": self.detect_anti_debug(),
            "crypto": self.detect_crypto(),
            "vulnerabilities": self.detect_vulnerabilities(),
            "yara": self.yara_scan(),
            "entropy": self.entropy_per_block(),
            "protections": self.detect_protections(),
        }

    def compute_hashes(self) -> Dict[str, str]:
        """Compute file hashes."""
        data = self._read()
        return {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "sha512": hashlib.sha512(data).hexdigest(),
            "ssdeep": self._ssdeep(),
        }

    def _ssdeep(self) -> str:
        """Fuzzy hash (ssdeep) if available."""
        try:
            import subprocess
            result = subprocess.run(
                ["ssdeep", str(self.target)],
                capture_output=True, text=True, timeout=30,
            )
            lines = result.stdout.strip().split("\n")
            if len(lines) > 1:
                return lines[1].split(",")[0]
        except Exception:
            pass
        return "unavailable"

    def detect_anti_debug(self) -> List[Dict[str, str]]:
        """Detect anti-debugging techniques."""
        data = self._read()
        findings = []

        for pattern, desc in ANTI_DEBUG_PATTERNS:
            if pattern in data:
                pos = data.find(pattern)
                findings.append({
                    "pattern": pattern.decode("ascii", errors="replace"),
                    "description": desc,
                    "offset": f"0x{pos:08x}",
                    "severity": "high" if "ptrace" in desc.lower() or "debugger" in desc.lower() else "medium",
                })

        # Deduplicate
        seen = set()
        unique = []
        for f in findings:
            key = (f["pattern"], f["description"])
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique

    def detect_crypto(self) -> List[Dict[str, str]]:
        """Detect cryptographic operations."""
        data = self._read()
        findings = []

        for pattern, desc in CRYPTO_PATTERNS:
            if pattern in data:
                pos = data.find(pattern)
                findings.append({
                    "pattern": pattern.decode("ascii", errors="replace"),
                    "description": desc,
                    "offset": f"0x{pos:08x}",
                })

        # Deduplicate
        seen = set()
        unique = []
        for f in findings:
            key = f["description"]
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique

    def detect_vulnerabilities(self) -> List[Dict[str, str]]:
        """Detect vulnerability patterns."""
        data = self._read()
        findings = []

        for pattern, desc, severity in VULN_PATTERNS:
            offset = 0
            count = 0
            while count < 5:  # Limit per pattern
                pos = data.find(pattern, offset)
                if pos == -1:
                    break
                findings.append({
                    "pattern": pattern.decode("ascii", errors="replace"),
                    "description": desc,
                    "offset": f"0x{pos:08x}",
                    "severity": severity,
                })
                offset = pos + 1
                count += 1

        return findings

    def yara_scan(self, rules_path: Optional[str] = None) -> List[Dict[str, str]]:
        """YARA rule matching."""
        try:
            import yara
            if rules_path:
                rules = yara.compile(filepath=rules_path)
            else:
                # Built-in rules
                rules_str = self._builtin_yara_rules()
                rules = yara.compile(source=rules_str)

            matches = rules.match(str(self.target))
            return [
                {
                    "rule": m.rule,
                    "tags": ",".join(m.tags),
                    "description": m.meta.get("description", ""),
                    "strings": [f"{s[1]}: {s[2][:50]}" for s in m.strings[:5]],
                }
                for m in matches
            ]
        except ImportError:
            logger.debug("yara-python not installed")
            return [{"rule": "yara-unavailable", "description": "Install yara-python for YARA scanning"}]
        except Exception as e:
            return [{"rule": "yara-error", "description": str(e)}]

    def _builtin_yara_rules(self) -> str:
        """Built-in YARA rules for common patterns."""
        return """
rule SuspiciousStrings {
    meta:
        description = "Suspicious strings found"
    strings:
        $a1 = "password" nocase
        $a2 = "secret" nocase
        $a3 = "admin" nocase
        $a4 = "root" nocase
        $a5 = "shell" nocase
        $a6 = "/bin/sh"
        $a7 = "chmod"
        $a8 = "curl" nocase
        $a9 = "wget" nocase
    condition:
        3 of them
}

rule CryptoKeys {
    meta:
        description = "Potential cryptographic keys"
    strings:
        $k1 = "BEGIN PUBLIC KEY"
        $k2 = "BEGIN PRIVATE KEY"
        $k3 = "BEGIN RSA PRIVATE KEY"
        $k4 = "BEGIN EC PRIVATE KEY"
        $k5 = "BEGIN CERTIFICATE"
        $k6 = "MII" // Base64 DER
    condition:
        any of them
}

rule Obfuscation {
    meta:
        description = "Possible obfuscation indicators"
    strings:
        $o1 = "Base64" nocase
        $o2 = "decode" nocase
        $o3 = "encode" nocase
        $o4 = "eval("
        $o5 = "exec("
        $o6 = "fromCharCode"
    condition:
        3 of them
}
"""

    def entropy_per_block(self, block_size: int = 4096) -> List[Dict[str, Any]]:
        """Calculate entropy per block."""
        import math
        data = self._read()
        blocks = []

        for i in range(0, min(len(data), 1024 * 1024), block_size):
            chunk = data[i : i + block_size]
            if not chunk:
                break

            # Calculate byte frequency
            freq = [0] * 256
            for b in chunk:
                freq[b] += 1

            # Shannon entropy
            entropy = 0.0
            size = len(chunk)
            for f in freq:
                if f > 0:
                    p = f / size
                    entropy -= p * math.log2(p)

            blocks.append({
                "offset": f"0x{i:08x}",
                "size": len(chunk),
                "entropy": round(entropy, 4),
                "packed": entropy > 7.5,
            })

        return blocks

    def detect_protections(self) -> Dict[str, Any]:
        """Detect binary protections."""
        data = self._read()
        protections = {
            "strip": False,
            "relro": False,
            "stack_canary": False,
            "nx": False,
            "pie": False,
            "aslr": False,
            "fortify": False,
            "control_flow_guard": False,
            "appguard": False,
            "packing": False,
        }

        # Check for stripping
        if not b".debug_info" in data and not b".symtab" in data:
            protections["strip"] = True

        # NX (non-executable stack)
        if b"GNU_STACK" in data:
            protections["nx"] = True

        # Stack canary
        if b"__stack_chk_fail" in data:
            protections["stack_canary"] = True

        # FORTIFY
        if b"__fortify" in data or b"_FORTIFY_SOURCE" in data:
            protections["fortify"] = True

        # RELRO
        if b"GNU_RELRO" in data:
            protections["relro"] = True

        # PIE
        if b"PIE" in data or b"pic" in data.lower():
            protections["pie"] = True

        # Control Flow Guard (Windows)
        if b"__guard_dispatch_icall_fptr" in data:
            protections["control_flow_guard"] = True

        # AppGuard (Android)
        if b"appguard" in data.lower():
            protections["appguard"] = True

        # Packing detection (high entropy)
        try:
            import math
            with open(self.target, "rb") as f:
                sample = f.read(min(65536, self.target.stat().st_size))
            freq = [0] * 256
            for b in sample:
                freq[b] += 1
            entropy = 0.0
            for f in freq:
                if f > 0:
                    p = f / len(sample)
                    entropy -= p * math.log2(p)
            if entropy > 7.5:
                protections["packing"] = True
        except Exception:
            pass

        return protections
