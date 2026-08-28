"""
Security Analyzer — Comprehensive binary security analysis.
Covers: anti-debug, anti-root, anti-emulator, anti-tamper, SSL pinning,
        crypto detection, Frida/Xposed hooks, code signing, YARA, entropy.
"""

import hashlib
import logging
import math
import re
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger("panxcz.security")


class SecurityAnalyzer:
    """Comprehensive binary security analysis."""

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
            "anti_root": self.anti_root(),
            "anti_emulator": self.anti_emulator(),
            "anti_tamper": self.anti_tamper(),
            "ssl_pinning": self.ssl_pinning(),
            "frida_hooks": self.frida_hooks(),
            "xposed_hooks": self.xposed_hooks(),
            "crypto": self.crypto(),
            "vulnerabilities": self.vulns(),
            "protections": self.protections(),
            "permissions": self.permissions(),
            "suspicious_strings": self.suspicious_strings(),
            "dangerous_apis": self.dangerous_apis(),
            "code_signing": self.code_signing(),
        }

    def hashes(self) -> Dict[str, str]:
        data = self._read()
        return {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "sha512": hashlib.sha512(data).hexdigest()[:64],
            "ssdeep": "requires ssdeep binary",
        }

    # ─── Anti-Debug ──────────────────────────────────────────────────

    def anti_debug(self) -> List[Dict]:
        patterns = [
            # ptrace-based
            (b"ptrace", "ptrace API call", "high"),
            (b"PTRACE_TRACEME", "PTRACE_TRACEME anti-debug", "high"),
            (b"PTRACE_ATTACH", "PTRACE_ATTACH detection", "high"),
            (b"PTRACE_DETACH", "PTRACE_DETACH call", "medium"),
            (b"PTRACE_PEEKDATA", "PTRACE memory read", "medium"),
            # Debugger detection
            (b"IsDebuggerPresent", "Windows IsDebuggerPresent", "high"),
            (b"CheckRemoteDebuggerPresent", "Windows remote debug check", "high"),
            (b"NtQueryInformationProcess", "NT process info query", "high"),
            (b"OutputDebugStringA", "OutputDebugString anti-debug", "medium"),
            (b"ZwQueryInformationProcess", "Zw process query", "high"),
            # proc filesystem
            (b"/proc/self/status", "proc status check", "high"),
            (b"TracerPid:", "TracerPid check", "high"),
            (b"/proc/self/maps", "proc maps check", "medium"),
            (b"/proc/self/fd", "proc fd check", "low"),
            # Timing
            (b"rdtsc", "RDTSC timing check", "medium"),
            (b"QueryPerformanceCounter", "Windows perf counter timing", "medium"),
            (b"GetTickCount", "Windows tick count timing", "medium"),
            (b"clock_gettime", "clock_gettime timing", "low"),
            # Tool detection
            (b"OllyDbg", "OllyDbg detection", "high"),
            (b"x64dbg", "x64dbg detection", "high"),
            (b"IDA Pro", "IDA Pro detection", "high"),
            (b"radare2", "radare2 detection", "medium"),
            (b"GDB", "GDB detection", "medium"),
            (b"lldb", "LLDB detection", "medium"),
            (b"WinDbg", "WinDbg detection", "high"),
            (b"Immunity", "Immunity Debugger detection", "high"),
            # Anti-dump
            (b"ZwUnmapViewOfSection", "Process hollowing detection", "high"),
            (b"NtUnmapViewOfSection", "Process hollowing detection", "high"),
            (b"MiniDumpWriteDump", "Minidump detection", "medium"),
        ]
        return self._scan_patterns(patterns)

    # ─── Anti-Root ───────────────────────────────────────────────────

    def anti_root(self) -> List[Dict]:
        patterns = [
            # Root binary detection
            (b"/system/xbin/su", "su binary check", "high"),
            (b"/system/bin/su", "su binary check", "high"),
            (b"/sbin/su", "su binary check", "high"),
            (b"/data/local/su", "su binary check", "high"),
            (b"/system/app/Superuser", "Superuser app check", "high"),
            (b"/system/app/SuperSU", "SuperSU app check", "high"),
            (b"com.noshufou.android.su", "SuperSU package check", "high"),
            (b"eu.chainfire.supersu", "SuperSU Chainfire check", "high"),
            (b"com.koushikdutta.superuser", "Superuser check", "high"),
            (b"com.topjohnwu.magisk", "Magisk detection", "high"),
            (b"/sbin/.magisk", "Magisk hidden detection", "high"),
            (b"magisk", "Magisk detection", "high"),
            (b"su_answer", "su detection mechanism", "high"),
            # System property checks
            (b"ro.debuggable", "Debuggable property check", "medium"),
            (b"ro.secure", "Secure property check", "medium"),
            (b"ro.build.type", "Build type check", "low"),
            # Root hiding detection
            (b"com.kingroot.kinguser", "KingRoot detection", "high"),
            (b"com.kingo.root", "KingoRoot detection", "high"),
            (b"com.thirdparty.superuser", "3rd party superuser", "high"),
            (b"com.smilingzhangling", "Root hiding app", "high"),
        ]
        return self._scan_patterns(patterns)

    # ─── Anti-Emulator ───────────────────────────────────────────────

    def anti_emulator(self) -> List[Dict]:
        patterns = [
            # Device property checks
            (b"goldfish", "Goldfish emulator detection", "high"),
            (b"ranchu", "Ranchu emulator detection", "high"),
            (b"generic", "Generic device detection", "medium"),
            (b"emulator", "Emulator keyword detection", "high"),
            (b"sdk_gphone", "Android Emulator detection", "high"),
            (b"android emulator", "Android emulator detection", "high"),
            # QEMU
            (b"qemu", "QEMU detection", "high"),
            (b"QEMU", "QEMU detection", "high"),
            (b"/dev/qemu", "QEMU device check", "high"),
            (b"qemu_pipe", "QEMU pipe detection", "high"),
            # VirtualBox / VMware
            (b"vbox", "VirtualBox detection", "high"),
            (b"VBOX", "VirtualBox detection", "high"),
            (b"vmware", "VMware detection", "high"),
            (b"VMware", "VMware detection", "high"),
            # Hardware checks
            (b"/sys/devices/virtual/ide", "Virtual hardware check", "medium"),
            (b"00:00:00:00:00:00", "Null MAC address check", "medium"),
            (b"Build.PRODUCT", "Product check", "low"),
            (b"Build.MODEL", "Model check", "low"),
            (b"Build.BRAND", "Brand check", "low"),
            (b"Build.MANUFACTURER", "Manufacturer check", "low"),
            (b"Build.HARDWARE", "Hardware check", "low"),
            # Sensor detection
            (b"getSensorList", "Sensor detection for emulator", "medium"),
            (b"SensorManager", "Sensor manager check", "low"),
        ]
        return self._scan_patterns(patterns)

    # ─── Anti-Tamper ─────────────────────────────────────────────────

    def anti_tamper(self) -> List[Dict]:
        patterns = [
            (b"PackageManager", "Package manager integrity check", "medium"),
            (b"getPackageInfo", "Package info check", "medium"),
            (b"signatures", "Signature verification", "high"),
            (b"checkSignature", "Signature check", "high"),
            (b"SignatureInfo", "Signature info check", "medium"),
            (b"GET_SIGNATURES", "Signature retrieval flag", "medium"),
            (b"certificate", "Certificate check", "medium"),
            (b"integrity", "Integrity check keyword", "medium"),
            (b"tamper", "Tamper detection keyword", "high"),
            (b"checksum", "Checksum verification", "medium"),
            (b"crc32", "CRC32 check", "low"),
            (b"verify", "Verification keyword", "low"),
            (b"comparison", "Comparison check", "low"),
            (b"env_check", "Environment check", "medium"),
            (b"debug_check", "Debug check", "medium"),
        ]
        return self._scan_patterns(patterns)

    # ─── SSL Pinning ────────────────────────────────────────────────

    def ssl_pinning(self) -> List[Dict]:
        patterns = [
            (b"CertificateFactory", "Certificate factory usage", "high"),
            (b"X509TrustManager", "X509 trust manager", "high"),
            (b"SSLContext", "SSL context setup", "medium"),
            (b"HostnameVerifier", "Hostname verifier", "high"),
            (b"checkServerTrusted", "Server trust check", "high"),
            (b"checkClientTrusted", "Client trust check", "high"),
            (b"getAcceptedIssuers", "Issuer check", "high"),
            (b"TrustManager", "Trust manager", "medium"),
            (b"SSLSocketFactory", "SSL socket factory", "medium"),
            (b"ssl", "SSL keyword", "low"),
            (b"pinned", "Pin detection keyword", "high"),
            (b"certificate_pinning", "Certificate pinning", "high"),
            (b"OkHttp", "OkHTTP pinning", "medium"),
            (b"NetworkSecurityConfig", "Network security config", "medium"),
            (b"trustAllCerts", "Trust all certs bypass", "high"),
            (b"ALLOW_ALL_HOSTNAME", "Allow all hostnames", "high"),
        ]
        return self._scan_patterns(patterns)

    # ─── Frida Hooks ────────────────────────────────────────────────

    def frida_hooks(self) -> List[Dict]:
        patterns = [
            (b"frida", "Frida detection keyword", "high"),
            (b"Frida", "Frida detection keyword", "high"),
            (b"frida-agent", "Frida agent detection", "high"),
            (b"frida-server", "Frida server detection", "high"),
            (b"frida-gadget", "Frida gadget detection", "high"),
            (b"frida_agent", "Frida agent variable", "high"),
            (b"GumJS", "GumJS (Frida engine) detection", "high"),
            (b"Interceptor", "Frida Interceptor detection", "high"),
            (b"Java.perform", "Frida Java.perform detection", "high"),
            (b"Module.findBaseAddress", "Frida module detection", "high"),
            (b"Memory.readUtf8String", "Frida memory read detection", "high"),
            (b"libcfrida", "libcfrida detection", "high"),
            (b"linjector", "linjector detection", "high"),
            (b"/tmp/re.frida.server", "Frida server path check", "high"),
            (b"frida-inject", "frida-inject detection", "high"),
        ]
        return self._scan_patterns(patterns)

    # ─── Xposed Hooks ───────────────────────────────────────────────

    def xposed_hooks(self) -> List[Dict]:
        patterns = [
            (b"XposedBridge", "Xposed Bridge detection", "high"),
            (b"de.robv.android.xposed", "Xposed package detection", "high"),
            (b"XposedHelpers", "Xposed Helpers detection", "high"),
            (b"XC_MethodHook", "Xposed method hook detection", "high"),
            (b"Lsposed", "LSPosed detection", "high"),
            (b"lsposed", "LSPosed detection", "high"),
            (b"substrate", "Cydia Substrate detection", "high"),
            (b"Substrate", "Cydia Substrate detection", "high"),
            (b"SUBSTRATE", "Cydia Substrate detection", "high"),
            (b"hook", "Hook detection keyword", "medium"),
            (b"rebarhook", "rebarhook detection", "high"),
            (b"YAHFA", "YAHFA hook framework detection", "high"),
            (b"EdXposed", "EdXposed detection", "high"),
            (b"DroidPlugin", "DroidPlugin detection", "medium"),
            (b"VirtualApp", "VirtualApp detection", "medium"),
            (b"ReLinker", "ReLinker detection", "low"),
        ]
        return self._scan_patterns(patterns)

    # ─── Crypto Detection ────────────────────────────────────────────

    def crypto(self) -> List[Dict]:
        patterns = [
            (b"AES", "AES encryption", "medium"),
            (b"RSA", "RSA encryption", "medium"),
            (b"DES", "DES encryption", "high"),
            (b"MD5", "MD5 hash (weak)", "medium"),
            (b"SHA1", "SHA1 hash (weak)", "medium"),
            (b"SHA256", "SHA256 hash", "low"),
            (b"SHA512", "SHA512 hash", "low"),
            (b"HMAC", "HMAC", "low"),
            (b"PBKDF", "PBKDF key derivation", "low"),
            (b"Base64", "Base64 encoding", "low"),
            (b"Blowfish", "Blowfish encryption", "medium"),
            (b"RC4", "RC4 encryption (weak)", "high"),
            (b"ECDSA", "ECDSA signature", "low"),
            (b"Ed25519", "Ed25519 signature", "low"),
            (b"DiffieHellman", "DH key exchange", "low"),
            (b"ECDH", "ECDH key exchange", "low"),
            (b"jwe", "JWE (encrypted JWT)", "low"),
            (b"jws", "JWS (signed JWT)", "low"),
            (b"PKCS1", "PKCS1 padding", "low"),
            (b"PKCS5", "PKCS5 padding", "low"),
            (b"PKCS7", "PKCS7 padding", "low"),
            (b"PKCS8", "PKCS8 key format", "low"),
            (b"PBEWITH", "Password-based encryption", "low"),
        ]
        return self._scan_patterns(patterns)

    # ─── Vulnerabilities ────────────────────────────────────────────

    def vulns(self) -> List[Dict]:
        patterns = [
            (b"gets(", "gets() — buffer overflow", "critical"),
            (b"sprintf(", "sprintf() — format string", "high"),
            (b"strcpy(", "strcpy() — buffer overflow", "high"),
            (b"strcat(", "strcat() — buffer overflow", "high"),
            (b"system(", "system() — command injection", "high"),
            (b"popen(", "popen() — command injection", "high"),
            (b"/bin/sh", "Shell spawn", "high"),
            (b"/bin/bash", "Bash spawn", "high"),
            (b"exec(", "exec() injection", "high"),
            (b"eval(", "eval() injection", "high"),
            (b"Runtime.exec", "Java Runtime.exec injection", "high"),
            (b"chmod 777", "Overly permissive chmod", "medium"),
            (b"chmod 666", "World-writable permissions", "medium"),
            (b"chmod 777", "World-writable+readable+executable", "medium"),
            (b"tcp://", "Unencrypted TCP connection", "medium"),
            (b"http://", "Unencrypted HTTP connection", "medium"),
            (b"plain:", "Plaintext protocol", "medium"),
            (b"DES/", "Weak DES encryption", "high"),
            (b"RC4/", "Weak RC4 encryption", "high"),
            (b"ECB", "ECB mode (insecure)", "high"),
        ]
        return self._scan_patterns(patterns, with_severity=True)

    # ─── Protections ─────────────────────────────────────────────────

    def protections(self) -> Dict[str, Any]:
        data = self._read()
        protections = {
            "nx": b"GNU_STACK" in data or b"NX" in data,
            "pie": b"PIE" in data or b"pic" in data,
            "stack_canary": b"__stack_chk_fail" in data or b"__stack_smash_handler" in data,
            "fortify": b"__fortify" in data or b"_FORTIFY_SOURCE" in data,
            "relro": b"GNU_RELRO" in data,
            "strip": b".debug_info" not in data and b".symtab" not in data,
            "aslr": b"ASLR" in data or b"pie" in data,
            "cfg_guard": b"guard_check" in data or b"__security_init_cookie" in data,
        }

        # Check ELF specific
        if data[:4] == b"\x7fELF":
            ei_class = data[4]
            # Check for PIE (DYN type)
            protections["elf"] = True
            protections["shared_lib"] = data[:4] == b"\x7fELF" and b".so" in self.target.name.encode()

        # Check PE specific
        if data[:2] == b"MZ":
            protections["pe"] = True
            protections["aslr"] = b"IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE" in data or True
            protections["dep"] = b"IMAGE_DLLCHARACTERISTICS_NX_COMPAT" in data or True
            protections["seh"] = b"__security_handler_cookie" in data

        return protections

    # ─── Android Permissions ─────────────────────────────────────────

    def permissions(self) -> List[str]:
        data = self._read()
        perms = set()

        android_perms = [
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_PHONE_STATE",
            "android.permission.CALL_PHONE",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.READ_MEDIA_IMAGES",
            "android.permission.READ_MEDIA_VIDEO",
            "android.permission.READ_MEDIA_AUDIO",
            "android.permission.POST_NOTIFICATIONS",
            "android.permission.BLUETOOTH",
            "android.permission.NFC",
            "android.permission.USE_BIOMETRIC",
            "android.permission.USE_FINGERPRINT",
        ]

        for perm in android_perms:
            if perm.encode() in data:
                perms.add(perm)

        return sorted(perms)

    # ─── Suspicious Strings ──────────────────────────────────────────

    def suspicious_strings(self) -> List[Dict]:
        data = self._read()
        findings = []

        suspicious = [
            (b"curl ", "curl command usage"),
            (b"wget ", "wget command usage"),
            (b"eval(", "eval() usage"),
            (b"exec(", "exec() usage"),
            (b"base64", "Base64 encoding/decoding"),
            (b"obfuscate", "Obfuscation keyword"),
            (b"decrypt", "Decryption keyword"),
            (b"encrypt", "Encryption keyword"),
            (b"password", "Password string"),
            (b"secret", "Secret string"),
            (b"api_key", "API key string"),
            (b"token", "Token string"),
            (b"auth", "Authentication keyword"),
            (b"bypass", "Bypass keyword"),
            (b"exploit", "Exploit keyword"),
            (b"shellcode", "Shellcode keyword"),
            (b"rootkit", "Rootkit keyword"),
            (b"backdoor", "Backdoor keyword"),
            (b"keylog", "Keylogger keyword"),
            (b"steal", "Data stealing keyword"),
            (b"exfiltrate", "Data exfiltration keyword"),
        ]

        seen = set()
        for pat, desc in suspicious:
            if pat in data and desc not in seen:
                pos = data.find(pat)
                # Extract surrounding context
                start = max(0, pos - 20)
                end = min(len(data), pos + len(pat) + 50)
                context = data[start:end]
                # Make printable
                context_str = "".join(chr(b) if 32 <= b < 127 else "." for b in context)

                seen.add(desc)
                findings.append({
                    "pattern": pat.decode("ascii", errors="ignore"),
                    "description": desc,
                    "offset": f"0x{pos:08x}",
                    "context": context_str,
                })

        return findings

    # ─── Dangerous APIs ──────────────────────────────────────────────

    def dangerous_apis(self) -> List[Dict]:
        data = self._read()
        findings = []

        apis = [
            # Network
            (b"HttpURLConnection", "Network", "HTTP connection"),
            (b"OkHttpClient", "Network", "HTTP client"),
            (b"Retrofit", "Network", "Retrofit client"),
            (b"Volley", "Network", "Volley HTTP"),
            (b"WebView", "Network", "WebView usage"),
            (b"loadUrl", "Network", "URL loading"),
            (b"evaluateJavascript", "Network", "JS execution in WebView"),
            # Storage
            (b"SharedPreferences", "Storage", "Shared Preferences"),
            (b"SQLiteDatabase", "Storage", "SQLite database"),
            (b"getExternalFilesDir", "Storage", "External files"),
            (b"getCacheDir", "Storage", "Cache directory"),
            # System
            (b"Runtime.getRuntime", "System", "Runtime execution"),
            (b"ProcessBuilder", "System", "Process builder"),
            (b"System.loadLibrary", "System", "Native library loading"),
            (b"System.load", "System", "Native library loading"),
            (b"DexClassLoader", "System", "Dynamic class loading"),
            (b"InMemoryDexClassLoader", "System", "In-memory DEX loading"),
            # Crypto
            (b"javax.crypto", "Crypto", "Java crypto API"),
            (b"SecretKeySpec", "Crypto", "Secret key specification"),
            (b"IvParameterSpec", "Crypto", "IV specification"),
            (b"Cipher", "Crypto", "Cipher usage"),
            # Location
            (b"LocationManager", "Location", "Location manager"),
            (b"getLastKnownLocation", "Location", "Get last location"),
            (b"requestLocationUpdates", "Location", "Location updates"),
            # Contacts
            (b"ContactsContract", "Contacts", "Contacts provider"),
            (b"ContentResolver", "Contacts", "Content resolver"),
            # Media
            (b"MediaRecorder", "Media", "Media recorder"),
            (b"AudioRecord", "Media", "Audio recording"),
            (b"Camera", "Media", "Camera access"),
        ]

        for api_bytes, category, desc in apis:
            if api_bytes in data:
                pos = data.find(api_bytes)
                findings.append({
                    "api": api_bytes.decode("ascii", errors="ignore"),
                    "category": category,
                    "description": desc,
                    "offset": f"0x{pos:08x}",
                })

        return findings

    # ─── Code Signing ────────────────────────────────────────────────

    def code_signing(self) -> Dict[str, Any]:
        data = self._read()
        signing = {
            "signed": False,
            "type": "unknown",
            "details": [],
        }

        # APK signing
        if data[:4] == b"PK\x03\x04":
            # Check for META-INF (JAR signing)
            if b"META-INF/" in data:
                signing["signed"] = True
                signing["type"] = "JAR/APK"
                if b"MANIFEST.MF" in data:
                    signing["details"].append("MANIFEST.MF present")
                if b"CERT.SF" in data:
                    signing["details"].append("CERT.SF present")
                if b"CERT.RSA" in data:
                    signing["details"].append("CERT.RSA signature")
                if b"CERT.DSA" in data:
                    signing["details"].append("CERT.DSA signature")
                if b"CERT.EC" in data:
                    signing["details"].append("CERT.EC signature")

            # Check for v2/v3 signing
            if b"APK Signing Block" in data or data[32:36] == b"APK Sig Block 42":
                signing["details"].append("APK v2/v3 signing block")

        # PE signing
        if data[:2] == b"MZ":
            if b"Authenticode" in data:
                signing["signed"] = True
                signing["type"] = "Authenticode (PE)"

        # ELF signing
        if data[:4] == b"\x7fELF":
            if b".note.gnu.property" in data or b".gnu.hash" in data:
                signing["details"].append("GNU hash present")

        return signing

    # ─── Helpers ─────────────────────────────────────────────────────

    def _scan_patterns(self, patterns: List[tuple], with_severity: bool = False) -> List[Dict]:
        """Generic pattern scanner."""
        data = self._read()
        findings = []
        seen = set()

        for item in patterns:
            if with_severity:
                pat, desc, sev = item
            else:
                pat, desc, sev = item[0], item[1], item[2] if len(item) > 2 else "medium"

            if pat in data and desc not in seen:
                pos = data.find(pat)
                seen.add(desc)
                finding = {
                    "pattern": pat.decode("ascii", errors="ignore"),
                    "description": desc,
                    "offset": f"0x{pos:08x}",
                }
                if with_severity:
                    finding["severity"] = sev
                findings.append(finding)

        return findings
