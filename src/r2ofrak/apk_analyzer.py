"""
APK/DEX Analyzer — Decompile, extract, analyze Android packages.
"""

import json
import logging
import os
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("r2ofrak.apk")


class APKAnalyzer:
    """Analyze Android APK/DEX/XAPK files."""

    def __init__(self, target: str, output_dir: Optional[str] = None):
        self.target = Path(target)
        self.output_dir = Path(output_dir) if output_dir else Path(tempfile.mkdtemp(prefix="r2ofrak_apk_"))
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def analyze(self) -> Dict[str, Any]:
        """Full APK analysis."""
        result = {
            "file": str(self.target),
            "size": self.target.stat().st_size,
            "type": self._detect_type(),
        }

        if result["type"] == "apk":
            result.update(self._analyze_apk())
        elif result["type"] == "dex":
            result.update(self._analyze_dex())
        elif result["type"] == "xapk":
            result.update(self._analyze_xapk())
        else:
            result["error"] = f"Unknown type: {result['type']}"

        return result

    def _detect_type(self) -> str:
        """Detect file type."""
        name = self.target.name.lower()
        if name.endswith(".apk") or name.endswith(".apks"):
            return "apk"
        elif name.endswith(".dex") or name.endswith(".odex"):
            return "dex"
        elif name.endswith(".xapk"):
            return "xapk"
        elif name.endswith(".aab"):
            return "aab"

        # Check magic bytes
        try:
            with open(self.target, "rb") as f:
                magic = f.read(4)
            if magic == b"PK\x03\x04":
                return "apk"
            elif magic == b"dex\n":
                return "dex"
        except Exception:
            pass

        return "unknown"

    def _analyze_apk(self) -> Dict[str, Any]:
        """Analyze APK structure."""
        result = {}

        # Parse AndroidManifest.xml
        try:
            manifest = self._extract_manifest()
            result["manifest"] = manifest
        except Exception as e:
            result["manifest_error"] = str(e)

        # List DEX files
        result["dex_files"] = self._list_dex_files()

        # List native libraries
        result["native_libs"] = self._list_native_libs()

        # List resources
        result["resources"] = self._list_resources()

        # Extract strings
        result["suspicious_strings"] = self._find_suspicious_strings()

        # Check permissions
        result["permissions"] = result.get("manifest", {}).get("permissions", [])

        # Check for security issues
        result["security"] = self._check_security()

        return result

    def _analyze_dex(self) -> Dict[str, Any]:
        """Analyze DEX file."""
        result = {}
        try:
            with open(self.target, "rb") as f:
                header = f.read(112)

            # DEX magic
            if header[:4] != b"dex\n":
                result["error"] = "Not a valid DEX file"
                return result

            # Version
            result["version"] = header[4:8].decode("ascii", errors="replace")

            # File size
            import struct
            result["file_size"] = struct.unpack("<I", header[32:36])[0]
            result["header_size"] = struct.unpack("<I", header[36:40])[0]
            result["endian_tag"] = struct.unpack("<I", header[40:44])[0]

            # String count
            result["string_count"] = struct.unpack("<I", header[56:60])[0]
            result["type_count"] = struct.unpack("<I", header[60:64])[0]
            result["proto_count"] = struct.unpack("<I", header[64:68])[0]
            result["field_count"] = struct.unpack("<I", header[68:72])[0]
            result["method_count"] = struct.unpack("<I", header[72:76])[0]
            result["class_count"] = struct.unpack("<I", header[96:100])[0]

            result["analysis"] = "DEX header parsed successfully"
        except Exception as e:
            result["error"] = str(e)

        return result

    def _analyze_xapk(self) -> Dict[str, Any]:
        """Analyze XAPK (split APK bundle)."""
        result = {"format": "xapk"}
        # XAPK is just a ZIP with manifest.json + multiple APKs
        try:
            import zipfile
            with zipfile.ZipFile(self.target, "r") as z:
                result["contents"] = z.namelist()
                if "manifest.json" in z.namelist():
                    manifest = json.loads(z.read("manifest.json"))
                    result["manifest"] = manifest
        except Exception as e:
            result["error"] = str(e)
        return result

    def _extract_manifest(self) -> Dict[str, Any]:
        """Try to extract and parse AndroidManifest.xml."""
        result = {}
        try:
            import zipfile
            with zipfile.ZipFile(self.target, "r") as z:
                if "AndroidManifest.xml" in z.namelist():
                    # Binary XML — can't parse directly without apktool
                    result["raw_size"] = len(z.read("AndroidManifest.xml"))
                    result["note"] = "Binary XML — use apktool for full parsing"
        except Exception:
            pass
        return result

    def _list_dex_files(self) -> List[Dict[str, str]]:
        """List DEX files in APK."""
        dex_files = []
        try:
            import zipfile
            with zipfile.ZipFile(self.target, "r") as z:
                for name in z.namelist():
                    if name.endswith(".dex"):
                        info = z.getinfo(name)
                        dex_files.append({
                            "name": name,
                            "size": info.file_size,
                            "compressed": info.compress_size,
                        })
        except Exception:
            pass
        return dex_files

    def _list_native_libs(self) -> List[Dict[str, str]]:
        """List native .so libraries."""
        libs = []
        try:
            import zipfile
            with zipfile.ZipFile(self.target, "r") as z:
                for name in z.namelist():
                    if name.startswith("lib/") and name.endswith(".so"):
                        info = z.getinfo(name)
                        libs.append({
                            "name": name,
                            "size": info.file_size,
                            "abi": name.split("/")[1] if "/" in name else "unknown",
                        })
        except Exception:
            pass
        return libs

    def _list_resources(self) -> Dict[str, Any]:
        """List resource types."""
        resources = {"layouts": [], "drawables": [], "strings": [], "other": []}
        try:
            import zipfile
            with zipfile.ZipFile(self.target, "r") as z:
                for name in z.namelist():
                    if name.startswith("res/layout"):
                        resources["layouts"].append(name)
                    elif name.startswith("res/drawable"):
                        resources["drawables"].append(name)
                    elif name.startswith("res/values"):
                        resources["strings"].append(name)
                    elif name.startswith("res/"):
                        resources["other"].append(name)
        except Exception:
            pass
        return resources

    def _find_suspicious_strings(self) -> List[str]:
        """Find suspicious strings in APK."""
        suspicious = []
        patterns = [
            "http://", "https://", "ftp://",
            "exec(", "Runtime.exec", "ProcessBuilder",
            "chmod", "chown", "mount",
            "su ", "/system/bin/su", "Superuser",
            "keylogger", "clipboard", "screenshot",
            "crypto", "encrypt", "decrypt", "cipher",
            "base64", "decode", "encode",
            "reflection", "Class.forName", "Method.invoke",
            "dynamic", "load", "dlopen",
            "socket", "connect", "bind",
            "content://sms", "READ_SMS", "SEND_SMS",
            "ACCESS_FINE_LOCATION", "CAMERA",
        ]

        try:
            with open(self.target, "rb") as f:
                data = f.read()

            for pattern in patterns:
                if isinstance(pattern, str):
                    pattern = pattern.encode()
                if pattern in data:
                    suspicious.append(pattern.decode("ascii", errors="replace"))
        except Exception:
            pass

        return suspicious

    def _check_security(self) -> Dict[str, Any]:
        """Basic security checks."""
        security = {
            "debuggable": False,
            "allow_backup": False,
            "network_security": False,
            "certificate_pinning": False,
        }

        try:
            with open(self.target, "rb") as f:
                data = f.read()

            if b"android:debuggable=\"true\"" in data:
                security["debuggable"] = True
            if b"android:allowBackup=\"true\"" in data:
                security["allowBackup"] = True
            if b"network_security_config" in data:
                security["network_security"] = True
            if b"CertificatePinner" in data or b"certificate_pinning" in data:
                security["certificate_pinning"] = True
        except Exception:
            pass

        return security

    def extract_strings(self, min_length: int = 4) -> List[str]:
        """Extract all strings from APK."""
        strings = []
        try:
            with open(self.target, "rb") as f:
                data = f.read()

            current = []
            for byte in data:
                if 32 <= byte < 127:
                    current.append(chr(byte))
                else:
                    if len(current) >= min_length:
                        strings.append("".join(current))
                    current = []
        except Exception:
            pass

        return strings
