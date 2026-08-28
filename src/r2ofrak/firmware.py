"""
Firmware Analyzer — Unpack and analyze embedded firmware images.
Supports: squashfs, cpio, jffs2, ubi, ext2/3/4, vmlinuz, uImage.
"""

import logging
import os
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("r2ofrak.firmware")


# Magic bytes for common firmware formats
MAGICS = {
    b"hsqs": "squashfs (le)",
    b"sqsh": "squashfs (be)",
    b"\x85\xc8\xd1\x0e": "jffs2",
    b"UBI#": "ubi",
    b"\x28\xcd\x3d\x45": "cpio (newc)",
    b"070701": "cpio (newc)",
    b"uImage": "uImage",
    b"\x1f\x8b": "gzip",
    b"BZh": "bzip2",
    b"7z\xbc\xaf\x27\x1c": "7z",
    b"PK\x03\x04": "zip",
    b"\xfd7zXZ": "xz",
    b"ZConfig": "squashfs (zstd)",
    b"\x2f\x2f\x2f\x2f": "vendor_boot",
    b"ANDROID!"  : "android boot.img",
    b"\x52\x49\x46\x46": "RIFF",
}


class FirmwareAnalyzer:
    """Unpack and analyze firmware images."""

    def __init__(self, target: str, output_dir: Optional[str] = None):
        self.target = Path(target)
        self.output_dir = Path(output_dir) if output_dir else Path(tempfile.mkdtemp(prefix="r2ofrak_fw_"))
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def analyze(self) -> Dict[str, Any]:
        """Full firmware analysis."""
        result = {
            "file": str(self.target),
            "size": self.target.stat().st_size,
            "format": self._detect_format(),
        }

        # Detect partitions
        result["partitions"] = self._find_partitions()

        # Try to identify embedded filesystems
        result["filesystems"] = self._detect_filesystems()

        # Extract strings
        result["strings"] = self._extract_strings(min_length=8)

        # Find URLs, IPs, credentials
        result["urls"] = self._find_urls()
        result["ips"] = self._find_ips()
        result["credentials"] = self._find_credentials()

        return result

    def _detect_format(self) -> str:
        """Detect firmware format."""
        try:
            with open(self.target, "rb") as f:
                magic = f.read(8)
        except Exception:
            return "unknown"

        for mag, fmt in MAGICS.items():
            if magic[: len(mag)] == mag:
                return fmt

        # Check for ELF
        if magic[:4] == b"\x7fELF":
            return "ELF"

        # Check for PE
        if magic[:2] == b"MZ":
            return "PE"

        return "unknown"

    def _find_partitions(self) -> List[Dict[str, Any]]:
        """Find partition boundaries in firmware image."""
        partitions = []
        try:
            with open(self.target, "rb") as f:
                data = f.read()

            # Search for squashfs headers
            for mag, fmt in MAGICS.items():
                offset = 0
                while True:
                    pos = data.find(mag, offset)
                    if pos == -1:
                        break
                    partitions.append({
                        "offset": f"0x{pos:08x}",
                        "format": fmt,
                        "size_estimate": "unknown",
                    })
                    offset = pos + len(mag)
                    if len(partitions) > 20:
                        break

        except Exception:
            pass

        return partitions

    def _detect_filesystems(self) -> List[Dict[str, Any]]:
        """Detect filesystem type at various offsets."""
        fs = []
        try:
            with open(self.target, "rb") as f:
                data = f.read(256 * 1024)  # Read first 256KB

            # SquashFS
            if data[:4] in (b"hsqs", b"sqsh"):
                fs.append({"type": "squashfs", "offset": "0x0"})

            # CPIO
            if b"070701" in data[:512]:
                fs.append({"type": "cpio", "offset": "0x0"})

            # JFFS2
            if b"\x85\xc8\xd1\x0e" in data:
                pos = data.find(b"\x85\xc8\xd1\x0e")
                fs.append({"type": "jffs2", "offset": f"0x{pos:08x}"})

        except Exception:
            pass

        return fs

    def _extract_strings(self, min_length: int = 8) -> List[Dict[str, str]]:
        """Extract printable strings."""
        strings = []
        try:
            with open(self.target, "rb") as f:
                data = f.read()

            current = []
            start = 0
            for i, byte in enumerate(data):
                if 32 <= byte < 127:
                    if not current:
                        start = i
                    current.append(chr(byte))
                else:
                    if len(current) >= min_length:
                        strings.append({
                            "offset": f"0x{start:08x}",
                            "string": "".join(current),
                        })
                    current = []
                    if len(strings) > 1000:
                        break
        except Exception:
            pass

        return strings

    def _find_urls(self) -> List[str]:
        """Find URLs in firmware."""
        urls = []
        try:
            with open(self.target, "rb") as f:
                data = f.read()

            import re
            matches = re.findall(rb"https?://[a-zA-Z0-9._/\-?&=%#:~]+", data)
            urls = list(set(m.decode("ascii", errors="replace") for m in matches[:100]))
        except Exception:
            pass

        return urls

    def _find_ips(self) -> List[str]:
        """Find IP addresses."""
        ips = []
        try:
            with open(self.target, "rb") as f:
                data = f.read()

            import re
            matches = re.findall(rb"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", data)
            ips = list(set(m.decode("ascii") for m in matches[:100]))
        except Exception:
            pass

        return ips

    def _find_credentials(self) -> List[Dict[str, str]]:
        """Find potential credentials."""
        creds = []
        try:
            with open(self.target, "rb") as f:
                data = f.read()

            import re
            # Common patterns
            patterns = [
                (rb"password\s*[=:]\s*(\S+)", "password"),
                (rb"passwd\s*[=:]\s*(\S+)", "passwd"),
                (rb"secret[_\s]*key\s*[=:]\s*(\S+)", "secret_key"),
                (rb"api[_\s]*key\s*[=:]\s*(\S+)", "api_key"),
                (rb"token\s*[=:]\s*(\S+)", "token"),
                (rb"admin[_\s]*pass\s*[=:]\s*(\S+)", "admin_password"),
                (rb"root[_\s]*pass\s*[=:]\s*(\S+)", "root_password"),
            ]

            for pattern, label in patterns:
                matches = re.findall(pattern, data, re.IGNORECASE)
                for m in matches[:5]:
                    creds.append({
                        "type": label,
                        "value": m.decode("ascii", errors="replace")[:100],
                    })
        except Exception:
            pass

        return creds

    def unpack_squashfs(self) -> Optional[Path]:
        """Unpack squashfs filesystem."""
        out = self.output_dir / "squashfs-root"
        try:
            subprocess.run(
                ["unsquashfs", "-d", str(out), str(self.target)],
                capture_output=True,
                timeout=120,
            )
            if out.exists():
                logger.info(f"SquashFS unpacked to {out}")
                return out
        except Exception as e:
            logger.warning(f"SquashFS unpack failed: {e}")
        return None

    def unpack_cpio(self) -> Optional[Path]:
        """Unpack CPIO archive."""
        out = self.output_dir / "cpio-root"
        out.mkdir(exist_ok=True)
        try:
            subprocess.run(
                ["cpio", "-idm", "-D", str(out)],
                stdin=open(self.target, "rb"),
                capture_output=True,
                timeout=120,
            )
            if any(out.iterdir()):
                logger.info(f"CPIO unpacked to {out}")
                return out
        except Exception as e:
            logger.warning(f"CPIO unpack failed: {e}")
        return None
