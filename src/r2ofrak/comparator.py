"""
Binary Comparator — Compare two binaries, find differences.
"""

import hashlib
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("r2ofrak.compare")


class BinaryComparator:
    """Compare two binary files."""

    def __init__(self, file_a: str, file_b: str):
        self.file_a = Path(file_a)
        self.file_b = Path(file_b)

        if not self.file_a.exists():
            raise FileNotFoundError(f"Not found: {self.file_a}")
        if not self.file_b.exists():
            raise FileNotFoundError(f"Not found: {self.file_b}")

    def compare(self) -> Dict[str, Any]:
        """Full comparison."""
        data_a = self.file_a.read_bytes()
        data_b = self.file_b.read_bytes()

        return {
            "file_a": str(self.file_a),
            "file_b": str(self.file_b),
            "size_a": len(data_a),
            "size_b": len(data_b),
            "size_diff": len(data_b) - len(data_a),
            "identical": data_a == data_b,
            "hash_a": hashlib.sha256(data_a).hexdigest(),
            "hash_b": hashlib.sha256(data_b).hexdigest(),
            "diff_blocks": self._diff_blocks(data_a, data_b),
            "diff_regions": self._diff_regions(data_a, data_b),
            "string_diffs": self._string_diffs(data_a, data_b),
            "entropy_a": self._entropy(data_a),
            "entropy_b": self._entropy(data_b),
        }

    def _diff_blocks(self, a: bytes, b: bytes, block_size: int = 64) -> List[Dict[str, Any]]:
        """Find differing blocks."""
        diffs = []
        max_len = max(len(a), len(b))

        for offset in range(0, min(max_len, 1024 * 1024), block_size):
            chunk_a = a[offset : offset + block_size]
            chunk_b = b[offset : offset + block_size]

            if chunk_a != chunk_b:
                # Find first difference within block
                first_diff = 0
                for i in range(min(len(chunk_a), len(chunk_b))):
                    if chunk_a[i] != chunk_b[i]:
                        first_diff = i
                        break

                diffs.append({
                    "offset": f"0x{offset:08x}",
                    "size": block_size,
                    "hex_a": chunk_a.hex()[:64],
                    "hex_b": chunk_b.hex()[:64],
                    "first_diff_at": first_diff,
                })

                if len(diffs) >= 100:
                    break

        return diffs

    def _diff_regions(self, a: bytes, b: bytes) -> List[Dict[str, Any]]:
        """Merge adjacent diffs into regions."""
        blocks = self._diff_blocks(a, b, block_size=1)
        if not blocks:
            return []

        regions = []
        current_start = int(blocks[0]["offset"], 16)
        current_end = current_start + 1

        for block in blocks[1:]:
            offset = int(block["offset"], 16)
            if offset == current_end:
                current_end = offset + 1
            else:
                regions.append({
                    "start": f"0x{current_start:08x}",
                    "end": f"0x{current_end:08x}",
                    "size": current_end - current_start,
                })
                current_start = offset
                current_end = offset + 1

        regions.append({
            "start": f"0x{current_start:08x}",
            "end": f"0x{current_end:08x}",
            "size": current_end - current_start,
        })

        return regions

    def _string_diffs(self, a: bytes, b: bytes) -> Dict[str, Any]:
        """Compare strings between binaries."""
        def extract(data, min_len=4):
            strings = set()
            current = []
            for byte in data:
                if 32 <= byte < 127:
                    current.append(chr(byte))
                else:
                    if len(current) >= min_len:
                        strings.add("".join(current))
                    current = []
            return strings

        strings_a = extract(a)
        strings_b = extract(b)

        return {
            "only_in_a": sorted(strings_a - strings_b)[:50],
            "only_in_b": sorted(strings_b - strings_a)[:50],
            "common_count": len(strings_a & strings_b),
        }

    def _entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy."""
        import math
        if not data:
            return 0.0

        freq = [0] * 256
        for b in data:
            freq[b] += 1

        entropy = 0.0
        size = len(data)
        for f in freq:
            if f > 0:
                p = f / size
                entropy -= p * math.log2(p)

        return round(entropy, 4)
