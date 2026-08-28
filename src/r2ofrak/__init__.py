"""
R2OFRAK — Unified Reverse Engineering Platform
Combines radare2 (disassembly/analysis) + OFRAK (unpack/modify/repack)
"""

__version__ = "0.1.0"
__author__ = "Opanxxc"
__license__ = "AGPL-3.0"

from r2ofrak.core import R2OFRAKContext
from r2ofrak.r2_bridge import R2Bridge
from r2ofrak.ofrak_bridge import OFRAKBridge

__all__ = ["R2OFRAKContext", "R2Bridge", "OFRAKBridge"]
