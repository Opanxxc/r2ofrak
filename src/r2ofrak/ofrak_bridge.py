"""
OFRAKBridge — OFRAK integration layer.
Wraps OFRAK for binary unpacking, modification, and repacking.
"""

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Optional, List, Dict, Any

logger = logging.getLogger("r2ofrak.ofrak")


class OFRAKBridge:
    """
    Bridge to OFRAK via Python API or CLI.
    Falls back to subprocess if ofrak Python API unavailable.
    """

    def __init__(self, target: Path, output_dir: Path):
        self.target = target
        self.output_dir = output_dir
        self._ofrak_ctx = None
        
        # Find ofrak binary
        self.ofrak_bin = shutil.which("ofrak")
        
        # Try Python API first
        try:
            from ofrak import OFRAK
            from ofrak.ofrak_context import OFRAKContext
            self._ofrak = OFRAK()
            logger.info("OFRAK Python API available")
        except ImportError:
            logger.info("OFRAK Python API not available, using CLI mode")
            self._ofrak = None
        except Exception as e:
            logger.warning(f"OFRAK API init failed: {e}")
            self._ofrak = None

    def identify(self) -> Dict[str, Any]:
        """Identify binary format using OFRAK."""
        if self._ofrak:
            return self._identify_python()
        elif self.ofrak_bin:
            return self._identify_cli()
        else:
            return self._identify_fallback()

    def _identify_python(self) -> Dict[str, Any]:
        """Identify using OFRAK Python API."""
        try:
            async def _identify():
                ctx = await self._ofrak.create_ofrak_context()
                resource = ctx.create_root_resource_from_file(str(self.target))
                
                # Identify
                tags = []
                try:
                    await resource.auto_identify()
                    data = await resource.data_info()
                    tags = [str(t) for t in (data.tags if hasattr(data, 'tags') else [])]
                except Exception as e:
                    logger.debug(f"auto_identify: {e}")
                
                return {
                    "format": tags[0] if tags else "unknown",
                    "tags": tags,
                    "size": self.target.stat().st_size,
                }
            
            import asyncio
            return asyncio.run(_identify())
        except Exception as e:
            logger.warning(f"OFRAK identify failed: {e}")
            return {"error": str(e)}

    def _identify_cli(self) -> Dict[str, Any]:
        """Identify using OFRAK CLI."""
        result = subprocess.run(
            [self.ofrak_bin, "identify", str(self.target)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        return {
            "output": result.stdout.strip(),
            "returncode": result.returncode,
        }

    def _identify_fallback(self) -> Dict[str, Any]:
        """Fallback identification using file command."""
        result = subprocess.run(
            ["file", str(self.target)],
            capture_output=True,
            text=True,
        )
        return {
            "format": result.stdout.strip(),
            "method": "file",
        }

    def unpack(self) -> Dict[str, Any]:
        """Unpack binary using OFRAK."""
        if self._ofrak:
            return self._unpack_python()
        elif self.ofrak_bin:
            return self._unpack_cli()
        else:
            raise RuntimeError("OFRAK not available. Install: pip install ofrak")

    def _unpack_python(self) -> Dict[str, Any]:
        """Unpack using OFRAK Python API."""
        try:
            async def _unpack():
                ctx = await self._ofrak.create_ofrak_context()
                resource = ctx.create_root_resource_from_file(str(self.target))
                
                # Auto-identify and unpack
                await resource.auto_identify()
                await resource.unpack()
                
                # Get children
                children = []
                async for child in resource.get_children():
                    tag = await child.get_node()
                    children.append({
                        "id": str(child.id),
                        "tags": [str(t) for t in (tag.tags if hasattr(tag, 'tags') else [])],
                    })
                
                # Save unpacked to output
                unpacked_dir = self.output_dir / "unpacked"
                unpacked_dir.mkdir(exist_ok=True)
                
                # Extract each child
                for child_resource in await resource.get_children():
                    try:
                        data = await child_resource.get_data()
                        child_path = unpacked_dir / str(child_resource.id)
                        child_path.write_bytes(bytes(data))
                    except Exception:
                        pass
                
                return {
                    "children_count": len(children),
                    "unpacked_dir": str(unpacked_dir),
                    "children": children[:50],
                }
            
            import asyncio
            return asyncio.run(_unpack())
        except Exception as e:
            logger.warning(f"OFRAK unpack failed: {e}")
            return {"error": str(e)}

    def _unpack_cli(self) -> Dict[str, Any]:
        """Unpack using OFRAK CLI."""
        unpacked_dir = self.output_dir / "unpacked"
        unpacked_dir.mkdir(exist_ok=True)
        
        result = subprocess.run(
            [
                self.ofrak_bin, "unpack",
                str(self.target),
                "--output-dir", str(unpacked_dir),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        return {
            "unpacked_dir": str(unpacked_dir),
            "output": result.stdout.strip(),
            "returncode": result.returncode,
        }

    def repack(self) -> Path:
        """Repack binary using OFRAK."""
        output = self.output_dir / f"repacked_{self.target.name}"
        
        if self._ofrak:
            return self._repack_python(output)
        elif self.ofrak_bin:
            return self._repack_cli(output)
        else:
            raise RuntimeError("OFRAK not available")

    def _repack_python(self, output: Path) -> Path:
        """Repack using OFRAK Python API."""
        try:
            async def _repack():
                ctx = await self._ofrak.create_ofrak_context()
                resource = ctx.create_root_resource_from_file(str(self.target))
                await resource.auto_identify()
                await resource.unpack()
                # Modify would happen here via patches
                await resource.pack()
                await resource.flush_to_disk(str(output))
                return output
            
            import asyncio
            return asyncio.run(_repack())
        except Exception as e:
            logger.warning(f"OFRAK repack failed: {e}")
            return self.target  # Return original if repack fails

    def _repack_cli(self, output: Path) -> Path:
        """Repack using OFRAK CLI."""
        result = subprocess.run(
            [
                self.ofrak_bin, "pack",
                str(self.target),
                "--output", str(output),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        return output

    def close(self):
        """Clean up resources."""
        if self._ofrak:
            try:
                async def _close():
                    await self._ofrak.teardown()
                import asyncio
                asyncio.run(_close())
            except Exception:
                pass
