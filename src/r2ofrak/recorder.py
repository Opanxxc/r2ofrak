"""
Script Recorder — Record and replay reverse engineering workflows.
Outputs Python scripts that can be re-run.
"""

import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("r2ofrak.recorder")


class ScriptRecorder:
    """Record RE operations and generate replay scripts."""

    def __init__(self, output_path: Optional[str] = None):
        self.output_path = Path(output_path) if output_path else Path("r2ofrak_session.py")
        self.actions: List[Dict[str, Any]] = []
        self.start_time = time.time()

    def record(self, action: str, **kwargs) -> None:
        """Record an action."""
        entry = {
            "action": action,
            "args": kwargs,
            "timestamp": time.time() - self.start_time,
        }
        self.actions.append(entry)
        logger.debug(f"Recorded: {action}({kwargs})")

    def generate_script(self) -> str:
        """Generate Python script from recorded actions."""
        lines = [
            '#!/usr/bin/env python3',
            '"""R2OFRAK Recorded Session"""',
            '',
            'from r2ofrak import R2OFRAKContext',
            'import json',
            '',
        ]

        target = None
        for action in self.actions:
            args = action["args"]
            if action in ("analyze", "disassemble", "strings", "imports",
                         "exports", "functions", "segments", "entropy",
                         "vulns", "unpack", "repack", "export"):
                target = args.get("target", "target")
                break

        lines.append(f'target = "{target or "binary"}"')
        lines.append('output = "r2ofrak_output"')
        lines.append('')
        lines.append('with R2OFRAKContext(target, output_dir=output) as ctx:')

        for action in self.actions:
            args = action["args"]
            ts = action["timestamp"]

            if action == "analyze":
                lines.append(f'    # t={ts:.1f}s')
                lines.append('    report = ctx.analyze()')
                lines.append('    print(json.dumps(report, indent=2, default=str))')

            elif action == "disassemble":
                mode = args.get("mode", "full")
                addr = args.get("addr")
                count = args.get("count", 100)
                lines.append(f'    # t={ts:.1f}s')
                if addr:
                    lines.append(f'    output = ctx.disassemble(mode="{mode}", addr="{addr}", count={count})')
                else:
                    lines.append(f'    output = ctx.disassemble(mode="{mode}", count={count})')
                lines.append('    print(output)')

            elif action == "strings":
                min_len = args.get("min_length", 4)
                lines.append(f'    # t={ts:.1f}s')
                lines.append(f'    strings = ctx.dump_strings(min_length={min_len})')
                lines.append('    print(json.dumps(strings, indent=2))')

            elif action == "imports":
                lines.append(f'    # t={ts:.1f}s')
                lines.append('    imports = ctx.dump_imports()')
                lines.append('    print(json.dumps(imports, indent=2))')

            elif action == "exports":
                lines.append(f'    # t={ts:.1f}s')
                lines.append('    exports = ctx.dump_exports()')
                lines.append('    print(json.dumps(exports, indent=2))')

            elif action == "functions":
                lines.append(f'    # t={ts:.1f}s')
                lines.append('    funcs = ctx.dump_functions()')
                lines.append('    print(json.dumps(funcs, indent=2))')

            elif action == "segments":
                lines.append(f'    # t={ts:.1f}s')
                lines.append('    segs = ctx.extract_segments()')
                lines.append('    print(json.dumps(segs, indent=2))')

            elif action == "entropy":
                lines.append(f'    # t={ts:.1f}s')
                lines.append('    entropy = ctx.entropy_analysis()')
                lines.append('    print(json.dumps(entropy, indent=2))')

            elif action == "vulns":
                lines.append(f'    # t={ts:.1f}s')
                lines.append('    vulns = ctx.find_vulnerabilities()')
                lines.append('    print(json.dumps(vulns, indent=2))')

            elif action == "unpack":
                lines.append(f'    # t={ts:.1f}s')
                lines.append('    result = ctx.unpack()')
                lines.append('    print(json.dumps(result, indent=2, default=str))')

            elif action == "patch":
                offset = args.get("offset", 0)
                hex_data = args.get("hex_data", "90909090")
                lines.append(f'    # t={ts:.1f}s')
                lines.append(f'    ctx.patch(0x{offset:x}, bytes.fromhex("{hex_data}"))')

            elif action == "repack":
                lines.append(f'    # t={ts:.1f}s')
                lines.append('    output = ctx.repack()')
                lines.append('    print(f"Repacked: {output}")')

            elif action == "r2_command":
                cmd = args.get("command", "")
                lines.append(f'    # t={ts:.1f}s')
                lines.append(f'    result = ctx.r2._cmd("{cmd}")')
                lines.append('    print(result)')

            elif action == "export":
                lines.append(f'    # t={ts:.1f}s')
                lines.append('    ctx.export("report.json")')

            else:
                lines.append(f'    # t={ts:.1f}s — unknown action: {action}')

        lines.append('')
        lines.append('print("\\n[+] Session complete!")')

        return "\n".join(lines)

    def save(self) -> Path:
        """Save generated script."""
        script = self.generate_script()
        self.output_path.write_text(script)
        logger.info(f"Script saved to {self.output_path}")
        return self.output_path

    def save_actions_json(self) -> Path:
        """Save raw actions as JSON."""
        json_path = self.output_path.with_suffix(".json")
        json_path.write_text(json.dumps(self.actions, indent=2, default=str))
        return json_path
