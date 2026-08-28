"""
Panxcz Tools — Web GUI Server
FastAPI backend providing REST API + WebSocket for the iaito-style web interface.
"""

import json
import os
import sys
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI(
    title="Panxcz Tools",
    description="Unified Reverse Engineering Platform — radare2 + OFRAK",
    version="1.0.0",
)

# Global state
_engine = None
_target = None


def get_engine():
    global _engine, _target
    if _engine is None and _target:
        from panxcz_tools.core.r2_engine import R2Engine
        _engine = R2Engine(_target)
    return _engine


# ─── Static files ─────────────────────────────────────────────────
static_dir = Path(__file__).parent / "static"
template_dir = Path(__file__).parent / "templates"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


# ─── Routes ───────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index():
    """Serve the main GUI."""
    html_file = template_dir / "index.html"
    return HTMLResponse(html_file.read_text())


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}


@app.post("/api/open")
async def open_file(data: dict):
    """Open a binary file."""
    global _engine, _target
    target = data.get("path", "")
    if not target or not Path(target).exists():
        return JSONResponse({"error": f"File not found: {target}"}, status_code=404)

    _target = target
    _engine = None  # Reset
    engine = get_engine()

    try:
        info = engine.info()
        return {"status": "ok", "target": target, "info": info}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/info")
async def file_info():
    """Get binary info."""
    engine = get_engine()
    if not engine:
        return JSONResponse({"error": "No file loaded"}, status_code=400)
    return engine.info()


@app.get("/api/analyze")
async def full_analysis():
    """Full analysis."""
    engine = get_engine()
    if not engine:
        return JSONResponse({"error": "No file loaded"}, status_code=400)
    return engine.analyze()


@app.get("/api/functions")
async def list_functions():
    """List functions."""
    engine = get_engine()
    if not engine:
        return JSONResponse({"error": "No file loaded"}, status_code=400)
    return engine.functions()


@app.get("/api/disasm")
async def disassemble(addr: Optional[str] = None, count: int = 200):
    """Disassemble."""
    engine = get_engine()
    if not engine:
        return JSONResponse({"error": "No file loaded"}, status_code=400)
    output = engine.disasm(addr=addr, count=count)
    return {"disassembly": output}


@app.get("/api/disasm/{function_name}")
async def disasm_function(function_name: str):
    """Disassemble a function."""
    engine = get_engine()
    if not engine:
        return JSONResponse({"error": "No file loaded"}, status_code=400)
    output = engine.disasm_function(function_name)
    return {"disassembly": output, "function": function_name}


@app.get("/api/strings")
async def list_strings(min_len: int = 4):
    """Extract strings."""
    engine = get_engine()
    if not engine:
        return JSONResponse({"error": "No file loaded"}, status_code=400)
    return engine.strings(min_len=min_len)


@app.get("/api/imports")
async def list_imports():
    """List imports."""
    engine = get_engine()
    if not engine:
        return JSONResponse({"error": "No file loaded"}, status_code=400)
    return engine.imports()


@app.get("/api/exports")
async def list_exports():
    """List exports."""
    engine = get_engine()
    if not engine:
        return JSONResponse({"error": "No file loaded"}, status_code=400)
    return engine.exports()


@app.get("/api/sections")
async def list_sections():
    """List sections."""
    engine = get_engine()
    if not engine:
        return JSONResponse({"error": "No file loaded"}, status_code=400)
    return engine.sections()


@app.get("/api/hex")
async def hexdump(offset: int = 0, size: int = 512):
    """Hex dump."""
    engine = get_engine()
    if not engine:
        return JSONResponse({"error": "No file loaded"}, status_code=400)
    return {"hexdump": engine.hexdump(offset=offset, size=size)}


@app.get("/api/entropy")
async def entropy():
    """Entropy analysis."""
    engine = get_engine()
    if not engine:
        return JSONResponse({"error": "No file loaded"}, status_code=400)
    return engine.entropy()


@app.get("/api/vulns")
async def vulnerabilities():
    """Vulnerability scan."""
    engine = get_engine()
    if not engine:
        return JSONResponse({"error": "No file loaded"}, status_code=400)
    return engine.vulnerabilities()


@app.get("/api/security")
async def security():
    """Security analysis."""
    engine = get_engine()
    if not engine:
        return JSONResponse({"error": "No file loaded"}, status_code=400)
    from panxcz_tools.core.security import SecurityAnalyzer
    sa = SecurityAnalyzer(_target)
    return sa.full()


@app.post("/api/patch")
async def patch(data: dict):
    """Patch binary."""
    engine = get_engine()
    if not engine:
        return JSONResponse({"error": "No file loaded"}, status_code=400)
    offset = data.get("offset", 0)
    hex_data = data.get("hex", "")
    engine.patch(offset, hex_data)
    return {"status": "ok", "offset": offset, "data": hex_data}


@app.post("/api/r2cmd")
async def r2_command(data: dict):
    """Execute r2 command."""
    engine = get_engine()
    if not engine:
        return JSONResponse({"error": "No file loaded"}, status_code=400)
    cmd = data.get("command", "")
    output = engine.r2cmd(cmd)
    return {"output": output}


@app.get("/api/search")
async def search(q: str):
    """Search in binary."""
    engine = get_engine()
    if not engine:
        return JSONResponse({"error": "No file loaded"}, status_code=400)
    return engine.search(q)


# ─── WebSocket for real-time ──────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket for real-time r2 commands."""
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                cmd = msg.get("command", "")
                engine = get_engine()
                if not engine:
                    await websocket.send_json({"error": "No file loaded"})
                    continue
                output = engine.r2cmd(cmd)
                await websocket.send_json({"output": output, "command": cmd})
            except Exception as e:
                await websocket.send_json({"error": str(e)})
    except WebSocketDisconnect:
        pass


# ─── Entry point ──────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Panxcz Tools GUI Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host")
    parser.add_argument("--port", type=int, default=8888, help="Port")
    parser.add_argument("--target", help="Binary to open on start")
    parser.add_argument("--open-browser", action="store_true", help="Open browser")
    args = parser.parse_args()

    global _target
    if args.target:
        _target = args.target

    if args.open_browser:
        import webbrowser
        webbrowser.open(f"http://{args.host}:{args.port}")

    import uvicorn
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
