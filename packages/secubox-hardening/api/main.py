#!/usr/bin/env python3
"""
SecuBox Hardening API — Kernel and System Hardening
"""
from fastapi import FastAPI, Depends
from typing import Optional
import subprocess
import json

import sys
sys.path.insert(0, '/usr/lib/python3/dist-packages')
try:
    from secubox_core.auth import require_jwt
except ImportError:
    async def require_jwt():
        return {"sub": "admin"}

app = FastAPI(
    title="SecuBox Hardening API",
    description="Kernel and system hardening management",
    version="1.0.0",
    docs_url="/docs",
    redoc_url=None
)

HARDENINGCTL = "/usr/sbin/hardeningctl"

def run_ctl(*args, parse_json=False):
    """Run hardeningctl command."""
    cmd = [HARDENINGCTL] + list(args)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if parse_json and result.returncode == 0:
            return json.loads(result.stdout)
        return {
            "success": result.returncode == 0,
            "output": result.stdout,
            "error": result.stderr if result.returncode != 0 else None
        }
    except json.JSONDecodeError:
        return {"success": False, "error": "Invalid JSON", "raw": result.stdout}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.get("/status")
async def get_status():
    """Get hardening status."""
    return run_ctl("status", "--json", parse_json=True)

@app.get("/components")
async def get_components():
    """Get hardening components."""
    return run_ctl("components", parse_json=True)

@app.get("/access")
async def get_access():
    """Get access information."""
    return run_ctl("access", parse_json=True)

@app.post("/benchmark")
async def run_benchmark(user: dict = Depends(require_jwt)):
    """Run security benchmark."""
    return run_ctl("benchmark")

@app.post("/apply")
async def apply_hardening(user: dict = Depends(require_jwt)):
    """Apply hardening settings."""
    return run_ctl("apply")

@app.post("/install")
async def install_hardening(user: dict = Depends(require_jwt)):
    """Install hardening configuration."""
    return run_ctl("install")

@app.get("/health")
async def health():
    return {"status": "ok", "service": "secubox-hardening"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
