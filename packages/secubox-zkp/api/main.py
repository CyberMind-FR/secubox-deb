#!/usr/bin/env python3
"""
SecuBox ZKP API — Zero-Knowledge Proof Hamiltonian Dashboard
Wraps zkp_keygen, zkp_prover, zkp_verifier CLI tools
"""
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional, List
import subprocess
import json
import os
import base64
from pathlib import Path

import sys
sys.path.insert(0, '/usr/lib/python3/dist-packages')
try:
    from secubox_core.auth import require_jwt
except ImportError:
    async def require_jwt():
        return {"sub": "admin"}

app = FastAPI(
    title="SecuBox ZKP API",
    description="Zero-Knowledge Proof Hamiltonian management",
    version="1.0.0",
    docs_url="/docs",
    redoc_url=None
)

ZKP_DIR = Path("/var/lib/zkp")
GRAPHS_DIR = ZKP_DIR / "graphs"
KEYS_DIR = ZKP_DIR / "keys"
PROOFS_DIR = ZKP_DIR / "proofs"

def init_dirs():
    """Ensure directories exist."""
    for d in [GRAPHS_DIR, KEYS_DIR, PROOFS_DIR]:
        d.mkdir(parents=True, exist_ok=True)

def check_tools() -> bool:
    """Check if ZKP tools are available."""
    for tool in ['zkp_keygen', 'zkp_prover', 'zkp_verifier']:
        if subprocess.run(['which', tool], capture_output=True).returncode != 0:
            return False
    return True

def get_version() -> str:
    """Get ZKP library version."""
    if check_tools():
        try:
            result = subprocess.run(['zkp_keygen', '--version'], capture_output=True, text=True)
            return result.stdout.strip().split('\n')[0] if result.returncode == 0 else "1.0.0"
        except:
            return "1.0.0"
    return "not installed"

class KeygenRequest(BaseModel):
    nodes: int = 20
    density: float = 0.8
    name: Optional[str] = None

class KeyRequest(BaseModel):
    name: str

@app.get("/status")
async def get_status():
    """Get ZKP status."""
    init_dirs()
    tools_ok = check_tools()
    version = get_version() if tools_ok else "not installed"
    key_count = len(list(KEYS_DIR.glob("*.key")))

    return {
        "tools_available": tools_ok,
        "version": version,
        "key_count": key_count,
        "graphs_dir": str(GRAPHS_DIR),
        "keys_dir": str(KEYS_DIR),
        "proofs_dir": str(PROOFS_DIR)
    }

@app.get("/keys")
async def list_keys():
    """List all generated keys."""
    init_dirs()
    keys = []

    for keyfile in KEYS_DIR.glob("*.key"):
        name = keyfile.stem
        graphfile = GRAPHS_DIR / f"{name}.graph"

        nodes = 0
        graph_size = 0
        if graphfile.exists():
            graph_size = graphfile.stat().st_size
            # Read nodes count from graph binary (byte 5)
            try:
                with open(graphfile, 'rb') as f:
                    f.seek(4)
                    nodes = f.read(1)[0]
            except:
                pass

        key_size = keyfile.stat().st_size
        created = int(keyfile.stat().st_mtime)

        keys.append({
            "name": name,
            "nodes": nodes,
            "graph_size": graph_size,
            "key_size": key_size,
            "created": created
        })

    return {"keys": keys}

@app.post("/keygen")
async def generate_key(req: KeygenRequest, user: dict = Depends(require_jwt)):
    """Generate a new ZKP key pair."""
    init_dirs()

    if not check_tools():
        raise HTTPException(status_code=503, detail="ZKP tools not installed")

    if req.nodes < 4 or req.nodes > 50:
        raise HTTPException(status_code=400, detail="Nodes must be between 4 and 50")

    name = req.name or f"key_{int(os.times().elapsed)}"
    name = ''.join(c if c.isalnum() or c in '_-' else '_' for c in name)

    keyfile = KEYS_DIR / f"{name}.key"
    graphfile = GRAPHS_DIR / f"{name}.graph"

    if keyfile.exists():
        raise HTTPException(status_code=409, detail=f"Key '{name}' already exists")

    # Generate using temp directory
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        prefix = os.path.join(tmpdir, name)
        result = subprocess.run(
            ['zkp_keygen', '-n', str(req.nodes), '-r', str(req.density), '-o', prefix],
            capture_output=True, text=True, timeout=60
        )

        if result.returncode == 0:
            tmp_graph = Path(f"{prefix}.graph")
            tmp_key = Path(f"{prefix}.key")
            if tmp_graph.exists() and tmp_key.exists():
                tmp_graph.rename(graphfile)
                tmp_key.rename(keyfile)

    if keyfile.exists() and graphfile.exists():
        return {
            "success": True,
            "name": name,
            "nodes": req.nodes,
            "density": req.density,
            "graph_size": graphfile.stat().st_size,
            "key_size": keyfile.stat().st_size
        }
    else:
        raise HTTPException(status_code=500, detail="Key generation failed")

@app.post("/prove")
async def generate_proof(req: KeyRequest, user: dict = Depends(require_jwt)):
    """Generate a ZKP proof."""
    init_dirs()

    if not check_tools():
        raise HTTPException(status_code=503, detail="ZKP tools not installed")

    graphfile = GRAPHS_DIR / f"{req.name}.graph"
    keyfile = KEYS_DIR / f"{req.name}.key"
    prooffile = PROOFS_DIR / f"{req.name}.proof"

    if not graphfile.exists() or not keyfile.exists():
        raise HTTPException(status_code=404, detail=f"Key '{req.name}' not found")

    result = subprocess.run(
        ['zkp_prover', '-g', str(graphfile), '-k', str(keyfile), '-o', str(prooffile)],
        capture_output=True, text=True, timeout=60
    )

    if result.returncode == 0 and prooffile.exists():
        # Base64 preview of first 1KB
        with open(prooffile, 'rb') as f:
            preview = base64.b64encode(f.read(1024)).decode()

        return {
            "success": True,
            "name": req.name,
            "proof_size": prooffile.stat().st_size,
            "proof_file": str(prooffile),
            "proof_preview": preview
        }
    else:
        raise HTTPException(status_code=500, detail=f"Proof failed: {result.stderr}")

@app.post("/verify")
async def verify_proof(req: KeyRequest, user: dict = Depends(require_jwt)):
    """Verify a ZKP proof."""
    init_dirs()

    if not check_tools():
        raise HTTPException(status_code=503, detail="ZKP tools not installed")

    graphfile = GRAPHS_DIR / f"{req.name}.graph"
    prooffile = PROOFS_DIR / f"{req.name}.proof"

    if not graphfile.exists():
        raise HTTPException(status_code=404, detail=f"Graph '{req.name}' not found")
    if not prooffile.exists():
        raise HTTPException(status_code=404, detail=f"Proof '{req.name}' not found")

    result = subprocess.run(
        ['zkp_verifier', '-g', str(graphfile), '-p', str(prooffile)],
        capture_output=True, text=True, timeout=60
    )

    output = result.stdout + result.stderr
    if "ACCEPT" in output:
        verdict = "ACCEPT"
        valid = True
    elif "REJECT" in output:
        verdict = "REJECT"
        valid = False
    else:
        verdict = "UNKNOWN"
        valid = False

    return {
        "success": True,
        "name": req.name,
        "result": verdict,
        "valid": valid,
        "output": output
    }

@app.delete("/keys/{name}")
async def delete_key(name: str, user: dict = Depends(require_jwt)):
    """Delete a key and associated files."""
    init_dirs()

    deleted = 0
    for ext in ['graph', 'key', 'proof']:
        d = {'graph': GRAPHS_DIR, 'key': KEYS_DIR, 'proof': PROOFS_DIR}[ext]
        f = d / f"{name}.{ext}"
        if f.exists():
            f.unlink()
            deleted += 1

    return {"success": True, "name": name, "files_deleted": deleted}

@app.get("/health")
async def health():
    return {"status": "ok", "service": "secubox-zkp"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
