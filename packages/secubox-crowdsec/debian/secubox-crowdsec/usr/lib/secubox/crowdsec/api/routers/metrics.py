"""secubox-crowdsec — metrics router"""
from fastapi import APIRouter, Depends
import subprocess, json
from secubox_core.auth import require_jwt

router = APIRouter()


@router.get("/metrics")
async def metrics(user=Depends(require_jwt)):
    r = subprocess.run(
        ["cscli", "metrics", "--output", "json"],
        capture_output=True, text=True, timeout=15
    )
    try:
        return json.loads(r.stdout)
    except Exception:
        return {"raw": r.stdout[:2000]}
