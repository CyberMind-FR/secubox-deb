"""SecuBox DNS Master API - BIND Zone Management"""
import subprocess
import json
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional, List
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox DNS Master")
config = get_config("dns")

DNSMASTER_CMD = "/usr/sbin/dnsmaster"

def run_cmd(args: list, capture=True) -> tuple:
    """Run dnsmaster command"""
    try:
        result = subprocess.run(
            [DNSMASTER_CMD] + args,
            capture_output=capture,
            text=True,
            timeout=30
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return 1, "", "dnsmaster not installed"
    except Exception as e:
        return 1, "", str(e)


# Models
class RecordCreate(BaseModel):
    zone: str
    type: str
    name: str
    value: str
    ttl: Optional[int] = 300

class RecordDelete(BaseModel):
    zone: str
    type: str
    name: str
    value: Optional[str] = None

class ZoneCreate(BaseModel):
    name: str


# Public endpoints
@app.get("/status")
async def status():
    """Get BIND status"""
    code, out, err = run_cmd(["status-json"])
    if code == 0:
        try:
            return json.loads(out)
        except:
            pass
    return {"running": False, "zones": 0, "records": 0}


@app.get("/zones")
async def list_zones():
    """List all DNS zones"""
    code, out, err = run_cmd(["zone-list-json"])
    if code == 0:
        try:
            return json.loads(out)
        except:
            pass
    return {"zones": []}


@app.get("/zone/{zone_name}/records")
async def get_records(zone_name: str):
    """Get records for a zone"""
    code, out, err = run_cmd(["records-json", zone_name])
    if code == 0:
        try:
            return json.loads(out)
        except:
            pass
    return {"error": "Zone not found", "zone": zone_name, "records": []}


# Protected endpoints
@app.post("/zone", dependencies=[Depends(require_jwt)])
async def add_zone(data: ZoneCreate):
    """Create a new DNS zone"""
    code, out, err = run_cmd(["zone-add", data.name])
    return {"success": code == 0, "code": code, "output": out or err}


@app.delete("/zone/{zone_name}", dependencies=[Depends(require_jwt)])
async def delete_zone(zone_name: str):
    """Delete a DNS zone"""
    code, out, err = run_cmd(["zone-del", zone_name])
    return {"success": code == 0, "code": code, "output": out or err}


@app.post("/record", dependencies=[Depends(require_jwt)])
async def add_record(data: RecordCreate):
    """Add a DNS record"""
    args = ["record-add", data.zone, data.type, data.name, data.value]
    if data.ttl:
        args.append(str(data.ttl))
    code, out, err = run_cmd(args)
    return {"success": code == 0, "code": code, "output": out or err}


@app.delete("/record", dependencies=[Depends(require_jwt)])
async def delete_record(data: RecordDelete):
    """Delete a DNS record"""
    args = ["record-del", data.zone, data.type, data.name]
    if data.value:
        args.append(data.value)
    code, out, err = run_cmd(args)
    return {"success": code == 0, "code": code, "output": out or err}


@app.post("/reload", dependencies=[Depends(require_jwt)])
async def reload_bind():
    """Reload BIND configuration"""
    code, out, err = run_cmd(["reload"])
    return {"success": code == 0, "code": code, "output": out or err}


@app.get("/check", dependencies=[Depends(require_jwt)])
async def check_config(zone: Optional[str] = None):
    """Check BIND configuration"""
    args = ["check"]
    if zone:
        args.append(zone)
    code, out, err = run_cmd(args)
    return {"valid": code == 0, "code": code, "output": out or err}


@app.get("/logs", dependencies=[Depends(require_jwt)])
async def get_logs(lines: int = 50):
    """Get BIND logs"""
    code, out, err = run_cmd(["logs", str(lines)])
    return {"logs": out}


@app.post("/backup/{zone_name}", dependencies=[Depends(require_jwt)])
async def backup_zone(zone_name: str):
    """Backup a DNS zone"""
    code, out, err = run_cmd(["backup", zone_name])
    return {"success": code == 0, "code": code, "output": out or err}
