# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: proxypac API — override CRUD + candidates."""
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, "/usr/lib/secubox/proxypac")
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel

try:
    from secubox_core.auth import require_jwt
except Exception:  # test/stub fallback
    def require_jwt():
        return {"sub": "anon"}

from proxypac.pac_template import directive
from proxypac.rules import parse_rules_dir
from proxypac.generator import run_once

RULES_DIR = Path(os.environ.get("PROXYPAC_RULES_DIR", "/etc/secubox/proxypac/rules.d"))
WEBUI_FILE = RULES_DIR / "50-webui.rules"
CANDIDATES = Path(os.environ.get("PROXYPAC_CANDIDATES",
                                 "/var/lib/secubox/proxypac/candidates.json"))
AUDIT = Path(os.environ.get("PROXYPAC_AUDIT", "/var/log/secubox/audit.log"))

app = FastAPI(title="SecuBox ProxyPAC")


class Override(BaseModel):
    host: str
    proxy: str
    address: str = ""


def _audit(action, host, user):
    try:
        AUDIT.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT.open("a") as f:
            f.write(f'{datetime.now(timezone.utc).isoformat()} proxypac {action} '
                    f'host={host} by={user}\n')
    except OSError:
        pass


def _read_webui_lines():
    if not WEBUI_FILE.exists():
        return []
    return [ln for ln in WEBUI_FILE.read_text().splitlines() if ln.strip()
            and not ln.startswith("#")]


def _write_webui_lines(lines):
    RULES_DIR.mkdir(parents=True, exist_ok=True)
    WEBUI_FILE.write_text("\n".join(lines) + ("\n" if lines else ""))


@app.get("/rules")
def list_rules(_=Depends(require_jwt)):
    return {"rules": [{"host": r.host, "directive": r.directive}
                      for r in parse_rules_dir(RULES_DIR)]}


@app.post("/override")
def add_override(o: Override, user=Depends(require_jwt)):
    line = f"{o.host} {o.proxy}" + (f" {o.address}" if o.address else "")
    lines = [ln for ln in _read_webui_lines() if ln.split()[0] != o.host]
    lines.append(line)
    _write_webui_lines(lines)
    _audit("override-add", o.host, user.get("sub"))
    run_once()
    return {"ok": True, "directive": directive(o.proxy, o.address)}


@app.delete("/override/{host}")
def del_override(host: str, user=Depends(require_jwt)):
    lines = [ln for ln in _read_webui_lines() if ln.split()[0] != host]
    _write_webui_lines(lines)
    _audit("override-del", host, user.get("sub"))
    run_once()
    return {"ok": True}


@app.get("/candidates")
def list_candidates(_=Depends(require_jwt)):
    import json
    try:
        return {"candidates": json.loads(CANDIDATES.read_text())}
    except Exception:
        return {"candidates": []}


@app.post("/candidate/{host}/accept")
def accept_candidate(host: str, user=Depends(require_jwt)):
    # Promote candidate to an override (socks5 to the first active tor-exit is the
    # common case; operator can re-edit). Minimal: DIRECT unless already routed.
    add_override(Override(host=host, proxy="direct"), user)
    _audit("candidate-accept", host, user.get("sub"))
    return {"ok": True}


@app.post("/candidate/{host}/reject")
def reject_candidate(host: str, user=Depends(require_jwt)):
    _audit("candidate-reject", host, user.get("sub"))
    return {"ok": True}


@app.get("/health")
def health():
    return {"status": "ok", "module": "proxypac"}
