# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: proxypac API — override CRUD + candidates."""
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, "/usr/lib/secubox/proxypac")
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel, field_validator

try:
    from secubox_core.auth import require_jwt
except Exception:  # test/stub fallback
    def require_jwt():
        return {"sub": "anon"}

from proxypac.pac_template import directive
from proxypac.rules import parse_rules_dir
from proxypac.generator import run_once
from proxypac import role, config as _cfg

config = _cfg  # alias so tests can monkeypatch api.main.config.load

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

    @field_validator("host")
    @classmethod
    def _no_whitespace(cls, v):
        if not v or any(c.isspace() for c in v):
            raise ValueError("host must be non-empty and contain no whitespace")
        return v


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
    run_once(rules_dir=str(RULES_DIR))
    return {"ok": True, "directive": directive(o.proxy, o.address)}


@app.delete("/override/{host}")
def del_override(host: str, user=Depends(require_jwt)):
    lines = [ln for ln in _read_webui_lines() if ln.split()[0] != host]
    _write_webui_lines(lines)
    _audit("override-del", host, user.get("sub"))
    run_once(rules_dir=str(RULES_DIR))
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


def _ctl(args, timeout=25):
    """Délègue une action privilégiée à un ctl scopé via sudo -n. Ne lève jamais."""
    try:
        p = subprocess.run(["sudo", "-n", *args], capture_output=True,
                            text=True, timeout=timeout)
        return p.returncode, p.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return 1, ""


@app.get("/status")
def status(_=Depends(require_jwt)):
    r = role.detect()
    c = config.load()
    dom = c.get("wpad_domain") or ""
    return {"role": r["role"], "tier": r["tier"], "dns_resolver": r.get("dns_resolver", False),
            "lan_ip": r.get("lan_ip", ""), "socks_endpoint": c["socks_endpoint"],
            "transparent": bool(c.get("transparent", True)),
            "pac_url": c.get("pac_url") or (f"http://wpad.{dom}/wpad.dat" if dom else "")}


@app.post("/wpad/apply")
def wpad_apply(_=Depends(require_jwt)):
    rc, out = _ctl(["/usr/sbin/proxypac-wpad", "apply"])
    return {"ok": rc == 0, "detail": out}


@app.get("/wpad/state")
def wpad_state(_=Depends(require_jwt)):
    import json as _j
    rc, out = _ctl(["/usr/sbin/proxypac-wpad", "state"])
    try:
        return _j.loads(out) if rc == 0 else {"error": "ctl indisponible"}
    except Exception:
        return {"error": "réponse illisible"}


class Toggle(BaseModel):
    on: bool


@app.post("/transparent")
def transparent(t: Toggle, _=Depends(require_jwt)):
    rc, out = _ctl(["/usr/sbin/torctl", "transparent", "on" if t.on else "off"])
    return {"ok": rc == 0, "detail": out}
