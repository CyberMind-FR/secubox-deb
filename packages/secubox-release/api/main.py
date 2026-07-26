# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: release API — reads in-process, mutations delegate to ctl."""
from __future__ import annotations

import json
import os
import subprocess
import sys

from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from secubox_core.auth import require_jwt

sys.path.insert(0, os.environ.get("ANNUAIRE_LIB", "/usr/lib/secubox/annuaire"))
sys.path.insert(0, os.environ.get("RELEASE_LIB", "/usr/lib/secubox/release"))
from annuaire.log import Journal          # noqa: E402
from annuaire import releases             # noqa: E402
from annuaire.model import Op             # noqa: E402
from annuaire.grants import _op, _payload  # noqa: E402  (payload/op accessors)

app = FastAPI(title="SecuBox Release")
CTL = ["/usr/sbin/secubox-releasectl"]


def _entries():
    try:
        return list(Journal(os.environ.get(
            "ANNUAIRE_JOURNAL", "/var/lib/secubox/annuaire/journal.db")).iter_entries())
    except Exception:
        return []


def _self_did():
    env = os.environ.get("SECUBOX_SELF_DID")
    if env:
        return env
    path = os.environ.get("ANNUAIRE_DID_PATH", "/etc/secubox/annuaire/node.did")
    try:
        with open(path) as f:
            v = f.read().strip()
            return v or None
    except OSError:
        return None


def _ctl(*args):
    try:
        r = subprocess.run(CTL + list(args), shell=False, capture_output=True,
                            text=True, timeout=30)
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=400, detail="ctl timed out")
    if r.returncode != 0:
        raise HTTPException(status_code=400, detail=r.stderr.strip() or "ctl failed")
    try:
        return json.loads(r.stdout or "{}")
    except json.JSONDecodeError:
        return {"raw": r.stdout}


@app.get("/status")
async def status():
    return {"module": "release", "ok": True}


@app.get("/health")
async def health():
    return {"status": "ok", "module": "release"}


@app.get("/evolutions", dependencies=[Depends(require_jwt)])
async def evolutions():
    entries = _entries()
    evo_ids = sorted({p.get("evo_id") for p in
                      (_payload(e) for e in entries if _op(e) == Op.RELEASE_PUBLISH.value)
                      if p.get("evo_id")})
    return {"evolutions": [{"evo_id": e, "ring": releases.current_ring(entries, e)}
                            for e in evo_ids]}


@app.get("/box-ring", dependencies=[Depends(require_jwt)])
async def box_ring():
    sid = _self_did()
    if not sid:
        return {"ring": "published"}
    return {"ring": releases.box_ring(_entries(), sid, sid)}


class PublishBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    artifacts: list
    notes: str


@app.post("/publish", dependencies=[Depends(require_jwt)])
async def publish(b: PublishBody):
    return _ctl("publish", "--artifacts", json.dumps(b.artifacts), "--notes", b.notes)


class EvoRef(BaseModel):
    model_config = ConfigDict(extra="forbid")
    evo_id: str


@app.post("/promote", dependencies=[Depends(require_jwt)])
async def promote(b: EvoRef):
    return _ctl("promote", b.evo_id)


@app.post("/demote", dependencies=[Depends(require_jwt)])
async def demote(b: EvoRef):
    return _ctl("demote", b.evo_id)


class AssignBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    box_did: str
    ring: str


@app.post("/assign", dependencies=[Depends(require_jwt)])
async def assign(b: AssignBody):
    return _ctl("assign", b.box_did, b.ring)
