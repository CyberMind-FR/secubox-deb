# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""SecuBox-Deb ToolBoX :: FastAPI routes (Phase 1)."""
from __future__ import annotations

import logging
import time
from pathlib import Path

import jinja2
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response

from . import ca, mac as macmod, nft, reports, store
from .config import load_config, resolve_secret
from .models import AcceptResp, ClientRow, Config, StatusResp

log = logging.getLogger("secubox.toolbox")

router = APIRouter(tags=["toolbox"])

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "conf"
_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(TEMPLATE_DIR),
    autoescape=True,
    keep_trailing_newline=True,
)

_cfg: Config | None = None
_salt: str | None = None


def _get_cfg() -> Config:
    global _cfg
    if _cfg is None:
        _cfg = load_config()
    return _cfg


def _get_salt() -> str:
    global _salt
    if _salt is None:
        cfg = _get_cfg()
        try:
            _salt = resolve_secret(cfg.portal.mac_salt_ref)
        except Exception as e:
            log.error("salt unavailable: %s — using transient", e)
            import secrets as _s
            _salt = _s.token_urlsafe(24)
    return _salt


def _resolve(request: Request) -> tuple[str | None, str | None]:
    """Return (ip, mac) for the request client."""
    ip = request.client.host if request.client else None
    if not ip:
        return None, None
    return ip, macmod.mac_of(ip)


# ───────────────── Public routes ─────────────────

@router.get("/", response_class=HTMLResponse)
@router.get("/hotspot-detect.html", response_class=HTMLResponse)
@router.get("/generate_204", response_class=HTMLResponse)
@router.get("/connecttest.txt", response_class=HTMLResponse)
async def splash(request: Request) -> HTMLResponse:
    ip, mac = _resolve(request)
    cfg = _get_cfg()
    salt = _get_salt()
    mac_hash = macmod.hash_mac(mac, salt) if mac else None

    validated = bool(mac and nft.is_validated(mac))
    if validated:
        return HTMLResponse(_env.get_template("success.html.j2").render(
            mac_hash=mac_hash, r2_enabled=cfg.r2.enabled,
        ))
    return HTMLResponse(_env.get_template("splash.html.j2").render(
        mac_hash=mac_hash or "??", ssid=cfg.ap.ssid, r2_enabled=cfg.r2.enabled,
    ))


@router.post("/accept", response_model=AcceptResp)
async def accept(request: Request) -> AcceptResp:
    ip, mac = _resolve(request)
    if not ip or not mac:
        raise HTTPException(400, "client mac unknown")
    cfg = _get_cfg()
    salt = _get_salt()
    mac_hash = macmod.hash_mac(mac, salt)

    if not nft.add_validated(mac, ttl="24h"):
        raise HTTPException(500, "nft add validated failed")
    r2_ok = False
    if cfg.r2.enabled and nft.add_consented(mac, ttl="24h"):
        r2_ok = True

    ua = request.headers.get("user-agent", "")
    store.record_consent(mac_hash, ip, ua, ttl_seconds=86400)
    store.upsert_client(mac_hash, ip)
    log.info("consent recorded mac_hash=%s r2=%s", mac_hash, r2_ok)
    return AcceptResp(ok=True, mac_hash=mac_hash, r2=r2_ok)


@router.get("/status", response_model=StatusResp)
async def status(request: Request) -> StatusResp:
    ip, mac = _resolve(request)
    if not mac:
        return StatusResp(ip=ip)
    salt = _get_salt()
    return StatusResp(
        ip=ip,
        mac_hash=macmod.hash_mac(mac, salt),
        validated=nft.is_validated(mac),
        r2_consented=nft.is_consented(mac),
    )


# ───────────────── CA distribution ─────────────────

@router.get("/ca/mobileconfig")
async def ca_mobileconfig() -> Response:
    body = ca.render_mobileconfig()
    return Response(
        content=body,
        media_type="application/x-apple-aspen-config",
        headers={"Content-Disposition": "attachment; filename=gondwana-toolbox.mobileconfig"},
    )


@router.get("/ca/android.crt")
async def ca_android_crt() -> Response:
    return Response(
        content=ca.ca_der(),
        media_type="application/x-x509-ca-cert",
        headers={"Content-Disposition": "attachment; filename=gondwana-toolbox.crt"},
    )


@router.get("/ca/install-help", response_class=HTMLResponse)
async def ca_install_help() -> HTMLResponse:
    return HTMLResponse(_env.get_template("ca-help.html.j2").render())


# ───────────────── Report (ephemeral HMAC) ─────────────────

@router.get("/report/{token}", response_class=HTMLResponse)
async def report(token: str) -> HTMLResponse:
    salt = _get_salt()
    ok, mac_hash = reports.verify_token(token, salt)
    if not ok:
        raise HTTPException(404, "report not found or expired")
    # Phase 1 = minimal placeholder. Phase 4 = real PDF + content.
    return HTMLResponse(
        f"<h1>Rapport ToolBoX</h1>"
        f"<p>mac_hash: <code>{mac_hash}</code></p>"
        f"<p>Phase 1 — rapport complet à venir Phase 4.</p>"
    )


# ───────────────── Admin (Phase 1 minimal) ─────────────────

@router.get("/admin/config")
async def admin_config() -> dict:
    return _get_cfg().model_dump()


@router.get("/admin/clients", response_model=list[ClientRow])
async def admin_clients() -> list[ClientRow]:
    rows = store.list_clients()
    return [ClientRow(**r) for r in rows]


@router.get("/health")
async def health() -> dict:
    return {"status": "ok", "module": "toolbox", "version": "1.0.0"}
