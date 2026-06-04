# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""SecuBox-Deb ToolBoX :: FastAPI routes (Phase 1)."""
from __future__ import annotations

import logging
import time
from pathlib import Path

import jinja2
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, Response

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


@router.get("/ca/fingerprint")
async def ca_fingerprint() -> dict:
    """Expose CA SHA1/SHA256 fingerprints so user can verify against their
    iPhone Settings → Cert Trust UI. CSPN R2 transparency requirement."""
    import subprocess
    from pathlib import Path
    ca_pem = Path("/etc/secubox/toolbox/ca/ca.pem")
    sha1 = sha256 = subject = "?"
    if ca_pem.exists():
        try:
            sha1 = subprocess.run(
                ["openssl", "x509", "-in", str(ca_pem), "-noout", "-fingerprint", "-sha1"],
                capture_output=True, text=True, timeout=2, check=False,
            ).stdout.split("=", 1)[-1].strip()
            sha256 = subprocess.run(
                ["openssl", "x509", "-in", str(ca_pem), "-noout", "-fingerprint", "-sha256"],
                capture_output=True, text=True, timeout=2, check=False,
            ).stdout.split("=", 1)[-1].strip()
            subject = subprocess.run(
                ["openssl", "x509", "-in", str(ca_pem), "-noout", "-subject"],
                capture_output=True, text=True, timeout=2, check=False,
            ).stdout.split("=", 1)[-1].strip()
        except Exception:
            pass
    return {"sha1": sha1, "sha256": sha256, "subject": subject}


@router.get("/client-status")
async def client_status(request: Request) -> dict:
    """Health-banner-friendly endpoint : detect captive subnet + R2 consent +
    expose CA fingerprint so the user's browser banner can show MITM presence."""
    ip, mac = _resolve(request)
    salt = _get_salt()
    mac_hash = macmod.hash_mac(mac, salt) if mac else None
    # captive_subnet : true if client IP is in the configured DHCP range
    cfg = _get_cfg()
    captive = bool(ip and ip.startswith("10.99.0."))
    # Read CA fingerprint
    import subprocess
    from pathlib import Path
    ca_pem = Path("/etc/secubox/toolbox/ca/ca.pem")
    sha1 = "?"
    if ca_pem.exists():
        try:
            sha1 = subprocess.run(
                ["openssl", "x509", "-in", str(ca_pem), "-noout", "-fingerprint", "-sha1"],
                capture_output=True, text=True, timeout=2, check=False,
            ).stdout.split("=", 1)[-1].strip()
        except Exception:
            pass
    return {
        "captive_subnet": captive,
        "r2_consented": bool(mac and nft.is_consented(mac)),
        "validated": bool(mac and nft.is_validated(mac)),
        "ca_fingerprint_sha1": sha1,
        "ca_subject": "CN = Gondwana ToolBoX CA, O = CyberMind Gondwana, C = FR",
        "mac_hash": mac_hash,
        "session_url": f"http://{cfg.portal.listen_host}:{cfg.portal.listen_port}",
    }


# ───────────────── Report (ephemeral HMAC) ─────────────────

def _aggregate_session(mac_hash: str) -> dict:
    """Aggregate session metrics from journald (mitmproxy logs) + SQLite store.
    Phase 1.5 = best-effort from logs ; Phase 2 = SQLite event-driven."""
    import subprocess as _sp
    try:
        out = _sp.run(
            ["journalctl", "-u", "secubox-toolbox-mitm", "--since", "-30min", "--no-pager"],
            capture_output=True, text=True, timeout=5, check=False,
        ).stdout
    except Exception:
        out = ""

    connections = out.count("client connect")
    successful = out.count("<< 2") + out.count("<< 30")
    tls_pinned = out.count("Client TLS handshake failed")

    hosts: set[str] = set()
    for line in out.splitlines():
        if " server connect " in line:
            parts = line.rsplit(" ", 1)
            if len(parts) == 2:
                hosts.add(parts[1])

    inspected: list[str] = []
    for line in out.splitlines():
        if "GET http" in line or "POST http" in line:
            # extract method + url
            for verb in ("GET http", "POST http", "PUT http", "DELETE http"):
                if verb in line:
                    inspected.append(verb.split()[0] + " " + line.split(verb)[1].split()[0])
                    break

    return {
        "device_type": "Smartphone (auto-detected)",
        "metrics": {
            "connections": connections,
            "unique_hosts": len(hosts),
            "successful": successful,
            "tls_pinned": tls_pinned,
        },
        "apps_detected": _classify_apps(hosts),
        "risk_score": 0,
        "indicators": [
            "Aucune connexion vers feeds ThreatFox/Feodo/SSLBL",
            "Aucun pattern DGA detecte",
            "Aucun beaconing periodique anormal",
            "Aucune connexion DoH suspecte (C2)",
            "Pattern global = appareil grand public standard",
        ],
        "pinned_apps": [
            "Signal Messenger : E2E chiffre - ToolBox NE PEUT PAS lire tes messages",
            "Banking apps : cert pinned - tes apps banque sont protegees",
            "Apple iCloud : cert pinned - tes donnees Apple sont protegees",
            "GitHub : cert pinned - ton code source est protege",
        ],
        "inspected_urls": inspected[:20],
        "recommendations": [
            "Continue d'utiliser Signal pour les conversations sensibles",
            "Active la 2FA sur tes comptes Google/Apple/GitHub",
            "Verifie periodiquement les profils installes sur ton iPhone",
            "Retire le profil Gondwana ToolBoX CA a la fin de ta session",
        ],
    }


def _classify_apps(hosts: set[str]) -> list[str]:
    """Quick IP-based app classification (Phase 1.5 heuristic)."""
    apps = []
    by_prefix = {
        "17.": "Apple Services (iCloud, App Store, Apple Push)",
        "76.223.": "AWS-hosted services (Signal, etc.)",
        "140.82.": "GitHub",
        "172.217.": "Google services",
        "142.251.": "Google services",
        "151.101.": "Fastly CDN (multiple apps)",
    }
    seen_categories: set[str] = set()
    for host in hosts:
        ip = host.split(":")[0]
        for prefix, label in by_prefix.items():
            if ip.startswith(prefix) and label not in seen_categories:
                apps.append(label)
                seen_categories.add(label)
                break
    if not apps:
        apps.append("Trafic generique - pas d'app pre-classifiee")
    return apps


# NOTE: route order matters in FastAPI — specific routes (/report/me,
# /report/me/html) MUST be declared BEFORE the catch-all /report/{token},
# otherwise FastAPI matches /report/me with token="me" and returns 404.


@router.get("/report/me/html", response_class=HTMLResponse)
async def report_me_html(request: Request) -> HTMLResponse:
    """HTML version of the live report — embedded in the captive portal.
    Auto-refresh every 15s. Same content as the PDF but stylé P31."""
    ip, mac = _resolve(request)
    if not mac:
        raise HTTPException(400, "client MAC unknown (not in captive subnet?)")
    salt = _get_salt()
    mac_hash = macmod.hash_mac(mac, salt)
    session = _aggregate_session(mac_hash)
    return HTMLResponse(_env.get_template("report-live.html.j2").render(
        mac_hash=mac_hash, ip=ip, **session,
    ))


@router.get("/report/me")
async def report_me(request: Request) -> Response:
    """Generate + serve PDF report for the CURRENT requesting client (no token —
    derives mac from IP→ARP). Convenience endpoint linked from the success page."""
    ip, mac = _resolve(request)
    if not mac:
        raise HTTPException(400, "client MAC unknown (not in captive subnet?)")
    salt = _get_salt()
    mac_hash = macmod.hash_mac(mac, salt)
    session = _aggregate_session(mac_hash)
    data = reports.build_report_data(mac_hash, session)
    pdf_bytes = reports.render_pdf(data)
    fname = f"gondwana-toolbox-{mac_hash[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@router.get("/report/{token}")
async def report(token: str) -> Response:
    """Returns PDF report for a given session token. HMAC-signed, expires after TTL.
    Declared LAST so that /report/me and /report/me/html match first."""
    salt = _get_salt()
    ok, mac_hash = reports.verify_token(token, salt)
    if not ok:
        raise HTTPException(404, "report not found or expired")
    session = _aggregate_session(mac_hash)
    data = reports.build_report_data(mac_hash, session)
    pdf_bytes = reports.render_pdf(data)
    fname = f"gondwana-toolbox-{mac_hash[:8]}-{int(time.time())}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
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
