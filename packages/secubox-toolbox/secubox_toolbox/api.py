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

from . import (
    beaconing,
    ca,
    dga,
    mac as macmod,
    nft,
    reports,
    scoring,
    store,
    threat_intel,
)
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
    """Aggregate session data from journald (mitmproxy logs) + SQLite events.
    Phase 1.5 :
      - global metrics + apps from journalctl
      - per-MAC DPI / cookies / JA4 / SOC events from SQLite (via local_store addon)
    """
    import json as _json
    import sqlite3 as _sq3
    import subprocess as _sp

    # ── 1. Global metrics from journalctl ──
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

    # ── 2. Per-MAC events from SQLite (local_store addon) ──
    dpi_hosts: dict[str, int] = {}
    dpi_methods: dict[str, int] = {}
    user_agents: set[str] = set()
    cookies_urls: list[dict] = []
    cookies_total_set = 0
    cookies_total_sent = 0
    soc_indicators: list[dict] = []
    ja4_snis: set[str] = set()
    ja4_alpns: set[str] = set()
    try:
        with _sq3.connect("/var/lib/secubox/toolbox/toolbox.db", timeout=2) as c:
            cur = c.execute(
                "SELECT source, payload FROM events WHERE mac_hash=? AND ts > ? "
                "ORDER BY ts DESC LIMIT 500",
                (mac_hash, int(time.time()) - 86400),
            )
            for source, payload_json in cur.fetchall():
                try:
                    p = _json.loads(payload_json)
                except Exception:
                    continue
                if source == "dpi":
                    host = p.get("host", "?")
                    dpi_hosts[host] = dpi_hosts.get(host, 0) + 1
                    m = p.get("method", "")
                    if m:
                        dpi_methods[m] = dpi_methods.get(m, 0) + 1
                    ua = p.get("user_agent")
                    if ua:
                        user_agents.add(ua[:80])
                elif source == "cookies":
                    cookies_total_set += p.get("set_cookie_count", 0)
                    cookies_total_sent += p.get("cookie_count", 0)
                    if len(cookies_urls) < 15:
                        cookies_urls.append({
                            "url": p.get("url", "?")[:120],
                            "set": p.get("set_cookie_count", 0),
                            "sent": p.get("cookie_count", 0),
                            "status": p.get("status"),
                        })
                elif source == "soc":
                    if len(soc_indicators) < 15:
                        soc_indicators.append({
                            "host": p.get("host", "?"),
                            "kind": p.get("kind", "?"),
                            "weight": p.get("weight", 0),
                        })
                elif source == "ja4":
                    if p.get("sni"):
                        ja4_snis.add(p["sni"])
                    for alpn in p.get("alpn_protocols", []) or []:
                        if isinstance(alpn, str):
                            ja4_alpns.add(alpn)
                        elif isinstance(alpn, bytes):
                            ja4_alpns.add(alpn.decode("ascii", errors="ignore"))
    except Exception:
        pass

    # ── 3. Phase 2a SOC scoring : threat-intel + DGA + beaconing ──
    # Threat-intel : match IPs in feeds (resolve hosts isn't done here — match domains
    # directly). On DPI hosts (which are domain names from SNI/Host) we check both.
    ti_matches: list[dict] = []
    unique_hosts_list = list(dpi_hosts.keys())
    for host in unique_hosts_list:
        for m in threat_intel.is_malicious_domain(host):
            m["ioc"] = host
            ti_matches.append(m)
    # Also check raw IPs seen in mitm logs
    for h in hosts:
        ip = h.split(":")[0]
        # crude IP detection : has dot + all digits
        if ip.replace(".", "").isdigit():
            for m in threat_intel.is_malicious_ip(ip):
                m["ioc"] = ip
                ti_matches.append(m)

    # DGA heuristic on domains
    dga_candidates = dga.analyze_hosts(unique_hosts_list)

    # Beaconing analysis from SQLite cadence
    beacon_candidates = beaconing.analyze_beaconing(mac_hash)

    # Multi-signal score
    score_result = scoring.compute_score(
        threat_intel_matches=ti_matches,
        dga_candidates=dga_candidates,
        beaconing_candidates=beacon_candidates,
        raw_soc_events=soc_indicators,
    )
    risk_score = score_result["score"]

    # ── 4. Top DPI hosts (Phase 1.5 = simple ranking) ──
    top_dpi = sorted(dpi_hosts.items(), key=lambda x: -x[1])[:15]

    return {
        "device_type": "Smartphone (auto-detected)",
        "metrics": {
            "connections": connections,
            "unique_hosts": len(hosts),
            "successful": successful,
            "tls_pinned": tls_pinned,
        },
        "apps_detected": _classify_apps(hosts),
        "risk_score": risk_score,
        "risk_label": score_result["label"],
        "risk_explanation": score_result["explanation"],
        "indicators": score_result["indicators_summary"] or [
            "Aucun signal de compromission détecté.",
        ],
        "pinned_apps": [
            "Signal Messenger : E2E chiffre - ToolBox NE PEUT PAS lire tes messages",
            "Banking apps : cert pinned - tes apps banque sont protegees",
            "Apple iCloud : cert pinned - tes donnees Apple sont protegees",
            "GitHub : cert pinned - ton code source est protege",
        ],
        "inspected_urls": [u["url"] for u in cookies_urls][:15] if cookies_urls else [],
        "recommendations": [
            "Continue d'utiliser Signal pour les conversations sensibles",
            "Active la 2FA sur tes comptes Google/Apple/GitHub",
            "Verifie periodiquement les profils installes sur ton iPhone",
            "Retire le profil Gondwana ToolBoX CA a la fin de ta session",
        ],
        # ── Phase 1.5 dpi/cookies/soc/ja4 ──
        "dpi": {
            "top_hosts": [{"host": h, "count": n} for h, n in top_dpi],
            "methods": dpi_methods,
            "user_agents": list(user_agents)[:5],
        },
        "cookies": {
            "total_set": cookies_total_set,
            "total_sent": cookies_total_sent,
            "details": cookies_urls,
        },
        "soc": {
            "indicators": soc_indicators,
            "score": risk_score,
        },
        "ja4": {
            "snis_seen": list(ja4_snis)[:10],
            "alpns_seen": list(ja4_alpns),
        },
        # ── Phase 2a SOC scoring ──
        "scoring": {
            "score": score_result["score"],
            "label": score_result["label"],
            "explanation": score_result["explanation"],
            "breakdown": score_result["breakdown"],
        },
        "threat_intel_matches": ti_matches[:10],
        "dga_candidates": dga_candidates[:10],
        "beaconing_candidates": beacon_candidates[:10],
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


@router.get("/admin/metrics")
async def admin_metrics() -> dict:
    """Live metrics for the admin WebUI : per-source event counts (DPI, cookies,
    SOC, JA4), recent clients, mitmproxy flow stats."""
    import sqlite3 as _sq3
    import subprocess as _sp
    metrics = {
        "events_by_source": {},
        "clients_active": 0,
        "events_24h_total": 0,
        "mitm": {"connections": 0, "tls_pinned": 0, "unique_hosts": 0},
    }
    # Per-source event counts (last 24h)
    try:
        with _sq3.connect("/var/lib/secubox/toolbox/toolbox.db", timeout=2) as c:
            since = int(time.time()) - 86400
            rows = c.execute(
                "SELECT source, COUNT(*) FROM events WHERE ts > ? GROUP BY source",
                (since,),
            ).fetchall()
            metrics["events_by_source"] = {r[0]: r[1] for r in rows}
            metrics["events_24h_total"] = sum(metrics["events_by_source"].values())
            metrics["clients_active"] = c.execute(
                "SELECT COUNT(*) FROM clients WHERE last_seen > ?",
                (since,),
            ).fetchone()[0]
    except Exception as e:
        metrics["sqlite_error"] = str(e)
    # Mitmproxy live stats (from journal)
    try:
        out = _sp.run(
            ["journalctl", "-u", "secubox-toolbox-mitm", "--since", "-30min", "--no-pager"],
            capture_output=True, text=True, timeout=3, check=False,
        ).stdout
        metrics["mitm"]["connections"] = out.count("client connect")
        metrics["mitm"]["tls_pinned"] = out.count("Client TLS handshake failed")
        hosts: set[str] = set()
        for line in out.splitlines():
            if " server connect " in line:
                parts = line.rsplit(" ", 1)
                if len(parts) == 2:
                    hosts.add(parts[1])
        metrics["mitm"]["unique_hosts"] = len(hosts)
    except Exception:
        pass
    return metrics


@router.get("/admin/clients/{mac_hash}/report")
async def admin_client_report(mac_hash: str) -> Response:
    """Admin endpoint : download PDF for a specific client by mac_hash."""
    session = _aggregate_session(mac_hash)
    data = reports.build_report_data(mac_hash, session)
    pdf_bytes = reports.render_pdf(data)
    fname = f"gondwana-toolbox-{mac_hash[:8]}-admin.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@router.get("/admin/clients/{mac_hash}/events")
async def admin_client_events(mac_hash: str) -> dict:
    """Admin endpoint : per-source event summary for a specific client."""
    import json as _json
    import sqlite3 as _sq3
    res = {"mac_hash": mac_hash, "events_by_source": {}, "recent": []}
    try:
        with _sq3.connect("/var/lib/secubox/toolbox/toolbox.db", timeout=2) as c:
            rows = c.execute(
                "SELECT source, COUNT(*) FROM events WHERE mac_hash=? GROUP BY source",
                (mac_hash,),
            ).fetchall()
            res["events_by_source"] = {r[0]: r[1] for r in rows}
            recent = c.execute(
                "SELECT source, ts, payload FROM events WHERE mac_hash=? "
                "ORDER BY ts DESC LIMIT 30",
                (mac_hash,),
            ).fetchall()
            for src, ts, payload in recent:
                try:
                    p = _json.loads(payload)
                except Exception:
                    p = {}
                res["recent"].append({"source": src, "ts": ts, **{
                    k: v for k, v in p.items()
                    if k in ("host", "url", "method", "kind", "weight", "sni", "status")
                }})
    except Exception as e:
        res["error"] = str(e)
    return res


@router.get("/health")
async def health() -> dict:
    return {"status": "ok", "module": "toolbox", "version": "1.0.0"}
