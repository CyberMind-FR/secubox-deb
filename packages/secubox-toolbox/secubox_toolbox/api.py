# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""SecuBox-Deb ToolBoX :: FastAPI routes (Phase 1)."""
from __future__ import annotations

import logging
import time
from pathlib import Path

import jinja2
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from . import (
    avatar_analysis,
    beaconing,
    ca,
    cookie_analysis,
    cumulative,
    dga,
    dpi_class,
    geo,
    mac as macmod,
    nft,
    reports,
    scoring,
    store,
    threat_intel,
)


def _cumulative_stats() -> dict:
    """Cached anonymous cumulative stats — see secubox_toolbox.cumulative."""
    try:
        return cumulative.get_cached()
    except Exception:
        return {}
# Phase 3 (#492) : transparency layer
try:
    from secubox_core import whitelist as _whitelist_mod
    from secubox_core.classifiers import security_quality as _sec_quality
    _HAS_TRANSPARENCY = True
except ImportError:
    _HAS_TRANSPARENCY = False
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
async def splash(request: Request):
    ip, mac = _resolve(request)
    cfg = _get_cfg()
    salt = _get_salt()
    mac_hash = macmod.hash_mac(mac, salt) if mac else None

    # Phase 6.I (#496) : if request comes from a WG peer (10.99.1.x), the
    # client is by construction R3 — bypass MAC/ARP resolution and use
    # the WG peer hash so the splash shows R3 status, masks R0/R1/R2
    # switch (useless when already in tunnel), and links to /report?mh=.
    client_ip = request.client.host if request.client else None
    is_wg_r3 = bool(client_ip and client_ip.startswith("10.99.1."))
    if is_wg_r3:
        try:
            from . import wg as _wg
            peers = _wg._load_peers().get("peers", {})
            import hashlib as _h
            for pk, m in peers.items():
                if m.get("ip") == client_ip:
                    mac_hash = _h.sha256(pk.encode()).hexdigest()[:16]
                    break
        except Exception:
            pass

    no_cache_headers = {
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
    }

    # Phase 3 (#492) : ALWAYS render splash on GET /. Even validated users
    # benefit from seeing the cert install buttons + level switcher + dashboard
    # link. Auto-redirect was hiding the cert links from users who already
    # validated — they had no path back to the install buttons.
    # Phase 6 (#496) : wg_enabled = server.pubkey exists = R3 ready
    wg_enabled = Path("/etc/secubox/toolbox/wg/server.pubkey").exists()
    current_level = "r3" if is_wg_r3 else (store.get_client_level(mac_hash) if mac_hash else None)
    html = _env.get_template("splash.html.j2").render(
        mac_hash=mac_hash or "??",
        ssid=cfg.ap.ssid,
        r2_enabled=cfg.r2.enabled,
        wg_enabled=wg_enabled,
        already_validated=bool(mac and nft.is_validated(mac)) or is_wg_r3,
        current_level=current_level,
        is_wg_r3=is_wg_r3,
        client_ip=client_ip,
    )
    return HTMLResponse(html, headers=no_cache_headers)


@router.post("/accept")
async def accept(request: Request):
    """Phase 3 (#492) : 3-level explicit opt-in.

    Form field 'level' = 'r0' | 'r1' | 'r2' (default 'r1' for backward compat
    with bare-button submission). Each level adds the MAC to incremental nft
    sets and persists the level in the clients table.
      r0 = validated only (net access, no inspection)
      r1 = r0 + consented_r2_macs (MITM enabled, passive analysis only)
      r2 = r1 + r2_banner_macs (banner injection + QUIC drop)
    """
    ip, mac = _resolve(request)
    if not ip or not mac:
        raise HTTPException(400, "client mac unknown")
    cfg = _get_cfg()
    salt = _get_salt()
    mac_hash = macmod.hash_mac(mac, salt)

    # Parse level from POST body — accept form-urlencoded or fallback to r1
    try:
        form = await request.form()
        level = (form.get("level") or "r1").lower()
    except Exception:
        level = "r1"
    if level not in ("r0", "r1", "r2", "r3"):
        level = "r1"
    # R2 only allowed if config enables it
    if level == "r2" and not cfg.r2.enabled:
        level = "r1"
    # R3 only allowed if WG container provisioned (presence of server.pubkey)
    if level == "r3" and not Path("/etc/secubox/toolbox/wg/server.pubkey").exists():
        level = "r1"

    # All levels get validated (net access)
    if not nft.add_validated(mac, ttl="24h"):
        raise HTTPException(500, "nft add validated failed")

    r2_ok = False
    if level in ("r1", "r2") and nft.add_consented(mac, ttl="24h"):
        r2_ok = True
    # R2-only : banner injection (separate nft set)
    if level == "r2":
        nft.add_r2_banner(mac, ttl="24h")
    # Phase 6 (#496) R3-only : WireGuard consent set
    if level == "r3":
        nft.add_r3_wg(mac, ttl="24h")

    ua = request.headers.get("user-agent", "")
    store.record_consent(mac_hash, ip, ua, ttl_seconds=86400)
    store.upsert_client(mac_hash, ip, level=level)
    log.info("consent recorded mac_hash=%s level=%s r2=%s", mac_hash, level, r2_ok)
    # Phase 3 (#492) : detect form-vs-API.
    # Browser : 303 redirect straight to the dashboard with welcome state.
    # API     : JSON AcceptResp for programmatic clients.
    accept_hdr = request.headers.get("accept", "")
    wants_json = "application/json" in accept_hdr and "text/html" not in accept_hdr
    if wants_json:
        return AcceptResp(ok=True, mac_hash=mac_hash, r2=r2_ok)
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url=f"/report/me/html?welcome=1&level={level}",
                             status_code=303)


@router.post("/change-level")
async def change_level(request: Request):
    """Phase 3 (#492) : change opt-in level from the dashboard.

    Adds/removes the MAC from the appropriate nft sets and updates the
    persisted level. Redirects back to /report/me/html.
    """
    ip, mac = _resolve(request)
    if not ip or not mac:
        raise HTTPException(400, "client mac unknown")
    cfg = _get_cfg()
    salt = _get_salt()
    mac_hash = macmod.hash_mac(mac, salt)

    try:
        form = await request.form()
        level = (form.get("level") or "r1").lower()
    except Exception:
        level = "r1"
    if level not in ("r0", "r1", "r2", "r3"):
        level = "r1"
    if level == "r2" and not cfg.r2.enabled:
        level = "r1"
    if level == "r3" and not Path("/etc/secubox/toolbox/wg/server.pubkey").exists():
        level = "r1"

    # Re-validate (idempotent extend)
    v_ok = nft.add_validated(mac, ttl="24h")
    # Membership in consented_r2_macs : add for r1/r2, remove for r0/r3
    if level in ("r1", "r2"):
        c_ok = nft.add_consented(mac, ttl="24h")
    else:
        c_ok = nft.del_consented(mac)
    # Membership in r2_banner_macs : add for r2, remove otherwise
    if level == "r2":
        b_ok = nft.add_r2_banner(mac, ttl="24h")
    else:
        b_ok = nft.del_r2_banner(mac)
    # Phase 6 (#496) : r3 WireGuard set
    if level == "r3":
        wg_ok = nft.add_r3_wg(mac, ttl="24h")
    else:
        wg_ok = nft.del_r3_wg(mac)

    store.upsert_client(mac_hash, ip, level=level)
    log.info("level switched mac_hash=%s -> %s (nft: validated=%s consented=%s banner=%s wg=%s)",
             mac_hash, level, v_ok, c_ok, b_ok, wg_ok)
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url=f"/report/me/html?switched=1&level={level}",
                             status_code=303)


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
    """Serve CA cert as PEM (Android-friendly).
    Chrome on Android prompts to install when MIME = application/x-x509-ca-cert."""
    return Response(
        content=ca.ca_pem(),
        media_type="application/x-x509-ca-cert",
        headers={"Content-Disposition": "attachment; filename=gondwana-toolbox.crt"},
    )


@router.get("/ca/android.der")
async def ca_android_der() -> Response:
    """Fallback DER binary for older Android versions / manual install."""
    return Response(
        content=ca.ca_der(),
        media_type="application/x-x509-ca-cert",
        headers={"Content-Disposition": "attachment; filename=gondwana-toolbox.der"},
    )


@router.get("/ca/android-help", response_class=HTMLResponse)
async def ca_android_help() -> HTMLResponse:
    """Step-by-step CA install guide for Android (Chrome + Settings flow)."""
    html = """<!DOCTYPE html><html lang=fr><head><meta charset=UTF-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Installer le certificat Gondwana ToolBoX — Android</title>
<style>body{font-family:sans-serif;background:#0a0a0f;color:#00ff55;padding:1.5rem;max-width:560px;margin:auto;line-height:1.6}
h1{color:#00ff55;text-shadow:0 0 4px #00dd44}h2{color:#cbb6ff;margin-top:1.5rem;font-size:1.1rem}
ol{padding-left:1.4rem}a.btn{display:block;text-align:center;padding:0.8rem;background:#9e76ff;color:#0a0a0f;
text-decoration:none;border-radius:4px;font-weight:bold;margin:1rem 0}code{background:#222;padding:0.1rem 0.4rem;border-radius:2px}</style>
</head><body>
<h1>🤖 Installer le certificat — Android</h1>
<p>Android &le; 13 et certaines apps (banques, gov) refusent les CAs utilisateur.
Le navigateur Chrome lui le respecte. R1/R2 fonctionnent dans Chrome ; les apps natives
peuvent rester en clear-text ou échouer.</p>

<a href="/ca/android.crt" class=btn>📥 Télécharger le certificat (.crt)</a>

<h2>Étape 1 — Télécharger</h2>
<p>Tap le bouton ci-dessus. Chrome demande où enregistrer le fichier
<code>gondwana-toolbox.crt</code> (Downloads).</p>

<h2>Étape 2 — Installer dans Réglages</h2>
<ol>
<li>Ouvre <b>Réglages</b> → <b>Sécurité</b> (ou <b>Sécurité et confidentialité</b>)</li>
<li>Cherche <b>Chiffrement et authentifiants</b> → <b>Installer un certificat</b></li>
<li>Choisis <b>Certificat CA</b></li>
<li>Sélectionne <code>gondwana-toolbox.crt</code> dans Downloads</li>
<li>Confirme l'avertissement (oui, c'est un CA tiers ; il vit le temps de ta session)</li>
</ol>

<h2>Étape 3 — Vérifier l'empreinte</h2>
<p>Après installation, retourne dans <b>Sécurité → Authentifiants de confiance →
Utilisateur</b> et compare l'empreinte SHA-1 affichée avec celle de la cabine :</p>
<p><code id=fp>chargement…</code></p>

<h2>⚠ Limite Android</h2>
<p>Depuis Android 7, les apps doivent <b>opt-in</b> aux CAs utilisateur via
<code>network_security_config.xml</code>. La plupart des apps banques/gov/streaming
NE LE FONT PAS — résultat : R1/R2 cassent leur connexion. Solution : utilise R0
pour ces apps, OU passe en R3 (WireGuard).</p>

<a href="/" class=btn style="background:transparent;color:#00ff55;border:1px solid #00ff55">← Retour splash</a>
<script>
fetch('/ca/fingerprint').then(r=>r.json()).then(d=>{document.getElementById('fp').textContent=d.sha1||'?';});
</script>
</body></html>"""
    return HTMLResponse(html)


@router.get("/cumulative-stats.json")
async def cumulative_stats_json() -> dict:
    """Public anonymous cumulative stats — fed by landing page + dashboards."""
    return _cumulative_stats()


@router.get("/landing", response_class=HTMLResponse)
@router.get("/cabine", response_class=HTMLResponse)
async def landing(request: Request) -> HTMLResponse:
    """Public landing page for the cabine — shown on kbin.gk2.secubox.in.

    Visitor-facing demo of the project : pitch + 4 levels + install + live
    cumulative anonymous stats + open source license + contact."""
    stats = _cumulative_stats()
    return HTMLResponse(_env.get_template("landing.html.j2").render(stats=stats),
                         headers={"Cache-Control": "public, max-age=60"})


@router.get("/ca/webclip-cabine.mobileconfig")
async def webclip_cabine() -> Response:
    """Phase 3 (#492) : iOS Add-to-Home-Screen profile that drops a 'ToolBoX
    Cabine' icon pointing at /report/me/html. User can then check the live
    session report in 1 tap, surviving Safari cache misses + native-app gaps."""
    import uuid as _uuid
    cfg = _get_cfg()
    body = _env.get_template("webclip.mobileconfig.j2").render(
        payload_uuid=str(_uuid.uuid4()),
        webclip_uuid=str(_uuid.uuid4()),
        report_url=f"http://{cfg.dhcp.gateway}/report/me/html",
    )
    return Response(
        content=body,
        media_type="application/x-apple-aspen-config",
        headers={"Content-Disposition": "attachment; filename=toolbox-cabine-icon.mobileconfig"},
    )


@router.get("/ca/install-help", response_class=HTMLResponse)
async def ca_install_help() -> HTMLResponse:
    return HTMLResponse(_env.get_template("ca-help.html.j2").render())


# Phase 6 (#496) : Android PWA manifest + R3 install page
# Android Chrome reads manifest.json + offers 'Add to Home Screen' = PWA
# (Android's equivalent of iOS WebClip).

@router.get("/manifest.json")
async def webapp_manifest(request: Request) -> dict:
    """Web App Manifest for Android Chrome 'Add to Home Screen' PWA install."""
    return {
        "name": "ToolBoX Cabine VILLAGE3B",
        "short_name": "ToolBoX",
        "description": "Cabine numérique Gondwana — diagnostic compromission iPhone/Android",
        "start_url": "/report/me/html",
        "scope": "/",
        "display": "standalone",
        "orientation": "portrait",
        "background_color": "#0a0a0f",
        "theme_color": "#00dd44",
        "icons": [
            {
                "src": "/qr/splash.png",
                "sizes": "232x232",
                "type": "image/png",
                "purpose": "any maskable"
            }
        ],
        "categories": ["security", "utilities"],
        "lang": "fr-FR"
    }


@router.get("/wg/r3-install", response_class=HTMLResponse)
async def wg_r3_install(request: Request) -> HTMLResponse:
    """R3 install page — 3-step install with per-OS instructions tabs.

    Optimized for first-time portable setup from anywhere (kbin.gk2.secubox.in).
    Step 1 = WG profile, Step 2 = CA install (per-OS), Step 3 = GO.
    """
    html = """<!DOCTYPE html><html lang=fr><head><meta charset=UTF-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<meta name=apple-mobile-web-app-capable content=yes>
<link rel=manifest href=/manifest.json>
<title>R3 — Tunnel portable Gondwana (install all-OS)</title>
<style>:root{--bg:#0a0a0f;--gold:#c9a84c;--phos:#00dd44;--phos-hot:#00ff55;--dim:#006622;--text:#e8e6d9;--purple:#9e76ff;--orange:#ffb347;--err:#e63946;--blue:#5fa8ff}
*{box-sizing:border-box;margin:0;padding:0}
html,body{background:var(--bg);color:var(--text);font-family:'Courier New',Menlo,monospace;line-height:1.5}
body{padding:1.2rem;max-width:720px;margin:auto}
h1{color:var(--gold);text-align:center;font-size:1.4rem;margin-bottom:0.2rem;letter-spacing:2px}
.lead{color:var(--phos);text-align:center;font-size:0.8rem;margin-bottom:1.4rem;opacity:0.85}
.lead b{color:var(--phos-hot)}
.step{border:1px solid #2a2a3f;border-left:4px solid var(--purple);padding:1rem 1.2rem;margin-bottom:1rem;background:linear-gradient(135deg,rgba(110,64,201,0.04),rgba(110,64,201,0.10));border-radius:6px;box-shadow:0 1px 8px rgba(0,0,0,0.25)}
.step h2{color:var(--purple);font-size:1rem;margin-bottom:0.6rem;display:flex;align-items:center;gap:8px}
.num{display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;background:var(--purple);color:#0a0a0f;border-radius:50%;font-weight:bold;font-size:0.95rem}
.qr{text-align:center;background:white;padding:14px;border-radius:8px;margin:0.6rem 0;box-shadow:0 2px 10px rgba(158,118,255,0.25)}
.qr img{max-width:300px;width:100%;height:auto}
.btn{display:block;text-align:center;padding:0.85rem 1rem;color:#0a0a0f;text-decoration:none;border-radius:6px;font-weight:bold;margin:0.5rem 0;font-size:0.95rem;transition:all 0.15s}
.btn-go{background:linear-gradient(90deg,var(--phos),var(--phos-hot));color:#0a0a0f;font-size:1.1rem;padding:1rem;letter-spacing:1px;text-shadow:0 0 6px rgba(0,255,85,0.5)}
.btn-warn{background:linear-gradient(90deg,var(--orange),#dd7e0a)}
.btn-small{display:inline-block;padding:0.4rem 0.8rem;background:var(--orange);color:#0a0a0f;border-radius:4px;font-weight:bold;font-size:0.78rem;text-decoration:none;margin:0.2rem 0.3rem 0.2rem 0}
.btn-small.blue{background:var(--blue)}
.btn:hover,.btn-small:hover{transform:translateY(-1px);box-shadow:0 4px 12px rgba(0,0,0,0.4)}
.alt{font-size:0.72rem;color:#909090;text-align:center;margin-top:0.4rem}
.alt a{color:var(--orange);text-decoration:underline}
.tip{font-size:0.72rem;color:#a0d8a8;background:rgba(0,221,68,0.05);border-left:2px solid var(--phos);padding:0.5rem 0.7rem;margin-top:0.5rem;border-radius:0 3px 3px 0}
.warn{font-size:0.78rem;color:#ffd6a0;background:rgba(255,179,71,0.08);border-left:3px solid var(--orange);padding:0.7rem;margin:0.4rem 0;border-radius:0 4px 4px 0}
.back{display:block;text-align:center;margin-top:1.5rem;color:#666;text-decoration:none;font-size:0.85rem}
.back:hover{color:var(--phos)}
.tabs{display:flex;gap:2px;border-bottom:1px solid #2a2a3f;margin-bottom:0.6rem;flex-wrap:wrap}
.tab{background:transparent;border:0;color:#888;padding:0.5rem 0.9rem;font-family:inherit;font-size:0.82rem;cursor:pointer;border-bottom:2px solid transparent;transition:all 0.15s}
.tab.active{color:var(--purple);border-bottom-color:var(--purple);background:rgba(158,118,255,0.06)}
.tab:hover{color:var(--text)}
.tab-content{display:none;padding:0.4rem 0.2rem}
.tab-content.active{display:block}
.tab-content h3{color:var(--gold);font-size:0.85rem;margin-bottom:0.3rem}
.tab-content ol{padding-left:1.4rem;font-size:0.82rem;line-height:1.7}
.tab-content code{background:#1a1a25;color:var(--phos-hot);padding:0.15rem 0.4rem;border-radius:3px;font-size:0.78rem;display:inline-block;word-break:break-all}
pre{background:#1a1a25;color:var(--phos-hot);padding:0.6rem 0.8rem;border-radius:4px;font-size:0.75rem;overflow-x:auto;margin:0.4rem 0;line-height:1.5}
</style></head><body>

<h1>🌐 R3 — TUNNEL PORTABLE</h1>
<p class=lead>3 étapes · install <b>multi-OS</b> · marche partout (4G / WiFi tiers)</p>

<div class=step>
<h2><span class=num>1</span> 📲 Profil WireGuard</h2>
<p style="font-size:0.85rem;margin-bottom:0.4rem">Installe l'app <b>WireGuard</b> (gratuite, tous OS) puis scanne ce QR :</p>
<div class=qr><img src="/wg/qr.png" alt="QR profil WireGuard"/></div>
<p class=alt>📥 Pas de scanner ? <a href="/wg/profile/new">Télécharger village3b-toolbox.conf</a></p>
<div class=tip>
🌐 <b>WireGuard download :</b>
<a class=btn-small href="https://apps.apple.com/app/wireguard/id1441195209">iOS</a>
<a class=btn-small href="https://play.google.com/store/apps/details?id=com.wireguard.android">Android</a>
<a class=btn-small href="https://www.wireguard.com/install/">Linux/Win/Mac</a>
</div>
</div>

<div class=step>
<h2><span class=num>2</span> 🔐 Certificat R3 (par OS)</h2>
<p style="font-size:0.85rem;margin-bottom:0.5rem">Le CA <b>« Gondwana ToolBoX R3 CA »</b> doit être ajouté à la racine de confiance.</p>

<div class=tabs>
<button class="tab active" data-tab=ios>🍎 iOS / iPad</button>
<button class="tab" data-tab=android>🤖 Android</button>
<button class="tab" data-tab=linux>🐧 Linux</button>
<button class="tab" data-tab=mac>💻 macOS</button>
<button class="tab" data-tab=win>🪟 Windows</button>
</div>

<div class="tab-content active" data-content=ios>
<a href="/wg/ca.mobileconfig" class="btn btn-warn">📲 Installer .mobileconfig (1-tap)</a>
<h3>Puis :</h3>
<ol>
<li>Réglages → Général → <b>VPN et gestion d'appareils</b> → installer le profil</li>
<li>Réglages → Général → Information → <b>Réglages de confiance des certificats</b></li>
<li>Activer le toggle <b>« Gondwana ToolBoX R3 CA »</b> 🟢</li>
</ol>
</div>

<div class="tab-content" data-content=android>
<a href="/wg/ca.crt" class="btn btn-warn">📥 Télécharger CA (.crt format Android)</a>
<div class=warn>
⚠ Chrome ne peut PAS installer un CA directement (sécurité Android 11+).
Tu DOIS passer par les <b>Paramètres système</b>.
<br><br>
🆕 Si tu as déjà un essai raté avec « émis par null » : <b>supprime l'ancien fichier</b>
dans Téléchargements + relance le téléchargement (le CA a été régénéré).
</div>
<h3>Procédure (toutes versions Android 7+) :</h3>
<ol>
<li>Tap <b>📥 Télécharger CA</b> ci-dessus → sauvé dans Téléchargements
   sous <code>gondwana-toolbox-r3-ca.crt</code></li>
<li>Ouvre <b>Paramètres système</b> (pas Chrome / pas Firefox)</li>
<li>→ <b>Sécurité et confidentialité</b> (ou « Sécurité »)</li>
<li>→ <b>Plus de paramètres de sécurité</b> → <b>Chiffrement et authentifiants</b>
   (ou « Identifiants » selon constructeur)</li>
<li>→ <b>Installer un certificat</b> → <b>Certificat d'autorité (CA)</b></li>
<li>Accepter l'avertissement de sécurité</li>
<li>Sélectionne <code>gondwana-toolbox-r3-ca.crt</code> dans Téléchargements</li>
<li>Confirme le PIN/empreinte si demandé</li>
</ol>
<h3>Fallback PEM :</h3>
<a href="/wg/ca.pem" style="color:var(--orange);font-size:0.85rem">📥 Télécharger en .pem</a>
si le .crt ne s'ouvre pas (rare).
<h3>Vérification :</h3>
<pre>Paramètres → Sécurité → Identifiants
de confiance → onglet UTILISATEUR
→ « Gondwana ToolBoX R3 CA » présent ✓</pre>
</div>

<div class="tab-content" data-content=linux>
<a href="/wg/ca.pem" class="btn btn-warn">📥 Télécharger ca.pem</a>
<h3>Debian / Ubuntu :</h3>
<pre>sudo cp ca.pem /usr/local/share/ca-certificates/gondwana-toolbox-r3.crt
sudo update-ca-certificates</pre>
<h3>Fedora / RHEL :</h3>
<pre>sudo cp ca.pem /etc/pki/ca-trust/source/anchors/gondwana-toolbox-r3.crt
sudo update-ca-trust</pre>
<h3>Arch :</h3>
<pre>sudo trust anchor --store ca.pem</pre>
<h3>Vérif Firefox / Chrome :</h3>
<pre># Firefox utilise son propre store
# Chrome utilise NSS :
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," \\
    -n "Gondwana ToolBoX R3 CA" -i ca.pem</pre>
<h3>Tunnel rapide (Linux) :</h3>
<pre>wget /wg/profile/new -O village3b.conf
sudo wg-quick up ./village3b.conf
# stop :
sudo wg-quick down ./village3b.conf</pre>
</div>

<div class="tab-content" data-content=mac>
<a href="/wg/ca.pem" class="btn btn-warn">📥 Télécharger ca.pem</a>
<h3>Install (Keychain Access) :</h3>
<ol>
<li>Double-clic <code>ca.pem</code> → s'ouvre dans <b>Trousseaux d'accès</b></li>
<li>Choisir trousseau <b>Système</b> (pas Login)</li>
<li>Authentifier avec ton mot de passe macOS</li>
<li>Double-clic le cert installé → <b>Approuver</b> → « Toujours approuver »</li>
</ol>
<h3>Ou en CLI :</h3>
<pre>sudo security add-trusted-cert -d -r trustRoot \\
    -k /Library/Keychains/System.keychain ca.pem</pre>
</div>

<div class="tab-content" data-content=win>
<a href="/wg/ca.pem" class="btn btn-warn">📥 Télécharger ca.pem</a>
<h3>Install (PowerShell admin) :</h3>
<pre>Import-Certificate -FilePath .\\ca.pem `
    -CertStoreLocation Cert:\\LocalMachine\\Root</pre>
<h3>Ou GUI :</h3>
<ol>
<li>Double-clic <code>ca.pem</code> → <b>Installer le certificat</b></li>
<li>Emplacement : <b>Ordinateur local</b> (pas Utilisateur courant)</li>
<li>Magasin : <b>Autorités de certification racines de confiance</b></li>
</ol>
</div>
</div>

<div class=step>
<h2><span class=num>3</span> 🚀 Activer le tunnel</h2>
<p style="font-size:0.85rem;margin-bottom:0.5rem">App WireGuard → toggle <b>ON</b> sur le profil <code>village3b-toolbox</code>. L'icône VPN apparaît dans la barre d'état.</p>
<a href="/report/me/html" class="btn btn-go">📊 GO — Voir mon rapport live</a>
<div class=tip>
✓ Trafic chiffré entre device et cabine (jamais en clair sur Internet)<br>
✓ Bandeau apparaît sur toutes les pages HTTPS<br>
✓ Signal / WhatsApp / Telegram / iCloud / banques → <b>passthrough</b> (jamais déchiffrés)
</div>
</div>

<p style="text-align:center;font-size:0.78rem;color:#666;margin-top:1.5rem">
📖 Wiki complet : <a href="https://github.com/CyberMind-FR/secubox-deb/wiki/R3-WireGuard-install" style="color:var(--purple)">github.com/CyberMind-FR/secubox-deb/wiki/R3-WireGuard-install</a>
</p>

<a href="/landing" class=back>← Retour landing</a>

<script>
document.querySelectorAll('.tab').forEach(function(t){
  t.addEventListener('click', function(){
    var tn = this.dataset.tab;
    document.querySelectorAll('.tab').forEach(function(x){x.classList.remove('active');});
    this.classList.add('active');
    document.querySelectorAll('.tab-content').forEach(function(x){x.classList.remove('active');});
    document.querySelector('[data-content='+tn+']').classList.add('active');
  });
});
</script>
</body></html>"""
    return HTMLResponse(html)


# ── Phase 6.F (#496) : MITM filtering whitelist ─────────────────────
# Some apps use cert-pinning / E2E protocols that BREAK if mitm decrypts
# their TLS (Signal, WhatsApp, Telegram, Apple Push, banking apps with
# pinned certs). They MUST be bypassed at the mitm layer (ignore_hosts).
# The whitelist file is the single source of truth — admin UI edits it,
# mitm reads it via --set ignore_hosts on (re)start.

MITM_BYPASS_FILE = Path("/var/lib/secubox/toolbox/mitm-bypass.conf")
_MITM_BYPASS_DEFAULT_ENTRIES = [
    "# SecuBox ToolBoX :: mitm bypass list (regex, one per line)",
    "# These hosts/domains are NOT decrypted by mitm — TLS passthrough.",
    "# Required for apps with cert pinning / E2E protocols.",
    "# Edit via /admin/filter-control or by hand, then restart mitm services.",
    "",
    "# Signal — pinned certs, E2E",
    "(.+\\.)?signal\\.org",
    "(.+\\.)?signal\\.com",
    "",
    "# WhatsApp — cert pinning",
    "(.+\\.)?whatsapp\\.net",
    "(.+\\.)?whatsapp\\.com",
    "",
    "# Telegram — pinned + custom protocols",
    "(.+\\.)?telegram\\.org",
    "(.+\\.)?telegram\\.me",
    "",
    "# Apple Push / iMessage / FaceTime — pinned",
    "(.+\\.)?push\\.apple\\.com",
    "(.+\\.)?gateway\\.icloud\\.com",
    "(.+\\.)?apple-cloudkit\\.com",
    "",
    "# Bank apps (common French banks) — pinned + ANSSI requirement",
    "(.+\\.)?bnpparibas\\.net",
    "(.+\\.)?creditmutuel\\.fr",
    "(.+\\.)?ca-.*\\.fr",  # Crédit Agricole regional sites
    "(.+\\.)?banquepopulaire\\.fr",
    "(.+\\.)?caisse-epargne\\.fr",
    "(.+\\.)?societegenerale\\.fr",
]


def _ensure_bypass_file() -> None:
    if not MITM_BYPASS_FILE.exists():
        MITM_BYPASS_FILE.parent.mkdir(parents=True, exist_ok=True)
        MITM_BYPASS_FILE.write_text("\n".join(_MITM_BYPASS_DEFAULT_ENTRIES) + "\n")


def _load_bypass_entries() -> list[str]:
    _ensure_bypass_file()
    try:
        lines = MITM_BYPASS_FILE.read_text().splitlines()
        return [ln for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]
    except Exception:
        return []


@router.get("/admin/filter-control", response_class=HTMLResponse)
async def admin_filter_control() -> HTMLResponse:
    """Whitelist control panel — view + edit mitm bypass entries."""
    entries = _load_bypass_entries()
    raw = MITM_BYPASS_FILE.read_text() if MITM_BYPASS_FILE.exists() else ""
    rows = "\n".join(
        f'<tr><td><code>{e}</code></td><td><form method=POST action=/admin/filter-control/remove style=display:inline><input type=hidden name=entry value="{e}"/><button class=del>✕</button></form></td></tr>'
        for e in entries
    )
    html = f"""<!DOCTYPE html><html lang=fr><head><meta charset=UTF-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Admin :: Filter Control</title>
<style>:root{{--bg:#0a0a0f;--gold:#c9a84c;--phos:#00dd44;--purple:#9e76ff;--text:#e8e6d9;--err:#e63946}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Courier New',monospace;background:var(--bg);color:var(--text);padding:1.2rem;max-width:780px;margin:auto;line-height:1.5}}
h1{{color:var(--gold);font-size:1.3rem;margin-bottom:0.4rem}}
.lead{{color:var(--purple);font-size:0.85rem;margin-bottom:1.2rem}}
table{{width:100%;border-collapse:collapse;margin-bottom:1rem;background:rgba(110,64,201,0.03);border:1px solid #2a2a3f;border-radius:4px}}
td,th{{padding:0.4rem 0.7rem;border-bottom:1px solid #2a2a3f;font-size:0.8rem;text-align:left}}
th{{background:rgba(110,64,201,0.15);color:var(--purple);font-weight:bold}}
code{{color:var(--phos);background:#111;padding:0.1rem 0.3rem;border-radius:2px}}
.del{{background:var(--err);color:white;border:0;padding:0.2rem 0.5rem;border-radius:3px;cursor:pointer;font-weight:bold}}
input[type=text]{{flex:1;background:#111;color:var(--text);border:1px solid #2a2a3f;padding:0.5rem;border-radius:4px;font-family:monospace;font-size:0.85rem}}
.add{{display:flex;gap:0.5rem;margin:0.5rem 0 1rem}}
button.add{{background:var(--phos);color:#0a0a0f;border:0;padding:0.5rem 1rem;border-radius:4px;cursor:pointer;font-weight:bold}}
.note{{font-size:0.75rem;color:#a0a0a0;background:rgba(255,179,71,0.06);border-left:2px solid #ffb347;padding:0.6rem 0.8rem;margin-top:1rem;border-radius:0 3px 3px 0}}
a.back{{color:var(--purple);text-decoration:underline;font-size:0.85rem}}
</style></head><body>
<h1>🛡️ Mitm Filter Control</h1>
<p class=lead>Hosts bypass — TLS passthrough, jamais déchiffrés. Apps avec cert-pinning ou E2E.</p>

<form method=POST action=/admin/filter-control/add class=add>
  <input type=text name=entry placeholder="ex: (.+\\.)?example\\.com" required>
  <button class=add type=submit>➕ Ajouter</button>
</form>

<table>
<tr><th>Pattern (regex)</th><th></th></tr>
{rows or '<tr><td colspan=2 style="color:#666;text-align:center;padding:1rem">Aucune entrée.</td></tr>'}
</table>

<div class=note>
ℹ Les modifications nécessitent un redémarrage de <code>secubox-toolbox-mitm-wg.service</code> + <code>secubox-mitmproxy</code> pour prendre effet.
<br><b>Source de vérité :</b> <code>{MITM_BYPASS_FILE}</code> ({len(entries)} pattern{'s' if len(entries)>1 else ''})
</div>

<p style=margin-top:1.5rem><a href=/admin/ class=back>← Admin home</a></p>
</body></html>"""
    return HTMLResponse(html)


@router.post("/admin/filter-control/add")
async def admin_filter_add(request: Request) -> Response:
    form = await request.form()
    entry = (form.get("entry") or "").strip()
    if entry and "\n" not in entry:
        _ensure_bypass_file()
        with MITM_BYPASS_FILE.open("a") as f:
            f.write(entry + "\n")
    return RedirectResponse("/admin/filter-control", status_code=303)


@router.post("/admin/filter-control/remove")
async def admin_filter_remove(request: Request) -> Response:
    form = await request.form()
    entry = (form.get("entry") or "").strip()
    if entry and MITM_BYPASS_FILE.exists():
        lines = MITM_BYPASS_FILE.read_text().splitlines()
        new_lines = [ln for ln in lines if ln.strip() != entry]
        MITM_BYPASS_FILE.write_text("\n".join(new_lines) + "\n")
    return RedirectResponse("/admin/filter-control", status_code=303)


@router.get("/admin/filter-control/regex")
async def admin_filter_regex() -> dict:
    """Returns the alternation regex consumable by mitmproxy --set ignore_hosts.
    Used by the mitm-wg/mitm services startup scripts."""
    entries = _load_bypass_entries()
    if not entries:
        return {"regex": "", "count": 0}
    # mitmproxy ignore_hosts wants a single regex; join with | wrapped in non-capture group
    regex = "(" + "|".join(entries) + ")"
    return {"regex": regex, "count": len(entries)}


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


# Phase 3.x (#497) : 3 QR code endpoints — splash, cert install, webclip
# Used by the splash page + reports + the public poster (POSTER-grand-public).

def _qr_png(payload: str, size: int = 8, border: int = 2) -> bytes:
    """Generate a PNG QR code for the given payload. Returns bytes."""
    import qrcode
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=size,
        border=border,
    )
    qr.add_data(payload)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    import io
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _portal_url(request: "Request", path: str = "/") -> str:
    """Build absolute URL based on request Host header — works regardless of
    whether the portal is reached via 10.99.0.1, village3b, or external."""
    host = request.headers.get("host", "10.99.0.1:8088")
    scheme = "http"  # captive portal is HTTP-only by design
    return f"{scheme}://{host.rstrip('/')}{path}"


@router.get("/qr/splash.png")
async def qr_splash(request: Request) -> Response:
    """QR encodes the splash URL — scannable from another device to join VILLAGE3B."""
    return Response(content=_qr_png(_portal_url(request, "/")),
                     media_type="image/png",
                     headers={"Cache-Control": "public, max-age=3600"})


@router.get("/qr/cert.png")
async def qr_cert(request: Request) -> Response:
    """QR encodes the CA install URL (.mobileconfig)."""
    return Response(content=_qr_png(_portal_url(request, "/ca/mobileconfig")),
                     media_type="image/png",
                     headers={"Cache-Control": "public, max-age=3600"})


@router.get("/qr/webclip.png")
async def qr_webclip(request: Request) -> Response:
    """QR encodes the webclip URL (Add-to-Home-Screen profile)."""
    return Response(content=_qr_png(_portal_url(request, "/ca/webclip-cabine.mobileconfig")),
                     media_type="image/png",
                     headers={"Cache-Control": "public, max-age=3600"})


# Phase 6 (#496) : WireGuard endpoints — R3 mode

@router.get("/wg/profile/new")
async def wg_profile_new(request: Request) -> Response:
    """Generate a fresh WG profile for this client. Returns .conf content
    suitable for direct import in WireGuard app (iOS + macOS + Linux).

    Phase 6.H (#496) : also registers the new peer in store.clients
    with level=r3 so reports, level lookups, and admin webui all show
    the WG client correctly (otherwise mac_hash is unknown to DB).
    """
    try:
        from . import wg as _wg
    except ImportError:
        raise HTTPException(503, "WG module not available (Phase 6 not provisioned)")
    profile = _wg.generate_client_profile(client_label=request.headers.get("user-agent", "")[:60])

    # Register the freshly generated peer in the clients table so all
    # downstream consumers (store.get_client_level, _aggregate_session,
    # /admin/clients/rich) know about it. mac_hash = sha256(pubkey)[:16].
    import hashlib as _h
    wg_hash = _h.sha256(profile["client_pubkey"].encode()).hexdigest()[:16]
    try:
        store.upsert_client(wg_hash, profile["client_ip"], level="r3")
    except Exception as e:
        log.warning("wg peer upsert failed for %s: %s", wg_hash, e)

    return Response(
        content=profile["conf_text"],
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": "attachment; filename=village3b-toolbox.conf",
            "X-Client-PubKey": profile["client_pubkey"],
            "X-Client-IP": profile["client_ip"],
            "X-Client-Hash": wg_hash,
        },
    )


@router.get("/wg/qr.png")
async def wg_qr(request: Request) -> Response:
    """QR code encoding the WG profile .conf — scannable by the iOS WG app."""
    try:
        from . import wg as _wg
    except ImportError:
        raise HTTPException(503, "WG module not available")
    profile = _wg.generate_client_profile(client_label=request.headers.get("user-agent", "")[:60])
    return Response(
        content=_qr_png(profile["conf_text"], size=6, border=2),
        media_type="image/png",
        headers={"Cache-Control": "no-store"},
    )


@router.get("/wg/ca.pem")
async def wg_ca_pem() -> Response:
    """The mitm-wg-specific CA — REQUIRED for R3 HTTPS interception.

    Separate from the R1/R2 CA at /ca/mobileconfig. iPhone in R3 mode must
    install BOTH the WG profile (tunnel) AND this CA (trust mitm certs).
    """
    p = Path("/etc/secubox/toolbox/ca-wg/mitmproxy-ca-cert.pem")
    if not p.exists():
        raise HTTPException(404, "mitm-wg CA not yet generated")
    return Response(
        content=p.read_bytes(),
        media_type="application/x-x509-ca-cert",
        headers={"Content-Disposition": "attachment; filename=gondwana-toolbox-wg.crt"},
    )


@router.get("/wg/ca.der")
@router.get("/wg/ca.crt")
async def wg_ca_der() -> Response:
    """DER (binary) version of the mitm-wg CA. Some Android installers
    (especially Android 11+ Settings → CA certificate) prefer DER over PEM
    and reject the .pem extension. Same cert, just binary-encoded."""
    p = Path("/etc/secubox/toolbox/ca-wg/mitmproxy-ca-cert.cer")
    if not p.exists():
        raise HTTPException(404, "mitm-wg CA DER not yet generated")
    return Response(
        content=p.read_bytes(),
        media_type="application/x-x509-ca-cert",
        headers={"Content-Disposition": "attachment; filename=gondwana-toolbox-r3-ca.crt"},
    )


@router.get("/wg/ca.mobileconfig")
async def wg_ca_mobileconfig() -> Response:
    """iOS profile that installs the mitm-wg CA in trust store."""
    import uuid as _uuid
    p = Path("/etc/secubox/toolbox/ca-wg/mitmproxy-ca-cert.pem")
    if not p.exists():
        raise HTTPException(404, "mitm-wg CA not yet generated")
    pem = p.read_text()
    # Strip headers + base64 body
    body_lines = [ln for ln in pem.splitlines() if ln and not ln.startswith("-----")]
    ca_b64 = "\n".join(body_lines)
    payload_uuid = str(_uuid.uuid4()).upper()
    cert_uuid = str(_uuid.uuid4()).upper()
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>PayloadType</key><string>Configuration</string>
<key>PayloadVersion</key><integer>1</integer>
<key>PayloadIdentifier</key><string>fr.cybermind.gondwana.toolbox.wg-ca</string>
<key>PayloadUUID</key><string>{payload_uuid}</string>
<key>PayloadDisplayName</key><string>Gondwana ToolBoX WG CA (R3)</string>
<key>PayloadDescription</key><string>Certificat racine WireGuard mitm pour analyse R3.</string>
<key>PayloadOrganization</key><string>CyberMind / Gondwana</string>
<key>PayloadContent</key><array><dict>
<key>PayloadType</key><string>com.apple.security.root</string>
<key>PayloadVersion</key><integer>1</integer>
<key>PayloadIdentifier</key><string>fr.cybermind.gondwana.toolbox.wg-ca.cert</string>
<key>PayloadUUID</key><string>{cert_uuid}</string>
<key>PayloadDisplayName</key><string>Gondwana ToolBoX WG Root CA</string>
<key>PayloadCertificateFileName</key><string>gondwana-toolbox-wg-ca.pem</string>
<key>PayloadContent</key><data>{ca_b64}</data>
</dict></array></dict></plist>"""
    return Response(
        content=xml,
        media_type="application/x-apple-aspen-config",
        headers={"Content-Disposition": "attachment; filename=gondwana-toolbox-wg.mobileconfig"},
    )


@router.get("/wg/status")
async def wg_status() -> dict:
    """Running wg-toolbox interface state (peer count, handshakes)."""
    import subprocess
    try:
        out = subprocess.run(
            ["wg", "show", "wg-toolbox"],
            capture_output=True, text=True, timeout=2, check=False,
        ).stdout
        return {"interface": "wg-toolbox", "active": "peer:" in out,
                "peer_count": out.count("peer:"),
                "endpoint": "kbin.gk2.secubox.in:51820"}
    except Exception as e:
        return {"interface": "wg-toolbox", "active": False, "error": str(e)[:80]}


@router.get("/qr/{target}")
async def qr_generic(target: str, request: Request) -> Response:
    """Generic fallback : ?target=splash|cert|webclip|fingerprint maps to fixed
    URLs ; anything else encodes the literal target string."""
    targets = {
        "splash": _portal_url(request, "/"),
        "cert": _portal_url(request, "/ca/mobileconfig"),
        "webclip": _portal_url(request, "/ca/webclip-cabine.mobileconfig"),
        "report": _portal_url(request, "/report/me/html"),
        "fingerprint": _portal_url(request, "/ca/fingerprint"),
    }
    payload = targets.get(target.removesuffix(".png"), target)
    return Response(content=_qr_png(payload),
                     media_type="image/png",
                     headers={"Cache-Control": "public, max-age=3600"})


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
    # Phase 3 (#492) : transparency layer state
    analysis_breakdown: dict[str, int] = {}
    host_analysis: dict[str, dict] = {}
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
                    # Phase 3 (#492) : analysis_status breakdown
                    status = p.get("analysis_status")
                    if status:
                        analysis_breakdown[status] = analysis_breakdown.get(status, 0) + 1
                        # Keep a per-host status for the quality table
                        host_analysis[host] = {
                            "status": status,
                            "reason": p.get("analysis_reason", ""),
                        }
                elif source == "cookies":
                    cookies_total_set += p.get("set_cookie_count", 0)
                    cookies_total_sent += p.get("cookie_count", 0)
                    if len(cookies_urls) < 15:
                        cookies_urls.append({
                            "url": p.get("url", "?")[:120],
                            "set": p.get("set_cookie_count", 0),
                            "sent": p.get("cookie_count", 0),
                            "set_cookie_names": p.get("set_cookie_names", []),
                            "cookie_names": p.get("cookie_names", []),
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

    # Phase 2a+ : combine DPI hosts (HTTP host or IP) with JA4 SNIs to get
    # real hostnames for classification. iOS captive probes + cert-pinned apps
    # only expose SNIs ; we lose ~80% of classification data without this merge.
    classifiable_hosts: dict[str, int] = dict(dpi_hosts)
    for sni in ja4_snis:
        classifiable_hosts[sni] = classifiable_hosts.get(sni, 0) + 1

    # ── 3. Phase 2a SOC scoring : threat-intel + DGA + beaconing ──
    # Threat-intel : match IPs in feeds (resolve hosts isn't done here — match domains
    # directly). On DPI hosts (which are domain names from SNI/Host) we check both.
    ti_matches: list[dict] = []
    unique_hosts_list = list(classifiable_hosts.keys())
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
    # Use combined (DPI + SNI) so classification works on FQDNs not IPs
    top_dpi = sorted(classifiable_hosts.items(), key=lambda x: -x[1])[:15]

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
        "threat_intel_matches": _enrich_with_geo(ti_matches[:10]),
        "dga_candidates": _enrich_dga_with_geo(dga_candidates[:10]),
        "beaconing_candidates": _enrich_beacon_with_geo(beacon_candidates[:10]),
        # ── Phase 2a+ (#486) geo + app classification + UA analyzer ──
        "dpi_classified": dpi_class.analyze_hosts(unique_hosts_list[:50]),
        "geo_top_hosts": _enrich_top_dpi_with_geo(top_dpi),
        "avatar_analysis": avatar_analysis.analyze_user_agents(user_agents),
        "cookies_providers": cookie_analysis.top_providers(cookies_urls, limit=10),
        # ── Phase 2b (#488) : pull events from receiving modules ──
        "mitm_modules": _pull_mitm_module_events(mac_hash),
        # ── Phase 3 (#492) : transparency layer ──
        "transparency": _build_transparency(
            analysis_breakdown, host_analysis, dpi_hosts, ja4_snis,
        ),
    }


def _build_transparency(
    breakdown: dict[str, int],
    host_analysis: dict[str, dict],
    dpi_hosts: dict[str, int],
    ja4_snis: set,
) -> dict:  # noqa: C901
    """Phase 3 (#492) : pack the inspection breakdown + per-host quality table.

    The breakdown shows what % of traffic was inspected / bypassed / pinned /
    e2e. The per-host quality table grades each destination via passive or
    active signals (currently passive, since header capture is not yet wired).
    """
    total = sum(breakdown.values()) or 1
    pct = {k: round(100 * v / total, 1) for k, v in breakdown.items()}

    # Backfill any host without explicit analysis_status (legacy events)
    for h in dpi_hosts:
        if h not in host_analysis:
            # Best-effort post-hoc tag : whitelist match → bypass, else inspected
            target = h.lower()
            if _HAS_TRANSPARENCY and _whitelist_mod.is_whitelisted(target):
                host_analysis[h] = {
                    "status": "bypassed-whitelist",
                    "reason": (_whitelist_mod.match(target) or {}).get("reason", ""),
                }
            else:
                host_analysis[h] = {
                    "status": "inspected",
                    "reason": "MITM decryption (post-hoc tag)",
                }

    # Build per-host quality (passive grading from what we have)
    per_host: list[dict] = []
    if _HAS_TRANSPARENCY:
        for h, info in host_analysis.items():
            status = info.get("status", "inspected")
            is_e2e = status == "e2e-opaque"
            # We don't know tls_version per host without further capture ; assume
            # 13 for whitelisted (cert-pinned apps use modern TLS) and unknown otherwise
            tls_v = "13" if status in ("bypassed-whitelist", "pinned-failed-mitm", "e2e-opaque") else None
            g = _sec_quality.grade_passive(
                tls_version=tls_v,
                sni=h if h in ja4_snis else None,
                is_e2e_messaging=is_e2e,
            )
            per_host.append({
                "host": h,
                "grade": g["grade"],
                "score": g["score"],
                "status": status,
                "reason": info.get("reason", ""),
            })
        # Sort : worst quality first (catches user attention)
        per_host.sort(key=lambda x: (x["score"], x["host"]))

    # Whitelist sanity stats
    wl_stats = _whitelist_mod.stats() if _HAS_TRANSPARENCY else {"count": 0}

    # Phase 3 (#492) : count whitelist hits per pattern + per category.
    # iPhone usage stores IPs in dpi_hosts (cert-pinning bypasses) but SNIs
    # in ja4_snis (TLS clienthello visible). Iterate BOTH so apple.com etc.
    # actually match patterns like *.apple.com.
    wl_hits_by_pattern: dict[str, int] = {}
    wl_hits_by_category: dict[str, int] = {}
    wl_hits_total = 0
    if _HAS_TRANSPARENCY:
        # Merge dpi_hosts (IP-tagged counts) and ja4_snis (FQDN tags with count 1)
        all_hosts: dict[str, int] = dict(dpi_hosts)
        for sni in ja4_snis:
            all_hosts[sni] = all_hosts.get(sni, 0) + 1
        for h, count in all_hosts.items():
            entry = _whitelist_mod.match(h)
            if entry:
                pat = entry.get("pattern", h)
                cat = entry.get("category", "other")
                wl_hits_by_pattern[pat] = wl_hits_by_pattern.get(pat, 0) + count
                wl_hits_by_category[cat] = wl_hits_by_category.get(cat, 0) + count
                wl_hits_total += count

    # Phase 3 (#492) : attempt counters — full transparency including failures
    attempts = {
        "total": sum(breakdown.values()),
        "inspected": breakdown.get("inspected", 0),
        "bypassed_whitelist": breakdown.get("bypassed-whitelist", 0),
        "pinned_failed": breakdown.get("pinned-failed-mitm", 0),
        "e2e_opaque": breakdown.get("e2e-opaque", 0),
        "blocked": breakdown.get("blocked", 0),  # Phase 4 placeholder
    }

    # Sensitivity profile info (rule engine)
    sensitivity = None
    try:
        from secubox_core import rule_engine as _re
        sensitivity = _re.get_sensitivity()
    except Exception:
        pass

    return {
        "breakdown": breakdown,
        "breakdown_pct": pct,
        "total_events": total,
        "per_host": per_host[:50],
        "whitelist_stats": wl_stats,
        "has_transparency": _HAS_TRANSPARENCY,
        # Phase 3 metrics for richer reporting
        "attempts": attempts,
        "whitelist_hits": {
            "total": wl_hits_total,
            "top_patterns": sorted(
                [{"pattern": k, "count": v} for k, v in wl_hits_by_pattern.items()],
                key=lambda x: -x["count"],
            )[:15],
            "by_category": wl_hits_by_category,
        },
        "sensitivity": sensitivity,
    }


# ── Phase 2b (#488) : cross-module mitm events pull ──

_MITM_MODULES = [
    ("dpi", "/run/secubox/dpi.sock"),
    ("cookies", "/run/secubox/cookies.sock"),
    ("avatar", "/run/secubox/avatar.sock"),
    ("soc", "/run/secubox/soc.sock"),
    ("threat-analyst", "/run/secubox/threat-analyst.sock"),
]


def _pull_mitm_module_events(mac_hash: str) -> dict:
    """Query each receiving module's GET /mitm-events for this client.

    Returns a dict {module: {count, sample_events}} for the report. Errors per
    module are non-fatal — if a module is down, it just shows count=0.
    """
    import socket as _sock
    import urllib.parse as _up
    import http.client as _hc

    out: dict[str, dict] = {}
    for kind, sock_path in _MITM_MODULES:
        try:
            class UDSConnection(_hc.HTTPConnection):
                def connect(self):
                    self.sock = _sock.socket(_sock.AF_UNIX, _sock.SOCK_STREAM)
                    self.sock.settimeout(self.timeout)
                    self.sock.connect(sock_path)

            conn = UDSConnection("localhost", timeout=2)
            qs = _up.urlencode({"mac_hash": mac_hash, "limit": 20})
            conn.request("GET", f"/mitm-events?{qs}")
            resp = conn.getresponse()
            if resp.status == 200:
                import json as _json
                data = _json.loads(resp.read().decode("utf-8", errors="ignore")[:50000])
                out[kind] = {
                    "count": data.get("count", 0),
                    "sample": data.get("events", [])[:5],
                }
            else:
                out[kind] = {"count": 0, "error": f"HTTP {resp.status}"}
            conn.close()
        except FileNotFoundError:
            out[kind] = {"count": 0, "error": "socket-missing"}
        except Exception as e:
            out[kind] = {"count": 0, "error": str(e)[:60]}
    return out


def _enrich_with_geo(matches: list[dict]) -> list[dict]:
    """Add geo info to threat_intel matches."""
    out = []
    for m in matches:
        ioc = m.get("ioc") or ""
        info = geo.lookup(ioc) if ioc else {}
        out.append({**m, "flag": info.get("flag", ""), "country": info.get("country_iso", ""), "asn_org": info.get("asn_org", "")})
    return out


def _enrich_dga_with_geo(candidates: list[dict]) -> list[dict]:
    out = []
    for c in candidates:
        info = geo.lookup(c.get("host", ""))
        out.append({**c, "flag": info.get("flag", ""), "country": info.get("country_iso", ""), "asn_org": info.get("asn_org", "")})
    return out


def _enrich_beacon_with_geo(candidates: list[dict]) -> list[dict]:
    out = []
    for c in candidates:
        info = geo.lookup(c.get("host", ""))
        out.append({**c, "flag": info.get("flag", ""), "country": info.get("country_iso", ""), "asn_org": info.get("asn_org", "")})
    return out


def _enrich_top_dpi_with_geo(top_dpi: list[tuple]) -> list[dict]:
    """Enrich top_dpi with geo + dpi_class + emoji."""
    out = []
    for host, count in top_dpi:
        info = geo.lookup(host)
        cls = dpi_class.classify_host(host)
        out.append({
            "host": host,
            "count": count,
            "flag": info.get("flag", ""),
            "country": info.get("country_iso", ""),
            "asn": info.get("asn", 0),
            "asn_org": info.get("asn_org", ""),
            "app": cls["app"],
            "category": cls["category"],
            "emoji": cls["emoji"],
        })
    return out


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
    Auto-refresh every 15s. Same content as the PDF but stylé P31.

    Phase 6 (#496) : accepts ?mh=<hash> query param so R3 WG clients (no
    ARP entry on captive subnet) and remote viewers via kbin can fetch
    their own report. The hash for R3 = sha256(wg_pubkey)[:16] derived
    by inject_banner.py and embedded in the banner 'Mon rapport' link.
    """
    # Bypass path : explicit mac_hash in query (R3 WG or kbin remote viewer)
    mh_qp = (request.query_params.get("mh") or "").strip().lower()
    if mh_qp and all(c in "0123456789abcdef" for c in mh_qp) and 8 <= len(mh_qp) <= 64:
        ip = request.client.host if request.client else "?"
        mac_hash = mh_qp
    else:
        ip, mac = _resolve(request)
        if not mac:
            raise HTTPException(400, "client MAC unknown (not in captive subnet?) — use ?mh=<hash>")
        salt = _get_salt()
        mac_hash = macmod.hash_mac(mac, salt)
    session = _aggregate_session(mac_hash)
    # Phase 3 (#492) : pass query args + force no-cache so iPhone Safari
    # actually fetches the new template.
    # Phase 6 (#496) : also pass wg_enabled so dashboard R3 link renders
    wg_enabled = Path("/etc/secubox/toolbox/wg/server.pubkey").exists()
    # Phase 6.D (#497) : cumulative anonymous stats for visual context
    cumulative = _cumulative_stats()
    html = _env.get_template("report-live.html.j2").render(
        mac_hash=mac_hash, ip=ip,
        request_args=dict(request.query_params),
        current_level=store.get_client_level(mac_hash) if mac_hash else "r1",
        wg_enabled=wg_enabled,
        cumulative=cumulative,
        **session,
    )
    return HTMLResponse(html, headers={
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
    })


@router.get("/report/me")
async def report_me(request: Request) -> Response:
    """Generate + serve PDF report for the CURRENT requesting client.

    Phase 6 (#496) : same ?mh=<hash> bypass as /report/me/html — R3 WG
    clients (no captive ARP entry) and remote viewers via kbin can
    download their PDF report.
    """
    mh_qp = (request.query_params.get("mh") or "").strip().lower()
    if mh_qp and all(c in "0123456789abcdef" for c in mh_qp) and 8 <= len(mh_qp) <= 64:
        mac_hash = mh_qp
    else:
        ip, mac = _resolve(request)
        if not mac:
            raise HTTPException(400, "client MAC unknown (not in captive subnet?) — use ?mh=<hash>")
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


@router.get("/admin/clients/rich")
async def admin_clients_rich() -> dict:
    """Phase 6.D : enriched client list with pseudo icons + statuses + levels.

    Returns each client decorated with device emoji, status emoji, level chip,
    and last activity. Designed for the admin webui table.
    """
    import time as _t
    rows = store.list_clients()
    now = _t.time()
    enriched = []
    for r in rows:
        age_min = (now - (r.get("last_seen") or 0)) / 60.0
        if age_min < 5:
            status_emoji = "🟢"
            status_label = "actif"
        elif age_min < 60:
            status_emoji = "🟡"
            status_label = "idle"
        else:
            status_emoji = "⚪"
            status_label = "expiré"
        if r.get("state") == "quarantine":
            status_emoji = "🔴"
            status_label = "quarantine"
        level = r.get("level") or "r1"
        level_emoji = {"r0": "🌐", "r1": "🛡", "r2": "🔍", "r3": "🌐"}.get(level, "❔")
        score = r.get("score", 0)
        risk_emoji = "🟢" if score < 30 else "🟡" if score < 70 else "🔴"
        enriched.append({
            "mac_hash": r.get("mac_hash"),
            "ip": r.get("ip"),
            "state": r.get("state"),
            "level": level,
            "level_emoji": level_emoji,
            "score": score,
            "risk_emoji": risk_emoji,
            "status_emoji": status_emoji,
            "status_label": status_label,
            "first_seen": r.get("first_seen"),
            "last_seen": r.get("last_seen"),
            "device_emoji": "📱",  # placeholder ; could derive from avatar_analysis
        })
    return {"clients": enriched, "count": len(enriched)}


@router.post("/admin/clients/{mac_hash}/level")
async def admin_override_level(mac_hash: str, request: Request) -> dict:
    """Phase 6.D : admin override of a client's level (operator-only).

    Allows the operator to force-change a client's R0/R1/R2/R3 level from
    the admin webUI without requiring the client to navigate the dashboard.
    """
    try:
        form = await request.form()
        new_level = (form.get("level") or "").lower()
    except Exception:
        new_level = ""
    if new_level not in ("r0", "r1", "r2", "r3"):
        raise HTTPException(400, f"invalid level '{new_level}', expected r0|r1|r2|r3")
    # Need to know the client's current MAC ; the store keeps mac_hash only.
    # Without raw MAC we can't update nft sets — operator must trigger the
    # client's own /change-level to push to nft. We update the store level
    # which the inject_banner addon reads.
    row = next((c for c in store.list_clients() if c.get("mac_hash") == mac_hash), None)
    if not row:
        raise HTTPException(404, "client not found")
    store.upsert_client(mac_hash, row.get("ip") or "?", level=new_level)
    log.info("admin override mac_hash=%s -> level=%s", mac_hash, new_level)
    return {"ok": True, "mac_hash": mac_hash, "new_level": new_level,
            "note": "nft sets not auto-updated; client must reload or operator manually adjusts nft"}


@router.get("/admin/", response_class=HTMLResponse)
@router.get("/admin", response_class=HTMLResponse)
async def admin_index() -> HTMLResponse:
    """Operator admin webUI with client list + level switcher."""
    html = """<!DOCTYPE html><html lang=fr><head><meta charset=UTF-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>🛡 Admin — Gondwana ToolBoX</title>
<style>:root{--bg:#0a0a0f;--bg2:#0e0e15;--phos:#00dd44;--phos-hot:#00ff55;--dim:#006622;--text:#e8e6d9;--purple:#9e76ff;--amber:#ffb347;--red:#ff4466}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Menlo,Consolas,monospace;background:var(--bg);color:var(--text);padding:1.2rem;max-width:1100px;margin:auto;line-height:1.55}
h1{color:var(--phos-hot);text-shadow:0 0 6px var(--phos);font-size:1.6rem;margin-bottom:0.4rem;letter-spacing:0.05em}
.sub{color:var(--dim);font-size:0.85rem;margin-bottom:1.2rem}
table{width:100%;border-collapse:collapse;font-size:0.85rem;background:var(--bg2);border:1px solid var(--dim)}
th,td{padding:0.5rem 0.6rem;text-align:left;border-bottom:1px solid var(--dim)}
th{color:var(--phos-hot);text-shadow:0 0 3px var(--phos);background:rgba(0,221,68,0.08)}
tr:hover{background:rgba(0,221,68,0.04)}
.chip{display:inline-block;padding:0.15rem 0.5rem;border-radius:99px;font-size:0.72rem;font-weight:bold}
.chip.r0{background:#222;color:#999}
.chip.r1{background:rgba(0,221,68,0.2);color:var(--phos-hot)}
.chip.r2{background:rgba(255,179,71,0.2);color:#ffd6a0}
.chip.r3{background:rgba(158,118,255,0.2);color:#cbb6ff}
.btn{background:var(--purple);color:#0a0a0f;padding:0.3rem 0.6rem;border:none;border-radius:3px;cursor:pointer;font-family:inherit;font-size:0.72rem;font-weight:bold;margin-right:0.2rem}
.btn:hover{background:#b598ff}
.btn.outline{background:transparent;color:var(--phos);border:1px solid var(--phos)}
code{background:#222;padding:0.1rem 0.3rem;border-radius:2px;font-size:0.75rem}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:0.8rem;margin-bottom:1.5rem}
.card{background:var(--bg2);border:1px solid var(--dim);padding:0.8rem;border-radius:4px;text-align:center}
.card .v{font-size:1.6rem;color:var(--phos-hot);font-weight:bold;display:block}
.card .l{font-size:0.7rem;color:var(--dim)}
.modal-bg{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.8);display:none;align-items:center;justify-content:center;z-index:100}
.modal-bg.show{display:flex}
.modal{background:var(--bg2);border:1px solid var(--phos);padding:1.5rem;border-radius:4px;max-width:400px;width:90%}
.modal h2{color:var(--phos-hot);font-size:1rem;margin-bottom:0.8rem}
.modal .lvl-row{display:grid;grid-template-columns:repeat(4,1fr);gap:0.4rem;margin-bottom:0.8rem}
.modal .lvl-row button{padding:0.5rem;cursor:pointer;font-family:inherit;font-size:0.75rem;border-radius:3px}
.modal .lvl-row .r0{background:#222;color:#999;border:1px solid #444}
.modal .lvl-row .r1{background:rgba(0,221,68,0.15);color:var(--phos-hot);border:1px solid var(--phos)}
.modal .lvl-row .r2{background:rgba(255,179,71,0.15);color:#ffd6a0;border:1px solid var(--amber)}
.modal .lvl-row .r3{background:rgba(158,118,255,0.15);color:#cbb6ff;border:1px solid var(--purple)}
.adm-tabs{display:flex;gap:2px;border-bottom:1px solid var(--dim);margin-bottom:0.8rem}
.adm-tab{background:transparent;border:0;color:#888;padding:0.5rem 1rem;font-family:inherit;font-size:0.85rem;cursor:pointer;border-bottom:2px solid transparent;transition:all 0.15s}
.adm-tab.active{color:var(--phos-hot);border-bottom-color:var(--phos);background:rgba(0,221,68,0.05)}
.adm-tab:hover{color:var(--text)}
.adm-content{display:none}
.adm-content.active{display:block}
button.del-pattern{background:var(--red);color:#fff;border:0;padding:0.2rem 0.5rem;border-radius:3px;cursor:pointer;font-weight:bold;font-size:0.75rem}
</style></head><body>
<h1>🛡 Admin — Gondwana ToolBoX</h1>
<p class=sub>// Console opérateur · client management · level override · mitm filtering</p>

{# Phase 6.I : tabbed sections #}
<div class=adm-tabs>
  <button class="adm-tab active" data-tab=clients>👥 Clients</button>
  <button class="adm-tab" data-tab=filter>🛡 Mitm filtering</button>
</div>

<div class="adm-content active" data-content=clients>
<div id=cards class=cards></div>

<table id=clients-table>
<thead><tr>
<th>Status</th><th>Device</th><th>Hash</th><th>IP</th>
<th>Level</th><th>Risk</th><th>Last seen</th><th>Actions</th>
</tr></thead>
<tbody id=clients-tbody><tr><td colspan=8>chargement…</td></tr></tbody>
</table>
</div>

<div class="adm-content" data-content=filter>
<h2 style="color:var(--purple);font-size:1.1rem;margin-bottom:0.4rem">🛡 Mitm bypass whitelist</h2>
<p style="font-size:0.78rem;color:var(--dim);margin-bottom:0.8rem">
  Hosts/domains qui ne sont JAMAIS déchiffrés par mitm (TLS passthrough).
  Pour apps cert-pinned ou E2E. Redémarre <code>secubox-toolbox-mitm-wg</code>
  après modif.
</p>

<form id=add-pattern-form style="display:flex;gap:0.5rem;margin-bottom:0.8rem">
  <input type=text name=entry placeholder="ex: (.+\\.)?example\\.com" required
    style="flex:1;background:#111;color:var(--text);border:1px solid #2a2a3f;padding:0.5rem;border-radius:3px;font-family:monospace;font-size:0.8rem">
  <button type=submit class=btn style="background:var(--phos);padding:0.5rem 1rem">➕ Ajouter</button>
</form>

<table id=filter-table style="font-size:0.78rem">
<thead><tr><th>Pattern (regex)</th><th width=60>×</th></tr></thead>
<tbody id=filter-tbody><tr><td colspan=2>chargement…</td></tr></tbody>
</table>

<p style="font-size:0.72rem;color:var(--dim);margin-top:0.6rem;border-left:2px solid var(--amber);padding-left:0.6rem">
  📁 <code>/var/lib/secubox/toolbox/mitm-bypass.conf</code> · Source de vérité
</p>
</div>

<div id=modal class=modal-bg>
<div class=modal>
<h2>🔀 Change level — <code id=modal-mh></code></h2>
<p style="font-size:0.78rem;color:var(--dim);margin-bottom:0.5rem">⚠ Admin override : updates store only. Client must reload to sync nft.</p>
<div class=lvl-row>
<button class=r0 onclick="setLevel('r0')">🌐 R0</button>
<button class=r1 onclick="setLevel('r1')">🛡 R1</button>
<button class=r2 onclick="setLevel('r2')">🔍 R2</button>
<button class=r3 onclick="setLevel('r3')">🌐 R3</button>
</div>
<button onclick="closeModal()" class=btn style="background:transparent;color:var(--dim);border:1px solid var(--dim)">Annuler</button>
</div>
</div>

<script>
var selectedMh = null;
function openModal(mh) {
  selectedMh = mh;
  document.getElementById('modal-mh').textContent = mh;
  document.getElementById('modal').classList.add('show');
}
function closeModal() {
  document.getElementById('modal').classList.remove('show');
}
async function setLevel(lvl) {
  if (!selectedMh) return;
  var fd = new FormData();
  fd.append('level', lvl);
  var r = await fetch('/admin/clients/'+selectedMh+'/level', {method:'POST', body:fd});
  if (r.ok) {
    closeModal();
    loadClients();
  } else {
    alert('Erreur: '+r.status);
  }
}
async function loadClients() {
  var r = await fetch('/admin/clients/rich');
  if (!r.ok) {
    document.getElementById('clients-tbody').innerHTML = '<tr><td colspan=8>Erreur '+r.status+'</td></tr>';
    return;
  }
  var data = await r.json();
  var tbody = document.getElementById('clients-tbody');
  tbody.innerHTML = '';
  data.clients.forEach(function(c){
    var lvlChip = '<span class="chip '+c.level+'">'+c.level_emoji+' '+c.level.toUpperCase()+'</span>';
    var dt = new Date(c.last_seen*1000).toISOString().substring(11,16);
    var tr = document.createElement('tr');
    tr.innerHTML = '<td>'+c.status_emoji+' '+c.status_label+'</td>'+
      '<td>'+c.device_emoji+'</td>'+
      '<td><code>'+c.mac_hash.substring(0,12)+'…</code></td>'+
      '<td>'+(c.ip||'?')+'</td>'+
      '<td>'+lvlChip+'</td>'+
      '<td>'+c.risk_emoji+' '+c.score+'</td>'+
      '<td>'+dt+'</td>'+
      '<td><button class=btn onclick="openModal(\\''+c.mac_hash+'\\')">🔀 Override</button>'+
      '<a href="/admin/clients/'+c.mac_hash+'/report" class="btn outline">📄 PDF</a></td>';
    tbody.appendChild(tr);
  });
  // KPI cards
  var counts = {r0:0,r1:0,r2:0,r3:0,actif:0,risk_low:0,risk_mh:0};
  data.clients.forEach(function(c){
    counts[c.level] = (counts[c.level]||0)+1;
    if (c.status_label==='actif') counts.actif++;
    if (c.score < 30) counts.risk_low++;
    if (c.score >= 30) counts.risk_mh++;
  });
  document.getElementById('cards').innerHTML =
    '<div class=card><span class=v>'+data.count+'</span><span class=l>Total clients</span></div>'+
    '<div class=card><span class=v>'+counts.actif+'</span><span class=l>🟢 Actifs (5min)</span></div>'+
    '<div class=card><span class=v>'+counts.r1+'</span><span class=l>🛡 R1</span></div>'+
    '<div class=card><span class=v>'+counts.r2+'</span><span class=l>🔍 R2</span></div>'+
    '<div class=card><span class=v>'+counts.r3+'</span><span class=l>🌐 R3 WG</span></div>'+
    '<div class=card><span class=v>'+counts.risk_low+'</span><span class=l>🟢 Risque LOW</span></div>';
}
loadClients();
setInterval(loadClients, 15000);

// ── Tabs (Phase 6.I) ──
document.querySelectorAll('.adm-tab').forEach(function(t){
  t.addEventListener('click', function(){
    var tn = this.dataset.tab;
    document.querySelectorAll('.adm-tab').forEach(function(x){x.classList.remove('active');});
    this.classList.add('active');
    document.querySelectorAll('.adm-content').forEach(function(x){x.classList.remove('active');});
    document.querySelector('[data-content='+tn+']').classList.add('active');
    if (tn === 'filter') loadFilter();
  });
});

// ── Filter Control (integrated tab) ──
async function loadFilter(){
  var r = await fetch('/admin/filter-control/list');
  var tb = document.getElementById('filter-tbody');
  if (!r.ok) { tb.innerHTML = '<tr><td colspan=2>Erreur '+r.status+'</td></tr>'; return; }
  var d = await r.json();
  if (!d.patterns || !d.patterns.length) {
    tb.innerHTML = '<tr><td colspan=2 style="color:#666;text-align:center">Aucune entrée</td></tr>';
    return;
  }
  tb.innerHTML = '';
  d.patterns.forEach(function(p){
    var tr = document.createElement('tr');
    var td1 = document.createElement('td');
    var code = document.createElement('code');
    code.textContent = p;
    td1.appendChild(code);
    var td2 = document.createElement('td');
    var btn = document.createElement('button');
    btn.className = 'del-pattern';
    btn.textContent = '×';
    btn.onclick = function(){ delPattern(p); };
    td2.appendChild(btn);
    tr.appendChild(td1); tr.appendChild(td2);
    tb.appendChild(tr);
  });
}
async function delPattern(p){
  var fd = new FormData(); fd.append('entry', p);
  var r = await fetch('/admin/filter-control/remove', {method:'POST', body:fd});
  if (r.ok || r.status === 303) loadFilter();
}
document.getElementById('add-pattern-form').addEventListener('submit', async function(ev){
  ev.preventDefault();
  var entry = ev.target.entry.value.trim();
  if (!entry) return;
  var fd = new FormData(); fd.append('entry', entry);
  var r = await fetch('/admin/filter-control/add', {method:'POST', body:fd});
  if (r.ok || r.status === 303) {
    ev.target.entry.value = '';
    loadFilter();
  }
});
</script>
</body></html>"""
    return HTMLResponse(html, headers={"Cache-Control": "no-store"})


@router.get("/admin/filter-control/list")
async def admin_filter_list() -> dict:
    """JSON list of bypass patterns — consumed by admin webui tab."""
    return {"patterns": _load_bypass_entries(), "file": str(MITM_BYPASS_FILE)}


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
