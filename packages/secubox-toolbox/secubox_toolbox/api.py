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
    avatar_analysis,
    beaconing,
    ca,
    cookie_analysis,
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

    no_cache_headers = {
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
    }

    # Phase 3 (#492) : ALWAYS render splash on GET /. Even validated users
    # benefit from seeing the cert install buttons + level switcher + dashboard
    # link. Auto-redirect was hiding the cert links from users who already
    # validated — they had no path back to the install buttons.
    html = _env.get_template("splash.html.j2").render(
        mac_hash=mac_hash or "??",
        ssid=cfg.ap.ssid,
        r2_enabled=cfg.r2.enabled,
        already_validated=bool(mac and nft.is_validated(mac)),
        current_level=store.get_client_level(mac_hash) if mac_hash else None,
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
    """R3 install page — download WG profile + QR + iOS/Android instructions."""
    html = """<!DOCTYPE html><html lang=fr><head><meta charset=UTF-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<meta name=apple-mobile-web-app-capable content=yes>
<link rel=manifest href=/manifest.json>
<title>R3 WireGuard — Installer le profil portable</title>
<style>:root{--bg:#0a0a0f;--phos:#00dd44;--phos-hot:#00ff55;--dim:#006622;--text:#e8e6d9;--purple:#9e76ff}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Courier New',monospace;background:var(--bg);color:var(--text);padding:1.2rem;max-width:560px;margin:auto;line-height:1.55}
h1{color:var(--phos-hot);text-shadow:0 0 6px var(--phos);margin-bottom:0.3rem}
.sub{color:var(--dim);font-size:0.85rem;margin-bottom:1rem}
.card{border:1px solid var(--purple);padding:1rem;margin-bottom:1rem;background:rgba(110,64,201,0.05)}
.card h2{color:var(--purple);font-size:0.95rem;margin-bottom:0.5rem}
.btn{display:block;text-align:center;padding:0.8rem;background:var(--purple);color:#0a0a0f;
text-decoration:none;border-radius:4px;font-weight:bold;margin:0.6rem 0;font-size:0.95rem}
.btn.outline{background:transparent;color:var(--purple);border:1px solid var(--purple)}
.qr{text-align:center;background:white;padding:0.8rem;border-radius:4px;margin:0.6rem 0}
.qr img{max-width:240px;width:100%}
ol{padding-left:1.4rem;font-size:0.85rem}
code{background:#222;padding:0.1rem 0.4rem;border-radius:2px;font-size:0.85rem}
.warn{font-size:0.75rem;color:#ffd6a0;background:rgba(255,179,71,0.08);padding:0.6rem;border-left:2px solid #ffb347;margin:0.6rem 0}
</style></head><body>
<h1>🌐 R3 — WireGuard portable</h1>
<p class=sub>// VPN tunnel mitm — marche partout (mobile data, WiFi tiers)</p>

<div class=card>
<h2>📲 Méthode 1 — Scanner le QR (recommandé)</h2>
<p style="font-size:0.82rem">Ouvre l'app <b>WireGuard</b> (gratuite, App Store / Play Store) → ➕ Ajouter un tunnel → <b>Scanner depuis QR</b> → pointe l'iPhone vers ce QR :</p>
<div class=qr><img src="/wg/qr.png" alt="QR profil WG"/></div>
<p style="font-size:0.7rem;opacity:0.7;text-align:center">⚠ Le QR contient ta clé privée. Ne le partage pas.</p>
</div>

<div class=card>
<h2>💾 Méthode 2 — Télécharger .conf</h2>
<a href=/wg/profile/new class=btn>📥 Télécharger village3b-toolbox.conf</a>
<ol>
<li>iPhone : ouvre le fichier → app WireGuard s'ouvre → tap 'Importer'</li>
<li>Android : ouvre l'app WireGuard → ➕ → Importer depuis fichier</li>
<li>Linux : <code>wg-quick up village3b-toolbox.conf</code></li>
</ol>
</div>

<div class=warn>
<b>⚠ Avant de connecter :</b> installe aussi le certificat racine ToolBoX
(<a href="/ca/mobileconfig" style="color:#ffb347">iPhone .mobileconfig</a> ou
<a href="/ca/android.crt" style="color:#ffb347">Android .crt</a>) sinon les
sites HTTPS échoueront dès que tu actives le tunnel.
</div>

<div class=card>
<h2>🔌 Après connection</h2>
<p style="font-size:0.82rem">Une fois le tunnel actif (icône VPN visible iOS) :</p>
<ul style="padding-left:1.2rem;font-size:0.82rem">
<li>Tout ton trafic (HTTPS + QUIC + DNS) passe par la cabine</li>
<li>Le bandeau apparaît sur TOUTES les pages web (incl Safari)</li>
<li>Le rapport <a href=/report/me/html style="color:var(--phos)">📊 /report/me/html</a> se remplit en temps réel</li>
<li>iCloud Push + FaceTime continuent de marcher (routing-bypass)</li>
</ul>
</div>

<a href=/ class=btn outline>← Retour splash</a>
</body></html>"""
    return HTMLResponse(html)


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
    suitable for direct import in WireGuard app (iOS + macOS + Linux)."""
    try:
        from . import wg as _wg
    except ImportError:
        raise HTTPException(503, "WG module not available (Phase 6 not provisioned)")
    profile = _wg.generate_client_profile(client_label=request.headers.get("user-agent", "")[:60])
    return Response(
        content=profile["conf_text"],
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": "attachment; filename=village3b-toolbox.conf",
            "X-Client-PubKey": profile["client_pubkey"],
            "X-Client-IP": profile["client_ip"],
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
    Auto-refresh every 15s. Same content as the PDF but stylé P31."""
    ip, mac = _resolve(request)
    if not mac:
        raise HTTPException(400, "client MAC unknown (not in captive subnet?)")
    salt = _get_salt()
    mac_hash = macmod.hash_mac(mac, salt)
    session = _aggregate_session(mac_hash)
    # Phase 3 (#492) : pass query args + force no-cache so iPhone Safari
    # actually fetches the new template.
    html = _env.get_template("report-live.html.j2").render(
        mac_hash=mac_hash, ip=ip,
        request_args=dict(request.query_params),
        current_level=store.get_client_level(mac_hash) if mac_hash else "r1",
        **session,
    )
    return HTMLResponse(html, headers={
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
    })


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
