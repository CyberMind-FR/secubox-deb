# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""HMAC-signed report tokens + PDF generation (fpdf2)."""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path

from .models import ReportToken

log = logging.getLogger("secubox.toolbox.reports")

# Phase 3 (#492) : Unicode fonts for real emoji rendering in PDF
DEJAVU_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
DEJAVU_BOLD_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
DEJAVU_OBLIQUE_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Oblique.ttf"
# Symbola : broad monochrome emoji + symbol coverage (📱📡🔍🔒🎯🎵🐙📊🍪…)
# Apt package : fonts-symbola
SYMBOLA_PATH = "/usr/share/fonts/truetype/ancient-scripts/Symbola_hint.ttf"


def mint_token(mac_hash: str, salt: str, ttl_seconds: int = 86400) -> ReportToken:
    """Mint an HMAC-signed ephemeral token for /report/{token} access."""
    expires_at = int(time.time()) + ttl_seconds
    nonce = secrets.token_urlsafe(8)
    raw = f"{mac_hash}:{expires_at}:{nonce}".encode()
    sig = hmac.new(salt.encode(), raw, hashlib.sha256).hexdigest()[:16]
    token = f"{mac_hash}.{expires_at}.{nonce}.{sig}"
    return ReportToken(token=token, mac_hash=mac_hash, expires_at=expires_at)


def verify_token(token: str, salt: str) -> tuple[bool, str | None]:
    """Returns (ok, mac_hash) — ok=False if expired / bad signature / malformed."""
    try:
        mac_hash, exp_str, nonce, sig = token.split(".")
        expires_at = int(exp_str)
    except (ValueError, AttributeError):
        return False, None
    if expires_at < int(time.time()):
        return False, None
    raw = f"{mac_hash}:{expires_at}:{nonce}".encode()
    expected = hmac.new(salt.encode(), raw, hashlib.sha256).hexdigest()[:16]
    if not hmac.compare_digest(sig, expected):
        return False, None
    return True, mac_hash


# ───────────────── PDF generation ─────────────────

def build_report_data(mac_hash: str, session_data: dict) -> dict:
    """Aggregate session data into the structure consumed by render_pdf().
    session_data is expected to be the dict produced by api._aggregate_session()."""
    return {
        "mac_hash": mac_hash,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        **session_data,
    }


def _setup_fonts(pdf) -> str:
    """Load DejaVu Sans (broad Unicode) + Symbola (emoji) for the PDF.

    Falls back to Helvetica (latin-1 only) if fonts are absent.

    Returns the font family name to use for set_font() calls.
    """
    family = "Helvetica"
    if Path(DEJAVU_PATH).exists():
        try:
            pdf.add_font("DejaVu", style="", fname=DEJAVU_PATH)
            if Path(DEJAVU_BOLD_PATH).exists():
                pdf.add_font("DejaVu", style="B", fname=DEJAVU_BOLD_PATH)
            if Path(DEJAVU_OBLIQUE_PATH).exists():
                pdf.add_font("DejaVu", style="I", fname=DEJAVU_OBLIQUE_PATH)
            family = "DejaVu"
            # Fallback chain : Symbola covers 📱📡🔍🔒🎯🎵🐙📊🍪 + most emoji
            # not present in DejaVu.
            fallback = []
            if Path(SYMBOLA_PATH).exists():
                try:
                    pdf.add_font("Symbola", style="", fname=SYMBOLA_PATH)
                    fallback.append("Symbola")
                except Exception as e:
                    log.warning("Symbola font load failed: %s", e)
            if fallback:
                try:
                    # exact_match=False so Bold/Italic text also falls back to
                    # regular Symbola (it has no Bold variant).
                    pdf.set_fallback_fonts(fallback, exact_match=False)
                except TypeError:
                    # Older fpdf2 without exact_match param
                    pdf.set_fallback_fonts(fallback)
                except Exception as e:
                    log.warning("set_fallback_fonts failed: %s", e)
        except Exception as e:
            log.warning("DejaVu font load failed (%s), falling back to Helvetica", e)
    return family


def render_pdf(report: dict) -> bytes:
    """Render the analysis report as PDF (fpdf2). Returns the binary blob."""
    try:
        from fpdf import FPDF
    except ImportError:
        # Fallback : return a text plain "PDF stub" if fpdf2 isn't installed
        return _render_text_fallback(report).encode()

    pdf = FPDF(orientation="P", unit="mm", format="A4")
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    # Phase 3 (#492) : Unicode font for emoji rendering
    family = _setup_fonts(pdf)
    # Stash for the helper functions to use
    pdf._secubox_family = family

    # Header
    pdf.set_font(family, "B", 20)
    pdf.set_text_color(0, 90, 64)  # P31 dim green
    pdf.cell(0, 12, "📡 GONDWANA TOOLBOX", ln=True, align="C")
    pdf.set_font(family, "", 10)
    pdf.set_text_color(110, 64, 201)
    pdf.cell(0, 5, "Rapport d'analyse de session — Cabine numérique VILLAGE3B", ln=True, align="C")
    pdf.ln(3)

    # ── HERO DASHBOARD : big global numbers ──
    _dashboard_hero(pdf, family, report)

    # Anonymous ID
    _section(pdf, "🔑 IDENTIFIANT ANONYME")
    _kv(pdf, "Hash session", report.get("mac_hash", "?"))
    _kv(pdf, "Type appareil", report.get("device_type", "?"))
    _kv(pdf, "Date analyse", report.get("generated_at", "?"))
    _kv(pdf, "Sandbox subnet", "10.99.0.0/24 (réseau isolé VILLAGE3B)")
    pdf.ln(2)

    # Compromise analysis (the hero shows the risk badge ; details below)
    _section(pdf, "🚨 ANALYSE COMPROMISSION")
    score = report.get("risk_score", 0)
    risk_label = report.get("risk_label") or ("LOW" if score < 30 else "MEDIUM" if score < 70 else "HIGH")
    pdf.set_text_color(0)
    pdf.set_font(getattr(pdf, "_secubox_family", "Helvetica"), "", 10)
    pdf.ln(1)
    explanation = report.get("risk_explanation", "")
    if explanation:
        pdf.multi_cell(_page_w(pdf), 5, _ascii_safe(explanation)[:600])
        pdf.ln(1)
    for sig in report.get("indicators", []):
        _bullet(pdf, sig)
    pdf.ln(2)

    # Score breakdown — per-category transparency (Phase 2a)
    scoring_data = report.get("scoring") or {}
    breakdown = scoring_data.get("breakdown") or []
    if breakdown:
        _section(pdf, "BREAKDOWN DU SCORE")
        for b in breakdown:
            pdf.set_font(getattr(pdf, "_secubox_family", "Helvetica"), "B", 9)
            pdf.cell(0, 5, f"{b.get('category', '?').upper()} : poids {b.get('weight_subtotal', 0)} (sur {b.get('raw_signal_count', 0)} signal)", ln=True)
            pdf.set_font(getattr(pdf, "_secubox_family", "Helvetica"), "", 8)
            for ex in (b.get("examples") or [])[:3]:
                _bullet(pdf, ex, font_size=8)
        pdf.ln(2)

    # Threat-intel matches (feeds malware) — Phase 2a
    ti = report.get("threat_intel_matches") or []
    if ti:
        _section(pdf, "THREAT INTEL - MATCHES FEEDS MALWARE")
        for m in ti[:10]:
            _bullet(pdf, f"[{m.get('source', '?')}/{m.get('weight', 0)}] {m.get('label', '?')} : {m.get('ioc', '?')[:60]}", font_size=8)
        pdf.ln(2)

    # DGA candidates — Phase 2a
    dga_list = report.get("dga_candidates") or []
    if dga_list:
        _section(pdf, "DGA - DOMAINES SUSPECTS")
        for d in dga_list[:8]:
            _bullet(pdf, f"[{d.get('score', 0)}] {d.get('host', '?')[:60]} ({','.join(d.get('indicators', []))})", font_size=8)
        pdf.ln(2)

    # Beaconing patterns — Phase 2a
    bc = report.get("beaconing_candidates") or []
    if bc:
        _section(pdf, "BEACONING - PATTERNS PERIODIQUES SUSPECTS")
        for b in bc[:8]:
            _bullet(pdf, f"[{b.get('score', 0)}] {b.get('host', '?')[:50]}  median={b.get('median_seconds', 0)}s  cv={b.get('cv', 0)}", font_size=8)
        pdf.ln(2)

    # Cert-pinning protection
    _section(pdf, "PROTECTION CERT-PINNING (apps qui RESISTENT au MITM)")
    for app in report.get("pinned_apps", []):
        _bullet(pdf, app)
    pdf.ln(2)

    # ── DPI classification (Phase 2a+ nDPI-style apps with emojis) ──
    dpi_cls = report.get("dpi_classified") or {}
    if dpi_cls.get("top_apps"):
        _section(pdf, "APPS DETECTEES (nDPI-style classification)")
        for a in dpi_cls["top_apps"][:15]:
            _bullet(pdf, f"{a.get('emoji', '?')} {a.get('app', '?')} ({a.get('category', '?')}) - {a.get('count', 0)} connexions", font_size=8)
        pdf.ln(2)

    # ── Geo top hosts (avec drapeaux + ASN) ──
    geo_hosts = report.get("geo_top_hosts") or []
    if geo_hosts:
        _section(pdf, "HOTES PAR PAYS + ASN + APP (PHASE 2A+)")
        for h in geo_hosts[:12]:
            flag = h.get("flag", "")
            line = f"{flag} {h.get('emoji', '')} {h.get('app', '?')} | {h.get('host', '?')[:40]} | {h.get('asn_org', '?')[:25]} | {h.get('count', 0)} hits"
            _bullet(pdf, line, font_size=8)
        pdf.ln(2)

    # ── Avatar / device fingerprint ──
    avatar = report.get("avatar_analysis") or {}
    if avatar.get("devices"):
        _section(pdf, f"AVATAR / DEVICE FINGERPRINT")
        _kv(pdf, "Most common", f"{avatar.get('most_common_emoji', '?')} {avatar.get('most_common', '?')}")
        _kv(pdf, "UA distincts", str(avatar.get('raw_count', 0)))
        for dev, info in (avatar.get("devices") or {}).items():
            _bullet(pdf, f"{info.get('emoji', '?')} {info.get('os_label', dev)} - {info.get('count', 0)}x", font_size=8)
        if avatar.get("browsers"):
            pdf.ln(1)
            for br, info in (avatar.get("browsers") or {}).items():
                _bullet(pdf, f"{info.get('emoji', '?')} {info.get('label', br)} - {info.get('count', 0)}x", font_size=8)
        pdf.ln(2)

    # ── Cookies providers (Phase 2a+) ──
    cookies_providers = report.get("cookies_providers") or []
    if cookies_providers:
        _section(pdf, "COOKIES / TRACKERS PROVIDERS")
        for p in cookies_providers[:12]:
            _bullet(pdf, f"{p.get('emoji', '?')} {p.get('provider', '?')} ({p.get('category', '?')}) x{p.get('count', 0)}", font_size=8)
        pdf.ln(2)

    # ── Cookies trackers ──
    cookies = report.get("cookies") or {}
    if cookies.get("total_set") or cookies.get("details"):
        _section(pdf, "COOKIES / TRACKERS")
        _kv(pdf, "Set-Cookie recus", str(cookies.get("total_set", 0)))
        _kv(pdf, "Cookies envoyes", str(cookies.get("total_sent", 0)))
        pdf.ln(1)
        for detail in (cookies.get("details") or [])[:10]:
            _bullet(pdf,
                    f"{detail.get('url', '?')[:60]}  set={detail.get('set', 0)} sent={detail.get('sent', 0)}",
                    font_size=8)
        pdf.ln(2)

    # ── SOC indicators ──
    soc = report.get("soc") or {}
    if soc.get("indicators"):
        _section(pdf, "SOC - INDICATEURS DETECTES")
        for ind in soc["indicators"][:10]:
            _bullet(pdf,
                    f"[poids {ind.get('weight', 0)}] {ind.get('kind', '?')} : {ind.get('host', '?')[:60]}",
                    font_size=8)
        pdf.ln(2)

    # ── JA4 (TLS fingerprinting) ──
    ja4 = report.get("ja4") or {}
    if ja4.get("snis_seen"):
        _section(pdf, "JA4 - EMPREINTES TLS (HOSTNAMES)")
        for sni in ja4["snis_seen"][:8]:
            _bullet(pdf, sni[:80], font_size=8)
        if ja4.get("alpns_seen"):
            pdf.ln(1)
            _kv(pdf, "ALPN protocols", ", ".join(ja4['alpns_seen'])[:80])
        pdf.ln(2)

    # Inspected traffic (cookies-flagged URLs - kept for compat)
    inspected = report.get("inspected_urls", [])
    if inspected and not cookies.get("details"):
        _section(pdf, "TRAFIC INSPECTE (R2 consent explicite)")
        for url in inspected[:15]:
            _bullet(pdf, url, font_size=8)
        pdf.ln(2)

    # Recommendations
    _section(pdf, "RECOMMANDATIONS")
    for rec in report.get("recommendations", []):
        _bullet(pdf, rec)
    pdf.ln(2)

    # Phase 3 (#492) : Transparency — inspection breakdown + per-host quality
    t = report.get("transparency") or {}
    if t.get("total_events"):
        _section(pdf, "INSPECTION : CE QUI A ETE REGARDE (et pas regarde)")
        b = t.get("breakdown_pct") or {}
        if b.get("inspected"):
            _bullet(pdf, f"Inspecte (MITM via notre CA) : {b['inspected']}% - contenu visible")
        if b.get("bypassed-whitelist"):
            _bullet(pdf, f"Bypass whitelist : {b['bypassed-whitelist']}% - decision policy (vendor cert-pinning)")
        if b.get("pinned-failed-mitm"):
            _bullet(pdf, f"Cert-pinning : {b['pinned-failed-mitm']}% - app refuse notre CA, normal+bon signe")
        if b.get("e2e-opaque"):
            _bullet(pdf, f"E2E messaging : {b['e2e-opaque']}% - opaque par design, ton chiffrement marche")
        _bullet(pdf, f"Total events analyses : {t.get('total_events', 0)}")
        wl = (t.get("whitelist_stats") or {}).get("count", 0)
        if wl:
            _bullet(pdf, f"Patterns whitelist actifs : {wl} (baseline + override operateur)")
        pdf.ln(2)

        # Per-host quality table — worst first, capped 10
        per_host = t.get("per_host") or []
        if per_host:
            _section(pdf, "🎯 QUALITÉ SÉCURITÉ PAR DESTINATION (worst-first)")
            for h in per_host[:10]:
                grade = h.get("grade", "?")
                host = h.get("host", "?")[:50]
                status = h.get("status", "?")
                _bullet(pdf, f"[{grade}] {host} — {status}", font_size=8)
            pdf.ln(2)

    # Phase 2b/2c (#488/#490) : per-module mitm-ingest aggregate metrics
    mm = report.get("mitm_modules") or {}
    if mm and any(v.get("count", 0) > 0 for v in mm.values() if isinstance(v, dict)):
        _section(pdf, "🛰 INGESTION PAR MODULE (Phase 2b/2c)")
        for kind, data in mm.items():
            if not isinstance(data, dict):
                continue
            cnt = data.get("count", 0)
            if cnt == 0:
                continue
            emoji = {"dpi": "🌐", "cookies": "🍪", "avatar": "👤",
                     "soc": "🛡", "threat-analyst": "🕵"}.get(kind, "📡")
            _bullet(pdf, f"{emoji} secubox-{kind} : {cnt} events ingérés (24h)", font_size=9)
            es = data.get("enriched_summary") or {}
            # Per-module top items
            if kind == "dpi" and es.get("top_apps"):
                apps_str = " · ".join(f"{a.get('emoji','?')} {a.get('app','?')}×{a.get('count',0)}"
                                       for a in es["top_apps"][:5])
                _bullet(pdf, f"   Top apps : {apps_str[:200]}", font_size=8)
            elif kind == "cookies" and es.get("top_providers"):
                provs = " · ".join(f"{p.get('emoji','?')} {p.get('provider','?')}×{p.get('count',0)}"
                                    for p in es["top_providers"][:5])
                _bullet(pdf, f"   Top trackers : {provs[:200]}", font_size=8)
                _bullet(pdf, f"   Total tracker hits : {es.get('tracker_total', 0)}", font_size=8)
            elif kind == "avatar":
                devs = es.get("devices") or {}
                if devs:
                    dev_str = " · ".join(f"{v.get('emoji','?')} {k}×{v.get('count',0)}"
                                          for k, v in list(devs.items())[:5])
                    _bullet(pdf, f"   Devices : {dev_str[:200]}", font_size=8)
                brws = es.get("browsers") or {}
                if brws:
                    brw_str = " · ".join(f"{v.get('emoji','?')} {k}×{v.get('count',0)}"
                                          for k, v in list(brws.items())[:5])
                    _bullet(pdf, f"   Browsers : {brw_str[:200]}", font_size=8)
            elif kind == "soc":
                _bullet(pdf, f"   Score total : {es.get('total_weight', 0)} · "
                             f"Band : {es.get('max_band', 'low')}", font_size=8)
                kinds = es.get("indicator_kinds") or {}
                if kinds:
                    k_str = " · ".join(f"{k}×{v}" for k, v in list(kinds.items())[:5])
                    _bullet(pdf, f"   Indicateurs : {k_str[:180]}", font_size=8)
            elif kind == "threat-analyst" and es.get("top_fingerprints"):
                fps = ", ".join(f.get("fingerprint", "?")[:12]
                                 for f in es["top_fingerprints"][:5])
                _bullet(pdf, f"   JA4 fingerprints uniques : {es.get('unique_count', 0)}",
                        font_size=8)
                _bullet(pdf, f"   Top : {fps[:180]}", font_size=8)
        pdf.ln(2)

    # Retention
    _section(pdf, "🔒 RÉTENTION DES DONNÉES")
    _bullet(pdf, "Hash MAC anonyme : 24h (sel rotatif quotidien)")
    _bullet(pdf, "Events detailles : 24h")
    _bullet(pdf, "Rapport ephemere : 24h (lien HMAC scelle)")
    _bullet(pdf, "Logs bruts : supprimes a la fin de la session")
    pdf.ln(2)

    # Support & soutien
    _section(pdf, "SUPPORT & SOUTIEN PROJET")
    _bullet(pdf, "Don recurrent  : liberapay.com/cybermind")
    _bullet(pdf, "Don ponctuel   : cybermind.fr/don")
    _bullet(pdf, "Support technique : support@cybermind.fr")
    _bullet(pdf, "Signaler un bug : github.com/CyberMind-FR/secubox-deb/issues")
    _bullet(pdf, "Deployer une borne : gondwana@cybermind.fr")
    _bullet(pdf, "Audit / formation : contact@cybermind.fr")
    pdf.ln(4)

    # Footer
    pdf.set_font(getattr(pdf, "_secubox_family", "Helvetica"), "I", 8)
    pdf.set_text_color(110, 64, 201)
    pdf.cell(0, 4, "Gondwana ToolBoX  -  LicenseRef-CMSD-1.0 (Source-Disclosed License)", ln=True, align="C")
    pdf.cell(0, 4, "Source : github.com/CyberMind-FR/secubox-deb (issues #474 #475 #477)", ln=True, align="C")

    return bytes(pdf.output(dest="S"))


def _page_w(pdf) -> float:
    """Available content width between margins."""
    return pdf.w - pdf.l_margin - pdf.r_margin


# Phase 3 (#492) : with DejaVu Sans + Noto fallback, most emojis render as
# real glyphs (monochrome). For chars not in either font (e.g. some flags,
# very recent emoji), we fall back to a small ASCII replacement table.
_EMOJI_REPLACEMENTS = {
    # Common emojis NOT in DejaVu Sans + Symbola fallback — replaced gracefully
    # Flag emojis (regional indicator pairs, not in monochrome fonts)
    "🇫🇷": "[FR]", "🇺🇸": "[US]", "🇩🇪": "[DE]", "🇨🇳": "[CN]",
    "🇬🇧": "[GB]", "🇯🇵": "[JP]", "🇨🇦": "[CA]", "🇮🇪": "[IE]",
    "🇮🇹": "[IT]", "🇪🇸": "[ES]", "🇧🇪": "[BE]", "🇨🇭": "[CH]",
    "🇳🇱": "[NL]", "🇸🇪": "[SE]", "🇮🇱": "[IL]", "🇧🇷": "[BR]",
    "🇷🇺": "[RU]", "🇮🇳": "[IN]", "🇰🇷": "[KR]", "🇦🇺": "[AU]",
    "🏳": "[??]",
    # Recent emoji (2020+) not in Symbola
    "🟢": "[OK]",  # green circle
    "🟡": "[WARN]",  # yellow circle
    "🔴": "[KO]",  # red circle (also used for Opera but contextual)
    "🟦": "[BOX]",  # blue square
    "🦋": "[BSKY]",  # butterfly
    "🦊": "[FF]",  # fox face
    "🪟": "[EDGE]",  # window
}


def _dashboard_hero(pdf, family: str, report: dict) -> None:
    """Phase 3 (#492) : visual hero with big global numbers + risk score badge.

    Layout :
      ┌──────────────────────────────────────────────────────────────────┐
      │  📊 TA SESSION VILLAGE3B                  Risk : LOW  [score]    │
      │                                                                  │
      │  [N connexions]  [N hosts]  [N inspectés]  [N cert-pinning]      │
      │                                                                  │
      │  Top app : 📺 YouTube · Top device : 📱 iPhone iOS 17.4         │
      │  Top country : 🇺🇸 United States (Amazon, Google, Apple)        │
      └──────────────────────────────────────────────────────────────────┘
    """
    m = report.get("metrics") or {}
    avatar = report.get("avatar_analysis") or {}
    dpi_cls = report.get("dpi_classified") or {}
    geo_hosts = report.get("geo_top_hosts") or []
    score = report.get("risk_score", 0)
    label = report.get("risk_label") or ("LOW" if score < 30 else "MEDIUM" if score < 70 else "HIGH")

    # Hero card background
    pdf.set_fill_color(20, 30, 25)  # dark green-tinted
    pdf.set_draw_color(0, 90, 64)
    pdf.set_line_width(0.5)
    hero_y = pdf.get_y()
    pdf.rect(pdf.l_margin, hero_y, _page_w(pdf), 42, "DF")

    # Title left + Risk badge right
    pdf.set_xy(pdf.l_margin + 4, hero_y + 3)
    pdf.set_font(family, "B", 13)
    pdf.set_text_color(0, 221, 68)
    pdf.cell(_page_w(pdf) - 60, 6, "📊 TA SESSION VILLAGE3B", ln=False)
    # Risk badge
    if score < 30:
        badge_r, badge_g, badge_b = 0, 200, 100
    elif score < 70:
        badge_r, badge_g, badge_b = 255, 179, 71
    else:
        badge_r, badge_g, badge_b = 255, 68, 102
    pdf.set_fill_color(badge_r, badge_g, badge_b)
    pdf.set_text_color(10, 10, 15)
    pdf.set_x(pdf.l_margin + _page_w(pdf) - 55)
    pdf.set_font(family, "B", 11)
    pdf.cell(50, 6, _safe(f"Risque: {label} ({score}/100)"), align="C", fill=True)
    pdf.ln(8)

    # Big numbers row (4 KPI cells)
    pdf.set_text_color(0, 221, 68)
    pdf.set_font(family, "B", 18)
    box_w = (_page_w(pdf) - 8) / 4
    y_kpi = pdf.get_y() + 2
    kpis = [
        (str(m.get("connections", 0)), "connexions"),
        (str(m.get("unique_hosts", 0)), "hôtes"),
        (str(m.get("successful", 0)), "OK 2xx/3xx"),
        (str(m.get("tls_pinned", 0)), "cert-pinning"),
    ]
    for i, (n, lbl) in enumerate(kpis):
        x = pdf.l_margin + 4 + i * box_w
        pdf.set_xy(x, y_kpi)
        pdf.set_font(family, "B", 16)
        pdf.set_text_color(0, 255, 85)
        pdf.cell(box_w, 7, n, ln=False, align="C")
        pdf.set_xy(x, y_kpi + 7)
        pdf.set_font(family, "", 8)
        pdf.set_text_color(150, 150, 150)
        pdf.cell(box_w, 4, _safe(lbl), ln=False, align="C")

    # Top device + top app + top country lines
    pdf.set_xy(pdf.l_margin + 4, hero_y + 30)
    pdf.set_font(family, "", 9)
    pdf.set_text_color(220, 220, 200)
    top_device = avatar.get("most_common") or "?"
    top_device_emoji = avatar.get("most_common_emoji") or ""
    top_app = "?"
    if dpi_cls.get("top_apps"):
        ta = dpi_cls["top_apps"][0]
        top_app = f"{ta.get('emoji', '')} {ta.get('app', '?')}"
    top_country = "?"
    if geo_hosts:
        gh = geo_hosts[0]
        if gh.get("flag") or gh.get("country"):
            top_country = f"{gh.get('flag', '')} {gh.get('asn_org', '?')[:30]}"
    pdf.cell(0, 4, _safe(f"Top device : {top_device_emoji} {top_device}  ·  Top app : {top_app}  ·  Top ASN : {top_country}"), ln=True)

    # Reset cursor + colors below the hero
    pdf.set_y(hero_y + 44)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(2)


def _safe(text: str) -> str:
    """Replace chars not in DejaVu+NotoSymbols fonts (mostly flag emojis).

    Most emoji render directly via DejaVu Sans + fallback. Flag emojis use
    regional indicator pairs that aren't in DejaVu, so we substitute them
    with their ISO country code in brackets.
    """
    if not text:
        return ""
    s = str(text)
    for emoji, repl in _EMOJI_REPLACEMENTS.items():
        if emoji in s:
            s = s.replace(emoji, repl)
    return s


def _ascii_safe(text: str) -> str:
    """Backward-compat alias (other code paths still call this name)."""
    return _safe(text)


def _section(pdf, title: str) -> None:
    pdf.set_x(pdf.l_margin)
    pdf.set_font(getattr(pdf, "_secubox_family", "Helvetica"), "B", 12)
    pdf.set_text_color(0, 221, 68)
    pdf.multi_cell(_page_w(pdf), 7, _ascii_safe(title)[:80])
    pdf.set_font(getattr(pdf, "_secubox_family", "Helvetica"), "", 10)
    pdf.set_text_color(0)


def _kv(pdf, key: str, value: str) -> None:
    pdf.set_x(pdf.l_margin)
    pdf.set_font(getattr(pdf, "_secubox_family", "Helvetica"), "B", 9)
    pdf.cell(45, 5, _ascii_safe(key)[:30], ln=False)
    pdf.set_font(getattr(pdf, "_secubox_family", "Helvetica"), "", 9)
    pdf.cell(_page_w(pdf) - 45, 5, _ascii_safe(value)[:100], ln=True)


def _bullet(pdf, text: str, font_size: int = 9) -> None:
    """Render a bullet line. multi_cell with hard truncation to avoid fpdf
    'Not enough horizontal space' errors on long tokens/URLs."""
    pdf.set_x(pdf.l_margin)
    pdf.set_font(getattr(pdf, "_secubox_family", "Helvetica"), "", font_size)
    safe = _ascii_safe(text)[:160]
    # Break unreasonably long single tokens (URLs over ~60 chars)
    parts = []
    for word in safe.split(" "):
        if len(word) > 60:
            for i in range(0, len(word), 60):
                parts.append(word[i:i + 60])
        else:
            parts.append(word)
    safe = " ".join(parts)
    pdf.multi_cell(_page_w(pdf), 5, "  - " + safe)


def _render_text_fallback(report: dict) -> str:
    """Plain text fallback when fpdf2 isn't installed."""
    lines = [
        "=" * 64,
        "GONDWANA TOOLBOX - Rapport d'analyse",
        "=" * 64,
        "",
        f"Hash session   : {report.get('mac_hash', '?')}",
        f"Type appareil  : {report.get('device_type', '?')}",
        f"Date           : {report.get('generated_at', '?')}",
        "",
        "fpdf2 not installed -- text fallback. apt install python3-fpdf2",
    ]
    return "\n".join(lines)
