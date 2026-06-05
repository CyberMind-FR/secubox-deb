# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""HMAC-signed report tokens + PDF generation (fpdf2)."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from datetime import datetime, timezone

from .models import ReportToken


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

    # Header
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(0, 90, 64)  # P31 dim green
    pdf.cell(0, 12, "GONDWANA TOOLBOX", ln=True, align="C")
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(110, 64, 201)
    pdf.cell(0, 6, "Rapport d'analyse de session - Cabine numerique VILLAGE3B", ln=True, align="C")
    pdf.ln(4)

    # Anonymous ID
    _section(pdf, "IDENTIFIANT ANONYME")
    _kv(pdf, "Hash session", report.get("mac_hash", "?"))
    _kv(pdf, "Type appareil", report.get("device_type", "?"))
    _kv(pdf, "Date analyse", report.get("generated_at", "?"))
    _kv(pdf, "Sandbox subnet", "10.99.0.0/24 (reseau isole VILLAGE3B)")
    pdf.ln(2)

    # Metrics
    _section(pdf, "METRIQUES SESSION")
    m = report.get("metrics", {})
    _kv(pdf, "Connexions totales", str(m.get("connections", 0)))
    _kv(pdf, "Hosts uniques", str(m.get("unique_hosts", 0)))
    _kv(pdf, "Reussies (200/3xx)", str(m.get("successful", 0)))
    _kv(pdf, "Cert-pin blocks", str(m.get("tls_pinned", 0)))
    pdf.ln(2)

    # Apps detected
    _section(pdf, "APPS DETECTEES")
    for line in report.get("apps_detected", []):
        _bullet(pdf, line)
    pdf.ln(2)

    # Compromise analysis
    _section(pdf, "ANALYSE COMPROMISSION")
    score = report.get("risk_score", 0)
    risk_label = report.get("risk_label") or ("LOW" if score < 30 else "MEDIUM" if score < 70 else "HIGH")
    pdf.set_font("Helvetica", "B", 13)
    if score < 30:
        pdf.set_text_color(0, 221, 68)
    elif score < 70:
        pdf.set_text_color(255, 179, 71)
    else:
        pdf.set_text_color(255, 68, 102)
    pdf.cell(0, 8, _ascii_safe(f"Score risque : {score}/100 ({risk_label})"), ln=True)
    pdf.set_text_color(0)
    pdf.set_font("Helvetica", "", 10)
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
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(0, 5, f"{b.get('category', '?').upper()} : poids {b.get('weight_subtotal', 0)} (sur {b.get('raw_signal_count', 0)} signal)", ln=True)
            pdf.set_font("Helvetica", "", 8)
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
            _section(pdf, "QUALITE SECURITE PAR DESTINATION (worst-first)")
            for h in per_host[:10]:
                grade = h.get("grade", "?")
                host = h.get("host", "?")[:50]
                status = h.get("status", "?")
                _bullet(pdf, f"[{grade}] {host} - {status}", font_size=8)
            pdf.ln(2)

    # Retention
    _section(pdf, "RETENTION DES DONNEES")
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
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(110, 64, 201)
    pdf.cell(0, 4, "Gondwana ToolBoX  -  LicenseRef-CMSD-1.0 (Source-Disclosed License)", ln=True, align="C")
    pdf.cell(0, 4, "Source : github.com/CyberMind-FR/secubox-deb (issues #474 #475 #477)", ln=True, align="C")

    return bytes(pdf.output(dest="S"))


def _page_w(pdf) -> float:
    """Available content width between margins."""
    return pdf.w - pdf.l_margin - pdf.r_margin


# Helvetica is latin-1 only ; PDF report uses ASCII replacements for emoji
# (HTML live report keeps the real emoji glyphs).
_EMOJI_REPLACEMENTS = {
    "📺": "[TV]", "🎬": "[FILM]", "🎵": "[MUSIC]", "👥": "[SOCIAL]",
    "📷": "[PHOTO]", "🐦": "[X]", "👾": "[REDDIT]", "💼": "[WORK]",
    "📌": "[PIN]", "🐘": "[MASTO]", "🦋": "[BSKY]", "🔒": "[E2E]",
    "💬": "[CHAT]", "✈": "[TG]", "🟢": "[OK]", "🔍": "[SEARCH]",
    "🦆": "[DDG]", "📦": "[BOX]", "☁": "[CLOUD]", "🐙": "[GH]",
    "🦊": "[FF]", "📚": "[DOC]", "🏦": "[BANK]", "📧": "[MAIL]",
    "🍎": "[APPLE]", "🧅": "[TOR]", "🔐": "[VPN]", "❔": "[?]",
    "📱": "[PHONE]", "💻": "[PC]", "🐧": "[LINUX]", "🎮": "[GAME]",
    "📟": "[BOT]", "🛠": "[TOOL]", "🪟": "[EDGE]", "🧭": "[SAFARI]",
    "🔴": "[OPERA]", "🇫🇷": "[FR]", "🇺🇸": "[US]", "🏳": "[??]",
    "📊": "[STATS]", "🎯": "[ADS]", "🟦": "[BLOCK]", "—": "-",
    "·": "-", "…": "...", "✅": "[OK]", "⚠": "[WARN]", "❌": "[KO]",
}


def _ascii_safe(text: str) -> str:
    """Strip / replace characters outside Helvetica's latin-1 coverage."""
    if not text:
        return ""
    s = str(text)
    for emoji, repl in _EMOJI_REPLACEMENTS.items():
        if emoji in s:
            s = s.replace(emoji, repl)
    # Final fallback : encode to latin-1 ignoring unknown chars
    return s.encode("latin-1", errors="replace").decode("latin-1")


def _section(pdf, title: str) -> None:
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(0, 221, 68)
    pdf.multi_cell(_page_w(pdf), 7, _ascii_safe(title)[:80])
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(0)


def _kv(pdf, key: str, value: str) -> None:
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(45, 5, _ascii_safe(key)[:30], ln=False)
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(_page_w(pdf) - 45, 5, _ascii_safe(value)[:100], ln=True)


def _bullet(pdf, text: str, font_size: int = 9) -> None:
    """Render a bullet line. multi_cell with hard truncation to avoid fpdf
    'Not enough horizontal space' errors on long tokens/URLs."""
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "", font_size)
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
