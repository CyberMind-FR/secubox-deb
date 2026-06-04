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
    pdf.set_font("Helvetica", "B", 13)
    if score < 30:
        pdf.set_text_color(0, 221, 68)
        risk_label = "LOW"
    elif score < 70:
        pdf.set_text_color(255, 179, 71)
        risk_label = "MEDIUM"
    else:
        pdf.set_text_color(255, 68, 102)
        risk_label = "HIGH"
    pdf.cell(0, 8, f"Score risque : {score}/100 ({risk_label})", ln=True)
    pdf.set_text_color(0)
    pdf.set_font("Helvetica", "", 10)
    pdf.ln(2)
    for sig in report.get("indicators", []):
        _bullet(pdf, sig)
    pdf.ln(2)

    # Cert-pinning protection
    _section(pdf, "PROTECTION CERT-PINNING (apps qui RESISTENT au MITM)")
    for app in report.get("pinned_apps", []):
        _bullet(pdf, app)
    pdf.ln(2)

    # Inspected traffic
    inspected = report.get("inspected_urls", [])
    if inspected:
        _section(pdf, "TRAFIC INSPECTE (R2 consent explicite)")
        for url in inspected[:15]:
            _bullet(pdf, url, font_size=8)
        pdf.ln(2)

    # Recommendations
    _section(pdf, "RECOMMANDATIONS")
    for rec in report.get("recommendations", []):
        _bullet(pdf, rec)
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
    pdf.cell(0, 4, "Gondwana ToolBoX  -  LicenseRef-CMSD-1.0  -  AGPL public", ln=True, align="C")
    pdf.cell(0, 4, "Source : github.com/CyberMind-FR/secubox-deb (issues #474 #475 #477)", ln=True, align="C")

    return bytes(pdf.output(dest="S"))


def _page_w(pdf) -> float:
    """Available content width between margins."""
    return pdf.w - pdf.l_margin - pdf.r_margin


def _section(pdf, title: str) -> None:
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(0, 221, 68)
    pdf.multi_cell(_page_w(pdf), 7, title[:80])
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(0)


def _kv(pdf, key: str, value: str) -> None:
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(45, 5, key[:30], ln=False)
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(_page_w(pdf) - 45, 5, str(value)[:100], ln=True)


def _bullet(pdf, text: str, font_size: int = 9) -> None:
    """Render a bullet line. multi_cell with hard truncation to avoid fpdf
    'Not enough horizontal space' errors on long tokens/URLs."""
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "", font_size)
    safe = str(text)[:160]
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
