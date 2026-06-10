# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""
SecuBox-Deb :: ToolBoX Social Mapping — bilingual FR/EN PDF report

Phase 11.C (#508, parent #502) — evidence-only legal report consumed by
the per-client view's "Rapport PDF" card.  Renders via fpdf2 (same
engine as reports.py) so no new dependency.

The report is FACT-ONLY : it documents what we observed (cross-site
cookie reuse, trackers fired before consent, extra-EU transfers) with
the relevant RGPD article references.  It makes NO interpretation about
SCC presence/absence or ToS contradiction.

FR is the source-of-truth ; EN is a secondary summary line per field.
"""
from __future__ import annotations

import logging
import time
from typing import Dict, List

from . import social as _social

log = logging.getLogger("secubox.toolbox.social.report")


# Bilingual label pairs (FR primary, EN secondary).
_L = {
    "title": ("Cartographie sociale — Rapport d'évidence", "Social mapping — Evidence report"),
    "subtitle": ("Cabine numérique VILLAGE3B · Analyseur R3", "VILLAGE3B digital booth · R3 analyzer"),
    "anon_id": ("Identifiant anonyme", "Anonymous identifier"),
    "hash": ("Hash session (sel rotatif 24h)", "Session hash (24h rotating salt)"),
    "window": ("Fenêtre d'analyse", "Analysis window"),
    "generated": ("Généré le", "Generated"),
    "summary": ("Synthèse", "Summary"),
    "n_trackers": ("Traqueurs distincts", "Distinct trackers"),
    "n_sites": ("Sites visités", "Sites visited"),
    "n_preconsent": ("Traqueurs avant consentement", "Trackers before consent"),
    "n_extraeu": ("Transferts hors UE/EEE", "Extra-EU/EEA transfers"),
    "ev_preconsent": ("Évidence : traqueurs déclenchés AVANT consentement",
                      "Evidence: trackers fired BEFORE consent"),
    "ev_preconsent_basis": ("Base légale : RGPD art. 6.1.a (consentement) + art. 7 (preuve)",
                            "Legal basis: GDPR art. 6.1.a (consent) + art. 7 (proof)"),
    "ev_extraeu": ("Évidence : transferts vers des pays hors UE/EEE",
                   "Evidence: transfers to non-EU/EEA countries"),
    "ev_extraeu_basis": ("Base légale : RGPD art. 44+ (transferts internationaux). "
                         "Nous rapportons le fait observé, pas l'absence de garanties (SCC).",
                         "Legal basis: GDPR art. 44+ (international transfers). We report the "
                         "observed fact, not the absence of safeguards (SCC)."),
    "col_tracker": ("Traqueur", "Tracker"),
    "col_sites": ("Sites", "Sites"),
    "col_hits": ("Occurrences", "Hits"),
    "col_country": ("Pays", "Country"),
    "col_asn": ("Hébergeur (ASN)", "Host (ASN)"),
    "none_pre": ("Aucun traqueur déclenché avant consentement détecté.",
                 "No tracker fired before consent detected."),
    "none_eu": ("Aucun transfert hors UE/EEE détecté.",
                "No extra-EU/EEA transfer detected."),
    "footer": ("Rapport factuel — données calculées localement, aucune donnée externe. "
               "Anonyme : aucune valeur de cookie brute conservée. Droit à l'effacement : RGPD art. 17.",
               "Factual report — computed locally, no external data. Anonymous: no raw cookie "
               "value stored. Right to erasure: GDPR art. 17."),
    "ca_disclaimer": ("Évidence d'observation réseau via cabine R3 consentie. "
                      "Ne constitue pas un avis juridique.",
                      "Network observation evidence via consented R3 booth. "
                      "Not legal advice."),
}


def _bi(key: str) -> str:
    fr, en = _L.get(key, (key, key))
    return fr


def build_social_report(mac_hash: str, since_seconds: int = 7 * 86400) -> Dict:
    """Assemble the data structure the PDF renderer consumes."""
    graph = _social.fetch_graph(mac_hash, since_seconds=since_seconds)
    evidence = _social.evidence(mac_hash, since_seconds=since_seconds)
    stats = graph.get("stats", {})
    return {
        "mac_hash": mac_hash,
        "window_days": max(1, since_seconds // 86400),
        "generated_at": None,  # stamped by the API layer (Date.* unavailable here is fine; time.time ok)
        "total_trackers": stats.get("total_trackers", 0),
        "total_sites": stats.get("total_sites", 0),
        "pre_consent": evidence.get("pre_consent", []),
        "extra_eu": evidence.get("extra_eu", []),
    }


def render_social_pdf(report: Dict) -> bytes:
    """Render the bilingual evidence report as PDF (fpdf2)."""
    try:
        from fpdf import FPDF
    except ImportError:
        return _text_fallback(report).encode()

    # Reuse the font setup from reports.py for emoji/Unicode support.
    try:
        from .reports import _setup_fonts  # type: ignore
    except Exception:
        _setup_fonts = None

    pdf = FPDF(orientation="P", unit="mm", format="A4")
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    family = _setup_fonts(pdf) if _setup_fonts else "helvetica"

    def _mc(h, text):
        # Robust multi_cell : reset X to the left margin and use the
        # effective page width so fpdf2 never hits "not enough
        # horizontal space" when the cursor has drifted to the edge.
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(pdf.epw, h, text)

    def bi(key, size=10, style="", r=0, g=0, b=0, gap=1.0):
        fr, en = _L.get(key, (key, key))
        pdf.set_text_color(r, g, b)
        pdf.set_font(family, "B" if "B" in style else "", size)
        _mc(size * 0.5, fr)
        pdf.set_text_color(120, 120, 120)
        pdf.set_font(family, "", max(7, size - 2))
        _mc((size - 2) * 0.5, en)
        pdf.ln(gap)

    # ── Cover ──
    pdf.set_font(family, "B", 20)
    pdf.set_text_color(10, 90, 64)
    pdf.cell(0, 12, "🕸️ VILLAGE3B", ln=True, align="C")
    bi("title", 13, "B", 110, 64, 201, gap=0.5)
    bi("subtitle", 9, "", 110, 110, 110, gap=3)

    # ── Anonymous id ──
    bi("anon_id", 12, "B", 0, 90, 64, gap=0.5)
    pdf.set_font(family, "", 9)
    pdf.set_text_color(0)
    pdf.cell(0, 5, f"  {_bi('hash')}: {report.get('mac_hash', '?')[:16]}…", ln=True)
    pdf.cell(0, 5, f"  {_bi('window')}: {report.get('window_days', 7)} j / days", ln=True)
    pdf.cell(0, 5, f"  {_bi('generated')}: {report.get('generated_at', '?')}", ln=True)
    pdf.ln(3)

    # ── Summary tiles ──
    bi("summary", 12, "B", 0, 90, 64, gap=0.5)
    pdf.set_font(family, "", 10)
    pdf.set_text_color(0)
    pdf.cell(0, 6, f"  {_bi('n_trackers')}: {report.get('total_trackers', 0)}", ln=True)
    pdf.cell(0, 6, f"  {_bi('n_sites')}: {report.get('total_sites', 0)}", ln=True)
    pdf.cell(0, 6, f"  {_bi('n_preconsent')}: {len(report.get('pre_consent', []))}", ln=True)
    pdf.cell(0, 6, f"  {_bi('n_extraeu')}: {len(report.get('extra_eu', []))}", ln=True)
    pdf.ln(3)

    # ── Evidence : pre-consent ──
    bi("ev_preconsent", 12, "B", 230, 57, 70, gap=0.3)
    bi("ev_preconsent_basis", 8, "", 120, 120, 120, gap=1)
    pre = report.get("pre_consent", [])
    if pre:
        _table(pdf, family, pre, [
            (_bi("col_tracker"), "tracker_domain", 70),
            (_bi("col_sites"), lambda r: str(len(r.get("sites", []))), 25),
            ("pre", "pre_consent_hits", 25),
            (_bi("col_country"), "country_iso", 25),
            (_bi("col_asn"), "asn_org", 45),
        ])
    else:
        _note(pdf, family, _bi("none_pre"))
    pdf.ln(2)

    # ── Evidence : extra-EU ──
    bi("ev_extraeu", 12, "B", 110, 64, 201, gap=0.3)
    bi("ev_extraeu_basis", 8, "", 120, 120, 120, gap=1)
    eu = report.get("extra_eu", [])
    if eu:
        _table(pdf, family, eu, [
            (_bi("col_tracker"), "tracker_domain", 70),
            (_bi("col_sites"), lambda r: str(len(r.get("sites", []))), 25),
            (_bi("col_hits"), "hits", 25),
            (_bi("col_country"), "country_iso", 25),
            (_bi("col_asn"), "asn_org", 45),
        ])
    else:
        _note(pdf, family, _bi("none_eu"))
    pdf.ln(4)

    # ── Footer ──
    pdf.set_font(family, "", 7)
    pdf.set_text_color(120, 120, 120)
    fr, en = _L["footer"]
    _mc(3.2, fr)
    _mc(3.0, en)
    pdf.ln(1)
    fr, en = _L["ca_disclaimer"]
    _mc(3.2, fr + " / " + en)

    out = pdf.output(dest="S")
    return bytes(out) if isinstance(out, (bytes, bytearray)) else out.encode("latin-1")


def _table(pdf, family, rows: List[Dict], cols) -> None:
    pdf.set_font(family, "B", 8)
    pdf.set_text_color(0, 90, 64)
    for label, _key, w in cols:
        pdf.cell(w, 5, str(label)[:24], border="B")
    pdf.ln()
    pdf.set_font(family, "", 8)
    pdf.set_text_color(0)
    for r in rows[:40]:
        for label, key, w in cols:
            if callable(key):
                val = key(r)
            else:
                val = r.get(key, "")
            pdf.cell(w, 4.5, str(val if val is not None else "—")[:int(w / 1.7)])
        pdf.ln()


def _note(pdf, family, text: str) -> None:
    pdf.set_font(family, "I", 9)
    pdf.set_text_color(0, 120, 80)
    pdf.cell(0, 6, "  " + text, ln=True)


def _text_fallback(report: Dict) -> str:
    lines = [
        "VILLAGE3B — Social mapping evidence report",
        f"hash: {report.get('mac_hash', '?')[:16]}",
        f"trackers: {report.get('total_trackers', 0)}  sites: {report.get('total_sites', 0)}",
        f"pre-consent: {len(report.get('pre_consent', []))}  extra-EU: {len(report.get('extra_eu', []))}",
        "",
        "Pre-consent trackers (GDPR art. 6.1.a + 7):",
    ]
    for e in report.get("pre_consent", [])[:40]:
        lines.append(f"  - {e.get('tracker_domain')} ({e.get('pre_consent_hits')} hits, {e.get('country_iso')})")
    lines.append("")
    lines.append("Extra-EU transfers (GDPR art. 44+):")
    for e in report.get("extra_eu", [])[:40]:
        lines.append(f"  - {e.get('tracker_domain')} ({e.get('country_iso')}, {e.get('asn_org')})")
    return "\n".join(lines)
