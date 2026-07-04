# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Rich PDF character sheet (#790): pips, on/off inventory, quests section."""
from secubox_toolbox import reports


def _base(**extra):
    d = {"mac_hash": "deadbeef", "device_type": "phone", "generated_at": "2026-07-04",
         "indicators": [], "recommendations": [], "pinned_apps": []}
    d.update(extra)
    return d


_PERSONA = {
    "emoji": "🧑‍💻", "tag": "VILLAGE3B·#A1B2", "klass": "Runner", "level": "R3",
    "align": "🛡️ Protégé", "hp": 85, "exposure": 15, "xp": 12480,
    "attrs": [
        {"icon": "🛡️", "name": "DÉFENSE", "v": 14, "pips": 5, "note": ""},
        {"icon": "⚔️", "name": "RIPOSTE", "v": 6, "pips": 2, "note": "312 pubs tuées"},
    ],
    "inventory": [
        {"icon": "🧅", "name": "Tunnel Tor", "on": True},
        {"icon": "🚫", "name": "Ad-blocker", "on": False},
    ],
}


def _spy_safe(monkeypatch):
    """Capture every string drawn (everything is wrapped in reports._safe)."""
    seen = []
    orig = reports._safe
    monkeypatch.setattr(reports, "_safe", lambda t: (seen.append(str(t)), orig(t))[1])
    return seen


def test_persona_rich_sections_and_pips(monkeypatch):
    seen = _spy_safe(monkeypatch)
    data = _base(persona=_PERSONA,
                 bestiary=[{"label": "doubleclick.net", "count": 42, "emoji": "👹"}],
                 dpi_exfil={"me": {"alerts": [
                     {"kind": "exfil_volume", "label": "exfil", "service": "drive.google", "detail": "up 4.2Mo"}]}})
    blob = reports.render_pdf(data)
    assert isinstance(blob, (bytes, bytearray)) and len(blob) > 1000
    joined = " ".join(seen)
    assert "CARACTERISTIQUES" in joined           # attributes section header
    assert "QUETES EN COURS" in joined            # quests section header
    assert "●" in joined and "○" in joined         # pip glyphs rendered
    assert any("✓" in s for s in seen) and any("✗" in s for s in seen)  # on/off inventory
    assert any("EXFIL" in s for s in seen)         # the alert surfaced in Quêtes
    assert any("doubleclick" in s for s in seen)   # bestiary


def test_persona_no_alerts_shows_safe_zone(monkeypatch):
    seen = _spy_safe(monkeypatch)
    data = _base(persona=_PERSONA, dpi_exfil={"me": {"alerts": []}})
    reports.render_pdf(data)
    assert any("zone sure" in s for s in seen)     # empty-threats message


def test_persona_missing_dpi_exfil_no_raise(monkeypatch):
    # dpi_exfil absent entirely (legacy/token path before enrichment) must not raise
    data = _base(persona=_PERSONA)
    blob = reports.render_pdf(data)
    assert isinstance(blob, (bytes, bytearray)) and len(blob) > 500
