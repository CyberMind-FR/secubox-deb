# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Carte dynamique : une carte `si_present` disparaît du Hall quand le module est absent de la box (VoiceStudio sur gk2)."""
import re
from pathlib import Path

HALL = (Path(__file__).resolve().parents[1] / "www" / "hall" / "index.html").read_text()


def test_les_cartes_voicestudio_portent_une_sonde_de_presence():
    for ident in ("voicestudio", "voix"):
        ligne = re.search(rf'\{{id:"{ident}",[^\n]*', HALL).group(0)
        assert 'si_present:"/api/v1/voicestudio/status"' in ligne, ident


def test_le_rendu_ecarte_les_modules_absents_de_la_mosaique_et_du_rail():
    assert "FEATURED_ALPHA.filter(f=>!ABSENTS.has(f.id))" in HALL
    assert "FEATURED_ORDONNE.filter(f=>!ABSENTS.has(f.id))" in HALL


def test_seul_un_refus_net_retire_la_carte():
    sonde = HALL[HALL.index("function sondePresence()"):HALL.index("function render(data,src)")]
    assert "r.status===404||r.status===502||r.status===503" in sonde
    assert ".catch(()=>null)" in sonde          # un échec réseau ne retire jamais une carte
    assert "render(DERNIER_RENDU.data" in sonde   # la mosaïque est redessinée quand une carte disparaît
