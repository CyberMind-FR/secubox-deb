# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2530 — l'assistant propose `<nom>.secubox.in` comme domaine (le DNS de secubox.in est géré par gk2).

Sans domaine, firstboot garde nginx seul (« frontal : domaine de la box inconnu ») : le champ vide du premier démarrage laissait la box sans
frontal HAProxy ni WAF."""
import re
import sys
from pathlib import Path

ICI = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ICI))
sys.path.insert(0, str(ICI.parents[1] / "common"))

from premier_pas import console, profil  # noqa: E402

PAGE = (ICI / "www" / "premier-pas" / "index.html").read_text(encoding="utf-8")


def test_le_suffixe_par_defaut_est_secubox_in():
    assert profil.DOMAINE_PAR_DEFAUT == "secubox.in"


def test_domaine_propose_depuis_le_nom():
    assert profil.domaine_propose("gk1") == "gk1.secubox.in"
    assert profil.domaine_propose("Ma-Box-2") == "ma-box-2.secubox.in"


def test_pas_de_proposition_sans_nom_exploitable():
    for nom in ("", None, "   ", "---", "é à"):
        assert profil.domaine_propose(nom) == ""


def test_la_proposition_est_un_domaine_que_le_profil_accepte():
    dom = profil.domaine_propose("gk1")
    assert re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+", dom)


def _champ_domaine(profil_vue):
    page = next(p for p in console.pages(profil_vue) if p.id == "reseau")
    return next(c for c in page.champs if c.cle == "domaine")


def test_la_console_pre_remplit_le_domaine_depuis_le_nom():
    assert _champ_domaine({"box": {"nom": "gk1"}}).valeur == "gk1.secubox.in"


def test_un_domaine_deja_choisi_n_est_pas_ecrase():
    assert _champ_domaine({"box": {"nom": "gk1"}, "reseau": {"domaine": "gk1.exemple.fr"}}).valeur == "gk1.exemple.fr"


def test_la_console_sans_nom_laisse_le_champ_vide():
    assert _champ_domaine({}).valeur == ""


def test_la_page_web_propose_le_meme_suffixe():
    assert 'const DOMAINE_PAR_DEFAUT = "secubox.in"' in PAGE
    assert "domainePropose" in PAGE and "placeholder=\"gk3.secubox.in\"" in PAGE
