# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3666, correctif final — pages : encart des indices de TV Privacy (interrupteurs, appel /indices, date du résumé, texte exact)
et origine visible des règles nées d'un indice dans ad-guard (F5, F7, F8)."""
import pathlib
import re

RACINE = pathlib.Path(__file__).resolve().parents[1]
TV = (RACINE / "www" / "tv-privacy" / "index.html").read_text(encoding="utf-8")
AG = (RACINE / "www" / "ad-guard" / "index.html").read_text(encoding="utf-8")
CODE_TV = re.sub(r"//[^\n]*", "", re.sub(r"<!--.*?-->", "", TV, flags=re.S))


def test_f7_encart_des_indices_interrupteurs_et_appel():
    assert '<input type="checkbox" id="ix-recevoir">' in TV and '<input type="checkbox" id="ix-publier">' in TV
    assert 'id="ix-producteurs"' in TV and 'id="ix-note"' in TV
    assert "lire('/indices')" in CODE_TV
    assert "ecrire('/indices',{publier:el('ix-publier').checked,recevoir:el('ix-recevoir').checked})" in CODE_TV
    assert "['ix-recevoir','ix-publier'].forEach" in CODE_TV


def test_f5_date_affichee_est_celle_du_resume():
    assert "new Date(j.maj*1000)" in CODE_TV
    ligne = next(x for x in CODE_TV.splitlines() if "el('ix-note').textContent=fmt(j.recus)" in x)
    assert "new Date()" not in ligne                               # plus l'heure du navigateur


def test_f8_texte_exact_sur_le_declenchement():
    assert "ils ne déclenchent jamais un blocage seuls" not in TV
    assert "passe à l’essai automatiquement" in TV and "réversible" in TV and "jamais pour une catégorie protégée" in TV


def test_f7_ad_guard_affiche_les_box_qui_ont_suggere():
    assert "function autoDomaine(r)" in AG
    assert "'suggéré par ' + r.indice.join(', ')" in AG
    assert "par('essai').forEach(r => tvLigne(tb, [r.appareil, autoDomaine(r)," in AG
    assert "par('confirme').forEach(r => tvLigne(tb, [r.appareil, autoDomaine(r)," in AG
    corps = AG[AG.index("function autoDomaine(r)"):AG.index("function autoCell(")]
    assert "innerHTML" not in corps and "tvEl(" in corps                  # texte seulement
