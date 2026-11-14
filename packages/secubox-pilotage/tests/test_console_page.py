# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3702 tâche 7 : page de la console de pilotage, vérifications statiques (sans navigateur)."""
import re
from pathlib import Path

PAGE = Path(__file__).resolve().parents[1] / "www" / "pilotage" / "console" / "index.html"


def _src() -> str:
    return PAGE.read_text(encoding="utf-8")


def _code() -> str:
    """Le source sans commentaires HTML ni commentaires JS de fin de ligne (les mots interdits peuvent y être cités)."""
    sans_html = re.sub(r"<!--.*?-->", "", _src(), flags=re.S)
    return re.sub(r"(?<![:'\"\\])//[^\n]*", "", sans_html)


def test_entete_spdx():
    tete = _src()[:600]
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in tete
    assert "Copyright (c) 2026 CyberMind" in tete


def test_hauteur_annoncee_sbxvue_et_onglet():
    src = _src()
    assert "sbxVue" in src and "onglet: 'pilotage-console'" in src and "location.origin" in src
    assert "documentElement.scrollHeight" not in src


def test_embed_et_demo():
    src = _src()
    assert "Q.get('embed')" in src and "Q.get('demo')" in src
    assert 'id="demo"' in src


def test_aucun_script_externe_ni_police_distante():
    src = _src()
    assert re.findall(r"<script\s+src=\"([^\"]*)\"", src) == ["/shared/sidebar.js"]
    assert "fonts.googleapis" not in src and "@import" not in src


def test_ni_boite_native_ni_innerhtml_ni_eval():
    code = _code()
    for f in ("confirm", "alert", "prompt"):
        assert not re.search(r"(?<![A-Za-z_.$])" + f + r"\(", code), f
    assert "innerHTML" not in code and "outerHTML" not in code and "insertAdjacentHTML" not in code
    assert "eval(" not in code and "new Function" not in code
    assert not re.search(r"\son[a-z]+=\"", code), "aucun attribut d'événement en ligne"


def test_routes_de_l_api_citees():
    src = _src()
    for r in ("/flotte", "/catalogue", "/macros", "/executions?limite=20", "/executions/action", "/lancer", "/arreter", "/flux",
              "/support", "/boxes/", "/actions/", "/releve"):
        assert r in src, r
    assert "const API = '/api/v1/pilotage'" in src


def test_fonctions_reprises_par_la_tache_8():
    src = _src()
    for f in ("function ouvrirLancement(", "function suivreExecution(", "function api("):
        assert f in src, f


def test_zoom_et_barre_de_commande_accessibles():
    src = _src()
    assert 'aria-label="Chercher une action, une macro ou une box"' in src
    assert 'aria-label="Panneaux de la console"' in src
    for nom in ("Flotte", "Journal en direct", "Macros"):
        assert f'aria-label="Agrandir le panneau {nom}"' in src, nom
    assert "sessionStorage" in src
    # Échap écouté sur le document de la page seulement, jamais sur la fenêtre de l'hôte
    assert "parent.addEventListener" not in src and "top.addEventListener" not in src


def test_pas_de_ligne_disque_dans_le_panneau_de_la_box():
    assert not re.search(r"[Dd]isque", _code())


def test_cadre_sans_min_height():
    assert not re.search(r"\.cadre\{[^}]*min-height", _src())


def test_routes_d_ecriture_des_macros():
    """#3702 tâche 8 : enregistrer (POST/PUT), supprimer, copier, simuler, lancer."""
    src = _src()
    for r in ("'/macros'", "/copier", "/simuler", "/lancer", "method: 'PUT'", "method: 'DELETE'", "method: 'POST'"):
        assert r in src, r


def test_ecran_de_lancement_et_editeur_accessibles():
    src = _src()
    assert re.search(r'id="lancement"[^>]*>\s*<div class="fenetre[^"]*" role="dialog"', src)
    assert 'aria-label="Nom de la macro"' in src
    # ordre au clavier : « Monter / Descendre / Supprimer l'étape N » ; ajout par glisser
    for f in ("function ouvrirEditeur(", "'Monter'", "'Descendre'", "'Supprimer'", "' l\\'étape '", "draggable"):
        assert f in src, f
