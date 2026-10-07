# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""La bulle des diffusions du parc : ouverte seulement par un clic sur le logo, fermée vite sauf si le pointeur est dans la bulle."""
import re
from pathlib import Path

HTML = (Path(__file__).resolve().parents[1] / "www" / "hall" / "index.html").read_text()


def test_le_survol_du_logo_n_ouvre_plus_la_bulle():
    assert ".logo-wrap:hover .logo-diff" not in HTML, "le survol du logo ne doit plus déployer la bulle"
    assert "logoWrap.addEventListener('mouseenter'" not in HTML
    assert "logoWrap.addEventListener('mouseleave'" not in HTML


def test_la_bulle_ne_se_montre_que_par_la_classe_on():
    regle = re.search(r"\.logo-diff\.on\s*\{[^}]*visibility:visible", HTML)
    assert regle, "la bulle visible = classe .on seulement"
    # :hover seul sur la bulle ne la montre pas quand elle est fermée (elle est alors pointer-events:none)
    assert ".logo-diff:hover{opacity:1" not in HTML.replace(" ", "")


def test_un_clic_sur_le_logo_ouvre_puis_ferme_la_bulle():
    assert "function ouvreLD(" in HTML and "function fermeLD(" in HTML
    assert re.search(r"logoLien\.addEventListener\('click'", HTML)
    # clic avec modificateur (nouvel onglet) : le lien reste un lien
    assert "ctrlKey" in HTML and "metaKey" in HTML


def test_fermeture_courte_sauf_pointeur_dans_la_bulle():
    assert re.search(r"DELAI_LD\s*=\s*[1-5]\d{3}\b", HTML), "quelques secondes, pas plus de 5 s"
    assert "logoDiff.addEventListener('mouseenter'" in HTML and "logoDiff.addEventListener('mouseleave'" in HTML


def test_clic_ailleurs_et_echap_ferment():
    assert "Escape" in HTML and "logoWrap.contains(" in HTML
