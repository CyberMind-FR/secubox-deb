# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: metablogizer — les copies de sauvegarde ne sont pas servies (#1034)

CyberMind — https://cybermind.fr

CE QUE CE TEST GARDE. Seize fichiers `.bak` / `.pre*` traînaient sous la racine
servie de la board, et nginx les rendait comme n'importe quelle page :
`shared/health-banner.js.pre750` et `cookies/index.html.pre749` s'obtenaient en
200 par leur simple nom. Rien ne les listait — rien ne les protégeait non plus.

LE TEST PORTE SUR LA CONFIGURATION ÉMISE, PAS SUR LE CODE QUI L'ÉCRIT. Le
gabarit est une f-string : un antislash de trop et nginx reçoit `\\\\.` au lieu
de `\\.`, c'est-à-dire une règle qui ne correspond à rien. Le défaut est
invisible à la lecture de la source — il ne se voit que dans le fichier produit.
Ce piège s'est déjà refermé une fois sur la règle des fichiers cachés.
"""
from __future__ import annotations

from test_conflits_domaines import prepare, site


def rendu(monkeypatch, tmp_path):
    s = [site(tmp_path, "essai", "essai.example.com")]
    main, enabled = prepare(monkeypatch, tmp_path, s)
    ok, _, msg = main.regenerate_nginx_config()
    assert ok, msg
    return (enabled / "metablogizer").read_text()


def test_la_regle_est_emise_avec_UN_antislash(monkeypatch, tmp_path):
    conf = rendu(monkeypatch, tmp_path)
    assert r"\.(?:bak|old|orig|save|swp|tmp)" in conf, \
        "règle absente ou mal échappée (nginx recevrait un motif inerte)"
    assert r"\\." not in conf.split("location ~*")[1].split("{")[0], \
        "double antislash : nginx ne ferait correspondre aucun nom"


def test_les_suffixes_vises_sont_couverts(monkeypatch, tmp_path):
    """Les noms REELLEMENT trouvés sur la board, un par un."""
    import re
    conf = rendu(monkeypatch, tmp_path)
    motif = re.search(r"location ~\* (.+?)\$ \{", conf)
    assert motif, "la location de garde n'est pas émise"
    rx = re.compile(motif.group(1) + "$", re.I)
    for nom in ("index.html.bak", "index.html.bak-20260803-130407",
                "index.html.bak.1778587975-test44", "index.html.pre749",
                "index.html.pre-tor-badge", "sentinelle.pre-v0.4.0-1779548524",
                "conf.old", "page.orig", "notes~"):
        assert rx.search(nom), f"{nom} resterait servi"


def test_la_garde_ne_mord_pas_sur_du_vrai_contenu(monkeypatch, tmp_path):
    """UNE GARDE QUI BLOQUE DU CONTENU LÉGITIME EST DÉSACTIVÉE DANS LA SEMAINE.

    `.presentation` est la raison pour laquelle le motif exige un chiffre ou un
    tiret après `.pre` : sans cette exigence, il emporterait des pages réelles.
    """
    import re
    conf = rendu(monkeypatch, tmp_path)
    motif = re.search(r"location ~\* (.+?)\$ \{", conf)
    rx = re.compile(motif.group(1) + "$", re.I)
    for nom in ("index.html", "cours.presentation", "style.css", "app.js",
                "photo.bakery.jpg", "archive.tar.gz", "preface.html"):
        assert not rx.search(nom), f"{nom} serait refusé à tort"
