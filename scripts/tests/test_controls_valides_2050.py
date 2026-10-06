# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Chaque champ de dépendance de chaque debian/control est une liste bien formée (virgules, éléments non vides).

Garde posé après qu'une réécriture automatique de dépendances a laissé, dans secubox-profils, un champ dont un commentaire
interrompait la liste : dpkg-gencontrol refusait le paquet (« parsing … Depends field »)."""
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]
CHAMPS = ("Depends", "Pre-Depends", "Recommends", "Suggests", "Enhances", "Replaces", "Breaks", "Conflicts", "Provides")
ELEMENT = re.compile(r"^(\$\{[^}]+\}|[a-z0-9][a-z0-9.+-]*(:[a-z0-9]+)?(\s*\([<>=]+\s*[^)]+\))?(\s*\[[^\]]+\])?)$")


def _champs(texte):
    # un champ = ligne « Nom: » + lignes de continuation ; les commentaires sont ignorés partout (deb822)
    courant, valeur = None, []
    for ligne in texte.split("\n"):
        if ligne.startswith("#"):
            continue
        if ligne and not ligne[0].isspace():
            if courant:
                yield courant, " ".join(valeur)
            nom, _, reste = ligne.partition(":")
            courant, valeur = (nom if nom in CHAMPS else None), [reste]
        elif courant:
            valeur.append(ligne)
        elif not ligne.strip():
            courant = None
    if courant:
        yield courant, " ".join(valeur)


def test_les_champs_de_dependance_sont_bien_formes():
    erreurs = []
    for ctrl in sorted(RACINE.glob("packages/*/debian/control")):
        if re.search(r"/debian/secubox-[^/]+/", str(ctrl)):
            continue
        for nom, valeur in _champs(ctrl.read_text()):
            elements = [e.strip() for e in valeur.split(",")]
            if elements and elements[-1] == "":
                elements.pop()                       # virgule finale tolérée sur le dernier élément vide seulement
            for e in elements:
                alternatives = [a.strip() for a in e.split("|")]
                if not e or any(not ELEMENT.match(a) for a in alternatives):
                    erreurs.append(f"{ctrl.parts[-3]} {nom} : {e!r}")
    assert not erreurs, "\n".join(erreurs[:15])
