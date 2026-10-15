# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2723 — l'étape « Maillage » enregistre ce que le formulaire envoie en mode automatique, y compris `aide`.

Constaté sur le kiosque (étape 7/9) : « Champs inconnus : aide ». Le formulaire envoie {mode: "automesh", aide: "demander"|"non"} ; `moteur.py` et
`provision.py` connaissaient `maillage.aide`, mais la liste des champs que `enregistre()` accepte pour l'étape ne l'avait pas."""
import re
from pathlib import Path

import pytest

from premier_pas import moteur as M, profil as P, remplir as R

HTML = (Path(__file__).resolve().parents[1] / "www" / "premier-pas" / "index.html").read_text(encoding="utf-8")


@pytest.fixture
def isole(tmp_path, monkeypatch):
    monkeypatch.setenv("PREMIER_PAS_DIR", str(tmp_path))
    monkeypatch.setattr(M, "MARQUEUR", tmp_path / "fait")
    return tmp_path


@pytest.mark.parametrize("aide", ["demander", "non"])
def test_l_etape_maillage_accepte_aide_comme_le_formulaire_l_envoie(isole, aide):
    R.enregistre("maillage", {"mode": "automesh", "aide": aide})
    assert R.lit()["maillage"] == {"mode": "automesh", "aide": aide}


def test_un_champ_vraiment_inconnu_reste_refuse(isole):
    with pytest.raises(R.Refus, match="Champs inconnus : pirate"):
        R.enregistre("maillage", {"mode": "automesh", "pirate": "x"})


def test_une_valeur_d_aide_hors_liste_ressort_dans_l_examen_a_l_etape(isole):
    """Le contrat de `enregistre` : une valeur mal formée est acceptée là et signalée par l'examen, pas refusée en silence."""
    R.enregistre("maillage", {"mode": "automesh", "aide": "toujours"})
    assert "maillage" in P.examine(R.lit(), ["full"]).erreurs


@pytest.mark.parametrize("autre", ["plus_tard", "premiere"])
def test_changer_de_mode_apres_avoir_coche_l_aide_ne_laisse_pas_une_aide_orpheline(isole, autre):
    """`enregistre` fusionne dans le bloc existant : sans nettoyage, `aide` survivrait au passage en « Plus tard » et l'examen la refuserait
    (une aide n'a de sens qu'en automesh), bloquant l'assistant sur une case que la personne ne voit plus."""
    R.enregistre("maillage", {"mode": "automesh", "aide": "demander"})
    R.enregistre("maillage", {"mode": autre})
    assert "aide" not in R.lit()["maillage"]
    assert "maillage" not in P.examine(R.lit(), ["full"]).erreurs


def test_tout_ce_que_le_formulaire_envoie_pour_le_maillage_est_permis():
    """Garde contre la même dérive : les clés de l'objet envoyé par chaque mode de l'étape sont toutes dans la liste du serveur."""
    bloc = re.search(r'valeurs: \(\) => brouillon\.mode === "rejoindre"(.*?)\n  \},', HTML, re.S).group(1)
    envoyees = set(re.findall(r"[{,]\s*(\w+):", "{" + bloc))
    envoyees -= {"mode"} | {"modes"}
    assert {"rejoindre", "jeton", "aide"} <= envoyees, envoyees
    assert envoyees <= R.CHAMPS["maillage"][1], envoyees - R.CHAMPS["maillage"][1]
