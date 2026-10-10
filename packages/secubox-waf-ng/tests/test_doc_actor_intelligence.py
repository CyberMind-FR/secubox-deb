# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2240 phase 6 : la documentation de la politique de scoring et de l'activation dit ce que le CODE fait — seuils, facteurs, drapeaux, modes. Si le code change
sans la doc, ce test échoue."""
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[3]
DOC = (RACINE / "docs" / "ACTOR-INTELLIGENCE-ACTIVATION.md").read_text()
GO = (RACINE / "packages" / "secubox-toolbox-ng" / "internal" / "actor" / "analysis" / "analysis.go").read_text()
MAIN = (RACINE / "packages" / "secubox-toolbox-ng" / "cmd" / "sbxwaf" / "main.go").read_text()
EXEMPLE = (RACINE / "packages" / "secubox-waf-ng" / "conf" / "actor-intelligence-simulation.conf.example").read_text()


def test_les_seuils_de_decision_de_la_doc_sont_ceux_du_code():
    for nom in ("SeuilMitigate", "SeuilConfianceMitige", "SeuilBlockRisque", "SeuilBlockConfiance", "MinCapteursBlock"):
        valeur = re.search(rf"{nom}\s*=\s*(\d+)", GO).group(1)
        assert re.search(rf"\|\s*`{nom}`\s*\|\s*{valeur}\s*\|", DOC), f"{nom} = {valeur} absent de la table des seuils"
    assert re.search(r'VersionPolitique\s*=\s*"(v\d+)"', GO).group(1) in DOC


def test_chaque_facteur_du_code_est_documente_avec_ses_points():
    facteurs = re.findall(r'ajoute\((?:r|c), (?:"([^"]+)"|fmt\.Sprintf\("([^"%]+)), (-?\d+)', GO)
    assert len(facteurs) >= 15
    for plein, debut, points in facteurs:
        libelle = plein or debut.strip()
        signe = f"+{points}" if not points.startswith("-") else points
        assert re.search(rf"{re.escape(libelle)}[^\n]*\|\s*{re.escape(signe)}\s*\|", DOC), f"facteur « {libelle} » ({signe}) absent de la doc"


def test_chaque_drapeau_d_activation_est_documente_avec_son_defaut():
    for drapeau in ("actor-ban", "campagne-ban", "leurre-ban", "reevaluation", "reeval-seuil", "scan-sensor", "scan-seuil", "actor-ban-min",
                    "actor-ban-max-heure", "campagne-ban-max-heure", "actor-ban-protegees"):
        assert f"`--{drapeau}" in DOC, drapeau
        assert re.search(rf'"{drapeau}"', MAIN), f"drapeau {drapeau} introuvable dans main.go"


def test_la_procedure_nomme_les_trois_modes_et_le_retour_arriere():
    for mot in ("PASSIVE_ONLY", "SIMULATION", "ACTIVE", "propose", "auto", "off", "WOULD_BLOCK", "reevaluations.jsonl", "Retour arrière"):
        assert mot in DOC, mot


def test_l_exemple_de_configuration_est_en_simulation_et_ne_bannit_rien():
    actifs = "\n".join(l for l in EXEMPLE.splitlines() if not l.lstrip().startswith("#"))
    for d in ("--actor-ban propose", "--campagne-ban propose", "--reevaluation propose"):
        assert d in actifs, d
    assert "auto" not in actifs and "--leurre-ban" not in actifs     # l'exemple n'active rien d'irréversible
