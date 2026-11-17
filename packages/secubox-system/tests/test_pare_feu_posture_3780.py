# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3780 : la posture « pare-feu » est une mesure de nftables, datée, jamais une affirmation."""
import importlib.machinery
import importlib.util
import json
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]


def _releve():
    chemin = str(RACINE / "sbin" / "secubox-pare-feu-releve")
    spec = importlib.util.spec_from_loader("releve", importlib.machinery.SourceFileLoader("releve", chemin))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


R = _releve()
# extrait réel de gk2 (17/11) : base inet filter input en drop + couches des modules en accept
DOC = {"nftables": [{"metainfo": {}}, {"table": {"family": "inet", "name": "filter"}}, {"table": {"family": "inet", "name": "secubox_nac"}},
                    {"chain": {"family": "inet", "table": "filter", "name": "input", "hook": "input", "policy": "drop"}},
                    {"chain": {"family": "inet", "table": "secubox_nac", "name": "input", "hook": "input", "policy": "accept"}},
                    {"chain": {"family": "inet", "table": "filter", "name": "forward", "hook": "forward", "policy": "drop"}},
                    {"rule": {}}, {"rule": {}}, {"rule": {}}]}


def test_resume_reel_entree_fermee():
    r = R.resumer(DOC, 100)
    assert r == {"releve": 100, "actif": True, "tables": 2, "regles": 3, "politique_entree": "drop", "chaines_drop": ["inet filter input"]}


def test_entree_ouverte_et_jeu_vide():
    ouvert = {"nftables": [c for c in DOC["nftables"] if not ("chain" in c and c["chain"]["policy"] == "drop")]}
    assert R.resumer(ouvert, 1)["politique_entree"] == "accept"
    assert R.resumer({"nftables": []}, 1)["actif"] is False


def test_api_traduit_le_releve(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("pare_feu_3780", RACINE / "api" / "pare_feu.py")
    P = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(P)
    f = tmp_path / "pare-feu.json"
    f.write_text(json.dumps(R.resumer(DOC, 1000)))
    assert P.lire(f, 1100)["etat"] == "actif"
    assert P.lire(f, 1000 + 16 * 60)["etat"] == "perime"
    assert P.lire(tmp_path / "absent.json", 1)["libelle"] == "Non relevé"
    f.write_text(json.dumps(R.resumer({"nftables": []}, 1000)))
    assert P.lire(f, 1001)["etat"] == "inactif"


def test_ecriture_lisible_par_l_api(tmp_path):
    p = tmp_path / "s" / "pare-feu.json"
    R.ecrire({"releve": 1, "actif": True}, str(p))
    assert oct(p.stat().st_mode & 0o777) == "0o644" and json.loads(p.read_text())["actif"] is True
