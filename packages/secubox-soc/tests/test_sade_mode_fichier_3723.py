# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3723 — publication du mode SADE pour gk2 : `/run/secubox/sade-mode.json`.

Contenu `{"mode", "depuis", "liste_blanche"}`, 0644, écrit par renommage atomique (jamais de fichier partiel visible),
après `changer_mode`, l'ajout ou le retrait d'une entrée de liste blanche, au démarrage de l'API et à chaque battement.
L'API du WAF de gk2 le lit (porte du mode, cibles protégées) sans jamais ouvrir la base du SOC.
"""
import asyncio
import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from api import defense_etat, main  # noqa: E402


@pytest.fixture(autouse=True)
def isole(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_SOC_DEFENSE_DB", str(tmp_path / "defense.db"))
    monkeypatch.setenv("SECUBOX_AUDIT_LOG", str(tmp_path / "audit.log"))
    return Path(os.environ["SECUBOX_SOC_SADE_MODE"])


def _lu(p):
    return json.loads(p.read_text(encoding="utf-8"))


def _age_s(depuis):
    return (datetime.now(timezone.utc) - datetime.fromisoformat(depuis.replace("Z", "+00:00"))).total_seconds()


def test_changer_mode_publie_le_fichier(isole):
    defense_etat.changer_mode("active", "admin")
    d = _lu(isole)
    assert set(d) == {"mode", "depuis", "liste_blanche"}
    assert d["mode"] == "active"
    assert 0 <= _age_s(d["depuis"]) < 60
    assert "10.0.0.0/8" in d["liste_blanche"]               # entrées amorcées comprises
    assert stat.S_IMODE(isole.stat().st_mode) == 0o644
    defense_etat.changer_mode("observe", "admin")
    assert _lu(isole)["mode"] == "observe"


def test_ecriture_atomique_pas_de_fichier_partiel(isole, monkeypatch):
    defense_etat.changer_mode("reactive", "admin")
    avant = isole.read_bytes()
    vu = {}
    vrai = os.replace

    def remplacer(src, dst):
        vu["src"], vu["dst"] = Path(src), Path(dst)
        vu["cible_pendant"] = Path(dst).read_bytes()          # la cible n'est jamais écrite en place
        vu["temp"] = json.loads(Path(src).read_text())         # le temporaire est complet AVANT le renommage
        vu["mode_temp"] = stat.S_IMODE(os.stat(src).st_mode)
        vrai(src, dst)
    monkeypatch.setattr(defense_etat.os, "replace", remplacer)
    defense_etat.changer_mode("active", "admin")
    assert vu["dst"] == isole and vu["src"].parent == isole.parent and vu["src"] != isole
    assert vu["cible_pendant"] == avant
    assert vu["temp"]["mode"] == "active" and vu["mode_temp"] == 0o644
    assert _lu(isole)["mode"] == "active"
    assert [p.name for p in isole.parent.iterdir() if p.name.startswith(".sade-mode")] == []


def test_liste_blanche_republie(isole):
    defense_etat.ajouter_liste_blanche("203.0.113.7", "partenaire", "admin")
    assert "203.0.113.7/32" in _lu(isole)["liste_blanche"]
    defense_etat.retirer_liste_blanche("203.0.113.7/32", "admin")
    assert "203.0.113.7/32" not in _lu(isole)["liste_blanche"]


def test_publication_impossible_ne_defait_pas_le_mode(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_SOC_SADE_MODE", str(tmp_path / "absent" / "sade-mode.json"))
    defense_etat.changer_mode("active", "admin")             # le mode change, la publication échoue sans lever
    assert defense_etat.mode_courant() == "active"
    assert defense_etat.publier_mode() is False


def test_base_illisible_rien_n_est_publie(isole, tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_SOC_DEFENSE_DB", str(tmp_path / "pas-un-dossier" / "x" / "defense.db"))
    (tmp_path / "pas-un-dossier").write_text("fichier")      # le parent est un fichier : base inaccessible
    assert defense_etat.publier_mode() is False
    assert not isole.exists()                                # jamais un mode ni une liste inventés


def test_demarrage_et_battement_publient(isole):
    assert any(f.__name__ == "_demarrer_battement_sade" for f in main.app.router.on_startup)
    asyncio.run(main._battement_sade(une_fois=True))
    d = _lu(isole)
    assert d["mode"] == "observe" and 0 <= _age_s(d["depuis"]) < 60
    assert main.BATTEMENT_SADE_S <= 300                      # bien en deçà des 15 min au-delà desquelles gk2 vaut observe


# ── ronde de correction 1 : une publication manquée se voit ───────────
def _audit(tmp_path):
    p = tmp_path / "audit.log"
    return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []


def test_publication_impossible_est_auditee_et_journalisee_en_erreur(tmp_path, monkeypatch, caplog):
    defense_etat._derniere_cause_publication.clear()
    monkeypatch.setenv("SECUBOX_SOC_SADE_MODE", str(tmp_path / "absent" / "sade-mode.json"))
    with caplog.at_level("ERROR", logger="secubox.soc.defense_etat"):
        assert defense_etat.publier_mode() is False
    assert any(r.levelname == "ERROR" and "sade-mode" in r.getMessage() for r in caplog.records)
    echecs = [a for a in _audit(tmp_path) if a["action"] == "sade-mode-publication-echec"]
    assert len(echecs) == 1 and echecs[0]["cause"] == "FileNotFoundError"
    assert defense_etat.publier_mode() is False                     # même cause : pas une ligne par battement
    assert len([a for a in _audit(tmp_path) if a["action"] == "sade-mode-publication-echec"]) == 1
    monkeypatch.setenv("SECUBOX_SOC_SADE_MODE", str(tmp_path / "sade-mode.json"))
    assert defense_etat.publier_mode() is True
    assert [a["action"] for a in _audit(tmp_path)][-1] == "sade-mode-publication-retablie"


def test_fichier_etranger_eperm_dit_explicitement(isole, monkeypatch, caplog, tmp_path):
    defense_etat._derniere_cause_publication.clear()

    def refuse(src, dst):
        raise PermissionError(1, "Operation not permitted")
    monkeypatch.setattr(defense_etat.os, "replace", refuse)
    with caplog.at_level("ERROR", logger="secubox.soc.defense_etat"):
        assert defense_etat.publier_mode() is False
    assert any("autre compte" in r.getMessage() for r in caplog.records)
    assert [a for a in _audit(tmp_path) if a["action"] == "sade-mode-publication-echec"][-1]["cause"] == \
        "fichier_etranger"
    assert [p.name for p in isole.parent.iterdir() if p.name.startswith(".sade-mode")] == []
