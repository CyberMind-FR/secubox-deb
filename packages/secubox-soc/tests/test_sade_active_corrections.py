# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3839 — SADE ACTIVE, corrections de la relecture finale : pairs wg_mesh.json (F1), classement des refus de wafctl
(F2), arriéré (F3), refus humain par adresse (F5), audit de conclusion et budget de temps (mineurs)."""
# ruff: noqa: F811 — les fixtures pytest importées sont « redéfinies » par les paramètres des tests (faux positif).
import json
import os
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_sade_auto import faux, actif, _actord, _brute, _audit, _Fini  # noqa: E402,F401
from api import defense, defense_etat, sade_auto  # noqa: E402


# ── F1 : pairs du maillage lus dans wg_mesh.json ─────────────────────────────────────────────────

def _wg_mesh(tmp_path, monkeypatch, contenu):
    chemin = tmp_path / "wg_mesh.json"
    chemin.write_text(contenu if isinstance(contenu, str) else json.dumps(contenu), encoding="utf-8")
    monkeypatch.setenv("SECUBOX_SOC_WG_MESH", str(chemin))
    return chemin


def test_pair_wg_mesh_jamais_banni(actif, tmp_path, monkeypatch):
    _wg_mesh(tmp_path, monkeypatch, {"peers": [{"name": "gk3", "mesh_ip": "10.10.0.5",
                                                "endpoint": "203.0.113.10:51820"}]})
    r = sade_auto.executer()
    assert actif.bans == [] and r["ecartees"] == 1 and r["erreur"] is None


def test_pair_wg_mesh_format_liste_et_ipv6(actif, tmp_path, monkeypatch):
    _wg_mesh(tmp_path, monkeypatch, [{"mesh_ip": "2001:db8::7"}])
    actif.rep[("actord", "/proposals")] = _actord(_brute(ips=["2001:db8::7"]))
    sade_auto.executer()
    assert actif.bans == []


def test_pair_wg_mesh_illisible_rien(actif, tmp_path, monkeypatch):
    _wg_mesh(tmp_path, monkeypatch, "{pas du json")
    r = sade_auto.executer()
    assert actif.bans == [] and r["erreur"] == "pairs_illisibles" and defense_etat.etats_decisions() == {}


def test_pair_wg_mesh_forme_inattendue_rien(actif, tmp_path, monkeypatch):
    _wg_mesh(tmp_path, monkeypatch, {"pairs": "x"})
    r = sade_auto.executer()
    assert actif.bans == [] and r["erreur"] == "pairs_illisibles"


def test_pair_wg_mesh_non_lisible_rien(actif, tmp_path, monkeypatch):
    chemin = _wg_mesh(tmp_path, monkeypatch, {"peers": []})
    chemin.unlink()
    chemin.mkdir()  # un répertoire : l'ouverture échoue autrement que par « absent »
    r = sade_auto.executer()
    assert actif.bans == [] and r["erreur"] == "pairs_illisibles"


def test_pair_wg_mesh_absent_continue(actif):
    r = sade_auto.executer()  # le fixture pointe vers un fichier absent : box sans maillage
    assert actif.bans == [("203.0.113.10", "3600s")] and r["erreur"] is None


def test_pairs_threatmesh_toujours_fusionnes(actif, tmp_path, monkeypatch):
    _wg_mesh(tmp_path, monkeypatch, {"peers": [{"mesh_ip": "10.10.0.5"}]})
    actif.rep[("threatmesh", "/peers")] = {"peers": [{"address": "203.0.113.10:51820"}]}
    r = sade_auto.executer()
    assert actif.bans == [] and r["ecartees"] == 1


# ── F2 : seuls les verdicts de garde de wafctl sont définitifs ───────────────────────────────────

@pytest.mark.parametrize("stderr,definitif", [
    ("refus:privee\n", True), ("refus:protegee\n", True), ("refus:box\n", True), ("refus:pair\n", True),
    ("refus:invalide\n", True),
    ("[2026-11-20 15:00:00] ERROR: Adresse privée refusée : 10.0.0.1\n", True),
    ("[2026-11-20 15:00:00] ERROR: Adresse invalide : x\n", True),
    ("refus:garde_illisible\n", False),
    ("[2026-11-20 15:00:00] ERROR: nft a refusé le bannissement de 203.0.113.10\n", False),
    ("[2026-11-20 15:00:00] ERROR: Durée invalide : 3600x (attendu 30m, 4h, 1d…)\n", False),
    ("refus:privee_ou_autre\n", False), ("quelque chose d'inconnu\n", False), ("", False),
    ("sudo: a password is required\n", False),
])
def test_classement_des_sorties_de_wafctl(monkeypatch, stderr, definitif):
    monkeypatch.setattr(sade_auto.subprocess, "run", lambda cmd, **kw: _Fini(1, stderr))
    ok, raison = sade_auto._wafctl_ban("203.0.113.10", "3600s")
    assert not ok and sade_auto.refus_definitif(raison) is definitif


def test_erreur_temporaire_remet_en_attente_et_arrete(actif):
    actif.rep[("actord", "/proposals")] = _actord(_brute(), _brute(actor="ACT-0002", ips=["203.0.113.20"]))
    actif.reponse_ban = lambda ip, duree: (False, "echec: refus:garde_illisible")
    r = sade_auto.executer()
    assert [ip for ip, _d in actif.bans] == ["203.0.113.10"]  # arrêt du passage au premier échec temporaire
    assert defense_etat.decision(defense.empreinte("ban", ["203.0.113.10"], 3600))["etat"] == "en_attente"
    assert r["bannies"] == []


# ── F3 : l'arriéré reste à la main ───────────────────────────────────────────────────────────────

def test_proposition_vue_avant_active_jamais_auto(faux):
    sade_auto.executer()                      # passage en OBSERVE : la proposition est vue (arriéré)
    with closing(sqlite3.connect(os.environ["SECUBOX_SOC_DEFENSE_DB"])) as db:
        db.execute("UPDATE propositions_vues SET vu_ts = '2026-01-01T00:00:00Z'")
        db.commit()
    defense_etat.changer_mode("active", "admin")
    r = sade_auto.executer()
    assert faux.bans == [] and r["arriere"] == 1 and defense_etat.etats_decisions() == {}


def test_proposition_vue_apres_active_auto(faux):
    sade_auto.executer()                      # A vue en OBSERVE
    with closing(sqlite3.connect(os.environ["SECUBOX_SOC_DEFENSE_DB"])) as db:
        db.execute("UPDATE propositions_vues SET vu_ts = '2026-01-01T00:00:00Z'")
        db.commit()
    defense_etat.changer_mode("active", "admin")
    faux.rep[("actord", "/proposals")] = _actord(_brute(), _brute(actor="ACT-0002", ips=["203.0.113.20"]))
    r = sade_auto.executer()
    assert faux.bans == [("203.0.113.20", "3600s")] and r["arriere"] == 1


def test_premiere_vue_conservee(actif):
    sade_auto.executer()
    with closing(sqlite3.connect(os.environ["SECUBOX_SOC_DEFENSE_DB"])) as db:
        avant = db.execute("SELECT empreinte, vu_ts FROM propositions_vues").fetchall()
    sade_auto.executer()
    with closing(sqlite3.connect(os.environ["SECUBOX_SOC_DEFENSE_DB"])) as db:
        assert db.execute("SELECT empreinte, vu_ts FROM propositions_vues").fetchall() == avant


def test_mode_detail(faux):
    assert defense_etat.mode_detail() == ("observe", None, None)
    defense_etat.changer_mode("active", "admin")
    valeur, depuis, par = defense_etat.mode_detail()
    assert valeur == "active" and par == "admin" and depuis.endswith("Z")


def test_releve_des_vues_illisible_rien(actif, monkeypatch):
    def panne(_e):
        raise defense_etat.EtatIndisponible("OperationalError")
    monkeypatch.setattr(defense_etat, "noter_propositions_vues", panne)
    r = sade_auto.executer()
    assert actif.bans == [] and r["erreur"] == "base_indisponible"


# ── F5 : refus humain par adresse ────────────────────────────────────────────────────────────────

def test_adresse_refusee_par_humain_jamais_auto(faux):
    defense_etat.changer_mode("active", "admin")
    emp = defense.empreinte("ban", ["203.0.113.10"], 3600)
    defense_etat.reclamer(emp, "ACT-0001", "ban", "203.0.113.10", 70, 3600, "admin", "refuse", "sade-refuse",
                          modes=("active",))
    faux.rep[("actord", "/proposals")] = _actord(_brute(ttl=7200, ips=["203.0.113.11", "203.0.113.10"]))
    r = sade_auto.executer()
    assert faux.bans == [] and r["bannies"] == []


def test_refus_par_l_executeur_ne_lie_pas_l_adresse(faux):
    defense_etat.changer_mode("active", "admin")
    emp = defense.empreinte("ban", ["203.0.113.10"], 3600)
    defense_etat.reclamer(emp, "ACT-0001", "ban", "203.0.113.10", 70, 3600, "sade-auto", "refuse", "x",
                          modes=("active",))
    faux.rep[("actord", "/proposals")] = _actord(_brute(ttl=7200))
    sade_auto.executer()
    assert faux.bans == [("203.0.113.10", "7200s")]


def test_refus_sans_operateur_compte_comme_humain(faux):
    defense_etat.changer_mode("active", "admin")
    emp = defense.empreinte("ban", ["203.0.113.10"], 3600)
    with closing(sqlite3.connect(os.environ["SECUBOX_SOC_DEFENSE_DB"])) as db, db:
        db.execute("INSERT INTO decisions(empreinte, generation, menace_id, cible, geste, score, ttl_s, etat, "
                   "demande_ts, tranche_ts, par) VALUES (?,1,'ACT-0001','203.0.113.10','ban',70,3600,'refuse',"
                   "'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',NULL)", (emp,))
    assert defense_etat.refuse_par_humain(emp) is True
    faux.rep[("actord", "/proposals")] = _actord(_brute(ttl=7200))
    sade_auto.executer()
    assert faux.bans == []


# ── mineurs : conclusion en échec auditée, budget de temps ──────────────────────────────────────

def test_audit_resultat_porte_conclusion_echec(actif, monkeypatch):
    def panne(*a, **k):
        raise defense_etat.EtatIndisponible("OperationalError")
    monkeypatch.setattr(defense_etat, "conclure", panne)
    r = sade_auto.executer()
    assert r["erreur"] == "base_indisponible"
    res = next(e for e in _audit() if e["action"] == "sade-auto-resultat")
    assert res["conclusion"] == "echec"


def test_audit_resultat_sans_conclusion_echec_si_conclue(actif):
    sade_auto.executer()
    res = next(e for e in _audit() if e["action"] == "sade-auto-resultat")
    assert "conclusion" not in res


def test_budget_de_temps_arrete_les_nouvelles_propositions(actif, monkeypatch):
    actif.rep[("actord", "/proposals")] = _actord(*[_brute(actor=f"ACT-{i:04d}", ips=[f"203.0.113.{i}"])
                                                    for i in range(1, 4)])
    instants = iter([0.0, 10.0, 179.0, 180.0, 500.0])  # départ, puis avant chaque proposition
    monkeypatch.setattr(sade_auto, "_horloge", lambda: next(instants))
    r = sade_auto.executer()
    assert len(actif.bans) == 2 and r["budget"] is True
    assert sade_auto.BUDGET_PASSAGE_S == 180


def test_vues_purgees_seulement_si_plus_proposees(faux):
    defense_etat.noter_propositions_vues(["a" * 64, "b" * 64])
    with closing(sqlite3.connect(os.environ["SECUBOX_SOC_DEFENSE_DB"])) as db, db:
        db.execute("UPDATE propositions_vues SET vu_ts = '2020-01-01T00:00:00Z'")
    vues = defense_etat.noter_propositions_vues(["a" * 64])
    assert vues == {"a" * 64: "2020-01-01T00:00:00Z"}  # encore proposée : première vue gardée, jamais rajeunie
    with closing(sqlite3.connect(os.environ["SECUBOX_SOC_DEFENSE_DB"])) as db:
        assert [e for (e,) in db.execute("SELECT empreinte FROM propositions_vues")] == ["a" * 64]


def test_migration_0002_sur_base_existante(faux):
    chemin = os.environ["SECUBOX_SOC_DEFENSE_DB"]
    sql = (Path(defense_etat.MIGRATIONS) / "0001-defense.sql").read_text(encoding="utf-8")
    with closing(sqlite3.connect(chemin)) as db:
        db.executescript(sql + "\nCREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, appliquee_le TEXT NOT NULL);"
                         "\nINSERT INTO schema_migrations VALUES (1, '2026-11-01T00:00:00Z');")
    assert defense_etat.noter_propositions_vues(["c" * 64])
    with closing(sqlite3.connect(chemin)) as db:
        assert db.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall() == [(1,), (2,), (3,)]
