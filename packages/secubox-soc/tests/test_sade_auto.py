# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3839 — SADE ACTIVE : exécuteur automatique du cas sûr (`api.sade_auto`).

Aucun sudo réel : `_wafctl_ban` est remplacé par un faux qui journalise ses appels ; actord et threatmesh sont des
faux `substrat.lire` ; base et audit temporaires.
"""
import copy
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fastapi.testclient import TestClient  # noqa: E402

from api import defense, defense_etat, main, sade_auto  # noqa: E402
from api.sade_auto import cas_sur  # noqa: E402
from secubox_core.auth import require_lecture  # noqa: E402


def _actord(*props):
    return {"genere_le": 1763630000, "shadow": False, "propositions": list(props)}


def _brute(actor="ACT-0001", mode="DENY", ips=("203.0.113.10",), ttl=3600, priorite=86):
    return {"actor": actor, "mode": mode, "raison": "essai", "ttl_s": ttl, "ips": list(ips), "priorite": priorite}


def prop(score=86, geste="ban", ips=("203.0.113.10",), ttl=3600):
    """Proposition normalisée (forme de `defense._propositions`)."""
    ips = list(ips)
    return {"id": f"ACT-0001:{geste}", "empreinte": defense.empreinte(geste, ips, ttl), "menace_id": "ACT-0001",
            "geste": geste, "ips": ips, "score": score, "bande": "contenir", "motif": None, "ttl_s": ttl}


class Faux:
    """Faux `substrat.lire` (actord, threatmesh) et faux `_wafctl_ban` ; journaux des appels."""

    def __init__(self):
        self.rep = {("actord", "/proposals"): _actord(_brute()),
                    ("threatmesh", "/peers"): {"peers": [{"id": "p1", "address": "198.51.100.9:51820"}]}}
        self.lus = []
        self.bans = []
        self.reponse_ban = lambda ip, duree: (True, "ok")
        self.pendant_lecture = None

    def lire(self, source, chemin, entetes=None, delai=3.0):
        self.lus.append((source, chemin, dict(entetes or {})))
        if self.pendant_lecture and chemin == "/proposals":
            self.pendant_lecture()
        cle = (source, chemin.split("?")[0])
        if cle in self.rep:
            return {"ok": True, "donnees": copy.deepcopy(self.rep[cle]), "erreur": None}
        return {"ok": False, "donnees": None, "erreur": "socket absent"}

    def ban(self, ip, duree):
        self.bans.append((ip, duree))
        return self.reponse_ban(ip, duree)


@pytest.fixture
def faux(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_SOC_DEFENSE_DB", str(tmp_path / "defense.db"))
    monkeypatch.setenv("SECUBOX_AUDIT_LOG", str(tmp_path / "audit.log"))
    monkeypatch.setenv("SECUBOX_TABLEAU_DE_BORD", "0")
    monkeypatch.setattr(defense, "ROUTES_PROC", str(tmp_path / "route-absente"))
    f = Faux()
    monkeypatch.setattr(defense.substrat, "lire", f.lire)
    monkeypatch.setattr(sade_auto, "_wafctl_ban", f.ban)
    return f


@pytest.fixture
def actif(faux):
    defense_etat.changer_mode("active", "admin")
    return faux


def _audit():
    chemin = Path(os.environ["SECUBOX_AUDIT_LOG"])
    if not chemin.exists():
        return []
    return [json.loads(ligne) for ligne in chemin.read_text(encoding="utf-8").splitlines() if ligne.strip()]


def _actions():
    return [e["action"] for e in _audit()]


# ── cas sûr ──────────────────────────────────────────────────────────────────────────────────────

def test_constantes():
    assert sade_auto.PLAFOND_HEURE == 20 and sade_auto.TTL_AUTO_MAX_S == 86400
    assert (sade_auto.SCORE_MIN, sade_auto.SCORE_MAX) == (60, 94)
    assert sade_auto.ADRESSES_AUTO_MAX == 8 and sade_auto.OPERATEUR == "sade-auto"


def test_cas_sur_bornes():
    assert cas_sur(prop(score=60), []) == (True, "ok") and cas_sur(prop(score=94), []) == (True, "ok")
    assert cas_sur(prop(score=59), [])[1] == "score" and cas_sur(prop(score=95), [])[1] == "score"
    assert cas_sur(prop(score=None), [])[1] == "score"
    assert cas_sur(prop(geste="quarantaine"), [])[1] == "geste"
    assert cas_sur(prop(ips=[]), [])[1] == "sans_adresse"
    assert cas_sur(prop(ips=[f"203.0.113.{i}" for i in range(9)]), [])[1] == "trop_d_adresses"
    assert cas_sur(prop(ips=[f"203.0.113.{i}" for i in range(8)]), []) == (True, "ok")
    assert cas_sur(prop(ips=["192.168.1.10"]), [])[1] == "adresse_protegee"


def test_cas_sur_reseau_protege():
    import ipaddress
    assert cas_sur(prop(ips=["198.51.100.9"]), [ipaddress.ip_network("198.51.100.0/24")])[1] == "adresse_protegee"


# ── passages ─────────────────────────────────────────────────────────────────────────────────────

def test_hors_active_rien(faux):
    defense_etat.changer_mode("reactive", "admin")
    r = sade_auto.executer()
    assert r["mode"] == "reactive" and r["bannies"] == [] and faux.bans == []
    assert defense_etat.etats_decisions() == {}
    assert not any(s == "actord" for s, _c, _e in faux.lus)


def test_observe_par_defaut_rien(faux):
    r = sade_auto.executer()
    assert r["mode"] == "observe" and faux.bans == [] and r["erreur"] is None


def test_ban_sur_avec_duree_bornee(actif):
    actif.rep[("actord", "/proposals")] = _actord(_brute(ttl=7 * 86400))
    r = sade_auto.executer()
    assert actif.bans == [("203.0.113.10", "86400s")]
    assert r["bannies"] == ["203.0.113.10"] and r["plafond"] is False and r["erreur"] is None
    emp = defense.empreinte("ban", ["203.0.113.10"], 7 * 86400)
    d = defense_etat.decision(emp)
    assert d["etat"] == "applique" and d["par"] == "sade-auto"
    assert d["ttl_s"] == 86400  # durée réellement posée : le ré-armement suit l'expiration réelle du ban
    actions = _actions()
    assert actions.index("sade-auto-demande") < actions.index("sade-auto-resultat")
    dem = next(e for e in _audit() if e["action"] == "sade-auto-demande")
    assert dem["operateur"] == "sade-auto" and dem["duree"] == "86400s" and dem["empreinte"] == emp
    res = next(e for e in _audit() if e["action"] == "sade-auto-resultat")
    assert res["issue"] == "applique" and res["bannies"] == "203.0.113.10"


def test_demande_auditee_avant_l_appel(actif):
    vu = []
    actif.reponse_ban = lambda ip, duree: (vu.append(_actions()), (True, "ok"))[1]
    sade_auto.executer()
    assert "sade-auto-demande" in vu[0] and "sade-auto-resultat" not in vu[0]


def test_duree_par_defaut_du_waf_quand_ttl_absent(actif):
    actif.rep[("actord", "/proposals")] = _actord(_brute(ttl=0))
    sade_auto.executer()
    assert actif.bans == [("203.0.113.10", "14400s")]


def test_ecartees_comptees(actif):
    actif.rep[("actord", "/proposals")] = _actord(
        _brute(), _brute(actor="ACT-0002", priorite=97, ips=["203.0.113.20"]),
        _brute(actor="ACT-0003", mode="QUARANTINE", ips=["203.0.113.30"]))
    r = sade_auto.executer()
    assert r["bannies"] == ["203.0.113.10"] and r["ecartees"] == 2


def test_plafond_repasse_en_observe(actif):
    for i in range(19):
        e = f"{i:064x}"
        defense_etat.reclamer(e, "ACT-x", "ban", f"203.0.113.{100 + i}", 70, 3600, "sade-auto", "en_cours",
                              "sade-auto-demande", modes=("active",))
        defense_etat.conclure(e, 1, "applique", "ok")
    actif.rep[("actord", "/proposals")] = _actord(_brute(ips=["203.0.113.10", "203.0.113.11"]))
    r = sade_auto.executer()
    assert actif.bans == [] and r["plafond"] is True and r["bannies"] == []
    assert defense_etat.mode_courant() == "observe"
    assert "sade-auto-plafond" in _actions()
    pl = next(e for e in _audit() if e["action"] == "sade-auto-plafond")
    assert pl["operateur"] == "sade-auto"


def test_plafond_atteint_exactement_passe(actif):
    for i in range(18):
        e = f"{i:064x}"
        defense_etat.reclamer(e, "ACT-x", "ban", f"203.0.113.{100 + i}", 70, 3600, "sade-auto", "en_cours",
                              "sade-auto-demande", modes=("active",))
        defense_etat.conclure(e, 1, "applique", "ok")
    actif.rep[("actord", "/proposals")] = _actord(_brute(ips=["203.0.113.10", "203.0.113.11"]))
    r = sade_auto.executer()
    assert len(actif.bans) == 2 and r["plafond"] is False and defense_etat.mode_courant() == "active"


def test_proposition_deja_appliquee_ne_declenche_pas_le_plafond(actif):
    for i in range(18):
        e = f"{i:064x}"
        defense_etat.reclamer(e, "ACT-x", "ban", f"203.0.113.{100 + i}", 70, 3600, "sade-auto", "en_cours",
                              "sade-auto-demande", modes=("active",))
        defense_etat.conclure(e, 1, "applique", "ok")
    actif.rep[("actord", "/proposals")] = _actord(_brute(ips=["203.0.113.10", "203.0.113.11"]))
    sade_auto.executer()                    # 18 + 2 = 20 : passe
    r = sade_auto.executer()                # 20 dans l'heure, proposition déjà appliquée : ignorée, pas de plafond
    assert len(actif.bans) == 2 and r["plafond"] is False and defense_etat.mode_courant() == "active"


def test_plafond_compte_les_bans_du_passage(actif):
    props = [_brute(actor=f"ACT-{i:04d}", ips=[f"203.0.113.{10 * i + j}" for j in range(8)]) for i in range(1, 4)]
    actif.rep[("actord", "/proposals")] = _actord(*props)
    r = sade_auto.executer()
    assert len(actif.bans) == 16 and r["plafond"] is True and defense_etat.mode_courant() == "observe"


def test_actord_muet_rien(actif):
    del actif.rep[("actord", "/proposals")]
    r = sade_auto.executer()
    assert actif.bans == [] and r["erreur"] == "actord_indisponible" and defense_etat.etats_decisions() == {}


def test_base_ou_audit_indisponible_rien(actif, monkeypatch, tmp_path):
    monkeypatch.setenv("SECUBOX_AUDIT_LOG", str(tmp_path))  # un répertoire : l'ouverture en ajout échoue
    r = sade_auto.executer()
    assert actif.bans == [] and r["erreur"] == "audit_indisponible"
    assert defense_etat.etats_decisions() == {}
    (tmp_path / "fichier").write_text("x")
    monkeypatch.setenv("SECUBOX_SOC_DEFENSE_DB", str(tmp_path / "fichier" / "defense.db"))
    r = sade_auto.executer()
    assert actif.bans == [] and r["erreur"] == "base_indisponible" and r["mode"] is None


def test_liste_blanche_illisible_rien(actif, monkeypatch):
    monkeypatch.setattr(defense_etat, "liste_blanche", lambda: [{"cidr": "pas-un-reseau"}])
    r = sade_auto.executer()
    assert actif.bans == [] and r["erreur"] == "liste_blanche_illisible"


def test_mode_change_pendant_le_passage(actif):
    actif.pendant_lecture = lambda: defense_etat.changer_mode("reactive", "admin")
    r = sade_auto.executer()
    assert actif.bans == [] and r["bannies"] == []
    assert defense_etat.etats_decisions() == {}


def test_pas_de_double_ban(actif):
    sade_auto.executer()
    r = sade_auto.executer()
    assert len(actif.bans) == 1 and r["bannies"] == []


def test_decision_refusee_par_l_administrateur_respectee(actif):
    emp = defense.empreinte("ban", ["203.0.113.10"], 3600)
    defense_etat.reclamer(emp, "ACT-0001", "ban", "203.0.113.10", 86, 3600, "admin", "refuse", "sade-refuse",
                          modes=("active",))
    sade_auto.executer()
    assert actif.bans == []


def _refus_humain_ancien(emp, cible, il_y_a_s):
    import sqlite3
    from contextlib import closing
    from datetime import datetime, timedelta, timezone
    ts = (datetime.now(timezone.utc) - timedelta(seconds=il_y_a_s)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with closing(sqlite3.connect(os.environ["SECUBOX_SOC_DEFENSE_DB"])) as db, db:
        db.execute("INSERT INTO decisions(empreinte, generation, menace_id, cible, geste, score, ttl_s, etat, "
                   "demande_ts, tranche_ts, par) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                   (emp, 1, "ACT-0001", cible, "ban", 86, 3600, "refuse", ts, ts, "admin"))


def test_refus_humain_lie_l_executeur_meme_re_arme(actif):
    emp = defense.empreinte("ban", ["203.0.113.10"], 3600)
    _refus_humain_ancien(emp, "203.0.113.10", 25 * 3600)
    assert defense_etat.decision(emp)["etat"] == "en_attente"  # ré-armée pour la file manuelle
    r = sade_auto.executer()
    assert actif.bans == [] and r["bannies"] == []
    d = defense_etat.decision(emp)
    assert d["generation"] == 1 and d["etat_enregistre"] == "refuse"  # aucune nouvelle décision


def test_refus_humain_illisible_rien(actif, monkeypatch):
    def panne(_e):
        raise defense_etat.EtatIndisponible("OperationalError")
    monkeypatch.setattr(defense_etat, "refuse_par_humain", panne)
    r = sade_auto.executer()
    assert actif.bans == [] and r["erreur"] == "base_indisponible"


def test_plafond_compte_les_partielles(actif):
    for i in range(19):
        e = f"{i:064x}"
        defense_etat.reclamer(e, "ACT-x", "ban", f"203.0.113.{100 + i}", 70, 3600, "sade-auto", "en_cours",
                              "sade-auto-demande", modes=("active",))
        defense_etat.conclure(e, 1, "refuse" if i % 2 else "en_attente", "partiel")
    r = sade_auto.executer()
    assert r["plafond"] is False and len(actif.bans) == 1  # 19 + 1 = 20
    actif.rep[("actord", "/proposals")] = _actord(_brute(actor="ACT-0009", ips=["203.0.113.50"]))
    r = sade_auto.executer()
    assert r["plafond"] is True and len(actif.bans) == 1


def test_refus_wafctl_conclu_refuse(actif):
    actif.rep[("actord", "/proposals")] = _actord(_brute(ips=["203.0.113.10", "203.0.113.11", "203.0.113.12"]))
    actif.reponse_ban = lambda ip, duree: ((True, "ok") if ip == "203.0.113.10" else (False, "refus: adresse protégée"))
    r = sade_auto.executer()
    assert [ip for ip, _d in actif.bans] == ["203.0.113.10", "203.0.113.11"]  # arrêt au premier échec
    emp = defense.empreinte("ban", ["203.0.113.10", "203.0.113.11", "203.0.113.12"], 3600)
    d = defense_etat.decision(emp)
    assert d["etat"] == "refuse" and "203.0.113.10" in d["resultat"]
    assert r["bannies"] == ["203.0.113.10"]
    res = next(e for e in _audit() if e["action"] == "sade-auto-resultat")
    assert res["issue"] == "refuse" and res["echec"] == "203.0.113.11"
    actif.bans.clear()
    sade_auto.executer()
    assert actif.bans == []  # jamais retenté à chaque passage


def test_delai_wafctl_reste_en_attente(actif):
    actif.rep[("actord", "/proposals")] = _actord(_brute(ips=["203.0.113.10", "203.0.113.11"]))
    actif.reponse_ban = lambda ip, duree: ((True, "ok") if ip == "203.0.113.10" else (False, "delai"))
    sade_auto.executer()
    emp = defense.empreinte("ban", ["203.0.113.10", "203.0.113.11"], 3600)
    d = defense_etat.decision(emp)
    assert d["etat"] == "en_attente" and "203.0.113.10" in d["resultat"]
    actif.reponse_ban = lambda ip, duree: (True, "ok")
    actif.bans.clear()
    sade_auto.executer()
    assert len(actif.bans) == 2 and defense_etat.decision(emp)["etat"] == "applique"


def test_pairs_non_lus_notes_dans_l_audit(actif):
    del actif.rep[("threatmesh", "/peers")]
    r = sade_auto.executer()
    assert r["bannies"] == ["203.0.113.10"]  # wafctl garde lui-même les pairs WireGuard
    for e in _audit():
        if e["action"] in ("sade-auto-demande", "sade-auto-resultat"):
            assert e["pairs_maillage"] == "non_verifies"


def test_entetes_lan_selon_tableau_de_bord(actif, monkeypatch):
    sade_auto.executer()
    assert [e for s, _c, e in actif.lus if s == "threatmesh"] == [{}]
    monkeypatch.setenv("SECUBOX_TABLEAU_DE_BORD", "1")
    actif.lus.clear()
    sade_auto.executer()
    assert [e for s, _c, e in actif.lus if s == "threatmesh"] == [{"X-SecuBox-LAN": "1"}]


def test_incident_95_reste_dans_la_file(actif):
    actif.rep[("actord", "/proposals")] = _actord(_brute(actor="ACT-0002", priorite=97, ips=["203.0.113.20"]))
    r = sade_auto.executer()
    assert actif.bans == [] and r["ecartees"] == 1 and defense_etat.etats_decisions() == {}
    main.app.dependency_overrides[require_lecture] = lambda: {"sub": "lecteur"}
    try:
        lignes = TestClient(main.app).get("/defense/proposals").json()["propositions"]
    finally:
        main.app.dependency_overrides.pop(require_lecture, None)
    assert lignes[0]["validation_humaine"] is True and lignes[0]["etat"] == "en_attente"


def test_main_rend_zero_et_une_ligne(actif, capsys):
    assert sade_auto.main() == 0
    sortie = capsys.readouterr().out.strip().splitlines()
    assert len(sortie) == 1 and "sade-auto" in sortie[0]


# ── point d'exécution unique ─────────────────────────────────────────────────────────────────────

class _Fini:
    def __init__(self, rc, err=""):
        self.returncode, self.stderr, self.stdout = rc, err, ""


def test_wafctl_ban_commande_et_classement(monkeypatch):
    vus = []

    def run(cmd, **kw):
        vus.append((cmd, kw.get("timeout")))
        return _Fini(0)
    monkeypatch.setattr(sade_auto.subprocess, "run", run)
    assert sade_auto._wafctl_ban("203.0.113.10", "3600s") == (True, "ok")
    assert vus == [(["sudo", "-n", "/usr/sbin/wafctl", "ban", "203.0.113.10", "3600s"], 30)]

    monkeypatch.setattr(sade_auto.subprocess, "run", lambda cmd, **kw: _Fini(1, "adresse protégée\n"))
    ok, raison = sade_auto._wafctl_ban("203.0.113.10", "3600s")
    assert not ok and sade_auto.refus_definitif(raison)

    monkeypatch.setattr(sade_auto.subprocess, "run", lambda cmd, **kw: _Fini(1, "sudo: a password is required\n"))
    ok, raison = sade_auto._wafctl_ban("203.0.113.10", "3600s")
    assert not ok and not sade_auto.refus_definitif(raison)

    def delai(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, 30)
    monkeypatch.setattr(sade_auto.subprocess, "run", delai)
    ok, raison = sade_auto._wafctl_ban("203.0.113.10", "3600s")
    assert not ok and raison == "delai" and not sade_auto.refus_definitif(raison)

    def absent(cmd, **kw):
        raise FileNotFoundError("sudo")
    monkeypatch.setattr(sade_auto.subprocess, "run", absent)
    ok, raison = sade_auto._wafctl_ban("203.0.113.10", "3600s")
    assert not ok and not sade_auto.refus_definitif(raison)


def test_seul_point_d_execution():
    src = Path(sade_auto.__file__).read_text(encoding="utf-8")
    assert src.count("subprocess.run(") == 1 and "substrat.ecrire" not in src
