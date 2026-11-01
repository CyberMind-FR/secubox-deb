# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Lot 3 SBX TV PRIVACY (#3374) : journal des décisions, exceptions unifiées, retour en OBSERVE, pause minutée et reprise,
route lambda « Ça ne marche plus ? Je débloque » (garde bornée, débit limité)."""
import csv
import io
import json
import stat
import time

import pytest

from api import dnstv, dnstv_journal as J, dnstv_protection as P, dnstv_regles as R
from test_dnstv_ctl_api import api, monde  # noqa: F401  (fixtures)

MAC1, MAC2 = "00:24:d4:00:00:01", "00:24:d4:00:00:02"
IP1, IP2, IP3 = "192.168.1.95", "192.168.1.96", "192.168.1.97"
T0 = 1_800_000_000


def etat_base():
    return {"actif": True, "clients": [{"ip": IP1, "nom": "TV salon", "mode": "auto", "mac": MAC1},
                                       {"ip": IP2, "nom": "TV chambre", "mode": "block", "mac": MAC2},
                                       {"ip": IP3, "nom": "Enceinte", "mode": "off"}]}


# ── journal ──────────────────────────────────────────────────────────────────────────────────────────
def test_journal_append_borne_rotation(tmp_path, monkeypatch):
    monkeypatch.setattr(J, "TAILLE_MAX", 2000)
    for i in range(60):
        J.ajouter([J.entree(T0 + i, "TV salon", MAC1, "x%d.example.com" % i, "PUBLICITE", "blocage", "auto", "m")], tmp_path)
    f = tmp_path / J.FICHIER
    assert f.stat().st_size <= 2000 + 400 and (tmp_path / (J.FICHIER + ".1")).is_file()
    assert stat.S_IMODE(f.stat().st_mode) == 0o640
    lignes = J.lire(tmp_path, 0)
    assert lignes and all(MAC1 not in json.dumps(x) for x in lignes) and lignes[0]["mac"] == "00:24:d4:…:01"


def test_journal_valide_ses_champs():
    with pytest.raises(ValueError):
        J.entree(T0, "TV", MAC1, "x.example.com", "PUBLICITE", "durcir", "auto", "")
    with pytest.raises(ValueError):
        J.entree(T0, "TV", MAC1, "x.example.com", "PUBLICITE", "blocage", "pirate", "")


def test_journal_depuis_l_historique_des_regles():
    r = R.Regles()
    avant = r.liste()
    rid = r.proposer("tv-salon", "ads.example.com", 50, "faible", T0)["id"]
    r.transiter(rid, "essai", "auto", "essai automatique", T0 + 1)
    e = J.depuis_regles(avant, r.liste(), etat_base(), lambda d: "PUBLICITE")
    assert [(x["action"], x["origine"], x["appareil"], x["mac"]) for x in e] == [
        ("candidat", "auto", "TV salon", "00:24:d4:…:01"), ("essai", "auto", "TV salon", "00:24:d4:…:01")]
    avant = r.liste()
    r.transiter(rid, "confirme", "admin", "action confirmer", T0 + 2)
    r.transiter(rid, "retire", "admin", "action retirer", T0 + 3)
    assert [x["action"] for x in J.depuis_regles(avant, r.liste(), etat_base())] == ["confirmation", "retrait"]


def test_journal_agrege_par_defaut(tmp_path):
    J.ajouter([J.entree(T0 + i, "TV salon", MAC1, "ads.example.com", "PUBLICITE", "retrait", "auto", "") for i in range(3)]
              + [J.entree(T0 + 5, "TV salon", MAC1, "", "", "pause", "usager", "1 h")], tmp_path)
    ag = J.agreger(J.lire(tmp_path, 0))
    a = {(x["appareil"], x["domaine"], x["action"]): x for x in ag}
    x = a[("TV salon", "ads.example.com", "retrait")]
    assert x["occurrences"] == 3 and x["premier"] == T0 and x["dernier"] == T0 + 2 and x["origines"] == ["auto"]
    assert ag[0]["action"] == "pause"                                              # le plus récent d'abord


# ── pause, reprise, observe ──────────────────────────────────────────────────────────────────────────
def test_pause_puis_reprise_echue():
    etat, pauses = etat_base(), []
    touches = P.mettre_en_pause(etat, pauses, None, 60, T0, "admin")
    assert touches == ["TV chambre", "TV salon"]
    assert [c["mode"] for c in etat["clients"]] == ["observe", "observe", "off"]
    assert P.reprendre(etat, pauses, None, T0 + 100, echues=True) == []           # pas encore échue
    assert P.reprendre(etat, pauses, None, T0 + 3601, echues=True) == ["TV chambre", "TV salon"]
    assert [c["mode"] for c in etat["clients"]] == ["auto", "block", "off"] and pauses == []


def test_pause_bornee_et_prolongee():
    etat, pauses = etat_base(), []
    with pytest.raises(P.ErreurProtection):
        P.mettre_en_pause(etat, pauses, None, 30, T0, "admin")
    P.mettre_en_pause(etat, pauses, ["TV salon"], 15, T0, "admin")
    P.mettre_en_pause(etat, pauses, ["TV salon"], 240, T0 + 10, "admin")
    assert len(pauses) == 1 and pauses[0]["fin"] == T0 + 10 + 240 * 60 and pauses[0]["modes"] == {IP1: "auto"}


def test_reprise_ne_touche_pas_un_appareil_change_entre_temps():
    etat, pauses = etat_base(), []
    P.mettre_en_pause(etat, pauses, ["TV salon"], 15, T0, "admin")
    etat["clients"][0]["mode"] = "block"                                           # l'administrateur a décidé entre-temps
    P.reprendre(etat, pauses, None, T0 + 10_000, echues=True)
    assert etat["clients"][0]["mode"] == "block" and pauses == []


def test_observe_retire_la_pause():
    etat, pauses = etat_base(), []
    P.mettre_en_pause(etat, pauses, ["TV salon"], 15, T0, "admin")
    assert P.passer_en_observe(etat, pauses, ["TV salon"]) == ["TV salon"]
    assert pauses == [] and etat["clients"][0]["mode"] == "observe"


def test_fichier_des_pauses_revalide(tmp_path):
    P.ecrire_pauses([{"appareil": "TV salon", "fin": T0, "modes": {IP1: "auto"}, "origine": "usager"}], tmp_path)
    assert P.charger_pauses(tmp_path)[0]["modes"] == {IP1: "auto"}
    (tmp_path / P.FICHIER_PAUSES).write_text(json.dumps({"version": 1, "pauses": [{"appareil": "x", "fin": 1, "modes": {"a b": "auto"}}]}))
    with pytest.raises(P.ErreurProtection):
        P.charger_pauses(tmp_path)


# ── exceptions unifiées ──────────────────────────────────────────────────────────────────────────────
def test_exception_autoriser_retire_et_rejette_la_regle():
    etat, regles = etat_base(), R.Regles()
    rid = regles.proposer("tv-salon", "pub.example.com", 50, "faible", T0)["id"]
    regles.transiter(rid, "essai", "auto", "", T0)
    ex = P.poser_exception([], etat, regles, "TV salon", "pub.example.com", "autoriser", True, T0, "admin")
    assert regles.get(rid)["etat"] == "rejete" and ex[0]["type"] == "autoriser" and ex[0]["mac"] == MAC1
    assert regles.proposer("tv-salon", "pub.example.com", 99, "faible", T0) is None          # jamais reproposé
    assert etat.get("autorisations", {}).get("tv-salon") == ["pub.example.com"]             # puits : exception posée aussi


def test_exception_bloquer_pose_une_regle_admin_confirmee_puis_la_retire():
    etat, regles = etat_base(), R.Regles()
    ex = P.poser_exception([], etat, regles, "TV chambre", "track.example.com", "bloquer", True, T0, "admin")
    r = regles.get(R.identifiant("tv-chambre", "track.example.com"))
    assert r["etat"] == "confirme" and r["historique"][-1]["origine"] == "admin"
    ex = P.poser_exception(ex, etat, regles, "TV chambre", "track.example.com", "bloquer", False, T0 + 1, "admin")
    assert ex == [] and regles.get(r["id"])["etat"] == "retire"


def test_exceptions_bornees():
    etat, regles = etat_base(), R.Regles()
    with pytest.raises(P.ErreurProtection):
        P.poser_exception([], etat, regles, "Inconnue", "x.example.com", "autoriser", True, T0, "admin")
    with pytest.raises(P.ErreurProtection):
        P.poser_exception([], etat, regles, "TV salon", "pas un domaine", "autoriser", True, T0, "admin")
    with pytest.raises(P.ErreurProtection):
        P.poser_exception([], etat, regles, "TV salon", "x.example.com", "durcir", True, T0, "admin")


def test_vue_unifiee_branche_les_mecanismes_existants():
    etat = dict(etat_base(), autorisations={"tv-salon": ["cdn.example.com"]})
    v = P.vue_exceptions([{"appareil": "tv-salon", "mac": MAC1, "domaine": "a.example.com", "type": "bloquer", "origine": "admin", "maj": T0}],
                         etat, {"legit.example.com"})
    src = {(x["domaine"], x["source"]) for x in v["exceptions"]}
    assert ("a.example.com", "exception") in src and ("cdn.example.com", "puits") in src and ("legit.example.com", "suspect-legitime") in src
    assert {x["mecanisme"] for x in v["hors_champ"]} == {"liste blanche globale (main.py)", "adult-exempt"}


# ── routes administrateur ────────────────────────────────────────────────────────────────────────────
@pytest.fixture
def tv(api, monde):
    dnstv.ecrire_etat(etat_base(), monde["etat"])
    return api


def test_route_pause_et_reprise(tv, monde):
    r = tv.post("/adblock-tv/protection/pause", json={"appareil": "TV salon", "minutes": 60})
    assert r.status_code == 200 and r.json()["appareils"] == ["TV salon"] and r.json()["jusqu_a"] > time.time()
    assert dnstv.lire_etat()[0]["clients"][0]["mode"] == "observe"
    assert any(x["action"] == "pause" and x["origine"] == "admin" for x in J.lire(monde["etat"], 0))
    assert tv.post("/adblock-tv/protection/pause", json={"appareil": None, "minutes": 7}).status_code == 422
    assert tv.post("/adblock-tv/protection/reprendre", json={"appareil": "TV salon"}).json()["appareils"] == ["TV salon"]
    assert dnstv.lire_etat()[0]["clients"][0]["mode"] == "auto"


def test_route_tout_en_observe(tv, monde):
    r = tv.post("/adblock-tv/protection/observe", json={"appareil": None})
    assert r.status_code == 200 and sorted(r.json()["appareils"]) == ["TV chambre", "TV salon"]
    assert [c["mode"] for c in dnstv.lire_etat()[0]["clients"]] == ["observe", "observe", "off"]
    assert "mode=observe" in (monde["tmp"] / "audit.log").read_text()                 # audité par le contrôleur root


def test_route_exceptions_et_journal_csv(tv, monde):
    r = tv.post("/adblock-tv/protection/exceptions", json={"appareil": "TV chambre", "domaine": "track.example.com", "type": "bloquer"})
    assert r.status_code == 200
    v = tv.get("/adblock-tv/protection/exceptions").json()
    assert any(x["domaine"] == "track.example.com" and x["type"] == "bloquer" for x in v["exceptions"])
    assert tv.post("/adblock-tv/protection/exceptions", json={"appareil": "TV chambre", "domaine": "x.example.com", "type": "bloquer",
                                                              "pirate": 1}).status_code == 422
    j = tv.get("/adblock-tv/protection/journal").json()
    assert any(x["action"] == "exception" for x in j["agregats"]) and "lignes" not in j
    assert "lignes" in tv.get("/adblock-tv/protection/journal?detail=1").json()
    c = tv.get("/adblock-tv/protection/journal.csv")
    rows = list(csv.reader(io.StringIO(c.text)))
    assert c.headers["content-type"].startswith("text/csv") and rows[0][:4] == ["horodatage", "appareil", "mac", "domaine"]
    assert all(MAC2 not in x for row in rows for x in row)


def test_ca_ne_marche_plus_journalise(tv, monde):
    regles = R.Regles()
    rid = regles.proposer("tv-salon", "pub.example.com", 50, "faible", T0)["id"]
    regles.transiter(rid, "essai", "auto", "", T0)
    R.ecrire(regles, monde["etat"])
    assert tv.post("/adblock-tv/auto/appareils/tv-salon/ca-ne-marche-plus").json()["retirees"] == 1
    assert any(x["action"] == "retrait" and x["domaine"] == "pub.example.com" for x in J.lire(monde["etat"], 0))


def test_gardes_des_routes():
    from api import dnstv_lot3_routes as L
    from api.dnstv_routes import require_lecture_nominative
    from secubox_core import auth
    g = {(y.path, tuple(sorted(y.methods))): {d.call for d in y.dependant.dependencies} for y in L.router.routes}
    for p in ("/protection/pause", "/protection/reprendre", "/protection/observe", "/protection/exceptions"):
        assert auth.require_jwt in g[(p, ("POST",))], p
    for p in ("/protection/exceptions", "/protection/journal", "/protection/diagnostic"):
        assert require_lecture_nominative in g[(p, ("GET",))], p
    assert auth.require_jwt in g[("/protection/journal.csv", ("GET",))]
    for p, m in (("/protection/usager/tv", "GET"), ("/protection/usager/debloquer", "POST")):
        assert auth.require_personne in g[(p, (m,))] and auth.require_jwt not in g[(p, (m,))], p


# ── route lambda ─────────────────────────────────────────────────────────────────────────────────────
@pytest.fixture
def usager(tv, monkeypatch):
    from secubox_core import auth
    from api import dnstv_lot3_routes as L
    L._DEBIT.clear()
    tv.app.dependency_overrides[auth.require_personne] = lambda: {"sub": "marie"}
    return tv


def test_usager_liste_minimale_des_tv(usager):
    j = usager.get("/adblock-tv/protection/usager/tv").json()
    assert [x["nom"] for x in j["tv"]] == ["TV chambre", "TV salon"]
    assert set(j["tv"][0]) == {"id", "nom", "protege", "pause_jusqu_a"}
    txt = json.dumps(j)
    assert MAC1 not in txt and IP1 not in txt and "Enceinte" not in txt and "example" not in txt
    assert "message" in j and "insère dans sa propre vidéo" in j["message"]


def test_usager_pause_d_une_tv(usager, monde):
    r = usager.post("/adblock-tv/protection/usager/debloquer", json={"tv": "tv-salon", "geste": "pause", "minutes": 60})
    assert r.status_code == 200 and r.json()["message"] == "protection en pause pour TV salon pendant 1 h"
    assert dnstv.lire_etat()[0]["clients"][0]["mode"] == "observe" and dnstv.lire_etat()[0]["clients"][1]["mode"] == "block"
    assert any(x["origine"] == "usager" and x["action"] == "pause" for x in J.lire(monde["etat"], 0))


def test_usager_toutes_en_pause_jamais_en_observe(usager):
    """Passe 2 (S3) : l'usager met toutes les TV en pause ; le retour en observation sans échéance lui est refusé."""
    assert usager.post("/adblock-tv/protection/usager/debloquer", json={"tv": "toutes", "geste": "observe"}).status_code == 422
    r = usager.post("/adblock-tv/protection/usager/debloquer", json={"tv": "toutes", "geste": "pause", "minutes": 240})
    assert r.status_code == 200 and "toutes les TV" in r.json()["message"]
    assert [c["mode"] for c in dnstv.lire_etat()[0]["clients"]] == ["observe", "observe", "off"]


@pytest.mark.parametrize("corps", [{"tv": "tv-salon", "geste": "proteger"}, {"tv": "tv-salon", "geste": "pause", "minutes": 600},
                                   {"tv": "tv-salon", "geste": "pause"}, {"tv": "enceinte", "geste": "observe"},
                                   {"tv": "tv-salon", "geste": "observe", "mode": "block"}, {"tv": "x" * 41, "geste": "observe"}])
def test_usager_gestes_bornes(usager, corps):
    assert usager.post("/adblock-tv/protection/usager/debloquer", json=corps).status_code in (404, 422)
    assert dnstv.lire_etat()[0]["clients"][1]["mode"] == "block"


def test_usager_debit_limite(usager):
    codes = [usager.post("/adblock-tv/protection/usager/debloquer", json={"tv": "tv-salon", "geste": "pause", "minutes": 15}).status_code
             for _ in range(7)]
    assert codes[:5] == [200] * 5 and codes[5:] == [429, 429]


# ── reprise automatique par le moteur ────────────────────────────────────────────────────────────────
def test_le_moteur_reprend_les_pauses_echues(monkeypatch, tmp_path):
    from test_dnstv_ajout_moteur import Rep, charger_script, lancer
    t = int(time.time())
    etat = {"actif": True, "clients": [{"ip": IP1, "nom": "TV salon", "mode": "observe", "mac": MAC1}]}
    mod = charger_script(monkeypatch, tmp_path, etat)
    P.ecrire_pauses([{"appareil": "TV salon", "fin": t - 1, "modes": {IP1: "auto"}, "origine": "usager"}], tmp_path)
    appels = []
    assert lancer(mod, lambda: appels.append(1) or Rep(), t) == 0
    assert dnstv.lire_etat(tmp_path)[0]["clients"][0]["mode"] == "auto" and appels
    assert any(x["action"] == "reprise" for x in J.lire(tmp_path, 0))


def test_pilotage_ouvre_les_gestes_admin_mais_pas_la_route_lambda():
    import re
    import tomllib
    from pathlib import Path
    conf = tomllib.loads((Path(__file__).resolve().parents[1] / "pilotage" / "routes-ouvertes.d" / "ad-guard.toml").read_text())
    motifs = [m for r in conf["routes"] if "POST" in r["methodes"] for m in r["chemins"]]
    ouvert = lambda c: any(re.match(m, c) for m in motifs)  # noqa: E731
    for g in ("observe", "pause", "reprendre", "exceptions"):
        assert ouvert(f"/adblock-tv/protection/{g}")
    assert not ouvert("/adblock-tv/protection/usager/debloquer")
