# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3794 — API de secubox-garde : gardes, état par appareil, demandes exécutées par le passage, réglages, clé SMS."""
import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from api import main  # noqa: E402
from garde import base, demandes  # noqa: E402
from secubox_core.auth import require_jwt, require_lecture  # noqa: E402

MAC = "aa:bb:cc:dd:ee:01"


@pytest.fixture
def env(tmp_path, monkeypatch):
    db_path = tmp_path / "garde.db"
    reg = tmp_path / "garde.toml"
    reg.write_text('automatique = true\ncourriel = "a@exemple.fr"\nquarantaines_max = 2\n')
    monkeypatch.setattr(main, "BASE", db_path)
    monkeypatch.setattr(main, "REGLAGES", reg)
    monkeypatch.setattr(main, "DEPOT", tmp_path / "depot")
    monkeypatch.setattr(main, "AUDIT", tmp_path / "audit.log")
    now = int(time.time())
    db = base.ouvrir(db_path)
    db.executemany("INSERT INTO decisions(id, menace, cible, mac, ip, motif, signe, debut, fin, etat) VALUES (?,?,?,?,?,?,?,?,?,?)", [
        ("d1", "infection", MAC, MAC, "192.168.1.95", "serveur de pirates connu", "actor", now - 600, now + 86000, "active"),
        ("d2", "evasion", "aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:02", "192.168.1.42", "DoH", "doh", now - 900, now + 80000, "active"),
        ("d3", "intrusion", "203.0.113.7", None, "203.0.113.7", "leurre", "leurre", now - 300, now + 14000, "active"),
        ("d4", "intrusion", "203.0.113.8", None, "203.0.113.8", "leurre", "leurre", now - 200, now + 14000, "active"),
        ("d5", "intrusion", "203.0.113.8", None, "203.0.113.8", "leurre", "leurre", now - 90000, now - 76000, "echue"),
        ("d6", "signale", MAC, MAC, "192.168.1.95", "DGA", "dga", now - 100, now - 100, "echue"),
    ])
    db.executemany("INSERT INTO adresses(decision_id, ip, fin) VALUES (?,?,?)",
                   [("d1", "192.168.1.95", now + 86000), ("d1", "fd00::95", now + 86000),
                    ("d2", "192.168.1.42", now + 80000)])
    db.execute("INSERT INTO appareils(cle, mac, nom, vu) VALUES (?,?,?,?)", (MAC, MAC, "TV salon", now))
    db.execute("INSERT INTO file_notifs(canal, cle, texte, cree, essais, envoye) VALUES ('sms','x','t',?,1,1)", (now - 50,))
    db.execute("INSERT INTO file_notifs(canal, cle, texte, cree, essais, envoye) VALUES ('courriel','x','t',?,0,0)", (now - 50,))
    db.commit()
    db.close()
    return SimpleNamespace(db=db_path, reg=reg, depot=tmp_path / "depot", audit=tmp_path / "audit.log", now=now)


def _client(admin=True):
    main.app.dependency_overrides.clear()
    if admin:
        main.app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
        main.app.dependency_overrides[require_lecture] = lambda: {"sub": "admin"}
        main.app.dependency_overrides[main.require_lecture_veille] = lambda: {"sub": "admin"}
    return TestClient(main.app)


def teardown_function():
    main.app.dependency_overrides.clear()


def test_actions_sans_jeton_401(env):
    c = _client(admin=False)
    for route, corps in (("/liberer", {"id": "d1"}), ("/rouvrir", {"id": "d2"}), ("/debannir", {"ip": "203.0.113.7"}),
                         ("/reglages", {"automatique": False}), ("/cle-sms", {"cle": "abc"}), ("/tester", {"canal": "sms"})):
        assert c.post("/api/v1/garde" + route, json=corps).status_code == 401, route
    # Lecture : mode tableau de bord (anonyme du LAN) permis par require_lecture, mais rien de personnel.
    for route in ("/etat", "/historique", "/reglages"):
        r = c.get("/api/v1/garde" + route)
        assert r.status_code in (200, 401), route
        if r.status_code == 200:
            t = json.dumps(r.json())
            assert "TV salon" not in t and "192.168.1.95" not in t and "a@exemple.fr" not in t, route


def test_gardes_declarees():
    gardes = {}
    for r in main.router.routes:
        deps = {d.call for d in r.dependant.dependencies}
        for m in r.methods:
            gardes[(m, r.path)] = deps
    for p in ("/etat", "/historique"):
        assert main.require_lecture_veille in gardes[("GET", "/api/v1/garde" + p)]
    assert require_lecture in gardes[("GET", "/api/v1/garde/reglages")]
    for p in ("/liberer", "/rouvrir", "/debannir", "/reglages", "/cle-sms", "/tester"):
        assert require_jwt in gardes[("POST", "/api/v1/garde" + p)]


def test_etat_tuiles_et_une_carte_par_appareil(env):
    r = _client().get("/api/v1/garde/etat").json()
    assert r["tuiles"] == {"isoles": 1, "evasions": 1, "bannis": 2, "recidivistes": 1,
                           "notifs_24h": {"sms": 1, "courriel": 0}, "en_attente": 1}
    assert r["automatique"] is True
    cartes = {c["menace"]: c for c in r["actives"]}
    inf = cartes["infection"]
    assert inf["nom"] == "TV salon" and inf["adresses"] == ["192.168.1.95", "fd00::95"] and inf["id"] == "d1"
    assert cartes["evasion"]["nom"].startswith("Appareil inconnu")
    intr = [c for c in r["actives"] if c["menace"] == "intrusion"]
    assert len(intr) == 1 and intr[0]["n"] == 2 and intr[0]["derniere"]["ip"] == "203.0.113.8"


def test_historique(env):
    r = _client().get("/api/v1/garde/historique?heures=24").json()
    menaces = [x["menace"] for x in r["lignes"]]
    assert "signale" in menaces and menaces.count("intrusion") == 1          # intrusions groupées par heure
    assert _client().get("/api/v1/garde/historique?heures=0").status_code == 422


def test_liberer_enregistre_7j(env):
    r = _client().post("/api/v1/garde/liberer", json={"id": "d1"})
    assert r.status_code == 200 and r.json()["etat"] == "en_attente"
    db = base.ouvrir(env.db)
    (mac, signe, jusqua), = db.execute("SELECT mac, signe, jusqua FROM liberations").fetchall()
    assert (mac, signe) == (MAC, "actor") and abs(jusqua - (env.now + 7 * 86400)) < 5
    assert db.execute("SELECT action, cible, etat FROM demandes").fetchall() == [("liberer", "d1", "en_attente")]
    ligne = json.loads(env.audit.read_text().splitlines()[-1])
    assert ligne["action"] == "liberer-demande" and ligne["cible"] == "d1"
    # deux fois : une seule demande ; carte marquée « en cours »
    _client().post("/api/v1/garde/liberer", json={"id": "d1"})
    assert db.execute("SELECT COUNT(*) FROM demandes").fetchone()[0] == 1
    carte = [c for c in _client().get("/api/v1/garde/etat").json()["actives"] if c.get("id") == "d1"][0]
    assert carte["en_cours"] is True


def test_liberer_refuse_mauvaise_menace_ou_inconnue(env):
    c = _client()
    assert c.post("/api/v1/garde/liberer", json={"id": "d2"}).status_code == 404     # évasion : rouvrir
    assert c.post("/api/v1/garde/liberer", json={"id": "zz"}).status_code == 404
    assert c.post("/api/v1/garde/rouvrir", json={"id": "d2"}).status_code == 200


def test_debannir_seulement_les_bans_de_la_garde(env):
    c = _client()
    assert c.post("/api/v1/garde/debannir", json={"ip": "198.51.100.1"}).status_code == 404
    assert c.post("/api/v1/garde/debannir", json={"ip": "pas une ip"}).status_code == 422
    assert c.post("/api/v1/garde/debannir", json={"ip": "203.0.113.7"}).status_code == 200


def test_reglages_sans_cle_dans_reponse(env):
    c = _client()
    r = c.get("/api/v1/garde/reglages").json()
    assert r["courriel"] == "a@exemple.fr" and "cle" not in json.dumps(r).replace("cle_sms_", "")
    assert r["cle_sms_enregistree"] is False
    assert c.post("/api/v1/garde/cle-sms", json={"cle": "AbC123xyz"}).status_code == 200
    r = c.get("/api/v1/garde/reglages").json()
    assert "AbC123xyz" not in json.dumps(r) and r["cle_sms_en_attente"] is True
    assert (env.depot / "cle-sms").read_text() == "AbC123xyz"
    assert oct((env.depot / "cle-sms").stat().st_mode & 0o777) == "0o600"
    assert "AbC123xyz" not in env.audit.read_text()
    assert c.post("/api/v1/garde/cle-sms", json={"cle": "a b;c"}).status_code == 422


def test_reglages_post_depose_puis_attend(env):
    c = _client()
    r = c.post("/api/v1/garde/reglages", json={"automatique": False, "courriel": "b@exemple.fr",
                                                 "sms_utilisateur": "12345678", "sms_bans": True})
    assert r.status_code == 200
    depose = json.loads((env.depot / "reglages.json").read_text())
    assert depose == {"automatique": False, "courriel": "b@exemple.fr", "sms_utilisateur": "12345678", "sms_bans": True}
    assert c.get("/api/v1/garde/reglages").json()["en_attente"] == depose
    assert c.post("/api/v1/garde/reglages", json={"courriel": "pas un courriel"}).status_code == 422
    assert c.post("/api/v1/garde/reglages", json={"quarantaines_max": 9}).status_code == 422


def test_tester(env):
    c = _client()
    assert c.post("/api/v1/garde/tester", json={"canal": "sms"}).status_code == 200
    assert c.post("/api/v1/garde/tester", json={"canal": "pigeon"}).status_code == 422


# ── Exécution des demandes par le passage ──
class Effets:
    def __init__(self, ok=True, motif="x"):
        self.appels, self.ok, self.motif = [], ok, motif

    def _r(self, *a):
        self.appels.append(a)
        return {"ok": self.ok, "motif": "" if self.ok else self.motif}

    def liberer(self, ip, mac=None, motif=""):
        return self._r("liberer", ip)

    def rouvrir(self, ip, mac=None, motif=""):
        return self._r("rouvrir", ip)

    def lever_mac(self, menace, mac, motif=""):
        return self._r("lever_mac", menace, mac)

    def debannir(self, ip, motif=""):
        return self._r("debannir", ip)

    def alerte(self, t):
        self.appels.append(("alerte", t))

    def audit(self, *a):
        self.appels.append(("audit",) + a)


class Notifs:
    def __init__(self):
        self.file = []

    def mettre_en_file(self, db, canal, cle, texte, t):
        self.file.append((canal, cle))
        return True


def test_passage_execute_les_demandes(env):
    c = _client()
    c.post("/api/v1/garde/liberer", json={"id": "d1"})
    c.post("/api/v1/garde/debannir", json={"ip": "203.0.113.7"})
    c.post("/api/v1/garde/tester", json={"canal": "courriel"})
    db = base.ouvrir(env.db)
    ef, nt = Effets(), Notifs()
    bilan = demandes.executer(db, ef, nt, env.now + 10)
    assert bilan == {"faites": 3, "echecs": 0}
    # #3914 : d1 tient deux adresses d'une même MAC → un seul geste par MAC
    assert [a for a in ef.appels if a[0] in ("liberer", "lever_mac")] == [("lever_mac", "infection", MAC)]
    assert ("debannir", "203.0.113.7") in ef.appels and nt.file[0][0] == "courriel"
    etats = dict(db.execute("SELECT id, etat FROM decisions").fetchall())
    assert etats["d1"] == "levee" and etats["d3"] == "levee"
    assert db.execute("SELECT leve_par FROM decisions WHERE id='d1'").fetchone()[0] == "utilisateur"
    assert {r[0] for r in db.execute("SELECT etat FROM demandes")} == {"faite"}


def test_passage_demande_debannir_echec_garde_la_decision(env):
    _client().post("/api/v1/garde/debannir", json={"ip": "203.0.113.7"})
    db = base.ouvrir(env.db)
    assert demandes.executer(db, Effets(ok=False), Notifs(), env.now) == {"faites": 0, "echecs": 1}
    assert db.execute("SELECT etat FROM decisions WHERE id='d3'").fetchone()[0] == "active"
    assert db.execute("SELECT etat FROM demandes").fetchone()[0] == "echec"


def test_passage_debannir_ban_repris_par_un_autre_final(env):
    _client().post("/api/v1/garde/debannir", json={"ip": "203.0.113.7"})
    db = base.ouvrir(env.db)
    assert demandes.executer(db, Effets(ok=False, motif="409 etranger"), Notifs(), env.now) == {"faites": 1, "echecs": 0}
    assert db.execute("SELECT etat, leve_par FROM decisions WHERE id='d3'").fetchone() == ("levee", "autre")
    assert db.execute("SELECT etat, resultat FROM demandes").fetchone() == ("faite", "ban repris par un autre mécanisme")
    assert demandes.executer(db, Effets(), Notifs(), env.now + 60) == {"faites": 0, "echecs": 0}     # aucun nouvel essai
    d = _client().get("/api/v1/garde/etat").json()["demandes"]
    assert d[0]["resultat"] == "ban repris par un autre mécanisme"
