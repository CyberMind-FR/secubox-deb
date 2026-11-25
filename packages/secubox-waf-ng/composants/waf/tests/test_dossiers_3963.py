# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3963 — dossiers par site : agrégat horaire incrémental du journal des menaces (rotation, troncature, reprise bornée,
heure non mesurée, plafonds, ligne corrompue, source muette), routes en lecture et phrases en français. Adresses de
test : documentation (RFC 5737)."""
import json
import os
import re
import sys
import types
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from api import dossiers as D  # noqa: E402

try:
    import geoip2  # noqa: F401
except ImportError:                                     # absent de l'environnement de test : un faux module suffit
    _g = types.ModuleType("geoip2")
    _g.database, _g.errors = types.ModuleType("geoip2.database"), types.ModuleType("geoip2.errors")
    _g.errors.AddressNotFoundError = type("AddressNotFoundError", (Exception,), {})
    sys.modules.update({"geoip2": _g, "geoip2.database": _g.database, "geoip2.errors": _g.errors})
from api import main as W  # noqa: E402  (pose les chemins réels, que la fixture remplace ensuite)

T = datetime(2026, 11, 25, 12, 30, 0, tzinfo=timezone.utc).timestamp()
H = 3600
IPV4 = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])")


def ligne(il_y_a=60, host="depot.exemple.test", action="banned", category="sqli", **k):
    d = {"timestamp": datetime.fromtimestamp(T - il_y_a, tz=timezone.utc).isoformat(), "client_ip": "203.0.113.7",
         "host": host, "method": "GET", "path": "/", "category": category, "severity": "high", "rule_id": "x-001",
         "action": action, "reseau_classe": "hebergeur", "asn": 64500}
    d.update(k)
    return json.dumps(d)


@pytest.fixture
def box(tmp_path, monkeypatch):
    D.vider()
    chemins = {n: tmp_path / f"{n}.json" for n in D.CHEMINS}
    chemins["journal"] = tmp_path / "waf-threats.log"
    monkeypatch.setattr(D, "CHEMINS", chemins)
    chemins["routes"].write_text(json.dumps({"depot.exemple.test": ["127.0.0.1", 80], "Www.Exemple.TEST": ["127.0.0.1", 80],
                                             "agenda.exemple.test": ["127.0.0.1", 80], "203.0.113.9": ["127.0.0.1", 80]}))

    class Box:
        c = chemins

        def ecrire(self, *lignes, mode="a"):
            with open(chemins["journal"], mode) as f:
                f.write("".join(x + "\n" for x in lignes))

        def vie(self, t=T):
            chemins["vie"].write_text("{}")
            os.utime(chemins["vie"], (t, t))

        def passe(self, t=T, **k):
            return D.rafraichir(t, **k)

        def site(self, ident="depot.exemple.test", t=T):
            return self.passe(t)["dossiers"][ident]
    yield Box()
    D.vider()


# ── comptes ────────────────────────────────────────────────────────────────────────────────────────────────────────

def test_couches_robots_et_lignes_d_etat(box):
    box.ecrire(ligne(), ligne(action="warning", category="lfi"), ligne(action="detect", category="recon_crawler"),
               ligne(action="robot", category="robots", severity="info"),
               ligne(action="leurre_redirige", category="leurre_redirige", severity="audit", servies=7),
               ligne(action="multipart-tronque", category="multipart-tronque", severity="audit"),
               ligne(action="body-inspect-skipped", category="body-inspect-skipped"),
               ligne(action="detect", category="body-inspect-x"))
    d = box.site()
    assert d["totaux"] == {"arrete": 1, "refuse": 1, "detourne": 7, "passe": 1, "robots": 1}
    assert d["total"] == 10 and d["tenu_pct"] == 90.0
    assert {o["cle"]: o["n"] for o in d["origine"]["lignes"]} == {"hebergeur": 10}        # robots à part
    assert [c["n"] for c in d["chaine"]] == [None, 10, 1, 1, 7, 1]                        # requêtes reçues : jamais inventées


def test_sites_servis_et_noms_inconnus(box):
    box.ecrire(ligne(host="WWW.exemple.test:443"), ligne(host="autre.invalide", category="host_anomaly:unrouted", action="warning"),
               ligne(host="203.0.113.9", category="host_anomaly:ip_literal"), ligne(host="", category="host_anomaly:empty"),
               ligne(host="depot.exemple.test", category="host_anomaly:unrouted"),        # catégorie d'hôte : jamais un site
               ligne(host="sshd", category="auth_ssh:invalid_user", tool="authwatch"))
    v = box.passe()
    assert set(v["dossiers"]) == {"www.exemple.test", D.INCONNUS}
    assert v["dossiers"][D.INCONNUS]["total"] == 4 and v["liste"]["chiffres"]["hors_web"] == 1
    assert v["liste"]["chiffres"]["sites_proteges"] == 3 and v["calmes"] == ["agenda.exemple.test", "depot.exemple.test"]
    inc = v["dossiers"][D.INCONNUS]
    assert "aucun site n’a répondu" in inc["phrase"] and inc["couches"][3]["nom"] == "Noté" and inc["tenu_pct"] is None
    assert not IPV4.search(json.dumps([v["liste"], v["dossiers"]]))


def test_heure_non_mesuree_vaut_null_jamais_zero(box):
    box.ecrire(ligne(5 * H), ligne(60))
    d = box.site()
    assert d["serie"][-6] == 1 and d["serie"][-1] == 1
    assert d["serie"][-5:-1] == [None] * 4 and d["serie"][0] is None                      # aucun signe de vie : pas mesuré
    assert d["heures_mesurees"] == 2 and "Mesure sur 2 heures seulement." in d["phrase"]
    box.vie(T + 2 * H)
    d = box.site(t=T + 2 * H)
    assert d["serie"][-1] == 0 and d["serie"][-2] is None                                 # le moteur vit : zéro mesuré


def test_signe_de_vie_perime_ou_journal_absent_ne_mesure_rien(box):
    box.vie(T - 2 * H)
    v = box.passe()
    assert v["commun"]["journal"] == "illisible" and not v["commun"]["complet"] and v["commun"]["heures_mesurees"] == 0
    assert v["liste"]["chiffres"]["hostiles"] is None and v["liste"]["chiffres"]["tenu_pct"] is None
    assert v["dossiers"][D.INCONNUS]["phrase"] == "Aucune heure n’est encore mesurée."
    box.vie()
    assert box.passe()["commun"]["heures_mesurees"] == 0                                  # moteur vivant, journal absent
    box.ecrire()
    assert box.passe()["commun"]["heures_mesurees"] == 1


# ── lecture ────────────────────────────────────────────────────────────────────────────────────────────────────────

def test_lecture_incrementale_sans_doublon_ni_ligne_coupee(box):
    box.ecrire(ligne(), ligne())
    assert box.site()["total"] == 2
    with open(box.c["journal"], "a") as f:
        f.write(ligne()[:40])
    assert box.site()["total"] == 2
    with open(box.c["journal"], "a") as f:
        f.write(ligne()[40:] + "\n")
    assert box.site()["total"] == 3 and box.site()["total"] == 3


def test_rotation_ni_trou_ni_doublon(box):
    box.ecrire(ligne())
    box.passe()
    box.ecrire(ligne(), ligne())                        # écrites après la dernière lecture, avant la rotation
    box.c["journal"].rename(box.c["journal"].with_name("waf-threats.log.1"))
    box.ecrire(ligne())
    v = box.passe()
    assert v["dossiers"]["depot.exemple.test"]["total"] == 4 and v["commun"]["complet"]
    assert D._fond["agregateur"].e["trous"] == 0


def test_double_rotation_ratee_est_un_trou_dit_partiel(box):
    box.ecrire(ligne(3 * H))
    box.passe(T - 3 * H)
    box.c["journal"].rename(box.c["journal"].with_name("waf-threats.log.7"))    # l'inode suivi n'est plus nulle part
    box.ecrire(ligne(90))
    v = box.passe()
    assert v["dossiers"]["depot.exemple.test"]["total"] == 2
    assert D._fond["agregateur"].e["trous"] == 1
    assert v["commun"]["partielles"] == [20, 23]        # heure du dernier relevé, heure de la reprise


def test_troncature_sur_place(box):
    box.ecrire(*[ligne(120) for _ in range(5)])
    box.passe()
    box.ecrire(ligne(), mode="w")
    assert box.site()["total"] == 6


def test_fichier_reecrit_sous_le_curseur_repart_sans_compter_deux_fois(box):
    box.ecrire(ligne(), ligne())
    box.passe()
    with open(box.c["journal"], "r+") as f:             # même inode, plus long, le curseur tombe au milieu d'une ligne
        f.truncate(0)
        f.write("".join(ligne(path="/" + "a" * 37) + "\n" for _ in range(3)))
    box.passe()
    assert box.site()["total"] == 3


def test_redemarrage_reprend_au_curseur(box):
    box.ecrire(ligne(), ligne())
    box.passe(forcer=True)
    D.vider()                                           # nouveau processus
    box.ecrire(ligne())
    assert box.site()["total"] == 3
    assert box.c["etat"].stat().st_mode & 0o777 == 0o640
    assert not list(box.c["etat"].parent.glob(".dossiers-*"))


def test_redemarrage_avec_etat_corrompu_relit_le_journal(box):
    box.ecrire(ligne())
    box.passe(forcer=True)
    for brut in ("{", "[]", json.dumps({"v": 1}), json.dumps({**D._neuf(), "heures": {"x": {}}}),
                 json.dumps({**D._neuf(), "curseur": "../../etc"}),
                 json.dumps({**D._neuf(), "heures": {"1": {"a": {"c": {"sqli": [1]}, "o": {}}}}})):
        D.vider()
        box.c["etat"].write_text(brut)
        assert box.site()["total"] == 1, brut


def test_premier_depart_borne_par_la_fin(box, monkeypatch):
    box.ecrire(*[ligne(2 * H) for _ in range(50)])
    box.c["journal"].rename(box.c["journal"].with_name("waf-threats.log.1"))
    box.ecrire(*[ligne(60) for _ in range(10)])
    taille = box.c["journal"].stat().st_size
    monkeypatch.setattr(D, "REPRISE_OCTETS", taille + 3 * len(ligne(60)))
    d = box.site()
    assert 10 < d["total"] < 15
    monkeypatch.setattr(D, "REPRISE_OCTETS", taille // 2)
    D.vider()
    box.c["etat"].unlink()
    assert 0 < box.site()["total"] < 10


def test_rattrapage_etale_sur_plusieurs_passes(box, monkeypatch):
    monkeypatch.setattr(D, "PASSE_LIGNES", 10)
    monkeypatch.setattr(D, "PASSE_TOURS", 2)
    box.ecrire(*[ligne() for _ in range(45)])
    v = box.passe()
    assert v["dossiers"]["depot.exemple.test"]["total"] == 20 and v["commun"]["rattrapage"] and not v["commun"]["complet"]
    box.passe()
    v = box.passe()
    assert v["dossiers"]["depot.exemple.test"]["total"] == 45 and v["commun"]["complet"]


def test_lignes_corrompues_ou_absurdes(box):
    box.ecrire("{pas du json", "[]", "null", '"x"', json.dumps({"timestamp": "hier"}), ligne(-3600),
               '{"timestamp": NaN, "action": "banned"}', '{"timestamp": 1e999, "action": "banned"}',
               ligne(action=["banned"]), ligne(category={"a": 1}), ligne(host={"a": 1}), ligne(reseau_classe=["x"]),
               ligne(action="leurre_redirige", category="leurre_redirige", servies=-5), ligne(category="<b>x</b>"), ligne())
    v = box.passe()
    d = v["dossiers"]["depot.exemple.test"]
    assert d["total"] == 5 and v["commun"]["illisibles"] >= 5
    assert "<b>" not in json.dumps(v["liste"]) + json.dumps(d)
    assert v["dossiers"][D.INCONNUS]["total"] == 1                      # hôte illisible


def test_plafonds(box, monkeypatch):
    monkeypatch.setattr(D, "MAX_SITES", 3)
    monkeypatch.setattr(D, "MAX_CATS", 2)
    box.c["routes"].unlink()                                            # sans table de routes, tout nom valide est un site
    box.ecrire(*[ligne(host=f"s{i}.exemple.test") for i in range(10)],
               *[ligne(host="s0.exemple.test", category=f"cat{i}") for i in range(6)])
    v = box.passe()
    assert len([s for s in v["dossiers"] if s != D.INCONNUS]) == 3 and v["commun"]["hors_plafond"] == 7
    assert v["liste"]["chiffres"]["sites_proteges"] is None
    cats = {c["cle"]: c["n"] for c in v["dossiers"]["s0.exemple.test"]["categories"]}
    assert cats == {"sqli": 1, "cat0": 1, "autres": 5}


def test_plafond_global_de_cellules(box, monkeypatch):
    monkeypatch.setattr(D, "MAX_CELLULES", 4)
    box.ecrire(*[ligne(category=f"cat{i}") for i in range(20)])
    box.passe()
    assert D._fond["agregateur"]._cellules <= 5
    assert box.site()["total"] == 20


def test_fenetre_glissante_oublie_les_vieilles_heures(box):
    box.ecrire(ligne(23 * H), ligne(30 * H), ligne(60))
    assert box.site()["total"] == 2
    v = box.passe(T + 10 * H)
    assert v["dossiers"]["depot.exemple.test"]["total"] == 1
    v = box.passe(T + 40 * H)
    assert "depot.exemple.test" in v["calmes"] and not D._fond["agregateur"].e["heures"]
    assert not D._fond["agregateur"].e["derniers"]


# ── sens ───────────────────────────────────────────────────────────────────────────────────────────────────────────

def test_sous_attaque_seulement_contre_un_rythme_mesure(box):
    box.ecrire(*[ligne(60) for _ in range(200)])
    assert box.site()["attaque"] is False                               # pas d'historique : rien à comparer
    D.vider()
    box.c["etat"].unlink()
    box.ecrire(*[ligne(h * H) for h in range(3, 20) for _ in range(2)])
    d = box.site()
    assert d["attaque"] and ["sous attaque", "r"] in d["etiquettes"] and d["urgence"] == 80
    assert "En ce moment : 200 en deux heures, 50 fois le rythme habituel." in d["phrase"]


def test_phrases_accords_et_nombres(box):
    box.ecrire(ligne())
    d = box.site()
    assert d["phrase"].startswith("1 requête hostile en 24 h, de type « injection SQL ». Le mur l’a écartée.")
    box.ecrire(*[ligne() for _ in range(1233)], *[ligne(action="detect", category="recon_crawler") for _ in range(1)])
    d = box.site()
    assert "1 235 requêtes hostiles en 24 h" in d["phrase"]
    assert "99,9 %" in d["phrase"] and "1 a été vue puis laissée passer" in d["phrase"]   # jamais arrondi à 100 %
    assert d["etiquettes"][-1] == ["1 laissée passer", "o"] and d["geste"]["href"] == "/waf/#modes"
    assert not IPV4.search(d["phrase"])
    assert D.pct(100) == "100 %" and D.pl(0, "adresse", "adresses") == "0 adresse"


def _rotation(box, **k):
    box.c["rotation"].write_text(json.dumps({"genere_le": int(T), "mode": "propose", "campagnes": [
        {"signature": "0a1b2c3d4e", "hote": "depot.exemple.test", "etablie_le": int(T) - 900, "dernier": int(T) - 60, "sources": 640,
         "bannies": 0, "epargnees": 3, "a_bannir": 19, "ecartees": 2}, {"signature": "../x", "hote": "depot.exemple.test"},
        {"signature": "ffffffff", "hote": "203.0.113.4"}], **k}))


def test_decisions_en_attente_et_geste(box):
    _rotation(box)
    box.c["campagnes"].write_text(json.dumps({"genere_le": int(T), "mode": "propose", "candidats": [
        {"ip": "203.0.113.1", "decision": "a_bannir"}, {"ip": "203.0.113.1", "decision": "a_bannir"},
        {"ip": "203.0.113.2", "decision": "banni"}, {"ip": "203.0.113.3", "decision": "ecarte:lan"}, "x"]}))
    box.ecrire(ligne())
    v = box.passe()
    d = v["dossiers"]["depot.exemple.test"]
    assert d["urgence"] == 100 and d["etiquettes"][0] == ["à décider", "r"] and d["geste"]["href"] == "/actor/"
    assert "19 adresses sont proposées au bannissement et attendent ta décision." in d["phrase"]
    assert any(f["preuve"] == "attend ta décision" and "19" in f["texte"] for f in d["faits"])
    dec = v["liste"]["decisions"]
    assert [c["id"] for c in dec["rotation"]["campagnes"]] == ["rotation:0a1b2c3d"]
    assert dec["campagnes"]["a_bannir"] == 1 and dec["campagnes"]["bannis"] == 1 and dec["acteurs"]["a_bannir"] is None
    assert not IPV4.search(json.dumps(v["liste"]))


def test_etat_de_rotation_perime_ou_auto_ne_demande_rien(box):
    box.ecrire(ligne())
    for k in ({"mode": "auto"}, {"genere_le": int(T) - 3600}):
        _rotation(box, **k)
        assert box.site()["etat"] != "a_decider"
    assert box.passe()["liste"]["decisions"]["rotation"]["etat"] == "perime"


def test_population_visant_le_site_devient_un_fait(box):
    box.c["populations"].write_text(json.dumps({"genere_le": int(T), "populations": [
        {"id": "famille:collecte", "famille": "collecte", "nom_cible": "depot.exemple.test", "adresses": 2454, "etat": "observee",
         "actives_24h": 12, "dernier": int(T) - 600}]}))
    box.ecrire(ligne())
    assert any(f["texte"] == "Collecte : 2 454 adresses en sept jours" for f in box.site()["faits"])
    assert len(box.site()["faits"]) <= D.MAX_FAITS


# ── routes ─────────────────────────────────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def waf():
    W.app.dependency_overrides.clear()
    yield W
    W.app.dependency_overrides.clear()


def test_routes_gardees_et_sans_calcul(box, waf, monkeypatch):
    from fastapi.testclient import TestClient
    c = TestClient(waf.app)
    hors_lan = {"X-SecuBox-LAN": "0"}                   # le harnais représente un tableau de bord du réseau local
    for u in ("/dossiers/sites", "/dossiers/sites/depot.exemple.test"):
        assert c.get(u, headers=hors_lan).status_code == 401
    waf.app.dependency_overrides[D.require_lecture] = lambda: {"sub": "lecteur"}
    assert c.get("/dossiers/sites").json() == {"disponible": False, "genere_le": None, "couverture_depuis": None}
    box.ecrire(ligne(8 * H), ligne(), ligne(host="autre.invalide", category="host_anomaly:unrouted"))
    box.passe()
    monkeypatch.setattr(D, "rafraichir", lambda *a, **k: pytest.fail("calcul sur le chemin d'une requête"))
    monkeypatch.setattr(D._veille, "lire_flux", lambda *a, **k: pytest.fail("journal lu sur le chemin d'une requête"))
    j = c.get("/dossiers/sites").json()
    assert j["disponible"] and j["genere_le"] == int(T) and j["couverture_depuis"] == int(T) - 8 * H and j["perime"] in (True, False)
    assert [s["id"] for s in j["sites"]] == ["depot.exemple.test", D.INCONNUS] and j["calmes_total"] == 2
    d = c.get("/dossiers/sites/depot.exemple.test").json()
    assert d["couches"][0]["nom"] == "Arrêté" and len(d["couches"][0]["serie"]) == 24 and d["couverture_depuis"]
    calme = c.get("/dossiers/sites/agenda.exemple.test").json()
    assert calme["total"] == 0 and calme["serie"][-1] == 0 and calme["serie"][-2] is None
    assert c.get("/dossiers/sites/inconnu.exemple.test").status_code == 404
    assert c.get("/dossiers/sites/<script>").status_code == 422
    assert not IPV4.search(c.get("/dossiers/sites").text + c.get("/dossiers/sites/noms-inconnus").text)


def test_autre_processus_sert_l_etat_ecrit(box, waf):
    """Monté dans l'agrégateur (sans tâche de fond), le module sert les vues du fichier d'état."""
    from fastapi.testclient import TestClient
    waf.app.dependency_overrides[D.require_lecture] = lambda: {"sub": "lecteur"}
    box.ecrire(ligne(), ligne(action="detect"))
    box.passe(forcer=True)
    D.vider()
    j = TestClient(waf.app).get("/dossiers/sites").json()
    assert j["sites"][0]["total"] == 2 and j["genere_le"] == int(T) and j["sites"][0]["totaux"]["passe"] == 1


def test_la_boucle_de_fond_est_branchee(waf):
    import inspect
    src = inspect.getsource(waf._warm_loop)
    assert "asyncio.to_thread(_dossiers.rafraichir)" in src
    assert all(any(d.call is D.require_lecture for d in r.dependant.dependencies)
               for r in D.router.routes)
