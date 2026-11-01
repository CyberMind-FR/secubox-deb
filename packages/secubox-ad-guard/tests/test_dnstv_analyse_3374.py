# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Lot 3 SBX TV PRIVACY (#3374) : cache de classification découpé (SQLite), analyseur côté serveur (filtres, agrégats, métriques,
pagination, bornes, export CSV) et événements récents agrégés."""
import csv
import io
import stat
import time
from pathlib import Path

import pytest

from api import dnstv, dnstv_analyse as A, dnstv_regles as R, dnstv_taxonomie as T
from test_dnstv_ctl_api import api, monde  # noqa: F401  (fixtures)

LISTES = Path(__file__).resolve().parents[1] / "lists"
MAC1, MAC2 = "00:24:d4:00:00:01", "00:24:d4:00:00:02"
IP1, IP2 = "192.168.1.95", "192.168.1.96"
T0 = int(time.time())


def _ligne(domaine, mac, cat, req, bloq, derniere, premiere=None, protegee=None, source="liste", confiance=80):
    return {"domaine": domaine, "mac": mac, "categorie": cat, "source": source, "confiance": confiance, "ancienne": None,
            "protegee": (cat in T.PROTEGEES) if protegee is None else protegee, "ips": [IP1 if mac == MAC1 else IP2],
            "requetes": req, "bloquees": bloq, "derniere_observation": derniere, "precision": "seconde",
            "premiere_observation": premiere if premiere is not None else derniere - 40 * 86400}


LIGNES = [
    _ligne("pubads.g.doubleclick.net", MAC1, "PUBLICITE", 100, 100, T0 - 100, premiere=T0 - 200),
    _ligne("googleads.g.doubleclick.net", MAC1, "PUBLICITE", 50, 10, T0 - 5000),
    _ligne("k7.ftven.fr", MAC1, "STREAMING", 300, 0, T0 - 60),
    _ligne("license.oqee.net", MAC2, "DRM", 20, 0, T0 - 3 * 86400),
    _ligne("logs.netflix.com", MAC2, "TELEMETRIE", 70, 70, T0 - 10 * 86400),
    _ligne("candidat.example.com", MAC2, "INCONNU", 5, 0, T0 - 30, source="apprentissage", confiance=40),
]
ETAT = {"actif": True, "clients": [{"ip": IP1, "nom": "TV salon", "mode": "auto", "mac": MAC1},
                                   {"ip": IP2, "nom": "TV chambre", "mode": "auto", "mac": MAC2}]}


@pytest.fixture
def cache(tmp_path):
    r = R.Regles()
    r.proposer("tv-chambre", "candidat.example.com", 40, "faible", T0)
    A.ecrire_cache(LIGNES, T0, tmp_path, etat=ETAT, regles=r.liste())
    return tmp_path


def an(d, **kw):
    kw.setdefault("maintenant", T0)
    return A.analyser(d, **kw)


# ── cache ────────────────────────────────────────────────────────────────────────────────────────────
def test_cache_sqlite_0640_remplace_l_ancien_json(tmp_path):
    (tmp_path / "classification-cache.json").write_text("{}")
    A.ecrire_cache(LIGNES, T0, tmp_path, etat=ETAT, regles=[])
    f = tmp_path / A.FICHIER
    assert f.is_file() and stat.S_IMODE(f.stat().st_mode) == 0o640
    assert not (tmp_path / "classification-cache.json").exists()
    assert A.genere(tmp_path) == T0


def test_cache_absent_ou_lien_rend_none(tmp_path):
    assert A.genere(tmp_path) is None and an(tmp_path)["cache"] is False
    (tmp_path / A.FICHIER).symlink_to(tmp_path / "ailleurs.db")
    assert A.genere(tmp_path) is None


def test_compat_taxonomie_lit_le_cache(cache):
    c = T.lire_cache(cache)
    assert c["genere"] == T0 and {x["domaine"] for x in c["domaines"]} >= {"k7.ftven.fr", "logs.netflix.com"}


# ── racine ───────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("d,r", [("pubads.g.doubleclick.net", "doubleclick.net"), ("a.b.bbc.co.uk", "bbc.co.uk"), ("free.fr", "free.fr"),
                                 ("x.y.gouv.fr", "y.gouv.fr")])
def test_racine(d, r):
    assert A.racine(d) == r


# ── filtres ──────────────────────────────────────────────────────────────────────────────────────────
def doms(res):
    return sorted(x["domaine"] for x in res["lignes"])


def test_sans_filtre_fenetre_30j(cache):
    r = an(cache)
    assert r["total"] == 6 and r["cache"] is True and len(r["lignes"]) == 6


@pytest.mark.parametrize("fenetre,attendus", [("1h", {"pubads.g.doubleclick.net", "k7.ftven.fr", "candidat.example.com"}),
                                              ("24h", {"pubads.g.doubleclick.net", "googleads.g.doubleclick.net", "k7.ftven.fr", "candidat.example.com"}),
                                              ("7j", {"pubads.g.doubleclick.net", "googleads.g.doubleclick.net", "k7.ftven.fr", "candidat.example.com", "license.oqee.net"})])
def test_fenetre(cache, fenetre, attendus):
    assert set(doms(an(cache, fenetre=fenetre))) == attendus


def test_filtre_appareils_multiples(cache):
    assert set(doms(an(cache, macs=[MAC2]))) == {"license.oqee.net", "logs.netflix.com", "candidat.example.com"}
    assert an(cache, macs=[MAC1, MAC2])["total"] == 6


def test_filtre_categories(cache):
    assert set(doms(an(cache, categories=["PUBLICITE", "DRM"]))) == {"pubads.g.doubleclick.net", "googleads.g.doubleclick.net", "license.oqee.net"}


@pytest.mark.parametrize("decision,attendus", [
    (["bloque"], {"pubads.g.doubleclick.net", "googleads.g.doubleclick.net", "logs.netflix.com"}),
    (["autorise"], {"googleads.g.doubleclick.net", "k7.ftven.fr", "license.oqee.net", "candidat.example.com"}),
    (["candidat"], {"candidat.example.com"}),
    (["protege"], {"k7.ftven.fr", "license.oqee.net", "candidat.example.com"}),
    (["candidat", "bloque"], {"pubads.g.doubleclick.net", "googleads.g.doubleclick.net", "logs.netflix.com", "candidat.example.com"})])
def test_filtre_decision(cache, decision, attendus):
    assert set(doms(an(cache, decisions=decision))) == attendus


def test_filtre_source_confiance_recherche(cache):
    assert doms(an(cache, sources=["apprentissage"])) == ["candidat.example.com"]
    assert doms(an(cache, confiance_max=50)) == ["candidat.example.com"]
    assert an(cache, confiance_min=50)["total"] == 5
    assert set(doms(an(cache, q="doubleclick"))) == {"pubads.g.doubleclick.net", "googleads.g.doubleclick.net"}


def test_filtres_combines(cache):
    assert doms(an(cache, macs=[MAC1], categories=["PUBLICITE"], decisions=["bloque"], fenetre="1h")) == ["pubads.g.doubleclick.net"]


def test_filtres_domaine_et_racine_exacts_pour_deplier(cache):
    assert doms(an(cache, racine_exacte="doubleclick.net")) == ["googleads.g.doubleclick.net", "pubads.g.doubleclick.net"]
    assert doms(an(cache, domaine_exact="k7.ftven.fr")) == ["k7.ftven.fr"]


# ── agrégats ─────────────────────────────────────────────────────────────────────────────────────────
def test_agreger_par_racine(cache):
    ag = {x["cle"]: x for x in an(cache, agreger="racine")["agregats"]}
    d = ag["doubleclick.net"]
    assert d["domaines"] == 2 and d["requetes"] == 150 and d["bloquees"] == 110 and d["part_bloquee"] == pytest.approx(110 / 150, abs=1e-3)


def test_agreger_par_categorie_appareil_domaine(cache):
    assert {x["cle"]: x["requetes"] for x in an(cache, agreger="categorie")["agregats"]}["PUBLICITE"] == 150
    app = {x["cle"]: x for x in an(cache, agreger="appareil")["agregats"]}
    assert app[MAC1]["requetes"] == 450 and app[MAC1]["nom"] == "TV salon"
    assert an(cache, agreger="domaine")["agregats"][0]["cle"] == "k7.ftven.fr"           # trié par requêtes
    assert an(cache, agreger="aucun")["agregats"] == []


# ── métriques ────────────────────────────────────────────────────────────────────────────────────────
def test_metriques(cache):
    m = an(cache)["metriques"]
    assert m["domaines"] == 6 and m["requetes"] == 545 and m["bloquees"] == 180
    assert m["part_bloquee"] == pytest.approx(180 / 545, abs=1e-3)
    assert m["par_categorie"]["PUBLICITE"] == {"domaines": 2, "requetes": 150}
    assert m["top_domaines"][0]["cle"] == "k7.ftven.fr" and len(m["top_domaines"]) <= 5
    assert m["top_appareils"][0]["cle"] == MAC1 and len(m["top_appareils"]) <= 5
    assert an(cache, fenetre="7j")["metriques"]["nouveaux"] == 1                          # pubads vu pour la première fois il y a 200 s
    assert an(cache, fenetre="1h")["metriques"]["nouveaux"] is None                     # passe 2 (I3) : non calculé sous un jour


# ── pagination et bornes ─────────────────────────────────────────────────────────────────────────────
def test_pagination(cache):
    p1, p2 = an(cache, limite=4), an(cache, limite=4, decalage=4)
    assert p1["total"] == p2["total"] == 6 and len(p1["lignes"]) == 4 and len(p2["lignes"]) == 2
    assert not set(doms(p1)) & set(doms(p2))
    assert (p1["decalage"], p1["limite"]) == (0, 4)


@pytest.mark.parametrize("kw", [{"fenetre": "2h"}, {"limite": 201}, {"limite": 0}, {"decalage": -1}, {"agreger": "ip"},
                                {"decisions": ["tout"]}, {"categories": ["PUB"]}, {"sources": ["x"]}, {"macs": ["zz"]},
                                {"macs": [MAC1] * 9}, {"q": "a" * 65}, {"q": "a'; drop"}, {"confiance_min": 101}, {"confiance_max": -1},
                                {"categories": ["PUBLICITE"] * 11}])
def test_bornes(cache, kw):
    with pytest.raises(A.ErreurAnalyse):
        an(cache, **kw)


# ── routes ───────────────────────────────────────────────────────────────────────────────────────────
def test_route_analyse_et_garde(api, monde):
    dnstv.ecrire_etat(ETAT, monde["etat"])
    A.ecrire_cache(LIGNES, T0, monde["etat"], etat=ETAT, regles=[])
    j = api.get("/adblock-tv/protection/analyse?categorie=PUBLICITE&categorie=DRM&agreger=racine&limite=2").json()
    assert j["total"] == 3 and len(j["lignes"]) == 2 and j["agregats"][0]["cle"] == "doubleclick.net"
    assert j["lignes"][0]["nom"] in ("TV salon", "TV chambre")
    assert api.get("/adblock-tv/protection/analyse?limite=500").status_code == 422
    assert api.get("/adblock-tv/protection/analyse?fenetre=1an").status_code == 422
    from api import dnstv_lot3_routes as L
    gardes = {(y.path, tuple(sorted(y.methods))): {d.call for d in y.dependant.dependencies} for y in L.router.routes}
    from api.dnstv_routes import require_lecture_nominative
    from secubox_core import auth
    assert require_lecture_nominative in gardes[("/adblock-tv/protection/analyse", ("GET",))]
    assert auth.require_jwt in gardes[("/adblock-tv/protection/analyse.csv", ("GET",))]


def test_route_analyse_mac_tronquee_hors_administrateur(api, monde, monkeypatch):
    from api import dnstv_lot3_routes as L
    dnstv.ecrire_etat(ETAT, monde["etat"])
    A.ecrire_cache(LIGNES, T0, monde["etat"], etat=ETAT, regles=[])
    monkeypatch.setattr(L, "est_admin_reel", lambda p: False)
    txt = api.get("/adblock-tv/protection/analyse?agreger=appareil").text
    assert MAC1 not in txt and "00:24:d4:…:01" in txt and IP1 not in txt


def test_route_export_csv(api, monde):
    dnstv.ecrire_etat(ETAT, monde["etat"])
    A.ecrire_cache(LIGNES + [_ligne("=cmd.example.com", MAC1, "INCONNU", 1, 0, T0 - 10)], T0, monde["etat"], etat=ETAT, regles=[])
    r = api.get("/adblock-tv/protection/analyse.csv?decision=bloque")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    rows = list(csv.reader(io.StringIO(r.text)))
    assert rows[0][:3] == ["domaine", "appareil", "mac"] and len(rows) == 4


# ── événements agrégés ───────────────────────────────────────────────────────────────────────────────
def _magasin(d):
    m = dnstv.Magasin(d / "dnstv.db")
    ev = [(dnstv.Evenement(T0 - 50 + i, IP1, "pubads.g.doubleclick.net", "A", "NXDOMAIN", "BLOCKED"), "advertising") for i in range(5)]
    ev += [(dnstv.Evenement(T0 - 30, IP1, "pubads.g.doubleclick.net.home", "A", "NXDOMAIN", "BLOCKED"), "")]
    ev += [(dnstv.Evenement(T0 - 20 + i, IP1, "k7.ftven.fr", "A", "NOERROR", "ALLOWED"), "") for i in range(20)]
    ev += [(dnstv.Evenement(T0 - 10, IP2, "neuf.example.com", "A", "NOERROR", "ALLOWED"), "")]
    ev += [(dnstv.Evenement(T0 - 3 * 3600, IP2, "vieux.example.com", "A", "NOERROR", "ALLOWED"), "")]
    m.ajouter(ev)
    with m._cx() as cx:                                                     # k7 déjà vu avant la fenêtre : pas nouveau
        cx.execute("INSERT INTO dnstv_counts VALUES (?,?,?,?,?,?)", (dnstv._jour(T0 - 5 * 86400), IP1, "k7.ftven.fr", "", "ALLOWED", 3))
    return m


def test_evenements_agreges(tmp_path):
    g = A.evenements_agreges(_magasin(tmp_path), 1, T0, {IP1: "TV salon", IP2: "TV chambre"})
    cles = [(x["appareil"], x["domaine"]) for x in g["groupes"]]
    assert cles[0] == ("TV salon", "pubads.g.doubleclick.net")                           # blocage d'abord, suffixe .home rattaché
    p = g["groupes"][0]
    assert p["occurrences"] == 6 and p["decision"] == "BLOCKED" and p["premier"] == T0 - 50 and p["dernier"] == T0 - 30
    assert cles[1] == ("TV chambre", "neuf.example.com") and g["groupes"][1]["nouveau"] is True    # puis les nouveautés
    k7 = g["groupes"][2]
    assert k7["domaine"] == "k7.ftven.fr" and k7["occurrences"] == 20 and k7["nouveau"] is False
    assert all(x["domaine"] != "vieux.example.com" for x in g["groupes"]) and "lignes" not in p
    assert any(x["domaine"] == "vieux.example.com" for x in A.evenements_agreges(_magasin(tmp_path / "b"), 24, T0, {})["groupes"])


def test_evenements_detail(tmp_path):
    g = A.evenements_agreges(_magasin(tmp_path), 1, T0, {}, detail=True)
    assert len(g["groupes"][0]["lignes"]) == 6


def test_route_evenements_detail_reserve_admin(api, monde, monkeypatch):
    from api import dnstv_lot3_routes as L
    dnstv.ecrire_etat(ETAT, monde["etat"])
    _magasin(monde["etat"])
    assert api.get("/adblock-tv/protection/evenements?heures=1").json()["groupes"][0]["appareil"] == "TV salon"
    assert "lignes" in api.get("/adblock-tv/protection/evenements?heures=1&detail=1").json()["groupes"][0]
    assert api.get("/adblock-tv/protection/evenements?heures=3").status_code == 422
    monkeypatch.setattr(L, "est_admin_reel", lambda p: False)
    assert api.get("/adblock-tv/protection/evenements?heures=1&detail=1").status_code == 403
