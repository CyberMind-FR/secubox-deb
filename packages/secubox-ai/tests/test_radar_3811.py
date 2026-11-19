# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Radar et chaîne d'attaque du POC dans la console (#3811). Aucun réseau réel : gk2 et le moteur sont simulés.

Échantillonneur par pays (veille, 15 min, 8 jours), « même heure » hier / J-7 (±15 min, jamais d'extrapolation),
forme des routes, comportement à vide, chaîne lue sur les vrais dossiers de la veille, et l'échec du résumé rendu
à la page (« analyse des menaces » qui semblait figée).
"""
import asyncio
import datetime as dt
import re
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi import HTTPException

from secubox_core.auth import require_jwt

from api import menaces, radar, taches
from api.main import app
from veille import base, correlation, dossiers, pays, retention
from test_menaces_3583 import appeler, attendre, env, gk2  # noqa: F401 — fixtures partagées
from test_veille_correlation_3721 import T0, _waf

PAGE = Path(__file__).resolve().parents[1] / "www" / "ai" / "index.html"
JOUR = 86400


@pytest.fixture(autouse=True)
def _radar_propre():
    radar._reinitialiser()
    yield
    radar._reinitialiser()


def _local(annee, mois, jour, h, m=0):
    """Horodatage d'une heure LOCALE (le Radar compare « même heure locale »)."""
    return dt.datetime(annee, mois, jour, h, m).astimezone().timestamp()


# ── échantillonneur (veille) ──

def test_extraire_top5_et_sources_illisibles():
    stats = {"threats_today": 1411, "top_countries": [{"country": "CN", "count": 400}, {"country": "US", "count": True},
                                                       {"country": "", "count": 3}, {"country": "NL", "count": 50}]}
    bans = {"bans": [{"ip": "1", "country": "CN"}] * 3 + [{"ip": "2", "country": "RU"}, {"ip": "3"}, "pas un ban"]}
    al, ta, bp, tb = pays.extraire(stats, bans)
    assert (al, ta) == ({"CN": 400, "NL": 50}, 1411)          # booléen et pays vide écartés, jamais devinés
    assert (bp, tb) == ({"CN": 3, "RU": 1}, 5)
    assert pays.extraire(None, None) == (None, None, None, None)
    assert pays.extraire({"top_countries": []}, {"x": 1}) == (None, None, None, None)   # sans total : illisible


def test_un_echantillon_par_creneau_et_retention_8_jours(tmp_path):
    db = base.ouvrir(tmp_path / "veille.db")
    t = 1_800_000_000 - 1_800_000_000 % 900
    assert pays.ecrire(db, t + 5, {"CN": 1}, 10, {"CN": 2}, 20)
    assert not pays.ecrire(db, t + 600, {"CN": 9}, 90, None, None)          # même créneau : le premier gagne
    assert pays.creneau_fait(db, t + 899) and not pays.creneau_fait(db, t + 900)
    assert not pays.ecrire(db, t + 900, None, None, None, None)               # deux sources illisibles : rien
    assert pays.ecrire(db, t + 900, None, None, {"US": 4}, 4)                  # une seule : l'autre reste NULL
    ligne = db.execute("SELECT alertes_json, tot_alertes, bans_json FROM pays_echantillons WHERE creneau = ?",
                       ((t + 900) // 900,)).fetchone()
    assert ligne == (None, None, '{"US": 4}')
    # 8 jours plus tard (+1 créneau) : les deux premiers partent à l'écriture suivante.
    assert pays.ecrire(db, t + 8 * JOUR + 1800, {"CN": 1}, 1, None, None)
    assert [q for (q,) in db.execute("SELECT quand FROM pays_echantillons ORDER BY 1")] == [t + 8 * JOUR + 1800]
    db.close()


def test_retention_purge_les_echantillons_de_plus_de_8_jours(tmp_path):
    db = base.ouvrir(tmp_path / "veille.db")
    maintenant = T0
    for jours in (9, 7):
        q = int((maintenant - timedelta(days=jours)).timestamp())
        db.execute("INSERT INTO pays_echantillons(creneau, quand, tot_alertes) VALUES (?, ?, 1)", (q // 900, q))
    assert retention.purger(db, maintenant)["pays"] == 1
    assert db.execute("SELECT count(*) FROM pays_echantillons").fetchone()[0] == 1
    db.close()


class ClientFaux:
    """Client signé simulé : aucune requête réelle ; compte les lectures."""

    def __init__(self, stats=None, bans=None, panne=()):
        self.lus, self.r, self.panne = [], {"stats": stats, "bans": bans}, panne

    async def get(self, nom, params=None):
        self.lus.append(nom)
        if nom in self.panne:
            raise RuntimeError("gk2 en panne")
        return self.r[nom]


def test_tour_lit_gk2_une_fois_par_creneau(tmp_path):
    db = base.ouvrir(tmp_path / "veille.db")

    async def sql(f):
        return f(db)
    c = ClientFaux({"threats_today": 7, "top_countries": [{"country": "CN", "count": 7}]}, {"bans": []}, panne=("bans",))
    t = 1_800_000_000 - 1_800_000_000 % 900
    assert asyncio.run(pays.tour(sql, c, t + 5))
    assert not asyncio.run(pays.tour(sql, c, t + 65))                      # créneau fait : pas de lecture de gk2
    assert c.lus == ["stats", "bans"]
    assert db.execute("SELECT alertes_json, tot_alertes, bans_json, tot_bans FROM pays_echantillons").fetchone() == \
        ('{"CN": 7}', 7, None, None)                                        # bans en panne : NULL, jamais 0
    db.close()


def test_boucle_de_la_veille_declaree():
    src = (Path(__file__).resolve().parents[1] / "sbin" / "secubox-ai-veille").read_text()
    assert 'Boucle("pays", PAS_PAYS_S, echantillonner_pays, collecte=True)' in src and "pays.tour(veille.sql" in src


# ── tendances « même heure » ──

def _ech(q, al=None, ta=None, bans=None, tb=None):
    return {"quand": q, "alertes": al, "tot_alertes": ta, "bans": bans, "tot_bans": tb}


def test_meme_heure_hier_et_j7_sans_extrapolation():
    maintenant = _local(2026, 11, 18, 14, 0)
    echs = [_ech(_local(2026, 11, 11, 14, 10), {"CN": 50, "US": 9}, 300),       # J-7, 10 min d'écart : retenu
            _ech(_local(2026, 11, 16, 13, 20), {"CN": 70}, 500),               # J-2 à 40 min : hors tolérance
            _ech(_local(2026, 11, 17, 13, 55), {"US": 30}, 800),               # hier : CN hors du top 5
            _ech(_local(2026, 11, 18, 3, 0), {"CN": 5}, 40)]
    t = radar.pays_tendances(echs, maintenant, {"CN": 120, "US": 40}, {}, 1000, None)
    cn = t["colonnes"]["alertes"]["pays"]["CN"]
    assert (cn["auj"], cn["hier"], cn["hier_hors"], cn["j7"], cn["j7_hors"]) == (120, None, True, 50, False)
    assert cn["serie7"] == [None, None, None, None, None, None, 120]           # J-2 trop loin : null, pas 70
    us = t["colonnes"]["alertes"]["pays"]["US"]
    assert (us["hier"], us["j7"]) == (30, 9)
    jour = t["colonnes"]["alertes"]["jour"]
    assert jour["auj"][3] == 40 and jour["auj"][4] is None                     # 04 h : aucun échantillon à ±15 min
    assert all(v is None for v in jour["auj"][15:])                            # l'avenir n'est jamais rempli
    assert jour["hier"][14] == 800 and jour["j7"][14] == 300
    assert jour["maintenant"] == {"h": 14.0, "valeur": 1000}
    assert t["colonnes"]["alertes"]["hier_dispo"] and t["colonnes"]["alertes"]["j7_dispo"]
    assert t["colonnes"]["bans"]["pays"] == {} and not t["colonnes"]["bans"]["hier_dispo"]
    assert (t["echantillons"], t["depuis"]) == (4, echs[0]["quand"])


def test_tendances_a_vide():
    t = radar.pays_tendances([], _local(2026, 11, 18, 9), {}, {}, None, None)
    for col in ("alertes", "bans"):
        c = t["colonnes"][col]
        assert c["pays"] == {} and not c["hier_dispo"] and not c["j7_dispo"]
        assert c["jour"]["auj"] == [None] * 24 and c["jour"]["maintenant"]["valeur"] is None
    assert (t["echantillons"], t["depuis"]) == (0, None)


# ── chaîne d'attaque (vrais dossiers de la veille) ──

def test_chaine_sur_les_dossiers_de_la_veille(tmp_path):
    db = base.ouvrir(tmp_path / "veille.db")
    ip = "100.64.12.1"
    _waf(db, ip, T0 - timedelta(minutes=25), cat="scanners:x", sev="low")
    _waf(db, ip, T0 - timedelta(minutes=20), cat="product_absent_probes:wp", sev="low")
    _waf(db, ip, T0 - timedelta(minutes=10), cat="sqli:union", sev="high")
    _waf(db, "100.64.13.7", T0 - timedelta(minutes=5), cat="scanners:y", sev="low")
    correlation.correler(db, T0)
    dossiers.construire(db, T0)
    db.commit()
    c = radar.chaine(db, T0.timestamp())
    assert c["disponible"] and c["acteurs"] == 2 and c["enchainees_2"] == 1
    assert c["entonnoir"] == {"reperage": 2, "essais": 1, "exploitation": 1, "persistance": 0}
    d = c["dossiers"][0]
    assert d["cle"] == ip and d["gravite"] == "high" and d["adresses"] == [ip] and d["enchainees"] == 3
    assert [e["etape"] for e in d["etapes"]] == ["reperage", "essais", "exploitation"]
    e = d["etapes"][2]
    assert e["regles"] == ["regle_waf_attaque"] and e["preuves"] == 1
    assert e["exemple"]["famille"] == "sqli" and e["exemple"]["vhost"] == "site.example.net"   # preuve réelle en base
    assert radar.chaine(db, (T0 + timedelta(days=2)).timestamp())["acteurs"] == 0          # hors fenêtre de 24 h
    db.close()


# ── routes : forme, garde, vide ──

@pytest.mark.asyncio
async def test_routes_avant_le_premier_calcul_et_veille_absente(env):  # noqa: F811
    assert (await appeler("GET", "/menaces/pays")).json() == {"pret": False, "raison": "premier calcul de fond en cours",
                                                               "calcule": None, "pays_tendances": None}
    assert (await appeler("GET", "/menaces/chaine")).json()["pret"] is False
    await radar.rafraichir()                                   # ni relevé, ni veille.db : rien d'inventé
    p = (await appeler("GET", "/menaces/pays")).json()
    assert p["pret"] and p["pays_tendances"]["echantillons"] == 0
    assert p["pays_tendances"]["colonnes"]["alertes"]["pays"] == {}
    c = (await appeler("GET", "/menaces/chaine")).json()["chaine"]
    assert c == {"disponible": False, "fenetre_s": 86400, "raison": "veille.db absente (veille arrêtée ?)"}
    s = (await appeler("GET", "/menaces/series", params={"fenetre": "1h"})).json()
    assert s["fenetre"] == "1h" and s["categories"] == {} and s["bans"] == [] and s["tuiles"]["alertes_jour"] is None
    assert (await appeler("GET", "/menaces/series", params={"fenetre": "24h"})).status_code == 400


@pytest.mark.asyncio
async def test_routes_gardees_par_require_jwt(env):  # noqa: F811
    app.dependency_overrides.pop(require_jwt, None)
    for chemin in ("/menaces/pays", "/menaces/chaine", "/menaces/series"):
        assert (await appeler("GET", chemin)).status_code in (401, 403), chemin
        assert (await appeler("POST", chemin)).status_code == 405, chemin       # lecture seule


@pytest.mark.asyncio
async def test_rafraichir_lit_releve_et_veille_en_lecture_seule(gk2, env):  # noqa: F811
    etat = env / "etat"
    etat.mkdir(exist_ok=True)
    db = base.ouvrir(etat / "veille.db")
    import time
    hier = int(time.time()) - JOUR
    pays.ecrire(db, hier, {"US": 300}, 900, {"NL": 800}, 900)
    db.close()
    await menaces.releve_menaces(force=True)
    await radar.rafraichir()
    t = (await appeler("GET", "/menaces/pays")).json()["pays_tendances"]
    us = t["colonnes"]["alertes"]["pays"]["US"]
    assert (us["auj"], us["hier"]) == (400, 300)                       # aujourd'hui = relevé, hier = échantillon
    assert t["colonnes"]["alertes"]["pays"]["DE"]["hier_hors"] is True
    assert t["colonnes"]["bans"]["pays"]["NL"]["hier"] == 800
    assert t["colonnes"]["alertes"]["jour"]["maintenant"]["valeur"] == 1234
    c = (await appeler("GET", "/menaces/chaine")).json()["chaine"]
    assert c["disponible"] and c["acteurs"] == 0 and c["dossiers"] == []
    rel = (await appeler("GET", "/menaces/releve")).json()
    assert "_pays_alertes" not in rel                                   # clé interne jamais servie
    # séries : deux relevés complets, écart rangé dans la tranche du second
    menaces.INSTANTANES.clear()
    q = time.time() - 300
    menaces.INSTANTANES.extend([{"quand": q, "menaces_jour": 10, "bans": 5, "categories": {"auth_smtp:sasl_failed": 4}},
                                {"quand": q + 120, "menaces_jour": 16, "bans": 6, "categories": {"auth_smtp:sasl_failed": 9}}])
    s = (await appeler("GET", "/menaces/series", params={"fenetre": "1h"})).json()
    assert [v for v in s["categories"]["sasl_failed"] if v is not None] == [5] and len(s["bans"]) == 2


def test_series_sans_interpolation_et_remise_a_zero():
    q = 1_800_000_000 - 1_800_000_000 % 600
    inst = [{"quand": q + 10, "menaces_jour": 50, "bans": 1, "categories": {"scanners": 10}},
            {"quand": q + 130, "menaces_jour": 2, "bans": 1, "categories": {"scanners": 1}},       # minuit : ignoré
            {"quand": q + 1300, "menaces_jour": 9, "bans": 1, "categories": {"scanners": 4}},
            {"quand": q + 1400, "menaces_jour": 9, "bans": 1, "categories": {}}]                  # incomplet
    s = radar.series_menaces(inst, q + 1500, 3600)
    assert list(s["categories"]) == ["scanners"]
    assert [v for v in s["categories"]["scanners"] if v is not None] == [3]
    assert None in s["categories"]["scanners"]                                                   # aucune tranche comblée


# ── « analyse des menaces » figée : l'échec est rendu ──

@pytest.mark.asyncio
async def test_resume_en_echec_rendu_par_le_releve(gk2, monkeypatch):  # noqa: F811
    async def refus(*a, **k):
        raise HTTPException(502, "le moteur a refusé la requête")
    monkeypatch.setattr(taches, "demander_modele", refus)
    r = await appeler("POST", "/menaces/resumer")
    t = await attendre(r.json()["tache"])
    assert t["etat"] == "echec"
    rel = (await appeler("GET", "/menaces/releve")).json()
    assert rel["resume_en_cours"] is None                                 # plus « en cours » : la page ne suit plus
    assert (rel["resume_etat"], rel["resume_echec"]) == ("echec", "le moteur a refusé la requête")
    taches.TACHES.clear()                                                 # module redémarré : tâche oubliée
    rel = (await appeler("GET", "/menaces/releve")).json()
    assert (rel["resume_en_cours"], rel["resume_etat"], rel["resume_echec"]) == (None, None, None)
    assert (await appeler("GET", "/taches/" + r.json()["tache"])).status_code == 404


def test_page_rend_echec_arret_et_suivi_perdu():
    h = PAGE.read_text(encoding="utf-8")
    corps = re.search(r"function suivreResume\(t\) \{(.*?)\n  \}\n", h, re.S).group(1)
    assert "'Résumé en échec : '" in corps and "'Résumé arrêté : '" in corps
    assert "e.status === 404" in corps and "Suivi perdu" in corps
    assert ".catch(function () { SUIVI_Z = null; })" not in h                 # plus d'erreur avalée
    assert "r.resume_echec" in h


# ── page : radar, chaîne, démonstration ──

def test_page_radar_chaine_et_demo():
    h = PAGE.read_text(encoding="utf-8")
    for route in ("/menaces/pays", "/menaces/chaine", "/menaces/series?fenetre="):
        assert route in h, route
    for ident in ('id="rPays"', 'id="rGravite"', 'id="rFil"', 'id="chEntonnoir"', 'id="chDossiers"', 'id="gAlertes"'):
        assert ident in h, ident
    assert "DEMO = q.get('demo') === '1'" in h and 'id="rDemo"' in h and 'id="chDemo"' in h
    neuf = h[h.index("// ---- Graphiques des menaces"):h.index("// ---- Code ----")]
    assert "<script src=\"http" not in h and "confirm(" not in neuf and "alert(" not in neuf and "prompt(" not in neuf
    assert "'POST'" not in neuf                                                # Radar et Chaîne : lecture seule
    demo = h[h.index("// ---- Démonstration"):h.index("// ---- Code ----")]
    ips = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", demo))
    assert ips and all(re.match(r"^(192\.0\.2|198\.51\.100|203\.0\.113)\.", x) for x in ips), ips
    assert "api(" not in demo                                                  # aucune lecture en démonstration
    # couleurs des marques : palette validée sur le fond sombre (#0a162e), jamais l'ancien rouge hors bande
    assert "#ff4d5e" not in h[h.index("/* Vue Radar"):h.index("</style>")]
