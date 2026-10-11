# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2287 — Guardian : le résumé du réseau domestique (tuiles, courbe, types, services, appareils), construit des compteurs DNS RÉELS ; rien d'inventé."""
import sqlite3
import time

import pytest

from api import dnstv
from api import dnstv_gardien as G

NOW = 1_800_000_000          # 2027-01-15 UTC
JOUR = dnstv._jour(NOW)
HIER = dnstv._jour(NOW - 86400)


@pytest.fixture
def magasin(tmp_path):
    m = dnstv.Magasin(tmp_path / "dnstv.db")
    return m


def pose(m, lignes):
    cx = sqlite3.connect(m.chemin)
    cx.executemany("INSERT INTO dnstv_counts(jour,client,domaine,categorie,decision,hits) VALUES (?,?,?,?,?,?)", lignes)
    cx.commit()
    cx.close()


def classer(domaine):
    table = {"ads.exemple.fr": ("Régie", "publicite"), "mesure.exemple.fr": ("Médiamétrie", "mesure_audience"), "stats.exemple.fr": ("Stats", "analytique")}
    return table.get(domaine, (None, "inconnu"))


def resume(m, **kw):
    return G.resume(m, now=NOW, sources=kw.get("sources", {}), classer=classer, nac=kw.get("nac"))


def test_les_tuiles_comptent_aujourd_hui_et_donnent_hier(magasin):
    pose(magasin, [(JOUR, "192.168.1.5", "a.fr", "", "ALLOWED", 700), (JOUR, "192.168.1.5", "ads.exemple.fr", "advertising", "BLOCKED", 300),
                   (JOUR, "192.168.1.5", "x.fr", "", "UPSTREAM_ERROR", 50), (HIER, "192.168.1.5", "a.fr", "", "ALLOWED", 900)])
    r = resume(magasin)
    assert r["dns"]["requetes"] == 1000 and r["dns"]["bloquees"] == 300 and r["dns"]["taux"] == 30     # les erreurs amont ne sont ni autorisées ni bloquées
    assert "hier" in r["dns"]["sous"] and "900" in r["dns"]["sous"].replace(" ", "")


def test_la_courbe_donne_sept_jours_dont_ceux_sans_donnee_a_zero(magasin):
    pose(magasin, [(JOUR, "c", "a.fr", "", "ALLOWED", 10), (dnstv._jour(NOW - 3 * 86400), "c", "a.fr", "", "BLOCKED", 4)])
    s = resume(magasin)["serie"]
    assert len(s) == 7 and s[-1]["a"] == 10 and s[-4]["b"] == 4 and s[0] == {"x": s[0]["x"], "a": 0, "b": 0}
    assert all(set(p) == {"x", "a", "b"} for p in s)


def test_les_types_bloques_somment_cent_pour_cent_avec_autres_en_dernier(magasin):
    pose(magasin, [(JOUR, "c", "ads.exemple.fr", "", "BLOCKED", 50), (JOUR, "c", "mesure.exemple.fr", "", "BLOCKED", 30), (JOUR, "c", "stats.exemple.fr", "", "BLOCKED", 15),
                   (JOUR, "c", "inconnu.fr", "", "BLOCKED", 5)])
    t = resume(magasin)["types"]
    assert [x["nom"] for x in t] == ["Publicité", "Mesure d'audience", "Analytique", "Autres"]
    assert sum(x["pct"] for x in t) == 100 and t[0]["pct"] == 50 and t[-1]["pct"] == 5
    assert all(x["c"] for x in t)                                      # chaque part a une couleur


def test_les_services_les_plus_bloques_sont_classes_et_bornes_a_six(magasin):
    pose(magasin, [(JOUR, "c", f"s{i}.fr", "", "BLOCKED", 100 - i) for i in range(9)] + [(JOUR, "c", "ads.exemple.fr", "", "BLOCKED", 500)])
    cats = resume(magasin)["cats"]
    assert len(cats) <= 6 and cats[0]["nom"] == "Régie" and cats[-1]["nom"].startswith("Autres")      # le connu d'abord, les non classés en dernier — même s'ils pèsent plus
    assert cats[0]["c"] == "rouge" and cats[-1]["c"] == "gris"


def test_aucun_blocage_donne_des_listes_vides_pas_des_parts_inventees(magasin):
    pose(magasin, [(JOUR, "c", "a.fr", "", "ALLOWED", 10)])
    r = resume(magasin)
    assert r["types"] == [] and r["cats"] == [] and r["dns"]["bloquees"] == 0 and r["dns"]["taux"] == 0


def test_un_magasin_vide_ne_plante_pas_et_ne_pretend_rien(magasin):
    r = resume(magasin)
    assert r["dns"]["requetes"] == 0 and r["serie"] and r["top"] == [] and r["appareils"] is None and r["menaces"] is None


def test_les_appareils_principaux_regroupent_les_adresses_d_un_meme_appareil(magasin):
    pose(magasin, [(JOUR, "192.168.1.9", "a.fr", "", "ALLOWED", 800), (JOUR, "2a01::9", "a.fr", "", "ALLOWED", 100), (JOUR, "2a01::9", "ads.exemple.fr", "", "BLOCKED", 100),
                   (JOUR, "192.168.1.7", "a.fr", "", "ALLOWED", 400), (JOUR, "192.168.1.7", "ads.exemple.fr", "", "BLOCKED", 100)])
    sources = {"aa:bb:cc:00:00:09": {"ips": ["192.168.1.9", "2a01::9"], "nom": "TV Salon"}, "aa:bb:cc:00:00:07": {"ips": ["192.168.1.7"], "nom": "Smartphone"}}
    nac = {"connectes": 2, "total": 5, "par_ip": {"192.168.1.9": "tv", "192.168.1.7": "phone"}}
    r = resume(magasin, sources=sources, nac=nac)
    assert [a["nom"] for a in r["top"]] == ["TV Salon", "Smartphone"]
    tv = r["top"][0]
    assert tv["req"] == 1000 and tv["blq"] == 100 and tv["pct"] == 10 and tv["type"] == "tv"
    assert r["top"][1]["type"] == "tel" and r["top"][1]["pct"] == 20 and r["appareils"] == {"connectes": 2, "total": 5}


def test_la_couleur_d_un_appareil_suit_son_taux_de_blocage(magasin):
    pose(magasin, [(JOUR, "1.1.1.1", "a.fr", "", "ALLOWED", 60), (JOUR, "1.1.1.1", "ads.exemple.fr", "", "BLOCKED", 40),
                   (JOUR, "2.2.2.2", "a.fr", "", "ALLOWED", 85), (JOUR, "2.2.2.2", "ads.exemple.fr", "", "BLOCKED", 15),
                   (JOUR, "3.3.3.3", "a.fr", "", "ALLOWED", 97), (JOUR, "3.3.3.3", "ads.exemple.fr", "", "BLOCKED", 3)])
    src = {k: {"ips": [k], "nom": n} for k, n in (("1.1.1.1", "A"), ("2.2.2.2", "B"), ("3.3.3.3", "C"))}
    couleurs = {a["nom"]: a["c"] for a in resume(magasin, sources=src)["top"]}
    assert couleurs == {"A": "rouge", "B": "orange", "C": "vert"}


def test_un_type_de_service_inconnu_du_dictionnaire_reste_lisible(magasin):
    pose(magasin, [(JOUR, "c", "z.fr", "", "BLOCKED", 10)])
    G_classer = lambda d: ("Zed", "type_exotique_x")
    r = G.resume(magasin, now=NOW, sources={}, classer=G_classer, nac=None)
    assert r["types"][0]["nom"] == "Type exotique x"


def test_nac_resume_compte_les_connectes_hors_conteneurs_lxc(tmp_path):
    p = tmp_path / "devices.db"
    cx = sqlite3.connect(p)
    cx.execute("CREATE TABLE devices(mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT, device_type TEXT, last_seen INTEGER, interface TEXT)")
    cx.executemany("INSERT INTO devices VALUES (?,?,?,?,?,?)", [
        ("aa:00:00:00:00:01", "192.168.1.20", "tv", "tv", NOW - 60, ""), ("aa:00:00:00:00:02", "192.168.1.21", "tel", "phone", NOW - 7200, ""),
        ("00:16:3e:00:00:03", "10.100.0.5", "ctn", "unknown", NOW - 30, "br-lxc"), ("aa:00:00:00:00:04", "192.168.1.22", "pc", "computer", NOW - 120, "")])
    cx.commit()
    cx.close()
    r = G.nac_resume(str(p), NOW)
    assert r["connectes"] == 2 and r["total"] == 3 and r["par_ip"]["192.168.1.20"] == "tv"       # le conteneur LXC n'est pas un appareil
    assert G.nac_resume(str(tmp_path / "absente.db"), NOW) is None


# ── Route ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
def test_la_route_est_en_lecture_et_ne_sert_que_du_cache_d_une_minute(monkeypatch, tmp_path):
    from api import dnstv_routes as R
    import inspect
    src = inspect.getsource(R.gardien)
    assert "require_lecture" in inspect.getsource(R) and "def gardien" in inspect.getsource(R)
    assert "_CACHE_GARDIEN" in src or "_cache_gardien" in src


def test_la_route_rend_le_resume_avec_les_menaces_d_actord(monkeypatch, tmp_path):
    import asyncio
    from api import dnstv_routes as R
    m = dnstv.Magasin(tmp_path / "dnstv.db")
    pose(m, [(JOUR, "192.168.1.5", "a.fr", "", "ALLOWED", 10)])
    monkeypatch.setattr(R, "_magasin", lambda: m)
    monkeypatch.setattr(R, "_sources", lambda: {})
    monkeypatch.setattr(R, "_menaces_actord", lambda: 4321)
    monkeypatch.setattr(R, "_NAC_DB", str(tmp_path / "absente.db"))
    R._cache_gardien.clear()
    monkeypatch.setattr(time, "time", lambda: NOW)
    r = asyncio.run(R.gardien())
    assert r["dns"]["requetes"] == 10 and r["menaces"] == {"n": 4321, "libelle": "Menaces bloquées (24 h)"} and r["appareils"] is None


def test_une_panne_d_actord_laisse_les_menaces_indisponibles_pas_a_zero(monkeypatch, tmp_path):
    import asyncio
    from api import dnstv_routes as R
    m = dnstv.Magasin(tmp_path / "dnstv.db")
    monkeypatch.setattr(R, "_magasin", lambda: m)
    monkeypatch.setattr(R, "_sources", lambda: {})
    monkeypatch.setattr(R, "_menaces_actord", lambda: None)
    monkeypatch.setattr(R, "_NAC_DB", str(tmp_path / "absente.db"))
    R._cache_gardien.clear()
    assert asyncio.run(R.gardien())["menaces"] is None
