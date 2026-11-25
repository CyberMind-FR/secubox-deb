# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3921 tâche 2 — connecteur « paysage » : relevé des populations du WAF vers un graphe typé."""
import ipaddress
import json
import re
import sys
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE))

from secubox_datascope import config  # noqa: E402
from secubox_datascope.connecteurs import paysage  # noqa: E402

NOW = 1795000000.0
ID = re.compile(r"^[a-z_]+:[A-Za-z0-9:._-]{1,160}$")


def _pop(ident="famille:collecte", **kw):
    p = {"id": ident, "famille": "collecte", "nom_cible": "gitea.gk2.secubox.in",
         "cibles": ["gitea.gk2.secubox.in"], "adresses": 120, "reseaux": 2, "une": 40, "le3": 80,
         "classes": {"hebergeur": 70, "acces": 30}, "pays_top": [["US", 60], ["DE", 20]],
         "reseaux_top": [{"asn": 212238, "org": "Datacamp", "classe": "hebergeur", "adresses": 80},
                         {"asn": 3215, "org": "Orange", "classe": "acces", "adresses": 40}],
         "serie": [1, 2, 3], "bans": 5, "premier": 1794000000, "dernier": 1794990000, "actives_24h": 3,
         "bannies_24h": 1, "rotation": False, "etat": "observee", "campagne_actord": "sig-abc_1",
         "cves": ["CVE-2024-1234"]}
    p.update(kw)
    return p


def _ecrire(tmp_path, populations, **kw):
    d = {"genere_le": 1794999000, "complet": True, "fenetre_jours": 7, "populations": populations,
         "recouvrement": {"adresses_communes": 0, "adresses_total": 0}}
    d.update(kw)
    p = tmp_path / "populations.json"
    p.write_text(json.dumps(d))
    return p


def _ids(g, t=None):
    return {n["id"] for n in g["noeuds"] if t is None or n["type"] == t}


def _aretes(g, t):
    return [a for a in g["aretes"] if a["type"] == t]


def test_lire_absent_ou_illisible(tmp_path):
    assert paysage.lire(tmp_path / "absent.json", "gk2") is None
    p = tmp_path / "t.json"
    p.write_text('{"genere_le": 17950')
    assert paysage.lire(p, "gk2") is None
    p.write_text(json.dumps({"populations": []}))
    assert paysage.lire(p, "gk2") is None
    p.write_text("[1,2]")
    assert paysage.lire(p, "gk2") is None
    p.write_bytes(b"\xff\xfe")
    assert paysage.lire(p, "gk2") is None
    assert paysage.lire(tmp_path, "gk2") is None  # un répertoire


@pytest.mark.parametrize("v", [True, -1, "1794999000", None, float("nan"), float("inf"), [1], 10 ** 20])
def test_genere_le_invalide(tmp_path, v):
    p = tmp_path / "g.json"
    p.write_text(json.dumps({"genere_le": v, "populations": []}))
    assert paysage.lire(p, "gk2") is None


def test_fichier_trop_gros(tmp_path):
    p = tmp_path / "gros.json"
    p.write_text(json.dumps({"genere_le": 1, "populations": [], "x": "a" * (paysage.MAX_OCTETS + 10)}))
    assert paysage.lire(p, "gk2") is None


def test_graphe_types_et_aretes(tmp_path):
    p2 = _pop("profileur:ab4f0c11", famille="messagerie", nom_cible="mail.gk2.secubox.in",
              cibles=["mail.gk2.secubox.in", "gitea.gk2.secubox.in"], bans=2, rotation=True, cves=[],
              reseaux_top=[{"asn": 212238, "org": "Datacamp", "classe": "hebergeur", "adresses": 10}],
              adresses=10, reseaux=1, campagne_actord=None)
    s = paysage.lire(_ecrire(tmp_path, [_pop(), p2]), "gk2")
    g = s.graphe
    assert s.epoch == 1794999000 and s.partiel is False
    assert {"pop:famille:collecte", "pop:profileur:ab4f0c11", "asn:212238", "asn:3215",
            "cible:gitea.gk2.secubox.in", "cible:mail.gk2.secubox.in", "infra:gk2", "camp:sig-abc_1",
            "cve:CVE-2024-1234", "pays:US", "pays:DE"} <= _ids(g)
    assert all(ID.match(n["id"]) for n in g["noeuds"])
    assert len(_ids(g)) == len(g["noeuds"])
    types = {n["type"] for n in g["noeuds"]}
    assert types == {"population", "campagne", "reseau_source", "cible", "cve", "pays", "infra"}
    src = {(a["de"], a["vers"]): a["poids"] for a in _aretes(g, "SOURCE_DE")}
    assert src[("asn:212238", "pop:famille:collecte")] == 80
    assert src[("asn:212238", "pop:profileur:ab4f0c11")] == 10
    assert ("pop:famille:collecte", "cible:gitea.gk2.secubox.in") in {(a["de"], a["vers"]) for a in _aretes(g, "VISE")}
    assert ("camp:sig-abc_1", "pop:famille:collecte") in {(a["de"], a["vers"]) for a in _aretes(g, "MEMBRE_DE")}
    assert ("pop:famille:collecte", "cve:CVE-2024-1234") in {(a["de"], a["vers"]) for a in _aretes(g, "EXPLOITE")}
    assert ("pop:famille:collecte", "pays:US") in {(a["de"], a["vers"]) for a in _aretes(g, "ORIGINE")}
    assert ("cible:gitea.gk2.secubox.in", "infra:gk2") in {(a["de"], a["vers"]) for a in _aretes(g, "HEBERGE")}
    ids = _ids(g)
    assert all(a["de"] in ids and a["vers"] in ids for a in g["aretes"])
    assert s.compteurs == {"populations": 2, "rotation": 1, "reseaux": 3, "adresses": 130,
                           "cibles": 2, "bans": 7, "cves": 1}
    pop = next(n for n in g["noeuds"] if n["id"] == "pop:famille:collecte")
    assert pop["famille"] == "collecte" and pop["metriques"]["adresses"] == 120


def test_champs_manquants(tmp_path):
    p = _pop()
    for k in ("cves", "campagne_actord", "pays_top"):
        del p[k]
    s = paysage.lire(_ecrire(tmp_path, [p]), "gk2")
    for t in ("cve", "campagne", "pays"):
        assert _ids(s.graphe, t) == set()
    assert s.compteurs["cves"] == 0


def test_champs_de_mauvais_type(tmp_path):
    mauvais = [
        {"id": "famille:x", "cibles": None, "reseaux_top": "abc", "classes": [1], "pays_top": {"US": 1},
         "cves": "CVE-2024-1234", "serie": "x", "adresses": "12", "bans": None, "campagne_actord": 5},
        {"id": "a:b", "cibles": [None, 3, {"x": 1}, "ok.example.org"], "reseaux_top": [None, 4, {"asn": "x"},
         {"asn": True, "adresses": 1}, {"asn": -3}, {"asn": 12, "adresses": "9", "org": ["z"]}],
         "pays_top": [[1, 2], "US", ["us", 3], ["FR"]], "cves": [1, None, "cve-1", "CVE-2024-4321"],
         "rotation": "oui", "etat": 7},
        {"id": None}, {"id": ""}, {"famille": "x"}, None, "chaine", 12, [],
    ]
    s = paysage.lire(_ecrire(tmp_path, mauvais), "gk2")
    assert s is not None
    g = s.graphe
    assert all(ID.match(n["id"]) for n in g["noeuds"])
    assert {"pop:famille:x", "pop:a:b", "cible:ok.example.org", "cve:CVE-2024-4321", "asn:12"} <= _ids(g)
    assert s.compteurs["populations"] == 2
    for brut in (None, "x", [], 5):
        for cle in ("populations",):
            p = tmp_path / "m.json"
            p.write_text(json.dumps({"genere_le": 5, cle: brut, "complet": "oui"}))
            r = paysage.lire(p, "gk2")
            assert r is not None and r.graphe["noeuds"] == [] and r.partiel is True


def test_plafonds(tmp_path):
    grosse = _pop("famille:grosse", reseaux=300, adresses=3000, cibles=[f"c{i}.example.org" for i in range(100)],
                  reseaux_top=[{"asn": 1000 + i, "org": f"Org{i}", "classe": "hebergeur" if i % 2 else "acces",
                                "adresses": 300 - i} for i in range(300)],
                  cves=[f"CVE-2024-{1000 + i}" for i in range(50)])
    autres = [_pop(f"famille:p{i}", cibles=[f"t{i}.example.org"], reseaux_top=[]) for i in range(14)]
    s = paysage.lire(_ecrire(tmp_path, [grosse] + autres), "gk2")
    g = s.graphe
    assert len(_ids(g, "population")) == 12
    assert any(n["libelle"] == "+ 3 autres" for n in g["noeuds"])
    asn_grosse = {a["de"] for a in _aretes(g, "SOURCE_DE") if a["vers"] == "pop:famille:grosse"
                  and a["de"].startswith("asn:")}
    assert len(asn_grosse) == 8
    classes = {a["de"] for a in _aretes(g, "SOURCE_DE") if a["vers"] == "pop:famille:grosse"
               and a["de"].startswith("classe:")}
    assert classes == {"classe:famille:grosse:hebergeur", "classe:famille:grosse:acces"}
    folded = sum(a["poids"] for a in _aretes(g, "SOURCE_DE") if a["de"].startswith("classe:famille:grosse"))
    assert folded == sum(300 - i for i in range(8, 300))
    assert len(_ids(g, "cible")) <= 60 and len(_ids(g, "cve")) <= 20
    assert len(g["noeuds"]) <= 400
    assert s.compteurs["populations"] == 15


def test_plafond_noeuds_global(tmp_path):
    pops = [_pop(f"famille:p{i}", cibles=[f"t{i}-{j}.example.org" for j in range(3)],
                 reseaux_top=[{"asn": 10000 * i + j, "org": "o", "classe": "acces", "adresses": 1}
                              for j in range(8)], cves=[], pays_top=[]) for i in range(12)]
    g = paysage.lire(_ecrire(tmp_path, pops), "gk2").graphe
    assert len(g["noeuds"]) <= 400
    ids = _ids(g)
    assert all(a["de"] in ids and a["vers"] in ids for a in g["aretes"])
    assert all(ID.match(n["id"]) for n in g["noeuds"])


def test_aucune_adresse_ip(tmp_path):
    pops = [_pop("pop:192.0.2.7", nom_cible="198.51.100.9", cibles=["198.51.100.9", "ok.example.org", "[2001:db8::1]",
                                                                    "x2001:db8::1", "a.b.203.0.113.5"],
                 reseaux_top=[{"asn": 64500, "org": "Hébergeur 203.0.113.9 SA", "classe": "2001:db8::2", "adresses": 3},
                              {"asn": 64501, "org": "Propre", "classe": "acces", "adresses": 2}],
                 campagne_actord="sig", cves=["CVE-2024-1234"]),
            _pop("ok:2001:db8::5"), _pop("profileur:ab4f0c11", famille="10.0.0.1", cibles=["ok.example.org", "[2001:db8::1]", "x2001:db8::1",
                                                              "a.b.203.0.113.5"],
                reseaux_top=[{"asn": 64500, "org": "Hébergeur 203.0.113.9 SA", "classe": "2001:db8::2", "adresses": 3}])]
    g = paysage.lire(_ecrire(tmp_path, pops), "gk2").graphe
    assert "cible:ok.example.org" in _ids(g)
    assert "pop:profileur:ab4f0c11" in _ids(g) and not any("203" in i or "2001" in i for i in _ids(g))

    def chaines(o):
        if isinstance(o, str):
            yield o
        elif isinstance(o, dict):
            for k, v in o.items():
                yield from chaines(k)
                yield from chaines(v)
        elif isinstance(o, list):
            for v in o:
                yield from chaines(v)

    for c in chaines(g):
        for m in re.findall(r"[0-9A-Fa-f:.]{2,}", c):
            try:
                ipaddress.ip_address(m)
            except ValueError:
                continue
            raise AssertionError(f"adresse dans le graphe : {c!r}")
    assert not re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", json.dumps(g))
    ids = _ids(g)
    assert all(a["de"] in ids and a["vers"] in ids for a in g["aretes"])


def test_ids_assainis(tmp_path):
    s = paysage.lire(_ecrire(tmp_path, [_pop("famille:é/ x", cibles=["Ex ample.org", "UP.Example.org"])]), "gk2 bad/")
    assert all(ID.match(n["id"]) for n in s.graphe["noeuds"])
    assert "cible:up.example.org" in _ids(s.graphe)
    long = paysage.lire(_ecrire(tmp_path, [_pop("a" * 500)]), "gk2")
    assert all(ID.match(n["id"]) for n in long.graphe["noeuds"])


def test_partiel(tmp_path):
    assert paysage.lire(_ecrire(tmp_path, [_pop()], complet=False), "gk2").partiel is True
    assert paysage.lire(_ecrire(tmp_path, [_pop()], complet=True), "gk2").partiel is False


def test_config_populations(tmp_path, monkeypatch):
    monkeypatch.delenv("SECUBOX_DATASCOPE_POPULATIONS", raising=False)
    assert config.charger(tmp_path / "rien.toml").populations == Path("/var/lib/secubox/waf/populations.json")
    t = tmp_path / "d.toml"
    t.write_text('[sources]\npopulations = "/tmp/x/p.json"\n')
    assert config.charger(t).populations == Path("/tmp/x/p.json")
    monkeypatch.setenv("SECUBOX_DATASCOPE_POPULATIONS", "/tmp/y.json")
    assert config.charger(t).populations == Path("/tmp/y.json")
