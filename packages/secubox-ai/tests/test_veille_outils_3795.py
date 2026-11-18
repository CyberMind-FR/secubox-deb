# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Identification des outils sur empreintes sourcées (#3795) : ≥ 2 traits indépendants, sinon « inconnu »."""
import json
import logging
import re
import time
import tomllib
from datetime import timedelta
from pathlib import Path

import pytest

from veille import base, dossiers, outils
from test_veille_correlation_3721 import T0, _ajout, _waf

PAQUET = Path(__file__).resolve().parents[1]

CATALOGUE = """
[[outil]]
nom = "OutilEssai"
source = "relevé gk2 2026-11-14"
[[outil.trait]]
type = "agent"
motif = "outilessai/"
[[outil.trait]]
type = "chemins"
valeurs = ["/essai-a", "/essai-b"]
[[outil.trait]]
type = "empreinte_http"
valeurs = ["abcd1234abcd1234"]
[[outil.trait]]
type = "identifiants"
min = 2
valeurs = ["root:6", "admin:5"]
"""


@pytest.fixture
def db(tmp_path):
    d = base.ouvrir(tmp_path / "veille.db")
    yield d
    d.close()


@pytest.fixture
def cat(tmp_path):
    f = tmp_path / "essai.toml"
    f.write_text(CATALOGUE, encoding="utf-8")
    return outils.charger([f])


def _evt(db, ip, minutes, **kw):
    kw.setdefault("cat", "scanners:x")
    return _waf(db, ip, T0 - timedelta(minutes=minutes), **kw)


def _evts(db):
    return [outils_evt(x) for x in db.execute(f"SELECT {dossiers._COLS} FROM evenements ORDER BY horodatage")]


def outils_evt(x):
    return dossiers._evt(x)


def test_deux_traits_independants_attribuent(db, cat):
    _evt(db, "100.64.20.1", 10, user_agent="OutilEssai/2.1", path="/essai-a", http_fingerprint="abcd1234abcd1234")
    [a] = outils.identifier(_evts(db), cat)
    assert a.outil == "OutilEssai" and a.confiance == "moyenne"               # une couche, deux groupes
    assert {t["type"] for t in a.traits_concordants} == {"agent", "chemins", "empreinte_http"}
    _ajout(db, "menaces", T0 - timedelta(minutes=5), category="auth_ssh:x", client_ip="100.64.20.1", tool="authwatch",
           essais=[{"compte": "root", "mot_de_passe_longueur": 6}, {"compte": "admin", "mot_de_passe_longueur": 5}])
    [a] = outils.identifier(_evts(db), cat)
    assert a.confiance == "forte"                                             # waf + leurre


def test_un_seul_trait_inconnu(db, cat):
    _evt(db, "100.64.21.1", 10, user_agent="OutilEssai/2.1")
    [a] = outils.identifier(_evts(db), cat)
    assert a.outil == "inconnu" and a.confiance is None and not a.traits_concordants
    assert a.traits_observes == [{"type": "agent", "couche": "waf", "observe": "OutilEssai/2.1"}]
    assert "OutilEssai" not in json.dumps([t for t in a.traits_observes if t.get("type") != "agent"])
    assert outils.identifier([], cat) == []


def test_agent_et_chemins_meme_outil_un_trait(db, cat):
    _evt(db, "100.64.22.1", 10, user_agent="OutilEssai/2.1", path="/essai-a", tool="outilessai")
    _evt(db, "100.64.22.1", 9, path="/essai-b")
    [a] = outils.identifier(_evts(db), cat)
    assert a.outil == "inconnu"
    assert {t["type"] for t in a.traits_observes} == {"agent", "chemins"}


def test_entree_sans_source_refusee(tmp_path, caplog):
    with pytest.raises(ValueError, match="sans source"):
        outils.entree({"nom": "X", "trait": [{"type": "agent", "motif": "x/"}]})
    with pytest.raises(ValueError):
        outils.entree({"nom": "X", "source": "  ", "trait": [{"type": "agent", "motif": "x/"}]})
    with pytest.raises(ValueError):
        outils.entree({"nom": "inconnu", "source": "s", "trait": [{"type": "agent", "motif": "x/"}]})
    f = tmp_path / "e.toml"
    f.write_text('[[outil]]\nnom = "SansSource"\n[[outil.trait]]\ntype = "agent"\nmotif = "s/"\n'
                 '[[outil]]\nnom = "Bon"\nsource = "relevé gk2 2026-11-14"\n[[outil.trait]]\ntype = "agent"\n'
                 'motif = "b/"\n', encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="secubox-ai-veille"):
        assert [o.nom for o in outils.charger([f, tmp_path / "absent.toml"])] == ["Bon"]
    assert "SansSource" in caplog.text


def test_echappement_motifs():
    o = outils.entree({"nom": "R", "source": "s", "trait": [{"type": "agent", "motif": "(a+)+$"}]})
    t = o.traits[0]
    assert t.motif.pattern == re.escape("(a+)+$")                             # littéral, jamais une regex
    debut = time.monotonic()
    assert outils.identifier([dossiers.Evt("e", "menaces", "t", "x", None, "info", None, None, None, None,
                                           {"user_agent": "a" * 100000 + "!"})], [o]) == []
    assert time.monotonic() - debut < 0.5
    [a] = outils.identifier([dossiers.Evt("e", "menaces", "t", "x", None, "info", None, None, None, None,
                                          {"user_agent": "x(a+)+$y"})], [o])
    assert a.traits_observes[0]["observe"] == "x(a+)+$y"
    with pytest.raises(ValueError):
        outils.entree({"nom": "R", "source": "s", "trait": [{"type": "agent", "motif": "x" * 200}]})


def test_catalogue_livre_source_et_lint():
    """Chaque entrée livrée a une source, se charge sans refus ; motifs littéraux et bornés ; aucun outil nommable sur
    un seul groupe de traits."""
    fichiers = sorted((PAQUET / "empreintes").glob("*.toml"))
    assert fichiers
    total = 0
    for f in fichiers:
        assert "SPDX-License-Identifier" in f.read_text(encoding="utf-8")
        for brut in tomllib.loads(f.read_text(encoding="utf-8")).get("outil", []):
            src = brut["source"].strip()
            # Jamais une racine de dépôt : un fichier et sa ligne, ou un relevé gk2 daté.
            assert re.search(r"/blob/[^ ]+#L\d+", src) or re.match(r"relevé gk2 \d{4}-\d{2}-\d{2}", src), src
            o = outils.entree(brut)
            total += 1
            for t in o.traits:
                assert t.source
                if t.motif is not None:
                    assert len(t.motif.pattern) <= 2 * outils.MOTIF_MAX
    assert len(outils.charger(fichiers)) == total
    noms = {o.nom for o in outils.charger(fichiers)}
    assert {"sqlmap", "gobuster", "ffuf", "WPScan", "Censys", "Cortex Xpanse", "zgrab", "Masscan"} == noms


def test_censys_reel_reste_inconnu(db):
    """Ligne réelle de gk2 (CensysInspect) : un seul trait sourcé → « inconnu », jamais « Censys »."""
    ligne = next(json.loads(x) for x in (PAQUET / "tests/donnees/menaces.jsonl").read_text().splitlines()
                 if "CensysInspect" in x and "http_fingerprint" in x)
    ligne["client_ip"] = "100.64.23.1"
    _ajout(db, "menaces", T0 - timedelta(minutes=3), **{k: v for k, v in ligne.items() if k != "timestamp"})
    [a] = outils.identifier(_evts(db), outils.charger([PAQUET / "empreintes"]))
    assert a.outil == "inconnu" and a.traits_observes[0]["type"] == "agent"


def test_dossier_outils_et_campagne_meme_outil(db, cat, monkeypatch):
    monkeypatch.setattr(outils, "_CATALOGUE", cat)
    for ip in ("100.64.30.1", "100.64.31.1"):
        _evt(db, ip, 10, user_agent="OutilEssai/2.1", path="/essai-a", http_fingerprint="abcd1234abcd1234",
             host=f"{ip}.example.net")
    _evt(db, "100.64.32.1", 10, user_agent="OutilEssai/2.1", host="seul.example.net")    # inconnu : hors campagne
    ds = {d.cle: d for d in dossiers.construire(db, T0)}
    assert [a["outil"] for a in ds["100.64.30.1"].outils] == ["OutilEssai"]
    assert ds["100.64.32.1"].outils[0]["outil"] == "inconnu"
    stocke = json.loads(db.execute("SELECT outils_json FROM dossiers WHERE cle = '100.64.31.1'").fetchone()[0])
    assert stocke[0]["outil"] == "OutilEssai"
    [c] = [d for d in ds.values() if d.cle.startswith("outil-nom:OutilEssai:")]
    assert c.membres == {"100.64.30.1": "meme_outil_multi_adresses", "100.64.31.1": "meme_outil_multi_adresses"}
    assert len(c.evenements) == 2
    assert not [d for d in ds.values() if d.cle.startswith("outil:inconnu")]


FAIBLES = """
[[outil]]
nom = "Robot"
source = "relevé gk2 2026-11-15"
[[outil.trait]]
type = "identifiants"
faible = true
requis = ["support:7", "root:7", "root:8"]
valeurs = ["support:7", "root:7", "root:8"]
[[outil.trait]]
type = "banniere"
faible = true
groupe = "autre"
motif = "SSH-2.0-robot"
[[outil.trait]]
type = "agent"
motif = "robot/"
"""


def _essais(*paires, banniere=None, agent=None):
    a = {"essais": [{"compte": c, "mot_de_passe_longueur": n} for c, n in paires]}
    if banniere:
        a["banniere"] = banniere
    if agent:
        a["user_agent"] = agent
    return dossiers.Evt("e", "menaces", "t", "x", None, "info", None, None, None, None, a)


def test_trait_faible_combinaison_et_couche(tmp_path, caplog):
    f = tmp_path / "f.toml"
    f.write_text(FAIBLES, encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="secubox-ai-veille"):
        cat = outils.charger([f])
    assert "groupe 'autre' ignoré" in caplog.text                      # pas d'indépendance fabriquée
    # combinaison incomplète : le trait ne concorde pas
    assert outils.identifier([_essais(("root", 7), ("root", 8))], cat) == []
    # deux traits faibles de la couche leurre : un seul trait
    [a] = outils.identifier([_essais(("support", 7), ("root", 7), ("root", 8), banniere="SSH-2.0-robot")], cat)
    assert a.outil == "inconnu" and len(a.traits_observes) == 2
    # faible (leurre) + agent (waf) : deux couches, nommé
    [a] = outils.identifier([_essais(("support", 7), ("root", 7), ("root", 8), agent="robot/1")], cat)
    assert a.outil == "Robot" and a.confiance == "forte"
