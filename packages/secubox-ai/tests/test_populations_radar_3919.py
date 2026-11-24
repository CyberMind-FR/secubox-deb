# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Populations d'attaquants dans le Radar (#3919, tâche 7) : relevé `/waf/populations` de gk2 porté par le relevé
des menaces (jamais lu par le modèle), cartes de la liste « Campagnes et populations » rendues sans innerHTML.
Aucun réseau réel : gk2 est simulé ; le rendu est essayé sous node avec un DOM factice."""
import json
import re
import shutil
import subprocess
from pathlib import Path

import httpx
import pytest

from api import menaces
from test_menaces_3583 import appeler, env, gk2  # noqa: F401 — fixtures partagées

PAGE = Path(__file__).resolve().parents[1] / "www" / "ai" / "index.html"
TEST_MJS = Path(__file__).with_name("populations_radar_3919.test.mjs")
HOSTILE = "<img src=x onerror=alert(1)>.exemple.test"


def _pop(ident, famille, derniers, **kw):
    p = {"id": ident, "famille": famille, "nom_cible": "gitea.gk2.secubox.in", "cibles": ["gitea.gk2.secubox.in"],
         "adresses": 120, "reseaux": 9, "une": 90, "le3": 98, "classes": {"proxy_loue": 80, "inconnu": 20},
         "pays_top": [["US", 50], ["GB", 10]], "reseaux_top": [{"asn": 64500, "org": "Exemple", "classe": "proxy_loue",
                                                                "adresses": 60}],
         "serie": [0, 0, 0, 0, 0, 0, derniers], "bans": 3, "premier": 1, "dernier": 2, "rotation": True,
         "etat": "bannie", "campagne_actord": None, "cves": []}
    p.update(kw)
    return p


def _releve_populations(complet=True):
    return {"disponible": True, "genere_le": 1_790_000_000, "complet": complet, "fenetre_jours": 7, "age_s": 42,
            "duree_s": 3.1, "populations": [_pop("famille:collecte", "collecte", 50),
                                             _pop("famille:messagerie", "messagerie", 7, rotation=False)],
            "recouvrement": {"adresses_communes": 2, "adresses_total": 240}}


# ── relevé (menaces.py) ──

def test_chemins_populations_en_dernier():
    assert menaces.CHEMINS[-1] == "/waf/populations"
    assert menaces.ESSENTIELS == ("/waf/stats", "/waf/bans", "/waf/campaigns", "/waf/alerts")


@pytest.mark.asyncio
async def test_releve_avec_populations(gk2):  # noqa: F811
    gk2["donnees"]["/waf/populations"] = _releve_populations()
    r = await menaces.releve_menaces(force=True)
    assert [p["id"] for p in r["populations"]] == ["famille:collecte", "famille:messagerie"]
    assert r["populations_meta"]["complet"] is True
    assert r["populations_meta"]["genere_le"] == 1_790_000_000 and r["populations_meta"]["age_s"] == 42
    assert r["populations_meta"]["recouvrement"] == {"adresses_communes": 2, "adresses_total": 240}
    assert "/waf/populations" not in r["erreurs"] and r["erreurs_secondaires"] == []
    rel = (await appeler("GET", "/menaces/releve")).json()
    assert len(rel["populations"]) == 2                                    # servi à la page


@pytest.mark.asyncio
async def test_populations_jamais_lues_par_le_modele(gk2):  # noqa: F811
    # cibles tirées d'en-têtes Host d'attaquants : jamais dans la consigne du modèle
    gk2["donnees"]["/waf/populations"] = _releve_populations()
    r = await menaces.releve_menaces(force=True)
    vu = json.loads(menaces.compact_releve(r))
    assert "populations" not in vu and "populations_meta" not in vu


@pytest.mark.asyncio
async def test_releve_sans_populations(env, monkeypatch):  # noqa: F811
    from test_menaces_3583 import donnees_gk2
    d = donnees_gk2()

    def handler(req):
        chemin = req.url.path.removeprefix("/api/v1")
        if chemin == "/waf/populations":
            return httpx.Response(503, json={"detail": "indisponible"})
        return httpx.Response(200, json=d[chemin])

    monkeypatch.setattr(menaces, "FABRIQUE_TRANSPORT_GK2", lambda: httpx.MockTransport(handler))
    r = await menaces.releve_menaces(force=True)
    assert r["populations"] is None and r["populations_meta"] is None
    assert menaces.motif_inutilisable(r) is None                            # les 4 essentiels sont là : résumé possible
    assert r["chiffres"]["bans_actifs"] == 948
    # source secondaire : hors des bandeaux globaux (`erreurs`), seule la carte dit « relevé indisponible »
    assert r["erreurs"] == [] and r["erreurs_secondaires"] == ["/waf/populations"]
    rel = (await appeler("GET", "/menaces/releve")).json()
    assert rel["erreurs"] == [] and rel["erreurs_secondaires"] == ["/waf/populations"] and rel["populations"] is None


@pytest.mark.asyncio
async def test_populations_en_panne_journalisee_une_fois(gk2, caplog):  # noqa: F811
    gk2["pannes"].add("/waf/populations")
    with caplog.at_level("WARNING", logger="secubox.ai.menaces"):
        await menaces.releve_menaces(force=True)
        await menaces.releve_menaces(force=True)
    traces = [x for x in caplog.records if "/waf/populations" in x.getMessage()]
    assert len(traces) == 1                                                 # une trace au changement d'état
    r = await menaces.releve_menaces(force=True)
    assert r["erreurs"] == [] and r["erreurs_secondaires"] == ["/waf/populations"] and r["populations"] is None


@pytest.mark.asyncio
async def test_releve_pas_encore_calcule(gk2):  # noqa: F811
    gk2["donnees"]["/waf/populations"] = {"disponible": False}
    r = await menaces.releve_menaces(force=True)
    assert r["populations"] is None and r["populations_meta"] is None
    assert "/waf/populations" not in r["erreurs"]                           # gk2 a répondu : pas une panne


@pytest.mark.asyncio
async def test_releve_partiel(gk2):  # noqa: F811
    gk2["donnees"]["/waf/populations"] = _releve_populations(complet=False)
    r = await menaces.releve_menaces(force=True)
    assert r["populations_meta"]["complet"] is False
    assert len(r["populations"]) == 2


# ── page ──

def _script():
    blocs = re.findall(r"<script>(.*?)</script>", PAGE.read_text(encoding="utf-8"), re.S)
    assert len(blocs) == 1
    return blocs[0]


def test_page_charge_les_reperes_et_la_carte():
    h = PAGE.read_text(encoding="utf-8")
    assert '<script src="/ai/reperes.js"></script>' in h
    assert h.index('<script src="/ai/reperes.js"></script>') < h.index("<script>\n")
    assert "Campagnes et populations" in h and 'id="rCampagnes"' in h


def test_rendu_jamais_par_innerhtml():
    s = _script()
    debut, fin = s.index("// ---- Populations (#3919"), s.index("// ---- Fin des populations")
    bloc = s[debut:fin]
    for interdit in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "DOMParser"):
        assert interdit not in bloc, interdit
    assert "SbxReperes" in bloc


def test_demo_trois_populations_fictives():
    h = PAGE.read_text(encoding="utf-8")
    demo = h[h.index("// ---- Démonstration"):h.index("// ---- Code ----")]
    corps = demo[demo.index("function demoPopulations("):]
    corps = corps[:corps.index("\n  }\n")]
    assert len(re.findall(r"\{ id: '", corps)) == 3
    for hote in re.findall(r"'([a-z0-9.-]+\.[a-z]{2,})'", corps):
        assert hote.endswith((".exemple.secubox.in", ".exemple.test")), hote
    assert not re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", corps)               # aucune adresse dans une population


def test_rendu_node_cible_hostile_inerte():
    if not shutil.which("node"):
        pytest.skip("node absent")
    r = subprocess.run(["node", "--test", str(TEST_MJS)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.asyncio
async def test_controle_ignore_les_chiffres_des_populations(gk2):  # noqa: F811
    # 98765 n'existe que dans les populations : le modèle ne les lit pas, le contrôle ne doit pas l'accepter
    gk2["donnees"]["/waf/populations"] = {**_releve_populations(), "populations": [_pop("p", "collecte", 98765)]}
    r = await menaces.releve_menaces(force=True)
    assert "98765" in menaces.controler_resume("Il y a 98765 attaques.", r)
