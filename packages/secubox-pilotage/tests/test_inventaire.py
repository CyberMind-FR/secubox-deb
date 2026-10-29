# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

import asyncio

import pytest

from pilotage.files import Files
from pilotage.inventaire import Inventaire
from pilotage.stockage import StockageSqlite
from outils import GK2, GK5, Horloge, releve_gk5


@pytest.fixture
def monde(tmp_path):
    h = Horloge()
    s = StockageSqlite(tmp_path / "p", horloge=h)
    f = Files()
    return h, s, f, Inventaire(f, s, horloge=h)


async def servir(f, box, corps, type_="GET_RESP"):
    (rq,) = await f.attendre_requetes(box.cle, 1)
    assert f.livrer_reponse(box.cle, {"msg_id": rq["msg_id"], "type": type_, "body": corps})
    return rq


@pytest.mark.asyncio
async def test_tour_depose_un_get_device_et_range_la_reponse(monde):
    h, s, f, inv = monde
    s.vu(GK5, {})
    assert await inv.tour() == 1
    rq = await servir(f, GK5, releve_gk5())
    assert rq["type"] == "GET" and rq["body"] == {"paths": ["Device."]}
    await inv.attendre_fin()
    assert s.resumes()[0]["swap_utilise_pct"] == 66


@pytest.mark.asyncio
async def test_un_seul_get_en_vol_par_box(monde):
    h, s, f, inv = monde
    s.vu(GK5, {})
    assert await inv.tour() == 1
    h.avance(60)
    s.vu(GK5, {})
    assert await inv.tour() == 0 and f.en_attente(GK5.cle) == 1
    await servir(f, GK5, releve_gk5())
    await inv.attendre_fin()
    assert await inv.tour() == 1  # le précédent est fini


@pytest.mark.asyncio
async def test_box_hors_ligne_non_sondee(monde):
    h, s, f, inv = monde
    s.vu(GK5, {})
    s.vu(GK2, {})
    h.avance(91)
    s.vu(GK2, {})
    assert await inv.tour() == 1
    assert f.en_attente(GK5.cle) == 0 and f.en_attente(GK2.cle) == 1
    await inv.arreter()


@pytest.mark.asyncio
async def test_reponse_en_erreur_ou_expiree_ne_casse_rien(monde):
    h, s, f, inv = monde
    s.vu(GK5, {})
    await inv.tour()
    await servir(f, GK5, {"err": "x"}, "ERROR")
    await inv.attendre_fin()
    assert s.inventaire(GK5.cle)["valeurs"] == {}
    f.expiration_s = 0.01
    await inv.tour()
    await asyncio.sleep(0.05)
    await inv.attendre_fin()
    assert await inv.tour() == 1  # l'expiration libère la box


@pytest.mark.asyncio
async def test_purge_au_plus_une_fois_par_heure(monde):
    h, s, f, inv = monde
    t0 = h.t
    await inv.tour()                     # première purge
    h.t = t0 - 31 * 86400
    s.vu(GK5, {})
    s.notification(GK5, {"type": "X_SECUBOX_Boot", "ts": 1})   # reçu il y a 31 jours
    h.t = t0 + 1800
    await inv.tour()
    assert len(s.evenements()) == 1      # moins d'une heure : pas de purge
    h.t = t0 + 3600
    await inv.tour()
    assert s.evenements() == []
    await inv.arreter()


@pytest.mark.asyncio
async def test_boucle_unique_et_arret_propre(monde):
    h, s, f, inv = monde
    appels = []
    gate = asyncio.Event()

    async def attente(d):
        appels.append(d)
        await gate.wait()

    inv._attente = attente
    s.vu(GK5, {})
    inv.demarrer()
    inv.demarrer()
    for _ in range(200):
        if appels:
            break
        await asyncio.sleep(0.01)
    assert appels == [60.0] and f.en_attente(GK5.cle) == 1  # un seul tour, un seul GET
    await inv.arreter()
    assert inv._boucle is None and not inv._taches and f.en_attente(GK5.cle) == 0


@pytest.mark.asyncio
async def test_tour_oublie_les_box_sans_contact_et_l_audite_m12(tmp_path):
    h = Horloge()
    s = StockageSqlite(tmp_path / "p", horloge=h)
    f = Files()
    lignes = []
    inv = Inventaire(f, s, horloge=h, audit=lambda ev, ch: lignes.append((ev, ch)))
    s.vu(GK2, {})
    vu_gk2 = int(h.t)
    h.avance(31 * 86400)
    s.vu(GK5, {})
    await inv.tour()
    assert [b["cle"] for b in s.boites()] == [GK5.cle]
    assert lignes == [("pilotage_box_oubliee", {"box": "gk2", "cle": GK2.cle, "reseau": "maillage", "dernier_contact": vu_gk2,
                                                "jours": 30})]


@pytest.mark.asyncio
async def test_oubli_suspendu_audite_une_fois_par_heure_r_l2_45(tmp_path):
    """Saut d'horloge de 40 jours, 5 box : aucune oubliée, anomalie auditée ; réévaluée ensuite, une ligne par heure au plus."""
    from pilotage.identite import Box
    h = Horloge()
    s = StockageSqlite(tmp_path / "p", horloge=h)
    lignes = []
    inv = Inventaire(Files(), s, horloge=h, audit=lambda ev, ch: lignes.append((ev, ch)))
    for i in range(5):
        s.vu(Box(f"gk{i}", f"10.10.0.{10 + i}", "maillage", None, None), {})
    h.avance(40 * 86400)
    await inv.tour()
    assert len(s.boites()) == 5
    assert lignes == [("pilotage_oubli_suspendu", {"candidates": 5, "total": 5})]
    for _ in range(3):                                # réévalué à chaque passage, sans nouvelle ligne dans l'heure
        await inv._oublier()
    assert len(lignes) == 1
    h.avance(3600)
    await inv.tour()
    assert [ev for ev, _ in lignes] == ["pilotage_oubli_suspendu"] * 2 and len(s.boites()) == 5


@pytest.mark.asyncio
async def test_tour_audite_une_fois_les_operations_sans_nouvelles_depuis_6_h(tmp_path):
    """I4 (R-L2-47) : à la passe horaire, une opération encore en cours 6 h après sa demande passe à « inconnu », auditée une
    seule fois (pilotage_action_echue) ; une orpheline (job inventé par la box) passe à « inconnu » sans audit."""
    h = Horloge()
    s = StockageSqlite(tmp_path / "p", horloge=h)
    lignes = []
    inv = Inventaire(Files(), s, horloge=h, audit=lambda ev, ch: lignes.append((ev, ch)))
    s.vu(GK5, {})
    op = s.operation_demander(GK5.cle, "maj-paquets", {}, "alice", None)
    s.operation_reponse(op, "accepte", "j1", "")
    s.operation_progression(GK5.cle, "j9", "en_cours", 50)
    demande_le = int(h.t)
    await inv.tour()
    assert lignes == []
    h.avance(6 * 3600)
    s.vu(GK5, {})
    await inv.tour()
    assert lignes == [("pilotage_action_echue", {"box": "gk5", "cle": GK5.cle, "action": "maj-paquets", "job": "j1", "operation": op,
                                                 "demande_le": demande_le, "resultat": "inconnu", "heures": 6})]
    h.avance(3600)
    s.vu(GK5, {})
    await inv.tour()
    assert len(lignes) == 1
