# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Recherche d'index et fabrication des magnets (#1032)."""
import asyncio

import httpx
import pytest

import recherche as R

HASH = "a" * 40


# ── La fabrication du magnet ─────────────────────────────────────────────

def test_magnet_bien_forme():
    m = R.fabrique_magnet(HASH, "Un Film 1080p")
    assert m.startswith(f"magnet:?xt=urn:btih:{HASH}")
    assert "dn=Un%20Film%201080p" in m
    assert m.count("tr=") == len(R.TRAQUEURS)


def test_les_traqueurs_sont_joints():
    """Sans eux, un client sans DHT ne trouve aucun pair : le lien paraîtrait
    cassé alors qu'il est seulement orphelin.

    L'encodage est celui de `quote`, qui laisse `/` littéral — légal dans une
    valeur de requête, et accepté par tous les clients. Ma première version de
    ce test exigeait `%2F` : elle décrivait une convention, pas la réalité.
    """
    import urllib.parse
    m = R.fabrique_magnet(HASH, "x")
    for t in R.TRAQUEURS:
        assert "tr=" + urllib.parse.quote(t) in m


@pytest.mark.parametrize("mauvais", ["", None, "zz", "a" * 39, "a" * 41, "g" * 40])
def test_un_hash_invalide_ne_produit_pas_de_magnet(mauvais):
    """Un lien qui ne mène à rien est PIRE qu'un lien absent : on l'essaie."""
    assert R.fabrique_magnet(mauvais, "titre") == ""


def test_le_titre_est_borne():
    m = R.fabrique_magnet(HASH, "x" * 500)
    assert len(m) < 1200


# ── Les sources ──────────────────────────────────────────────────────────

def transport(charge, status=200):
    return httpx.MockTransport(lambda req: httpx.Response(status, json=charge))


def lance(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def test_apibay_normalise():
    charge = [{"id": "12", "name": "Un.Film.1080p", "info_hash": HASH.upper(),
               "seeders": "42", "leechers": "7", "size": "1073741824"}]
    async def go():
        async with httpx.AsyncClient(transport=transport(charge)) as c:
            return await R.cherche_apibay(c, "film")
    r = lance(go())
    assert len(r) == 1
    assert r[0].hash == HASH and r[0].seeders == 42 and r[0].taille == 1073741824
    assert r[0].magnet.startswith("magnet:?xt=urn:btih:" + HASH)


def test_apibay_ecarte_sa_ligne_sentinelle():
    """APIBAY rend un faux resultat « No results returned » quand il n'a rien.
    Le rendre tel quel afficherait un torrent inexistant en tete de liste."""
    charge = [{"id": "0", "name": "No results returned",
               "info_hash": "0" * 40, "seeders": "0", "leechers": "0", "size": "0"}]
    async def go():
        async with httpx.AsyncClient(transport=transport(charge)) as c:
            return await R.cherche_apibay(c, "rien")
    assert lance(go()) == []


def test_yts_rend_un_resultat_par_qualite():
    charge = {"data": {"movies": [{"title": "Film", "title_long": "Film (2020)",
              "torrents": [
                  {"hash": HASH, "quality": "1080p", "type": "bluray",
                   "seeds": 10, "peers": 2, "size_bytes": 2000},
                  {"hash": "b" * 40, "quality": "720p", "type": "web",
                   "seeds": 5, "peers": 1, "size_bytes": 1000}]}]}}
    async def go():
        async with httpx.AsyncClient(transport=transport(charge)) as c:
            return await R.cherche_yts(c, "film")
    r = lance(go())
    assert len(r) == 2
    assert "1080p" in r[0].titre and r[0].source == "YTS"


# ── L'agregation ─────────────────────────────────────────────────────────

def test_une_source_en_panne_n_emporte_pas_les_autres(monkeypatch):
    """Un index en panne est le cas ORDINAIRE. Rendre une erreur globale
    priverait l'utilisateur de ce que les autres ont bien rendu."""
    async def bonne(c, q):
        return [R.Resultat("ok", HASH, 1, 9, 0, "TPB")]
    async def mauvaise(c, q):
        raise httpx.ConnectError("index injoignable")
    monkeypatch.setitem(R.SOURCES, "tpb", bonne)
    monkeypatch.setitem(R.SOURCES, "yts", mauvaise)

    d = lance(R.cherche("film"))
    assert len(d["resultats"]) == 1
    assert d["sources_ok"] == ["tpb"]
    # L'echec est NOMME : une liste courte sans explication laisserait croire
    # que la recherche n'a rien trouve.
    assert "yts" in d["sources_ko"]


def test_les_resultats_sans_magnet_sont_ecartes(monkeypatch):
    async def source(c, q):
        return [R.Resultat("bon", HASH, 1, 5, 0, "TPB"),
                R.Resultat("sans hash", "zz", 1, 99, 0, "TPB")]
    monkeypatch.setattr(R, "SOURCES", {"x": source})
    d = lance(R.cherche("q"))
    # Celui a 99 seeders serait en tete du tri : c'est bien le magnet, et non
    # le classement, qui decide.
    assert [r["titre"] for r in d["resultats"]] == ["bon"]


def test_tri_par_seeders(monkeypatch):
    async def source(c, q):
        return [R.Resultat("peu", HASH, 1, 3, 0, "TPB"),
                R.Resultat("beaucoup", "b" * 40, 1, 300, 0, "TPB")]
    monkeypatch.setattr(R, "SOURCES", {"x": source})
    d = lance(R.cherche("q"))
    assert [r["titre"] for r in d["resultats"]] == ["beaucoup", "peu"]


def test_requete_vide_ne_sort_pas_sur_le_reseau(monkeypatch):
    appele = False
    async def source(c, q):
        nonlocal appele
        appele = True
        return []
    monkeypatch.setattr(R, "SOURCES", {"x": source})
    d = lance(R.cherche("   "))
    assert d["resultats"] == [] and not appele
