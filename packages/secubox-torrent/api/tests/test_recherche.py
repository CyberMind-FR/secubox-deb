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
    # `asyncio.run` ET NON `get_event_loop()`. La seconde rend une boucle
    # partagee et depreciee : le premier test qui la ferme fait echouer tous
    # les suivants avec « There is no current event loop » — une panne qui
    # semble venir du test qu'on vient d'ecrire, jamais de celui qui l'a
    # provoquee.
    return asyncio.run(coro)


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


def test_les_resultats_sans_magnet_sont_ecartes(monkeypatch):
    async def source(c, q):
        return [R.Resultat("bon", HASH, 1, 5, 0, "TPB"),
                R.Resultat("sans hash", "zz", 1, 99, 0, "TPB")]
    monkeypatch.setattr(R, "SOURCES", {"x": {"libelle": "X", "fn": source}})
    d = lance(R.cherche("q"))
    # Celui a 99 seeders serait en tete du tri : c'est bien le magnet, et non
    # le classement, qui decide.
    assert [r["titre"] for r in d["resultats"]] == ["bon"]


def test_tri_par_seeders(monkeypatch):
    async def source(c, q):
        return [R.Resultat("peu", HASH, 1, 3, 0, "TPB"),
                R.Resultat("beaucoup", "b" * 40, 1, 300, 0, "TPB")]
    monkeypatch.setattr(R, "SOURCES", {"x": {"libelle": "X", "fn": source}})
    d = lance(R.cherche("q"))
    assert [r["titre"] for r in d["resultats"]] == ["beaucoup", "peu"]


def test_requete_vide_ne_sort_pas_sur_le_reseau(monkeypatch):
    appele = False
    async def source(c, q):
        nonlocal appele
        appele = True
        return []
    monkeypatch.setattr(R, "SOURCES", {"x": {"libelle": "X", "fn": source}})
    d = lance(R.cherche("   "))
    assert d["resultats"] == [] and not appele


def test_le_meme_torrent_vu_par_trois_index_ne_fait_qu_une_ligne():
    """Knaben agrege des index qu'on interroge aussi en direct : sans
    deduplication, la moitie de la liste serait des doublons."""
    from recherche import Resultat, dedoublonne
    h = "a" * 40
    r = dedoublonne([
        Resultat("Un film", h, 100, 5, 1, "TPB"),
        Resultat("Un.Film.2026", h, 0, 42, 3, "Knaben"),
        Resultat("un film", h, 100, 7, 0, "Nyaa"),
    ])
    assert len(r) == 1
    # On garde le mieux pourvu en seeders...
    assert r[0].seeders == 42
    # ...la taille que l'un des trois seul connaissait...
    assert r[0].taille == 100
    # ...et on dit que trois index le connaissent.
    assert r[0].source == "TPB, Knaben, Nyaa"


def test_la_deduplication_se_fait_sur_l_empreinte_pas_le_titre():
    """Deux index nomment rarement un fichier pareil ; deduire du titre
    fusionnerait des torrents differents."""
    from recherche import Resultat, dedoublonne
    r = dedoublonne([Resultat("Meme titre", "a" * 40, 1, 1, 0, "TPB"),
                     Resultat("Meme titre", "b" * 40, 1, 1, 0, "TPB")])
    assert len(r) == 2


def test_tout_decocher_n_est_pas_tout_selectionner():
    """Rendre l'integralite des index quand l'utilisateur les a tous decoches
    reviendrait a ignorer son geste."""
    from recherche import cherche
    d = lance(cherche("debian", []))
    assert d["resultats"] == []
    assert "aucune source" in d["detail"]


def test_une_source_inconnue_ne_fait_pas_tomber_la_recherche():
    from recherche import SOURCES
    assert "inexistant" not in SOURCES


def test_un_index_qui_ignore_la_requete_est_ecarte():
    """Knaben rendait, pour TOUTE requete, le dernier contenu indexe — de la
    pornographie en tete pour une recherche « debian ». Elle repondait 200,
    vite, avec des resultats bien formes : seul le contenu la trahissait."""
    from recherche import pertinent
    assert not pertinent("(C108) Fate Grand Order doujin", "debian")
    assert not pertinent("IPZZ-915 1080p", "debian")


def test_la_garde_reste_lache():
    """Exiger TOUS les termes ecarterait des resultats legitimes."""
    from recherche import pertinent
    assert pertinent("ubuntu-24.04.1-desktop-amd64.iso", "ubuntu 24")
    assert pertinent("Debian.12.Bookworm.DVD", "debian bookworm arm64")
    assert pertinent("[Debian] Sakura Trick [BD 1080p]", "debian")


def test_une_requete_sans_terme_exploitable_n_ecarte_rien():
    """On ne juge pas sur une base qu'on n'a pas."""
    from recherche import pertinent
    assert pertinent("n importe quoi", "ab")
    assert pertinent("n importe quoi", "!!")
