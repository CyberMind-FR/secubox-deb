# packages/secubox-metablogizer/api/tests/test_publish_flux.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""L'assistant rend compte PENDANT qu'il travaille (#1323).

Ces tests n'utilisent pas `TestClient` : ils appellent la séquence directement.
C'est volontaire — la séquence EST le correctif, et l'éprouver sans passer par
la pile HTTP la tient à l'abri de la version de `starlette` installée.
"""
import asyncio
import io
import zipfile
from pathlib import Path

import pytest

import routers.publish as rp


def _zip_bytes():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("index.html", "<h1>zem</h1>")
    return buf.getvalue()


@pytest.fixture
def prepare(tmp_path, monkeypatch):
    monkeypatch.setattr(rp, "SITES_ROOT", tmp_path / "sites")
    (tmp_path / "sites" / "zem" / "public").mkdir(parents=True)
    monkeypatch.setattr(rp, "apply_route",
                        lambda domain, port=8900: {"route_ok": True})
    monkeypatch.setattr(rp, "provision_cert",
                        lambda domain: {"mode": "wildcard", "detail": ""})
    monkeypatch.setattr(rp, "git_commit_push",
                        lambda d, m: {"pushed": True, "commit": "abc"})
    monkeypatch.setattr(rp, "regenerer_nginx", lambda: (True, 3, "Published 3"))
    return tmp_path


async def _recolte(name="zem", domain="zem.gk2.secubox.in"):
    vu = []
    async for nom, res in rp._sequence_publication(name, domain, _zip_bytes(), "site.zip"):
        vu.append((nom, res))
    return vu


def test_chaque_etape_est_rendue_des_qu_elle_est_finie(prepare):
    """Le point du correctif : les étapes arrivent UNE PAR UNE, pas en bloc."""
    vu = asyncio.run(_recolte())
    assert [n for n, _ in vu] == ["content", "version", "domaine", "vhost", "route", "cert"]


def test_l_ordre_du_domaine_avant_le_vhost_est_tenu(prepare):
    """ORDRE VOULU, et il n'est pas cosmétique : le domaine doit être
    enregistré AVANT la régénération, sans quoi le générateur relit le disque
    et retombe sur `<nom>.gk2.secubox.in`."""
    ordre = [n for n, _ in asyncio.run(_recolte())]
    assert ordre.index("domaine") < ordre.index("vhost")


def test_le_vhost_est_une_etape_affichable(prepare):
    """Il décidait du verdict sans jamais être montré : une publication
    refusée par `nginx -t` affichait quatre pastilles vertes et aucune rouge."""
    cles = [c for c, _ in rp.ETAPES_ASSISTANT]
    assert "vhost" in cles and "domaine" in cles
    rendues = {n for n, _ in asyncio.run(_recolte())}
    assert rendues == set(cles), "toute étape annoncée doit être rendue, et l'inverse"


def test_le_verdict_exige_que_le_domaine_soit_servi():
    """Une publication qui n'est pas servie n'est pas une publication."""
    complet = {"content": {"index_present": True}, "route": {"route_ok": True},
               "vhost": {"ok": True}}
    assert rp._verdict(complet) is True
    for manquant in ("content", "route", "vhost"):
        partiel = {k: v for k, v in complet.items() if k != manquant}
        assert rp._verdict(partiel) is False, f"{manquant} doit peser sur le verdict"


def test_un_contenu_dangereux_arrete_la_sequence(prepare):
    """Et il l'arrête AVANT d'avoir versionné ou touché nginx."""
    from fastapi import HTTPException

    async def go():
        vu = []
        with pytest.raises(HTTPException):
            async for nom, res in rp._sequence_publication(
                    "zem", "zem.gk2.secubox.in", b"ceci n'est pas un zip", "site.zip"):
                vu.append(nom)
        return vu

    assert asyncio.run(go()) == []


# ── L'ÉTAT D'UNE ÉTAPE ─────────────────────────────────────────────────────
# La page marquait `version` et `cert` réussies EN DUR. Un `git push` refusé
# s'affichait donc en vert : une pastille qui ment est pire qu'une absente.

def test_une_etape_ratee_ne_passe_pas_pour_reussie():
    assert rp.etat_etape("version", {"pushed": False, "committed": False,
                                     "reason": "dépôt en lecture seule"})[0] == "echec"
    assert rp.etat_etape("vhost", {"ok": False, "detail": "nginx -t a échoué"})[0] == "echec"
    assert rp.etat_etape("route", {"route_ok": False})[0] == "echec"
    assert rp.etat_etape("content", {"index_present": False})[0] == "echec"


def test_un_certificat_en_cours_n_est_ni_vert_ni_rouge():
    """Certbot obtient un domaine custom en tâche de fond : le peindre en vert
    serait mentir, en rouge serait alarmer pour rien."""
    etat, detail = rp.etat_etape("cert", {"mode": "provisioning", "detail": "certbot en cours"})
    assert etat == "encours"
    assert "certbot" in detail


def test_la_raison_de_l_echec_est_transmise():
    """Sans elle, « ça s'arrête » est tout ce que l'utilisateur peut dire."""
    _, detail = rp.etat_etape("vhost", {"ok": False, "detail": "nginx -t a échoué"})
    assert "nginx -t" in detail


def test_toute_etape_annoncee_sait_dire_son_etat():
    for cle, _ in rp.ETAPES_ASSISTANT:
        etat, _ = rp.etat_etape(cle, {})
        assert etat in ("ok", "echec", "encours"), cle


# ── LE BATTEMENT ───────────────────────────────────────────────────────────
# HAProxy coupe à 30 s D'INACTIVITÉ. Régénérer nginx pour 163 sites peut les
# dépasser sans émettre un octet : la connexion tomberait au milieu et la page
# croirait à un plantage, alors que la publication se poursuit côté serveur.

def _lis_flux(uf, **kw):
    """Déroule la réponse en flux SANS passer par TestClient (cassé selon la
    version de starlette installée) : on appelle la route et on lit son corps."""
    async def go():
        resp = await rp.publish_wizard(name="zem", domain=None, file=uf, flux=1,
                                       user={"sub": "tester"}, **kw)
        lignes = []
        async for bout in resp.body_iterator:
            for l in bout.splitlines():
                if l.strip():
                    lignes.append(__import__("json").loads(l))
        return lignes
    return asyncio.run(go())


def _fichier():
    from starlette.datastructures import UploadFile
    return UploadFile(filename="site.zip", file=io.BytesIO(_zip_bytes()))


def test_le_flux_bat_pendant_une_etape_longue(prepare, monkeypatch):
    monkeypatch.setattr(rp, "BATTEMENT_SEC", 0.05)

    def lente(domaine):
        import time
        time.sleep(0.4)          # sur un thread : la boucle reste libre
        return {"ok": True, "detail": "163 sites"}
    monkeypatch.setattr(rp, "publie_vhost", lente)
    monkeypatch.setattr(rp, "marque_publie", lambda site, ok: {"ok": ok})

    lignes = _lis_flux(_fichier())
    assert any(l["type"] == "attente" for l in lignes), (
        "sans battement, HAProxy coupe au milieu d'une étape longue")
    assert lignes[0]["type"] == "debut"
    assert lignes[-1]["type"] == "fin" and lignes[-1]["ok"] is True


def test_le_flux_annonce_les_etapes_avant_de_les_faire(prepare, monkeypatch):
    """La page ne tient plus la liste : elle divergeait (quatre sur six)."""
    monkeypatch.setattr(rp, "marque_publie", lambda site, ok: {"ok": ok})
    lignes = _lis_flux(_fichier())
    annonces = [e["cle"] for e in lignes[0]["etapes"]]
    faites = [l["cle"] for l in lignes if l["type"] == "etape"]
    assert annonces == faites


def test_un_echec_est_dit_DANS_le_flux(prepare, monkeypatch):
    """Le flux a déjà commencé : on ne peut plus changer le code HTTP. Sans ce
    message, la page attendrait une suite qui ne viendrait jamais."""
    monkeypatch.setattr(rp, "marque_publie", lambda site, ok: {"ok": ok})
    monkeypatch.setattr(rp, "publie_vhost",
                        lambda d: {"ok": False, "detail": "nginx -t a échoué"})
    lignes = _lis_flux(_fichier())
    fin = lignes[-1]
    assert fin["type"] == "fin" and fin["ok"] is False
    vhost = [l for l in lignes if l.get("cle") == "vhost"][0]
    assert vhost["etat"] == "echec" and "nginx -t" in vhost["detail"]


def test_une_panne_imprevue_ne_laisse_pas_la_page_en_attente(prepare, monkeypatch):
    """Une exception non prévue coupait le flux sans rien dire : la page
    tournait indéfiniment. Elle doit sortir par le flux, avec son motif."""
    monkeypatch.setattr(rp, "marque_publie", lambda site, ok: {"ok": ok})

    def boum(domaine):
        raise RuntimeError("publishctl introuvable")
    monkeypatch.setattr(rp, "publie_vhost", boum)
    lignes = _lis_flux(_fichier())
    assert lignes[-1]["type"] == "fin" and lignes[-1]["ok"] is False
    assert "publishctl introuvable" in lignes[-1]["detail"]
