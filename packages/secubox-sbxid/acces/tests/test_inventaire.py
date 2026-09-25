# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Tests de l'inventaire des accès et des privilèges (#1313).

Le test qui compte vraiment ici est `test_matrice_suit_une_route_ajoutee` : il
ne verifie pas une valeur, il verifie que l'inventaire se MET A JOUR SEUL. Si
un jour quelqu'un remplace la derivation par une table ecrite a la main, tous
les autres tests continueront de passer et celui-la, seul, tombera.
"""

from fastapi import Depends, FastAPI

from api.inventaire import inventaire, matrice_privileges, surface_admin
from api.profileur import PROFILS


async def require_admin():           # même nom que la vraie garde : c'est le nom
    return {"sub": "root"}           # que l'inventaire cherche, pas l'objet


async def _autre_garde():
    return None


def _app_exemple() -> FastAPI:
    app = FastAPI()

    @app.get("/ouvert")
    async def ouvert():
        """Une route publique."""
        return {}

    @app.get("/file", dependencies=[Depends(require_admin)])
    async def file():
        """Les demandes à trancher."""
        return {}

    @app.post("/file/accepter", dependencies=[Depends(require_admin)])
    async def accepter():
        """Admettre un appareil."""
        return {}

    @app.get("/tiede", dependencies=[Depends(_autre_garde)])
    async def tiede():
        """Gardée, mais pas par l'administration."""
        return {}

    return app


# ── la surface d'administration se lit dans l'application ───────────────────

def test_surface_ne_retient_que_les_routes_gardees():
    s = surface_admin(_app_exemple())
    chemins = [r["chemin"] for r in s]
    assert chemins == ["/file", "/file/accepter"]


def test_surface_ignore_une_garde_qui_n_est_pas_l_administration():
    """Une route gardée AUTREMENT n'est pas une route d'administration.

    Sans cette distinction, l'inventaire enflerait de tout ce qui porte une
    dépendance quelconque et cesserait de vouloir dire quelque chose.
    """
    s = surface_admin(_app_exemple())
    assert "/tiede" not in [r["chemin"] for r in s]


def test_surface_porte_les_verbes_et_le_resume():
    s = {r["chemin"]: r for r in surface_admin(_app_exemple())}
    assert s["/file/accepter"]["methodes"] == ["POST"]
    assert s["/file"]["resume"] == "Les demandes à trancher."


def test_surface_est_triee():
    """Deux exports doivent se comparer ligne à ligne."""
    a = surface_admin(_app_exemple())
    b = surface_admin(_app_exemple())
    assert a == b == sorted(a, key=lambda x: (x["chemin"], x["methodes"]))


def test_matrice_suit_une_route_ajoutee():
    """LE test : la matrice se met à jour SEULE.

    On ajoute une route gardée après coup. Une table écrite à la main
    l'ignorerait — et affirmerait tranquillement une chose fausse. La
    dérivation, elle, la voit.
    """
    app = _app_exemple()
    avant = matrice_privileges(app)["admin"]["nombre_routes"]

    @app.delete("/profils/revoquer", dependencies=[Depends(require_admin)])
    async def revoquer():
        """Retirer un accès."""
        return {}

    apres = matrice_privileges(app)
    assert apres["admin"]["nombre_routes"] == avant + 1
    assert "/profils/revoquer" in [r["chemin"] for r in apres["admin"]["routes"]]


# ── l'inventaire dit ce qui déplaît ─────────────────────────────────────────

def test_seul_admin_est_effectif():
    m = matrice_privileges(_app_exemple())
    assert m["admin"]["effectif"] is True
    assert m["user"]["effectif"] is False
    assert m["guest"]["effectif"] is False


def test_user_et_guest_portent_la_meme_remarque():
    """`user` n'accorde rien de plus que `guest`, et l'écran doit le DIRE.

    Un administrateur qui promeut en croyant donner un droit décide sur une
    croyance fausse. Trois lignes d'apparence également significative
    fabriquent exactement cette croyance.
    """
    m = matrice_privileges(_app_exemple())
    assert m["user"]["remarque"] == m["guest"]["remarque"]
    assert "équivalents" in m["user"]["remarque"]


def test_tous_les_profils_sont_couverts():
    m = matrice_privileges(_app_exemple())
    assert set(m) == set(PROFILS)


# ── l'inventaire ne filtre aucun état ───────────────────────────────────────

class _Demande:
    def __init__(self, did, etat, profil=None):
        self.did, self.etat, self.profil = did, etat, profil

    def vue_admin(self):
        return {"did": self.did, "etat": self.etat, "profil": self.profil}


class _Profileur:
    def __init__(self, demandes):
        self._demandes = {d.did: d for d in demandes}


def test_inventaire_rend_tous_les_etats():
    """Un refus et une expiration doivent se relire.

    `/profils` ne rend que les `acceptee` — juste pour décider, faux pour
    auditer. C'est précisément l'écart que cet inventaire comble.
    """
    p = _Profileur([
        _Demande("did:a:1", "acceptee", "admin"),
        _Demande("did:a:2", "en_attente"),
        _Demande("did:a:3", "refusee"),
        _Demande("did:a:4", "expiree"),
    ])
    inv = inventaire(_app_exemple(), p)
    assert inv["resume"]["total"] == 4
    assert inv["resume"]["par_etat"] == {
        "acceptee": 1, "en_attente": 1, "refusee": 1, "expiree": 1}


def test_resume_par_profil_ne_compte_que_les_admis():
    """Un appareil refusé n'a pas de profil à compter.

    Le compter donnerait un total de droits accordés supérieur à la réalité —
    et un inventaire d'audit qui surestime les droits est inutilisable.
    """
    p = _Profileur([
        _Demande("did:a:1", "acceptee", "admin"),
        _Demande("did:a:2", "acceptee", "guest"),
        _Demande("did:a:3", "refusee", "admin"),
    ])
    inv = inventaire(_app_exemple(), p)
    assert inv["resume"]["par_profil_admis"] == {"admin": 1, "guest": 1}


def test_profileur_vide_ne_casse_pas():
    inv = inventaire(_app_exemple(), _Profileur([]))
    assert inv["appareils"] == [] and inv["resume"]["total"] == 0
    # La matrice, elle, existe toujours : elle décrit le code, pas les données.
    assert inv["privileges"]["admin"]["effectif"] is True
