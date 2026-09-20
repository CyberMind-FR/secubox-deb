# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""SecuBox-Deb :: ACCÈS — l'inventaire complet des accès et des privilèges (#1313).

POURQUOI CE MODULE EXISTE
-------------------------

Le profileur montre deux listes : ce qui attend une décision, et ce qui vit
déjà. C'est ce qu'il faut pour DÉCIDER. Ce n'est pas ce qu'il faut pour
AUDITER, et les deux besoins ne se recouvrent pas :

  * `admis()` ne rend que les demandes `acceptee`. Un appareil refusé ou
    expiré devient invisible — or « à qui avons-nous dit non, et quand » est
    une question d'audit parfaitement légitime, et la seule trace vit dans un
    fichier que personne n'ouvre.
  * Le profil (`guest` / `user` / `admin`) est affiché comme une ÉTIQUETTE.
    Rien ne dit ce qu'il autorise. Un droit qu'on ne peut pas relire est un
    droit qu'on ne peut pas auditer.

LA MATRICE DE PRIVILÈGES EST DÉRIVÉE, JAMAIS ÉCRITE À LA MAIN
-------------------------------------------------------------

C'est la décision structurante de ce fichier. Une table de privilèges tenue à
la main est juste le jour où on l'écrit, puis elle dérive : quelqu'un ajoute
une route gardée, personne ne pense à la table, et l'écran d'audit se met à
affirmer tranquillement une chose fausse. On aurait remplacé une absence
d'information par une désinformation — c'est pire, parce que ça se croit.

On INTERROGE donc l'application elle-même : quelles routes portent réellement
`require_admin`. Ajoutez-en une demain, elle apparaît ici sans que personne
n'y pense. C'est le seul inventaire qui ne peut pas mentir, parce qu'il ne
décrit pas le code : il EST le code.

CE QUE L'INVENTAIRE DIT ET QUI DÉPLAÎT
--------------------------------------

`PROFILS` est ordonné — `guest` < `user` < `admin` — ce qui laisse croire à
trois niveaux de droits. Or, dans ce module :

  * `require_admin` est l'unique garde de rang ;
  * il n'existe AUCUN `require_user` ;
  * `PROFILS.index` n'est comparé nulle part.

Donc `user` n'accorde aujourd'hui rien de plus que `guest`. Promouvoir
quelqu'un de `guest` vers `user` change une étiquette et absolument rien
d'autre.

L'inventaire le DIT, au lieu d'afficher trois lignes d'apparence également
significative. Un administrateur qui promeut en croyant donner un droit prend
une décision sur une croyance fausse ; le rôle de cet écran est précisément de
l'en empêcher. Si `user` doit signifier quelque chose, c'est une décision à
prendre — pas un fait à présenter comme acquis.
"""

from __future__ import annotations

from typing import Any, Iterable

from .profileur import PROFILS

#: Nom de la dépendance qui garde la surface d'administration. On le cherche
#: par NOM plutôt que par identité d'objet : FastAPI enveloppe les dépendances,
#: et comparer les fonctions demanderait de connaître l'emballage — un détail
#: d'implémentation qui changerait sous nous sans prévenir.
GARDE_ADMIN = "require_admin"


def _garde_admin(route: Any) -> bool:
    """La route est-elle gardée par `require_admin` ?

    On regarde les deux endroits où FastAPI range les dépendances : celles
    déclarées sur la route (`dependencies=[...]`, la forme utilisée ici) et
    celles injectées dans la signature (`Depends(...)` en paramètre). Ne
    regarder qu'un seul des deux ferait passer pour OUVERTE une route
    parfaitement gardée — l'erreur exactement inverse de celle qu'on veut
    éviter, et la plus dangereuse des deux.
    """
    vues: list[Any] = []
    for attr in ("dependencies", "dependant"):
        obj = getattr(route, attr, None)
        if obj is None:
            continue
        if attr == "dependencies":
            vues.extend(obj)
        else:
            vues.extend(getattr(obj, "dependencies", []) or [])
    for d in vues:
        appel = getattr(d, "call", None) or getattr(d, "dependency", None)
        if getattr(appel, "__name__", "") == GARDE_ADMIN:
            return True
        # Dépendance imbriquée : `require_admin` peut se cacher un cran plus
        # bas quand une garde en compose une autre.
        for sous in getattr(d, "dependencies", []) or []:
            sappel = getattr(sous, "call", None) or getattr(sous, "dependency", None)
            if getattr(sappel, "__name__", "") == GARDE_ADMIN:
                return True
    return False


def surface_admin(app: Any) -> list[dict[str, Any]]:
    """Les routes réellement réservées à l'administration, telles qu'elles sont.

    Rendue triée : un inventaire qui change d'ordre à chaque appel se relit mal
    d'une fois sur l'autre, et deux exports ne se comparent plus.
    """
    out: list[dict[str, Any]] = []
    for r in getattr(app, "routes", []):
        chemin = getattr(r, "path", None)
        methodes = getattr(r, "methods", None)
        if not chemin or not methodes:
            continue
        if not _garde_admin(r):
            continue
        verbes = sorted(m for m in methodes if m not in ("HEAD", "OPTIONS"))
        fn = getattr(r, "endpoint", None)
        out.append({
            "chemin": chemin,
            "methodes": verbes,
            # Trois sources, de la plus parlante à la plus maigre. La dernière —
            # le nom de la fonction — vaut mieux qu'un blanc : dans un écran
            # d'audit, une route sans libellé se lit comme une route qu'on n'a
            # pas comprise, alors qu'elle est simplement sans docstring.
            "resume": (getattr(r, "summary", "")
                       or _premiere_ligne(getattr(fn, "__doc__", "") or "")
                       or getattr(fn, "__name__", "")),
        })
    return sorted(out, key=lambda x: (x["chemin"], x["methodes"]))


def _premiere_ligne(doc: str) -> str:
    for ligne in (doc or "").strip().splitlines():
        ligne = ligne.strip()
        if ligne:
            return ligne
    return ""


def matrice_privileges(app: Any) -> dict[str, Any]:
    """Ce que chaque profil autorise, dérivé de l'application.

    La structure porte `effectif` — un booléen qui dit si le profil change
    quoi que ce soit — et `remarque`, qui explique quand il ne change rien.
    Sans ces deux champs, trois lignes s'affichent avec la même apparence de
    signification, et c'est exactement ce qu'on cherche à éviter.
    """
    admin = surface_admin(app)
    matrice: dict[str, Any] = {}
    for p in PROFILS:
        if p == "admin":
            matrice[p] = {
                "profil": p,
                "effectif": True,
                "routes": admin,
                "nombre_routes": len(admin),
                "remarque": "Seul profil qui ouvre la surface d'administration.",
            }
        else:
            matrice[p] = {
                "profil": p,
                "effectif": False,
                "routes": [],
                "nombre_routes": 0,
                "remarque": (
                    "Aucun privilège propre dans ce module : il n'existe pas de "
                    "garde `require_user`, et l'ordre de `PROFILS` n'est comparé "
                    "nulle part. `user` et `guest` sont donc aujourd'hui "
                    "équivalents — promouvoir de l'un à l'autre change une "
                    "étiquette, pas un droit."
                ),
            }
    return matrice


def inventaire(app: Any, profileur: Any) -> dict[str, Any]:
    """L'inventaire complet : tous les appareils, tous les états, et les droits.

    « Tous les états » est le point : `admis()` filtre sur `acceptee` et c'est
    juste pour décider, mais faux pour auditer. Ici on ne filtre rien, et
    chaque entrée porte son état — un refus et une expiration se relisent.
    """
    demandes = list(_toutes(profileur))
    par_etat: dict[str, int] = {}
    for d in demandes:
        e = str(d.get("etat") or "?")
        par_etat[e] = par_etat.get(e, 0) + 1

    par_profil: dict[str, int] = {}
    for d in demandes:
        if d.get("etat") != "acceptee":
            continue
        p = str(d.get("profil") or "guest")
        par_profil[p] = par_profil.get(p, 0) + 1

    return {
        "appareils": demandes,
        "profils": list(PROFILS),
        "privileges": matrice_privileges(app),
        "resume": {
            "total": len(demandes),
            "par_etat": par_etat,
            "par_profil_admis": par_profil,
        },
    }


def _toutes(profileur: Any) -> Iterable[dict[str, Any]]:
    """Toutes les demandes connues, quel que soit leur état.

    Le profileur n'expose que des vues filtrées — c'est bien pour l'écran de
    décision. On passe donc par son registre interne, faute de mieux, et on le
    dit franchement ici plutôt que de le laisser découvrir : si `_demandes`
    change de forme, c'est CETTE ligne qu'il faut corriger, et le commentaire
    est ce qui permet de la retrouver.
    """
    reg = getattr(profileur, "_demandes", None)
    if not reg:
        return []
    return [d.vue_admin() for d in reg.values()]
