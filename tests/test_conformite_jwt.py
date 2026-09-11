# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# tests/test_conformite_jwt.py
"""SecuBox-Deb :: conformité JWT des routes API (#1256).

`.claude/MODULE-COMPLIANCE.md` §Authentication : « All endpoints (except
/health) MUST use JWT authentication ». L'audit du 10/09/2026 a compté **581
routes sans garde sur 2 936** — dont l'intégralité du coffre à secrets. Rien
en amont ne rattrapait l'oubli : l'aggregator se contente de `app.mount()`,
le snippet nginx TRANSMET `Authorization` sans le vérifier, et
`auth_request /__sbx_auth_verify` teste le LAN, pas un jeton.

CE TEST EST UN CLIQUET, PAS UN VERDICT. Corriger 581 routes d'un coup n'est
pas réaliste ; laisser la dette sans mesure garantit qu'elle regrossit. Le
test fige donc l'inventaire connu dans `tests/dette-jwt.txt` et échoue :

* si une route NON gardée apparaît hors de l'inventaire — la dette augmente,
  c'est le cas qu'on refuse ;
* si une entrée de l'inventaire est désormais gardée ou a disparu — la dette
  a baissé, il faut retirer la ligne pour que le cliquet reste serré.

Le second cas est ce qui empêche l'inventaire de pourrir : on ne peut pas
réparer un module sans mettre le fichier à jour dans le même commit.

ANALYSE STATIQUE, ET C'EST DÉLIBÉRÉ. Importer les 143 applications
demanderait fastapi, jose, argon2, python-multipart… et déclencherait les
effets de bord d'import de chaque module. Pire, la forme de `app.routes`
dépend de la version de FastAPI (à partir de 0.14x un routeur inclus est un
`_IncludedRouter` opaque, alors que les versions de bookworm aplatissent) :
un test qui inspecte l'objet routeur passerait ici et raterait là-bas. `ast`
lit la source, ne dépend de rien, et donne le même verdict partout.
"""
from __future__ import annotations

import ast
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
INVENTAIRE = Path(__file__).resolve().parent / "dette-jwt.txt"
ASSUMEES = Path(__file__).resolve().parent / "publiques-assumees.txt"

VERBES = {"get", "post", "put", "delete", "patch"}

# Seules les sondes restent publiques : systemd, nginx et les probes de santé
# les appellent sans jeton par construction. `/metrics` n'y est PAS — selon les
# modules il rend des agrégats de trafic, des domaines ou des statistiques
# d'attaques, c'est-à-dire de la reconnaissance, et aucun scrutateur du dépôt
# ne le consomme en anonyme.
# Sondes de sante : elles restent publiques, ou qu'elles soient montees.
#
# On compare le DERNIER SEGMENT, pas le chemin entier : un module qui declare
# `/api/v1/health` (eye-remote), `/api/v1/mastodon/healthz` ou
# `/api/v1/metrics/health` sert la meme sonde qu'un `/health` a la racine, et
# systemd comme nginx l'appellent sans jeton. La premiere version de ce jeu
# exigeait l'egalite stricte : trois sondes se sont retrouvees gardees, et
# c'est un test d'integration qui l'a dit — pas la relecture.
SONDES = {"health", "healthz", "readyz", "livez", "ping", "alive"}


def _est_sonde(route: str) -> bool:
    return route.rsplit("/", 1)[-1].lower() in SONDES



def _est_garde(noeud: ast.AST) -> bool:
    """Un nom qui dénote une garde.

    Deux gardes coexistent depuis le passage du parc en lecture gardée :

    * `require_jwt` — jeton obligatoire, sans exception. C'est la garde des
      écritures et de tout ce qui touche à un secret, une clé ou un journal.
    * `require_lecture` — jeton, **ou** mode tableau de bord depuis le LAN si
      l'opérateur l'a explicitement armé dans `secubox.conf`. C'est la garde
      des lectures d'affichage, celles qui alimentaient les cardlets sans
      authentification avant #1256.

    `Depends` seul compte aussi : quelques modules définissent leur propre
    fabrique (`secubox-antirootkit`) ou leur propre dépendance locale
    (`secubox-annuaire`).
    """
    return isinstance(noeud, ast.Name) and (
        noeud.id == "Depends"
        or "require_jwt" in noeud.id
        or "require_lecture" in noeud.id
    )


def _routes_du_fichier(chemin: Path):
    """Rend (méthode, chemin_route, gardée) pour chaque route déclarée.

    Trois écritures sont en usage dans le parc et protègent aussi bien :

    * `@app.get("/x", dependencies=[Depends(require_jwt)])` — dans le décorateur ;
    * `async def x(user=Depends(require_jwt))` — dans la signature ;
    * `dependencies=[require_jwt()]` où `require_jwt()` est une fabrique locale
      rendant `Depends(_require_jwt)` — c'est la forme de `secubox-antirootkit`,
      et ne chercher que le nom `Depends` la déclarait à tort non gardée.

    On reconnaît donc `Depends` **ou** un nom contenant `require_jwt`.
    """
    try:
        arbre = ast.parse(chemin.read_text(encoding="utf-8", errors="ignore"))
    except SyntaxError:  # fichier non-Python valide : rien à dire dessus
        return

    for noeud in ast.walk(arbre):
        if not isinstance(noeud, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        signature_gardee = any(_est_garde(n) for n in ast.walk(noeud.args))
        for deco in noeud.decorator_list:
            if not isinstance(deco, ast.Call):
                continue
            if not isinstance(deco.func, ast.Attribute) or deco.func.attr not in VERBES:
                continue
            if not deco.args or not isinstance(deco.args[0], ast.Constant):
                continue
            route = deco.args[0].value
            # `@router.post("")` est une VRAIE route : le chemin vide vaut le
            # prefixe du routeur (`include_router(..., prefix="/devices")`).
            # L'exiger commencant par « / » la rendait invisible — angle mort
            # trouve en auditant secubox-eye-remote/api/routers/pairing.py.
            if not isinstance(route, str) or (route and not route.startswith("/")):
                continue
            route = route or "(prefixe du routeur)"

            deco_garde = any(_est_garde(n) for n in ast.walk(deco))
            yield deco.func.attr.upper(), route, (deco_garde or signature_gardee)


def _scanner() -> set[str]:
    """Inventaire des routes non gardées, en clés stables `module METHODE chemin`."""
    assumees = _publiques_assumees()
    nues = set()
    for fichier in sorted(RACINE.glob("packages/*/api/**/*.py")):
        module = fichier.relative_to(RACINE).parts[1]
        for methode, route, gardee in _routes_du_fichier(fichier):
            if gardee:
                continue
            if methode == "GET" and _est_sonde(route):
                continue
            cle = f"{module} {methode} {route}"
            if cle in assumees:
                continue
            nues.add(cle)
    return nues


def _publiques_assumees() -> set[str]:
    """Routes publiques à dessein, chacune avec sa raison en commentaire.

    Ce n'est pas une dérogation de confort : une route n'entre ici que si elle
    porte SA PROPRE protection (session + CSRF de `billets`, HMAC du webhook
    `metablogizer`, requête signée de `soc-gateway`, restriction à localhost de
    `p2p`) ou si exiger un jeton la casserait par construction (les points
    d'entrée de `secubox-auth` DÉLIVRENT le jeton ; l'autodiscover Outlook est
    parlé par un client qui n'en porte pas).
    """
    lignes = ASSUMEES.read_text(encoding="utf-8").splitlines()
    entrees = set()
    for l in lignes:
        l = l.split("#", 1)[0].strip()
        if l:
            entrees.add(" ".join(l.split()))
    return entrees


def _inventaire() -> set[str]:
    lignes = INVENTAIRE.read_text(encoding="utf-8").splitlines()
    return {l.strip() for l in lignes if l.strip() and not l.startswith("#")}


def test_aucune_route_non_gardee_nouvelle():
    """La dette ne doit pas augmenter : toute route nue est déjà inventoriée."""
    nouvelles = sorted(_scanner() - _inventaire())
    assert not nouvelles, (
        f"{len(nouvelles)} route(s) sans garde JWT hors inventaire — "
        "ajoute `dependencies=[Depends(require_jwt)]` (cf. #1256) :\n  "
        + "\n  ".join(nouvelles)
    )


def test_dette_close():
    """L'inventaire doit rester VIDE : la dette est soldée, pas gérée.

    Tant qu'il restait des centaines de routes nues, `dette-jwt.txt` mesurait
    une dette et le test empêchait qu'elle grossisse. Depuis le passage du
    parc en lecture gardée, il n'y a plus rien à mesurer — et rouvrir le
    fichier serait le moyen le plus simple de faire taire ce test au lieu de
    poser une garde. Une route nue est un défaut, plus une ligne d'inventaire.
    """
    assert not _inventaire(), (
        "tests/dette-jwt.txt doit rester vide : pose `require_jwt` ou "
        "`require_lecture` sur la route, ou justifie-la dans "
        "tests/publiques-assumees.txt.\n  "
        + "\n  ".join(sorted(_inventaire()))
    )


def test_inventaire_sans_entree_perimee():
    """La dette réparée doit sortir de l'inventaire, sinon le cliquet se desserre."""
    perimees = sorted(_inventaire() - _scanner())
    assert not perimees, (
        f"{len(perimees)} entrée(s) de tests/dette-jwt.txt sont réparées ou "
        "disparues — retire ces lignes dans le même commit :\n  "
        + "\n  ".join(perimees)
    )


def test_le_scanner_voit_les_deux_formes_de_garde(tmp_path):
    """Garde-fou du garde-fou : les deux écritures doivent être reconnues."""
    f = tmp_path / "main.py"
    f.write_text(
        "@app.get('/a', dependencies=[Depends(require_jwt)])\n"
        "async def a(): ...\n"
        "@router.post('/b')\n"
        "async def b(user=Depends(require_jwt)): ...\n"
        "@app.get('/c')\n"
        "async def c(): ...\n"
        "@app.get('/health')\n"
        "async def h(): ...\n",
        encoding="utf-8",
    )
    vu = {(m, r): g for m, r, g in _routes_du_fichier(f)}
    assert vu[("GET", "/a")] is True, "dependencies=[...] non reconnu"
    assert vu[("POST", "/b")] is True, "user=Depends(...) non reconnu"
    assert vu[("GET", "/c")] is False, "route nue non détectée"


def test_publiques_assumees_sans_ligne_morte():
    """Une route publique assumée doit exister : sinon la ligne ment.

    Une entrée qui ne correspond plus à aucune route (route renommée, module
    retiré) donne l'illusion d'une décision prise alors qu'elle ne couvre plus
    rien — et masquerait la réapparition de la vraie route sous un autre nom.
    """
    toutes = set()
    for fichier in sorted(RACINE.glob("packages/*/api/**/*.py")):
        module = fichier.relative_to(RACINE).parts[1]
        for methode, route, _ in _routes_du_fichier(fichier):
            toutes.add(f"{module} {methode} {route}")
    mortes = sorted(_publiques_assumees() - toutes)
    assert not mortes, (
        f"{len(mortes)} ligne(s) de tests/publiques-assumees.txt ne "
        "correspondent à aucune route :\n  " + "\n  ".join(mortes)
    )
