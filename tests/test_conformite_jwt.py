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

VERBES = {"get", "post", "put", "delete", "patch"}

# Seules les sondes restent publiques : systemd, nginx et les probes de santé
# les appellent sans jeton par construction. `/metrics` n'y est PAS — selon les
# modules il rend des agrégats de trafic, des domaines ou des statistiques
# d'attaques, c'est-à-dire de la reconnaissance, et aucun scrutateur du dépôt
# ne le consomme en anonyme.
PUBLIQUES = {"/health", "/healthz", "/readyz", "/ping"}

# Modules réparés — ils ne doivent JAMAIS reparaître dans l'inventaire.
# Cette liste ne fait que grandir : chaque module ferme rejoint le cliquet.
REPARES = {
    # P0 (#1256) — les trois critiques
    "secubox-vault", "secubox-certs", "secubox-cloner",
    # P1 (#1256) — les modules qui n'importaient jamais require_jwt
    "secubox-simplex", "secubox-vm", "secubox-wazuh", "secubox-rezapp",
    "secubox-jabber", "secubox-ossec", "secubox-redroid", "secubox-magicmirror",
}


def _routes_du_fichier(chemin: Path):
    """Rend (méthode, chemin_route, gardée) pour chaque route déclarée.

    Une route est « gardée » si `Depends` apparaît dans son décorateur
    (`dependencies=[Depends(require_jwt)]`) ou dans la signature de la
    fonction (`user=Depends(require_jwt)`) — les deux formes sont en usage
    dans le parc et protègent aussi bien l'une que l'autre.
    """
    try:
        arbre = ast.parse(chemin.read_text(encoding="utf-8", errors="ignore"))
    except SyntaxError:  # fichier non-Python valide : rien à dire dessus
        return

    for noeud in ast.walk(arbre):
        if not isinstance(noeud, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        signature_gardee = any(
            isinstance(n, ast.Name) and n.id == "Depends"
            for n in ast.walk(noeud.args)
        )
        for deco in noeud.decorator_list:
            if not isinstance(deco, ast.Call):
                continue
            if not isinstance(deco.func, ast.Attribute) or deco.func.attr not in VERBES:
                continue
            if not deco.args or not isinstance(deco.args[0], ast.Constant):
                continue
            route = deco.args[0].value
            if not isinstance(route, str) or not route.startswith("/"):
                continue
            deco_garde = any(
                isinstance(n, ast.Name) and n.id == "Depends" for n in ast.walk(deco)
            )
            yield deco.func.attr.upper(), route, (deco_garde or signature_gardee)


def _scanner() -> set[str]:
    """Inventaire des routes non gardées, en clés stables `module METHODE chemin`."""
    nues = set()
    for fichier in sorted(RACINE.glob("packages/*/api/**/*.py")):
        module = fichier.relative_to(RACINE).parts[1]
        for methode, route, gardee in _routes_du_fichier(fichier):
            if gardee:
                continue
            if methode == "GET" and route in PUBLIQUES:
                continue
            nues.add(f"{module} {methode} {route}")
    return nues


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


def test_inventaire_sans_entree_perimee():
    """La dette réparée doit sortir de l'inventaire, sinon le cliquet se desserre."""
    perimees = sorted(_inventaire() - _scanner())
    assert not perimees, (
        f"{len(perimees)} entrée(s) de tests/dette-jwt.txt sont réparées ou "
        "disparues — retire ces lignes dans le même commit :\n  "
        + "\n  ".join(perimees)
    )


def test_modules_p0_totalement_gardes():
    """Les modules déjà fermés le restent : aucune régression tolérée (#1256)."""
    restant = sorted(r for r in _scanner() if r.split(" ", 1)[0] in REPARES)
    assert not restant, (
        "régression sur un module déjà réparé :\n  " + "\n  ".join(restant)
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
