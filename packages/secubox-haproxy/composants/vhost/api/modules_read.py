# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: vhost.modules_read — quel module SecuBox sert ce vhost (#1217).

Un vhost n'est pas toujours un site : la plupart des noms de gk2 sont la façade
d'un MODULE SecuBox — gitea et peertube dans leur conteneur, ytsas, podcaster…
Le tableau des vhosts les affichait comme n'importe quelle entrée, sans dire
qu'il y a un module derrière ni comment il tourne.

La source est le registre /etc/secubox/modules.d/*.toml, manifestes dérivés par
`secubox-profilectl scan` et faisant autorité une fois corrigés. Deux qualités
de lien, jamais confondues :

  - CERTAIN — le manifeste déclare `portal = { domain = "…" }` : le module dit
    lui-même quel nom il sert.
  - CERTAIN — la configuration nginx du vhost route vers le socket du module,
    `proxy_pass http://unix:/run/secubox/<id>.sock`. Ce n'est pas une
    ressemblance de nom, c'est le chemin que prend la requête. C'est ainsi que
    depot.gk2.secubox.in se révèle être une gouttelette de l'aggregator, et
    non le module `repo` que son nom laissait supposer.
  - PROBABLE — le premier label du vhost est l'id d'un module connu. Utile,
    mais c'est une déduction : elle est marquée comme telle plutôt que
    présentée comme un fait.

Lecture tolérante et mise en cache sur la date du répertoire : le panneau doit
s'afficher même sans registre, et ne pas relire 188 fichiers à chaque requête.
"""
import re
from pathlib import Path

try:  # Python >= 3.11
    import tomllib
except ModuleNotFoundError:  # repli, jamais utilisé sur bookworm
    tomllib = None

REGISTRE = Path("/etc/secubox/modules.d")

_cache = {"signature": None, "par_domaine": {}, "par_id": {}}


def _lire_registre(registre: Path) -> tuple:
    par_domaine, par_id = {}, {}
    if tomllib is None or not registre.is_dir():
        return par_domaine, par_id
    for f in sorted(registre.glob("*.toml")):
        try:
            d = tomllib.loads(f.read_text())
        except (OSError, ValueError):
            continue  # un manifeste illisible n'en condamne pas 187 autres
        mid = str(d.get("id") or f.stem).strip()
        if not mid:
            continue
        fiche = {
            "id": mid,
            "category": d.get("category") or "",
            "runtime": d.get("runtime") or "",
            "lifecycle": d.get("lifecycle") or "",
            "protected": bool(d.get("protected")),
        }
        par_id[mid] = fiche
        portail = d.get("portal")
        if isinstance(portail, dict):
            dom = str(portail.get("domain") or "").strip().lower()
            if dom:
                par_domaine[dom] = fiche
    return par_domaine, par_id


def _charger(registre: Path = None):
    r = registre if registre is not None else REGISTRE
    try:
        signature = (str(r), r.stat().st_mtime_ns)
    except OSError:
        signature = (str(r), None)
    if _cache["signature"] != signature:
        pd, pi = _lire_registre(r)
        _cache.update(signature=signature, par_domaine=pd, par_id=pi)
    return _cache["par_domaine"], _cache["par_id"]


# proxy_pass http://unix:/run/secubox/<id>.sock:/chemin
_SOCKET = re.compile(r"proxy_pass\s+http://unix:/run/secubox/([a-z0-9_-]+)\.sock")


def _module_du_socket(content: str, par_id: dict):
    """Module nommé par le socket vers lequel la conf nginx route réellement."""
    if not content:
        return None
    for mid in _SOCKET.findall(content):
        fiche = par_id.get(mid)
        if fiche:
            return fiche
    return None


def module_de(vhost: str, registre: Path = None, content: str = ""):
    """Fiche du module servant ce vhost, ou None.

    `certain` distingue la déclaration du module de la simple déduction sur le
    nom — on ne présente pas une supposition comme un fait.
    """
    if not vhost:
        return None
    par_domaine, par_id = _charger(registre)
    nom = vhost.strip().lower()
    fiche = par_domaine.get(nom)
    if fiche:
        return {**fiche, "certain": True}
    fiche = _module_du_socket(content, par_id)
    if fiche:
        return {**fiche, "certain": True}
    label = nom.split(".")[0]
    fiche = par_id.get(label)
    if fiche:
        return {**fiche, "certain": False}
    return None
