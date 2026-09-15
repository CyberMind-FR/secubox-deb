# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: LE REGISTRE DES APPAREILS — des identités qui ne sont pas des
utilisateurs (#1351).

POURQUOI UN REGISTRE À PART, ET PAS UNE LIGNE DE PLUS DANS users.json.

Un APPAREIL admis par le parcours d'accès n'est pas un utilisateur :

    un utilisateur   a un nom choisi, un mot de passe, une adresse, des droits
                     qu'un administrateur lui attribue, et une vie propre
    un appareil      est une CLÉ. Son nom dérive d'elle, il n'a pas de mot de
                     passe — il entre en signant —, et il disparaît avec la clé

Les loger ensemble produisait exactement la confusion que le module d'accès
existe pour dissiper : des entrées `sbx-3704f0234ea3` apparaissaient dans le
panneau « Users », où personne ne peut rien en faire, et où les gestes de
gestion d'utilisateurs — changer un mot de passe, envoyer un courriel de
réinitialisation — n'ont aucun sens.

CE QUE CE FICHIER NE FAIT PAS. Il n'authentifie personne. La preuve
d'identité d'un appareil est une SIGNATURE, vérifiée par le module d'accès. Ce
registre ne répond qu'à une question, et c'est celle que le cœur pose en
validant un jeton : « ce porteur existe-t-il, et est-il encore admis ? »

POURQUOI UN FICHIER, ET PAS UN CROCHET ENREGISTRÉ EN MÉMOIRE. Le cœur offre
déjà `set_session_validator()` pour les sessions — mais un crochet n'est posé
que dans le processus qui l'installe, et SecuBox en fait tourner des dizaines.
Un jeton frappé dans un processus et présenté à un autre trouverait un
validateur d'un côté et rien de l'autre : c'est précisément le défaut qui
faisait cohabiter « session ouverte » et « non connecté » (#1350). Un fichier
lu par tous n'a pas ce problème.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

log = logging.getLogger("secubox.appareils")

#: Le registre. DÉLIBÉRÉMENT DISTINCT de /etc/secubox/users.json : deux
#: fichiers, deux notions, et aucun panneau d'administration ne mélange les
#: deux par accident.
FICHIER = Path(os.environ.get("SECUBOX_APPAREILS", "/etc/secubox/appareils.json"))

#: Préfixe des noms de compte d'appareil. Il rend l'origine LISIBLE partout où
#: un nom s'affiche — journal, audit, barre du Hall — sans rien avoir à
#: interroger.
PREFIXE = "sbx-"


def _lit() -> Dict[str, Any]:
    try:
        d = json.loads(FICHIER.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        # Absent ou illisible : registre vide. Un appareil non reconnu se voit
        # refuser l'entrée — c'est le bon défaut, et il ne casse rien d'autre.
        return {"appareils": []}
    return d if isinstance(d, dict) else {"appareils": []}


def get(compte: str) -> Optional[Dict[str, Any]]:
    """L'appareil portant ce nom de compte, ou None."""
    if not compte or not compte.startswith(PREFIXE):
        # ON NE CHERCHE MÊME PAS hors du préfixe. Sans cette borne, le registre
        # deviendrait une seconde source d'utilisateurs, et deux magasins qui
        # peuvent répondre pour le même nom finissent toujours par diverger.
        return None
    for a in _lit().get("appareils", []):
        if a.get("compte") == compte:
            return a
    return None


def est_admis(compte: str) -> bool:
    """Cet appareil est-il connu ET encore admis ?"""
    a = get(compte)
    return bool(a and a.get("actif", False))


def profil_de(compte: str) -> str:
    a = get(compte)
    return (a or {}).get("profil") or "guest"


def inscris(compte: str, *, nom: str, profil: str, did: str,
            empreinte: str = "") -> Dict[str, Any]:
    """Inscrit ou met à jour un appareil. Écriture ATOMIQUE.

    LE NOM DÉCLARÉ EST CONSERVÉ TEL QUEL, comme étiquette — il vient d'un
    inconnu et ne désigne rien. C'est `compte`, dérivé de la clé, qui identifie.
    """
    d = _lit()
    liste = [a for a in d.get("appareils", []) if a.get("compte") != compte]
    liste.append({
        "compte": compte, "nom": nom, "profil": profil,
        "did": did, "empreinte": empreinte, "actif": True,
    })
    d["appareils"] = liste
    _ecrit(d)
    return liste[-1]


def revoque(compte: str) -> bool:
    """Retire l'accès SANS effacer la ligne : garder la trace évite qu'un
    appareil écarté revienne sans que personne ne s'en souvienne."""
    d = _lit()
    trouve = False
    for a in d.get("appareils", []):
        if a.get("compte") == compte:
            a["actif"] = False
            trouve = True
    if trouve:
        _ecrit(d)
    return trouve


def _ecrit(d: Dict[str, Any]) -> None:
    FICHIER.parent.mkdir(parents=True, exist_ok=True)
    # Temporaire DANS le même répertoire : `os.replace` n'est atomique qu'au
    # sein d'un même système de fichiers.
    fd, tmp = tempfile.mkstemp(dir=str(FICHIER.parent), prefix=".appareils.", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False, indent=1)
        os.chmod(tmp, 0o640)
        os.replace(tmp, FICHIER)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
