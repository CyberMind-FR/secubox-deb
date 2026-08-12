# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — réveil des applications Streamlit (#1018).

POURQUOI CE MODULE EXISTE À PART DES MANIFESTES.

Le réveilleur résout un vhost vers un *module*, via les manifestes de
`modules.d`. Les applications Streamlit ne sont pas des modules : elles sont
créées dynamiquement par la forge, à la demande de l'utilisateur. Leur donner
un manifeste tenu à la main dériverait dès la création suivante — précisément
le défaut que ce correctif répare.

Elles ont en revanche une propriété stable et vérifiable : une application
`X` est servie par l'unité `streamlit-app@X.service` **dans le conteneur**, et
son vhost est `X.<domaine>`. Ce module fait ce seul pont, et rien d'autre.

Il ne pilote pas systemd lui-même : la commande privilégiée est confiée au
ctl root (`secubox-wakectl`), comme le réveil des modules.
"""

from __future__ import annotations

import re
from typing import Callable

# Le nom d'application entre dans un nom d'unité systemd DÉMARRÉ EN ROOT.
#
# La liste blanche n'est pas cosmétique : un nom porteur de `..`, d'espace, de
# `/` ou d'un métacaractère permettrait de désigner une autre unité que celle
# voulue. On accepte donc exactement ce que la forge produit — lettres,
# chiffres, tiret, souligné — et rien de plus.
#
# `@` est exclu en particulier : il séparerait un second niveau d'instance.
# Le nom DOIT commencer par une lettre ou un chiffre. Un nom ouvrant sur `-`
# serait pris pour une option par la premiere commande qui le placerait ailleurs
# dans une ligne d'arguments — et « - » seul, que la forge ne produit jamais,
# n'aurait designe aucune application.
_NOM_APP = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")

CONTENEUR = "streamlit"
UNITE = "streamlit-app@{}.service"


def nom_valide(app: str) -> bool:
    """Le nom est-il sûr à insérer dans un nom d'unité ?"""
    return bool(_NOM_APP.match(app or ""))


def app_depuis_vhost(vhost: str) -> str | None:
    """L'application servie par ce vhost, ou None.

    L'application est la PREMIÈRE étiquette du nom : `cpf.gk2.secubox.in` est
    servi par `streamlit-app@cpf`. Vérifié sur sept applications de gk2 —
    `cpf`, `hermes`, `yling`, `pdf`, `files_40`, `secubox_control`,
    `fabricator` — toutes chargées sous ce nom.

    Rend None si l'étiquette ne passe pas la liste blanche : mieux vaut ne pas
    réveiller que réveiller n'importe quoi.
    """
    if not vhost or "." not in vhost:
        return None
    app = vhost.split(".", 1)[0]
    return app if nom_valide(app) else None


def vhosts_streamlit(routes: dict, ip_conteneur: str) -> list[str]:
    """Les vhosts routés vers le conteneur Streamlit.

    LA LISTE SE DÉDUIT DES ROUTES, elle ne se tient pas à la main. Une liste
    figée manquerait la prochaine application créée, et celle-ci rendrait 502
    sans que rien ne le signale — c'est exactement l'état qu'on répare : 28
    vhosts routés, 1 seul déclaré.

    `routes` est le fichier que lit sbxwaf : {vhost: [ip, port]}.
    """
    out = []
    for vhost, cible in (routes or {}).items():
        try:
            ip = cible[0]
        except (TypeError, IndexError):
            continue
        if ip == ip_conteneur and app_depuis_vhost(vhost):
            out.append(vhost)
    return sorted(set(out))


def reveille(app: str, *, run: Callable[[list[str]], tuple], conteneur: str = CONTENEUR,
             lxc_path: str = "/data/lxc") -> dict:
    """Démarre l'unité de l'application dans le conteneur.

    Ne juge pas si l'application existe : `systemctl start` sur une unité
    absente échoue proprement et le dit. Dupliquer ce test ici ajouterait un
    aller-retour et une seconde vérité à tenir à jour.
    """
    if not nom_valide(app):
        return {"status": "refused", "app": app, "reason": "nom invalide"}
    rc, sortie = run([
        "/usr/bin/lxc-attach", "-n", conteneur, "-P", lxc_path, "--",
        "systemctl", "start", UNITE.format(app),
    ])
    if rc == 0:
        return {"status": "woken", "app": app}
    return {"status": "failed", "app": app, "rc": rc, "detail": (sortie or "")[:200]}
