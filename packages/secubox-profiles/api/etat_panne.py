# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Profils — qualifier une panne avant de l'afficher.

POURQUOI CE MODULE EXISTE

« Ce service ne répond pas » est vrai dans quatre situations qui n'appellent
pas du tout la même réaction :

  - il **démarre** — il faut attendre, et rafraîchir a un sens ;
  - il **redémarre en boucle** — attendre ne sert à rien, et relancer non plus :
    il a déjà essayé des milliers de fois ;
  - il est **arrêté** — quelqu'un doit le relever ;
  - il **répond trop lentement** (504) — il tourne, mais n'aboutit pas : c'est
    une panne de charge ou de dépendance, pas d'absence.

Servir le même texte aux quatre, c'est laisser l'utilisateur deviner. Le cas de
zigbee le montre : la page disait « rien ne va le relever tout seul » alors que
le service se relançait une fois par minute depuis 4050 tentatives — l'inverse
de ce qui se passait.

CE MODULE NE DÉCIDE RIEN, IL CONSTATE. C'est délibéré : il est lu par une page
d'erreur, donc par du code qui doit rester rapide et sans effet de bord. Aucune
action n'est déclenchée ici.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass

# Un module qui a redémarré plus que ça sur la fenêtre observée est considéré
# comme battant. Le seuil est bas EXPRÈS : trois relances rapprochées suffisent
# à dire qu'attendre ne sert à rien, et se tromper coûte seulement un message
# plus prudent.
SEUIL_BATTEMENT = 3

ETAT_DEMARRE = "demarre"
ETAT_BATTEMENT = "battement"
ETAT_ARRETE = "arrete"
ETAT_LENT = "lent"
ETAT_INCONNU = "inconnu"


@dataclass(frozen=True)
class Panne:
    """Ce qu'on sait de l'état d'un module au moment de rendre la page."""

    etat: str
    titre: str
    explication: str
    action: str
    # `reessayer` porte le nombre de secondes à conseiller au navigateur, ou
    # None quand rafraîchir ne servirait à rien. C'est la différence visible
    # entre « patiente » et « ne reste pas là ».
    reessayer: int | None
    redemarrages: int = 0


def _systemctl(unite: str, propriete: str, *, conteneur: str | None = None) -> str:
    """Lit une propriété systemd, dans l'hôte ou dans un conteneur.

    Toute erreur rend une chaîne vide : cette fonction sert une page d'erreur,
    elle n'a pas le droit d'en produire une autre.
    """
    if conteneur:
        if not shutil.which("lxc-attach"):
            return ""
        cmd = ["lxc-attach", "-n", conteneur, "-P", "/data/lxc", "--",
               "systemctl", "show", unite, "-p", propriete, "--value"]
    else:
        cmd = ["systemctl", "show", unite, "-p", propriete, "--value"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=4)
    except (OSError, subprocess.SubprocessError):
        return ""
    return r.stdout.strip() if r.returncode == 0 else ""


def qualifie(unite: str, *, conteneur: str | None = None,
             statut_amont: int = 502) -> Panne:
    """Qualifie la panne d'un module déclaré toujours actif."""

    # UN 504 SE DISTINGUE AVANT TOUT LE RESTE. Le service tourne — il a accepté
    # la connexion — mais n'a pas répondu dans le temps imparti. Aller
    # interroger systemd dirait « active » et ferait conclure à tort que tout
    # va bien.
    if statut_amont == 504:
        return Panne(
            etat=ETAT_LENT,
            titre="Ce service met trop de temps à répondre",
            explication=(
                "Il tourne et accepte les connexions, mais n'a pas terminé sa "
                "réponse dans le délai accordé. C'est une panne de lenteur, pas "
                "d'absence : le redémarrer masquerait la cause."
            ),
            action=(
                "Regardez la charge de la board et les dépendances du module "
                "(base de données, service amont). Un premier accès après un "
                "réveil peut légitimement dépasser le délai."
            ),
            reessayer=15,
        )

    sous_etat = _systemctl(unite, "SubState", conteneur=conteneur)
    actif = _systemctl(unite, "ActiveState", conteneur=conteneur)
    brut = _systemctl(unite, "NRestarts", conteneur=conteneur)
    redem = int(brut) if brut.isdigit() else 0

    if sous_etat in ("start", "start-pre", "start-post", "auto-restart") or actif == "activating":
        # `auto-restart` est le cas le plus trompeur : systemd le rapporte comme
        # « activating », donc comme un démarrage — alors qu'il s'agit d'une
        # relance après échec. Le compteur de redémarrages tranche.
        if redem >= SEUIL_BATTEMENT:
            return _battement(redem)
        return Panne(
            etat=ETAT_DEMARRE,
            titre="Ce service démarre",
            explication=(
                "Il est en cours de lancement. Certains modules chargent des "
                "index ou attendent une dépendance avant d'ouvrir leur port."
            ),
            action="Cette page se rafraîchit toute seule. Laissez-lui un instant.",
            reessayer=5,
            redemarrages=redem,
        )

    if redem >= SEUIL_BATTEMENT:
        return _battement(redem)

    return Panne(
        etat=ETAT_ARRETE if actif in ("inactive", "failed", "") else ETAT_INCONNU,
        titre="Ce service ne répond pas",
        explication=(
            "Il est déclaré <strong>toujours actif</strong> : il devrait tourner "
            "en permanence, et il ne tourne pas. Aucun réveil automatique ne le "
            "concerne — le réveil à la demande ne s'applique qu'aux modules mis "
            "en veille délibérément."
        ),
        action=(
            "Rafraîchir cette page n'y changera rien. Il faut le relever depuis "
            "la console, ou regarder pourquoi il s'est arrêté."
        ),
        reessayer=None,
        redemarrages=redem,
    )


def _battement(redem: int) -> Panne:
    """Le service se relance en boucle : le dire, plutôt que d'inviter à attendre."""
    return Panne(
        etat=ETAT_BATTEMENT,
        titre="Ce service redémarre en boucle",
        explication=(
            f"Il a déjà été relancé <strong>{redem} fois</strong> et échoue à "
            "chaque tentative. La panne est donc reproductible : ce n'est pas un "
            "incident passager, et une relance de plus donnerait le même résultat."
        ),
        action=(
            "Ne relancez pas — regardez son journal. Une boucle de redémarrage "
            "consomme du processeur en continu sans jamais aboutir."
        ),
        reessayer=None,
        redemarrages=redem,
    )
