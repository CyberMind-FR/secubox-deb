# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Accès — DU VERDICT À LA SESSION (#1344).

LE CHAÎNON QUI MANQUAIT. La file d'invitation savait dire « accepté ». Elle ne
savait pas OUVRIR quoi que ce soit : l'appareil affichait « Accès accordé »,
puis le Hall continuait de le voir comme un visiteur non connecté. Le parcours
s'arrêtait sur un mot.

Ce fichier ferme la boucle. Un appareil admis échange sa demande contre une
SESSION — le même cookie SSO que tout le reste de SecuBox, posé sur
`.gk2.secubox.in`, donc valable sur tous les vhosts d'un coup.

ET IL LA MÉRITE PAR UNE SIGNATURE, PAS PAR UN JETON RECOPIÉ. Le jeton de suivi
est un identifiant d'attente : il voyage, il s'affiche, il finit dans un
historique de navigation. S'il suffisait à ouvrir la session, le quiconque qui
le lirait entrerait à la place du demandeur — et l'empreinte comparée par
l'administrateur n'aurait servi à rien.

L'appareil prouve donc qu'il détient la clé privée dont l'empreinte a été
validée :

    1. il demande un DÉFI            → 32 octets aléatoires, à usage unique
    2. il le SIGNE                   → ECDSA P-256, clé non exportable
    3. la box vérifie la signature   → contre la clé publique QU'ELLE A ADMISE
    4. la box pose le cookie         → session `guest`

CE QUE CETTE CHAÎNE EMPÊCHE, concrètement : rejouer un défi (usage unique),
utiliser un défi émis pour un autre appareil (il est lié au DID), garder un défi
sous le coude (il expire), et entrer avec un jeton volé sans la clé (la
signature échoue).
"""
from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Optional

#: Durée de vie d'un défi. Assez pour une signature dans un navigateur (quelques
#: dizaines de millisecondes), beaucoup trop court pour être transporté ailleurs.
DEFI_TTL_S = 120

#: Plafond de défis en vol. Un défi tient 80 octets ; ce plafond borne la mémoire
#: même si quelqu'un en demande en boucle — et la cadence par IP fait le reste.
DEFIS_MAX = 512

#: Durée de la session ouverte. Un invité revient ; on ne le fait pas
#: redemander l'accès chaque matin.
SESSION_S = 7 * 24 * 3600


class SessionRefusee(Exception):
    """Le défi, la signature ou l'état de la demande ne permettent pas d'ouvrir.

    LE MESSAGE EST VOLONTAIREMENT PAUVRE. Distinguer « défi inconnu » de
    « signature fausse » apprendrait à qui essaie où il en est de son essai.
    """


@dataclass
class Defi:
    did: str
    valeur: str          # 64 signes hexadécimaux
    emis_le: float

    def perime(self, maintenant: Optional[float] = None) -> bool:
        m = maintenant if maintenant is not None else time.monotonic()
        return (m - self.emis_le) > DEFI_TTL_S


class Portier:
    """Émet les défis, vérifie les signatures, décide d'ouvrir.

    Le portier ne SAIT PAS qui a le droit d'entrer : il demande au profileur.
    Cette séparation est ce qui permet de tester l'un sans l'autre — et
    d'empêcher qu'un correctif de session touche par mégarde à la file.
    """

    def __init__(self, profileur, verifie_signature):
        self._profileur = profileur
        self._verifie = verifie_signature
        self._defis: dict[str, Defi] = {}

    # — le défi ————————————————————————————————————————————————————

    def defi(self, did: str, jeton: str) -> str:
        """Émet un défi pour un appareil ADMIS. Lève sinon.

        On exige déjà le jeton de suivi ici : sans lui, n'importe qui pourrait
        faire émettre des défis pour un DID deviné, et s'en servir pour mesurer
        qui a été admis.
        """
        vue = self._profileur.suivi(did, jeton)
        if not vue or vue.get("etat") != "acceptee":
            raise SessionRefusee("accès non accordé")

        self._purge()
        if len(self._defis) >= DEFIS_MAX:
            raise SessionRefusee("trop de demandes en cours")

        d = Defi(did=did, valeur=secrets.token_hex(32), emis_le=time.monotonic())
        self._defis[d.valeur] = d
        return d.valeur

    def _purge(self) -> None:
        for v, d in list(self._defis.items()):
            if d.perime():
                del self._defis[v]

    # — l'ouverture ————————————————————————————————————————————————

    def ouvre(self, did: str, jeton: str, defi: str, signature: str) -> dict:
        """Vérifie la preuve et rend de quoi poser la session.

        LE DÉFI EST CONSOMMÉ AVANT MÊME D'ÊTRE JUGÉ. On le retire de la table
        dès qu'on le retrouve, quelle que soit la suite : une signature fausse
        ne doit pas laisser le défi disponible pour un second essai, sinon
        l'attaquant dispose d'autant de tentatives qu'il veut sur la même cible.
        """
        d = self._defis.pop(defi, None)
        if d is None or d.perime() or d.did != did:
            raise SessionRefusee("preuve invalide")

        vue = self._profileur.suivi(did, jeton)
        if not vue or vue.get("etat") != "acceptee":
            raise SessionRefusee("accès non accordé")

        demande = self._profileur.demande_de(did)
        if demande is None:
            raise SessionRefusee("accès non accordé")

        # Le message signé est le défi LUI-MÊME, en octets bruts. On ne signe
        # pas sa représentation hexadécimale : deux implémentations qui
        # choisiraient différemment ne se comprendraient jamais, et le débogage
        # de ce désaccord coûte une journée.
        if not self._verifie(demande.cle_publique, bytes.fromhex(defi), signature):
            raise SessionRefusee("preuve invalide")

        return {
            "nom": demande.nom,
            "profil": demande.profil or "guest",
            "did": did,
            "duree": SESSION_S,
        }
