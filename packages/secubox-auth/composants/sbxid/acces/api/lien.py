# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Accès — LE LIEN D'ENTRÉE À USAGE UNIQUE (#1354).

CE QU'IL EST, ET POURQUOI IL EST PLUS FAIBLE QUE LE RESTE.

Le parcours normal fait entrer un appareil en lui faisant SIGNER un défi : il
faut détenir la clé, et la clé ne sort pas du navigateur. Un lien, lui, est un
PORTEUR — il suffit de le lire pour s'en servir. Quiconque voit l'écran, le
courriel ou l'historique entre à la place du destinataire.

On l'accepte quand même, pour un cas que la signature ne couvre pas : la clé
vit PAR ORIGINE et PAR NAVIGATEUR. Quelqu'un qui a demandé l'accès depuis son
téléphone et qui ouvre SecuBox depuis son ordinateur n'a aucune clé à présenter,
et se retrouverait à redemander un accès qu'on vient de lui accorder.

CE QUE LA FAIBLESSE IMPOSE, ET QU'ON APPLIQUE :

    usage unique      consommé à la première présentation, réussie ou non.
                      CE N'EST PAS QU'UNE LIMITE, C'EST UN DÉTECTEUR : il
                      n'empêche pas l'interception, il la REND VISIBLE. Si le
                      destinataire légitime trouve un lien qui ne marche plus,
                      il sait que quelqu'un est passé avant lui — et peut le
                      dire. Un lien réutilisable laisserait les deux entrer
                      sans que personne ne s'en aperçoive.
    courte durée      quelques heures, pas quelques jours
    haute entropie    32 octets — on ne devine pas, on ne force pas
    profil plafonné   il ouvre une session `guest`, jamais davantage
    montré une fois   il n'est pas relu ; ce qui n'est pas noté est perdu

CE QU'ON NE FAIT PAS. On ne l'envoie pas par courriel depuis la box : poser une
chaîne SMTP fiable est un projet en soi, et un lien d'entrée qui échoue
silencieusement en route est pire qu'un lien qu'on recopie à la main. Il est
rendu À L'ADMINISTRATEUR, une fois, au moment où il accorde — à lui de le
transmettre par le canal qu'il juge bon.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Optional

#: Durée de vie. Assez pour être transmis et suivi dans la foulée, trop court
#: pour dormir dans une boîte de réception.
TTL_S = 6 * 3600

#: Plafond de liens en vol. Chacun tient une centaine d'octets ; ce plafond
#: borne la mémoire si quelqu'un en fait émettre en boucle.
MAX = 256


class LienInvalide(Exception):
    """Inconnu, périmé, ou déjà servi.

    UN SEUL MESSAGE POUR LES TROIS. Distinguer « inconnu » de « déjà servi »
    apprendrait à qui essaie qu'un lien a existé — et donc qu'une personne a
    été admise.
    """


@dataclass
class Lien:
    did: str
    #: On garde l'EMPREINTE du jeton, pas le jeton. Un fichier de journal, une
    #: trace mémoire ou un vidage ne doivent pas rendre le lien réutilisable.
    empreinte: str
    emis_le: float

    def perime(self, maintenant: Optional[float] = None) -> bool:
        m = maintenant if maintenant is not None else time.monotonic()
        return (m - self.emis_le) > TTL_S


def _empreinte(jeton: str) -> str:
    return hashlib.sha256(jeton.encode("utf-8")).hexdigest()


class Liens:
    """Émet et consomme les liens d'entrée. En mémoire, volontairement.

    UN REDÉMARRAGE LES ANNULE, et c'est un comportement acceptable pour un
    porteur à courte durée : le pire cas est qu'on en redemande un. Les
    persister ferait vivre sur disque des jetons d'entrée pour six heures, ce
    qu'aucune de leurs propriétés ne réclame.
    """

    def __init__(self):
        self._liens: dict[str, Lien] = {}

    def emet(self, did: str) -> str:
        self._purge()
        if len(self._liens) >= MAX:
            raise LienInvalide("trop de liens en cours")
        jeton = secrets.token_urlsafe(32)
        e = _empreinte(jeton)
        self._liens[e] = Lien(did=did, empreinte=e, emis_le=time.monotonic())
        return jeton

    def consomme(self, jeton: str) -> str:
        """Rend le DID, et INVALIDE le lien. Lève `LienInvalide` sinon.

        LE LIEN EST RETIRÉ AVANT D'ÊTRE JUGÉ — comme le défi de signature. Une
        présentation ratée ne doit pas le laisser disponible pour une seconde
        tentative, sinon celui qui l'a intercepté dispose d'autant d'essais
        qu'il veut.
        """
        e = _empreinte(jeton or "")
        # `pop` avec comparaison à temps constant sur ce qu'on a trouvé : la
        # recherche par empreinte ne fuit rien, mais on reste homogène avec le
        # reste du module.
        lien = self._liens.pop(e, None)
        if lien is None or lien.perime() or not hmac.compare_digest(lien.empreinte, e):
            raise LienInvalide("lien invalide ou expiré")
        return lien.did

    def _purge(self) -> None:
        for k, v in list(self._liens.items()):
            if v.perime():
                del self._liens[k]
