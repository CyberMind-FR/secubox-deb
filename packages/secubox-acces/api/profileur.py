# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Accès — LA FILE D'ADMISSION ET LES PROFILS (#1344).

POURQUOI CE MODULE N'EST PAS `secubox-users`. Ce qui se joue ici n'est pas la
gestion d'utilisateurs : c'est l'ouverture de SESSIONS à des appareils. Les deux
se ressemblent de loin et divergent partout :

    un utilisateur   a un nom, un mot de passe, des droits, une durée de vie
    une session      appartient à UN APPAREIL, se prouve par une clé, expire

Les loger ensemble menait à des phrases fausses dans l'interface — « profil
accordé » sur un écran qui affichait « non connecté » juste à côté.

    l'appareil engendre sa clé  →  il remplit le formulaire  →  DEMANDE
                                                                   ↓
    l'admin compare l'empreinte, tranche                   →  ACCEPTÉE (guest)
                                                                   ↓
    l'appareil SIGNE un défi                               →  SESSION ouverte
                                                                   ↓
    (plus tard, séparément)                                →  promotion en user

UNE ADMISSION N'A QU'UNE ISSUE : `guest`. `accepte()` ne prend pas de profil —
et c'est plus fort qu'un contrôle qui refuserait `admin`, parce qu'il n'y a rien
à contrôler. Monter en `user` puis `admin` passe par `promeut()`, qui se lit
comme un geste distinct dans le journal.
"""
from __future__ import annotations

import json
import re
import secrets
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Literal, Optional

from .identite import CleInvalide, charge_cle, empreinte_courte

#: Profils, du moins au plus doté. L'ORDRE COMPTE : il sert à comparer.
PROFILS = ("guest", "user", "admin")
PROFIL_ADMISSION = "guest"

#: Une demande non traitée finit par expirer — une file qui ne se vide jamais
#: cesse d'être lue, et une file qu'on ne lit plus ne sert à rien.
EXPIRATION_S = 14 * 24 * 3600

ETATS = ("en_attente", "acceptee", "refusee", "expiree")
Etat = Literal["en_attente", "acceptee", "refusee", "expiree"]

_RE_DID = re.compile(r"^did:[a-z0-9]+:[A-Za-z0-9._-]{8,128}$")


class DemandeInvalide(ValueError):
    """Le formulaire ou l'identité ne tient pas la route. Le message est
    destiné au demandeur : il doit dire QUOI corriger."""


@dataclass
class Demande:
    """Une demande d'accès — inscription, invitation et demande à la fois."""
    did: str
    cle_publique: str          # point P-256 SEC1 non compressé, hex (130 signes)
    nom: str
    message: str
    appareil: str
    demandee_le: int
    etat: Etat = "en_attente"
    traitee_le: Optional[int] = None
    traitee_par: Optional[str] = None
    profil: Optional[str] = None
    motif_refus: Optional[str] = None
    jeton: str = field(default_factory=lambda: secrets.token_urlsafe(16))
    #: Dernière session ouverte. Sert à l'administrateur : un appareil admis qui
    #: n'a JAMAIS ouvert de session est un parcours resté en plan, et c'est
    #: précisément ce qu'on ne voyait pas avant.
    session_le: Optional[int] = None

    @property
    def empreinte(self) -> str:
        return empreinte_courte(self.cle_publique)

    def expiree(self, maintenant: Optional[int] = None) -> bool:
        m = maintenant if maintenant is not None else int(time.time())
        return self.etat == "en_attente" and (m - self.demandee_le) > EXPIRATION_S

    def vue_admin(self) -> dict:
        d = asdict(self)
        d["empreinte"] = self.empreinte
        # Le jeton de suivi ne regarde QUE le demandeur : c'est avec lui qu'il
        # interroge l'état de sa demande sans être authentifié.
        d.pop("jeton", None)
        # La clé entière n'apprend rien à l'œil et allonge la file ; l'empreinte
        # est ce qu'on compare.
        d.pop("cle_publique", None)
        return d

    def vue_demandeur(self) -> dict:
        """Ce que le demandeur a le droit de savoir : où en est SA demande.

        Ni le motif de refus, ni qui a tranché. Un refus se dit ; il ne se
        justifie pas à qui l'a essuyé, sinon la file devient un terrain d'essai
        où l'on ajuste sa demande jusqu'à passer.
        """
        return {
            "etat": self.etat,
            "demandee_le": self.demandee_le,
            "empreinte": self.empreinte,
            "profil": self.profil if self.etat == "acceptee" else None,
            # Dit au client s'il lui reste quelque chose à faire. Sans ce
            # drapeau, l'interface ne peut pas distinguer « admis, session à
            # ouvrir » de « admis, session en cours » — la confusion exacte qui
            # affichait « accès accordé » à côté de « non connecté ».
            "session_ouverte": bool(self.session_le),
        }


def valide_demande(brut: dict) -> Demande:
    """Valide le formulaire. Lève `DemandeInvalide` avec un message utile."""
    if not isinstance(brut, dict):
        raise DemandeInvalide("formulaire illisible")

    did = str(brut.get("did", "")).strip()
    if not _RE_DID.match(did):
        raise DemandeInvalide("identifiant d'appareil hors format")

    cle = str(brut.get("cle_publique", "")).strip().lower()
    try:
        # ON CHARGE LA CLÉ POUR DE BON, on ne se contente pas d'une expression
        # régulière : un point bien formé mais hors courbe passerait le filtre
        # de forme et ne vérifierait jamais aucune signature. Mieux vaut le
        # refuser à l'entrée, quand on peut encore le dire au demandeur.
        charge_cle(cle)
    except CleInvalide as e:
        raise DemandeInvalide(str(e)) from e

    nom = str(brut.get("nom", "")).strip()
    if not 1 <= len(nom) <= 60:
        raise DemandeInvalide("le nom doit faire entre 1 et 60 caractères")

    # Champs libres BORNÉS à la lecture : un message de quarante mille signes
    # n'apporte rien à l'administrateur et alourdit la file pour tout le monde.
    message = str(brut.get("message", "")).strip()[:500]
    appareil = str(brut.get("appareil", "")).strip()[:60] or "appareil inconnu"

    return Demande(did=did, cle_publique=cle, nom=nom, message=message,
                   appareil=appareil, demandee_le=int(time.time()))


class Profileur:
    """La file d'admission, persistée en JSON.

    UNE DEMANDE PAR DID. Re-demander depuis le même appareil MET À JOUR la
    demande au lieu d'en empiler une seconde : sans cette règle, un client qui
    réessaie parce qu'il n'a pas vu de réponse remplit la file tout seul, et
    l'administrateur ne sait plus laquelle trancher.
    """

    def __init__(self, chemin: Path, creer_compte=None):
        self.chemin = Path(chemin)
        self._creer_compte = creer_compte
        self._demandes: dict[str, Demande] = {}
        self._relit()

    # — persistance ————————————————————————————————————————————————

    def _relit(self) -> None:
        try:
            brut = json.loads(self.chemin.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        for d in brut.get("demandes", []):
            try:
                self._demandes[d["did"]] = Demande(**d)
            except (TypeError, KeyError):
                continue      # une entrée corrompue ne perd pas les autres

    def _ecrit(self) -> None:
        self.chemin.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.chemin.with_suffix(".tmp")
        tmp.write_text(json.dumps(
            {"demandes": [asdict(d) for d in self._demandes.values()]},
            ensure_ascii=False, indent=1), encoding="utf-8")
        # Remplacement ATOMIQUE : une coupure pendant l'écriture ne doit pas
        # laisser une file tronquée.
        tmp.replace(self.chemin)

    # — côté demandeur ————————————————————————————————————————————

    def demande(self, brut: dict) -> Demande:
        d = valide_demande(brut)
        ancienne = self._demandes.get(d.did)
        if ancienne and ancienne.etat == "acceptee":
            # Déjà admis : on ne recrée pas de demande, on le lui dit.
            return ancienne
        if ancienne:
            d.jeton = ancienne.jeton      # le suivi reste valable
        self._demandes[d.did] = d
        self._ecrit()
        return d

    def suivi(self, did: str, jeton: str) -> Optional[dict]:
        """État de SA demande. Le jeton évite qu'un tiers sonde l'état d'un DID
        qu'il aurait deviné."""
        d = self._demandes.get(did)
        if not d or not secrets.compare_digest(d.jeton, jeton or ""):
            return None
        if d.expiree():
            d.etat = "expiree"
            self._ecrit()
        return d.vue_demandeur()

    def demande_de(self, did: str) -> Optional[Demande]:
        """La demande complète — réservée au portier, qui a besoin de la clé."""
        return self._demandes.get(did)

    def note_session(self, did: str) -> None:
        d = self._demandes.get(did)
        if d:
            d.session_le = int(time.time())
            self._ecrit()

    # — côté administrateur ————————————————————————————————————————

    def en_attente(self) -> list[dict]:
        maintenant = int(time.time())
        change = False
        for d in self._demandes.values():
            if d.expiree(maintenant):
                d.etat = "expiree"
                change = True
        if change:
            self._ecrit()
        return [d.vue_admin() for d in self._demandes.values()
                if d.etat == "en_attente"]

    def admis(self) -> list[dict]:
        """Les appareils qui ONT un accès. C'est la matière du profileur : on ne
        promeut pas une demande, on promeut un accès existant."""
        return [d.vue_admin() for d in self._demandes.values()
                if d.etat == "acceptee"]

    def accepte(self, did: str, *, par: str) -> Demande:
        """Admettre un appareil. L'issue est TOUJOURS `guest`.

        Pas de paramètre de profil, et c'est le cœur de la règle : accepter une
        invitation ouvre une SESSION, ça ne crée pas un utilisateur.
        """
        d = self._demandes.get(did)
        if not d:
            raise DemandeInvalide("demande inconnue")
        if d.etat != "en_attente":
            raise DemandeInvalide(f"demande déjà {d.etat}")

        d.etat = "acceptee"
        d.traitee_le = int(time.time())
        d.traitee_par = par
        d.profil = PROFIL_ADMISSION
        if self._creer_compte:
            self._creer_compte(d.nom, PROFIL_ADMISSION, d.did, d.cle_publique)
        self._ecrit()
        return d

    def refuse(self, did: str, *, par: str, motif: str = "") -> Demande:
        d = self._demandes.get(did)
        if not d:
            raise DemandeInvalide("demande inconnue")
        if d.etat != "en_attente":
            raise DemandeInvalide(f"demande déjà {d.etat}")
        d.etat = "refusee"
        d.traitee_le = int(time.time())
        d.traitee_par = par
        d.motif_refus = motif[:200]
        self._ecrit()
        return d

    def promeut(self, did: str, *, vers: str, par: str) -> Demande:
        """Change le profil d'un admis. C'est ICI que `admin` devient possible,
        et nulle part ailleurs."""
        d = self._demandes.get(did)
        if not d or d.etat != "acceptee":
            raise DemandeInvalide("aucun accès accordé à cet appareil")
        if vers not in PROFILS:
            raise DemandeInvalide(f"profil inconnu : {vers}")
        d.profil = vers
        d.traitee_par = par
        d.traitee_le = int(time.time())
        self._ecrit()
        return d

    def revoque(self, did: str, *, par: str) -> Demande:
        """Retire l'accès. La demande repasse en `refusee` plutôt que d'être
        effacée : garder la trace évite qu'un appareil écarté revienne sans que
        personne ne s'en souvienne."""
        d = self._demandes.get(did)
        if not d:
            raise DemandeInvalide("demande inconnue")
        d.etat = "refusee"
        d.profil = None
        d.session_le = None
        d.traitee_par = par
        d.traitee_le = int(time.time())
        d.motif_refus = "accès révoqué"
        self._ecrit()
        return d

    def profil_de(self, did: str) -> str:
        """Le profil effectif d'un appareil. `guest` tant qu'il n'est pas admis.

        NOTE — `guest` désigne donc à la fois celui qui n'a rien demandé et
        celui qui vient d'être admis. Ce n'est pas une confusion : ce qui les
        sépare n'est pas un droit, c'est une SESSION. L'admis peut en ouvrir
        une, l'inconnu non.
        """
        d = self._demandes.get(did)
        return d.profil if (d and d.etat == "acceptee" and d.profil) else "guest"
