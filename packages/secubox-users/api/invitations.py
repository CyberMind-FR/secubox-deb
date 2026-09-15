# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: LE PROFILEUR — file d'invitation et profils (#1297).

CE QUE ÇA AJOUTE À secubox-users. Le module savait déjà gérer des comptes, des
groupes, des rôles et des ACL. Il ne savait pas accueillir quelqu'un qui n'a
pas encore de compte : il n'y avait ni inscription, ni file d'attente, ni
validation. C'est ce chaînon-là, et lui seul, qu'on écrit ici.

LE PARCOURS, EN UN COUP D'ŒIL

    le client engendre sa clé  →  il remplit le formulaire  →  DEMANDE
                                                                  ↓
    l'admin voit la demande, compare l'empreinte, tranche  →  ACCEPTÉE
                                                                  ↓
    compte créé au profil `user`  →  le client sonde et s'enregistre seul

SANS QR CODE, ET SANS SECRET À RECOPIER. Rien de confidentiel ne circule : le
client publie sa clé PUBLIQUE, l'administrateur décide. Le garde-fou contre la
validation d'un mauvais appareil n'est pas un code à saisir mais une EMPREINTE
COURTE, affichée des deux côtés — à comparer d'un coup d'œil.

LE PROFIL D'ADMISSION EST TOUJOURS `user`. Jamais `admin`, jamais par
inadvertance, jamais parce qu'un champ du formulaire le demandait. La promotion
est un geste à part, explicite, fait après coup.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Literal, Optional

#: Profils, du moins au plus doté. L'ORDRE COMPTE : il sert à comparer.
PROFILS = ("guest", "user", "admin")
PROFIL_ADMISSION = "user"

#: Une demande non traitée finit par expirer — une file qui ne se vide jamais
#: cesse d'être lue, et une file qu'on ne lit plus ne sert à rien.
EXPIRATION_S = 14 * 24 * 3600

ETATS = ("en_attente", "acceptee", "refusee", "expiree")
Etat = Literal["en_attente", "acceptee", "refusee", "expiree"]

_RE_DID = re.compile(r"^did:[a-z0-9]+:[A-Za-z0-9._-]{8,128}$")
_RE_HEX32 = re.compile(r"^[0-9a-f]{64}$")


class DemandeInvalide(ValueError):
    """Le formulaire ou l'identité ne tient pas la route. Le message est
    destiné au demandeur : il doit dire QUOI corriger."""


def empreinte_courte(cle_publique_hex: str) -> str:
    """Six groupes de quatre, dérivés de la clé publique.

    C'EST LE REMPLAÇANT DU QR CODE. Affichée sur le client et dans le panneau
    d'administration, elle se compare d'un regard. On la découpe parce qu'une
    chaîne de 24 signes d'affilée ne se compare pas — l'œil décroche au
    huitième.
    """
    brut = hashlib.sha256(bytes.fromhex(cle_publique_hex)).hexdigest()[:24]
    return " ".join(brut[i:i + 4] for i in range(0, 24, 4))


@dataclass
class Demande:
    """Une demande d'accès. C'est à la fois l'inscription, l'invitation et la
    demande d'accès — un seul geste, trois noms pour la même chose."""
    did: str
    cle_publique: str          # X25519 publique, hex (64 signes)
    nom: str                   # ce que le demandeur déclare
    message: str               # pourquoi il demande — lu par l'admin
    appareil: str              # « iPhone de Gérald » : ce qui aide à trancher
    demandee_le: int
    etat: Etat = "en_attente"
    traitee_le: Optional[int] = None
    traitee_par: Optional[str] = None
    profil: Optional[str] = None
    motif_refus: Optional[str] = None
    jeton: str = field(default_factory=lambda: secrets.token_urlsafe(16))

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
        return d

    def vue_demandeur(self) -> dict:
        """Ce que le demandeur a le droit de savoir : où en est SA demande.

        On ne rend ni le motif de refus, ni qui a tranché. Un refus se dit ; il
        ne se justifie pas à qui l'a essuyé, sinon la file devient un terrain
        d'essai où l'on ajuste sa demande jusqu'à passer.
        """
        return {
            "etat": self.etat,
            "demandee_le": self.demandee_le,
            "empreinte": self.empreinte,
            "profil": self.profil if self.etat == "acceptee" else None,
        }


def valide_demande(brut: dict) -> Demande:
    """Valide le formulaire. Lève `DemandeInvalide` avec un message utile."""
    if not isinstance(brut, dict):
        raise DemandeInvalide("formulaire illisible")

    did = str(brut.get("did", "")).strip()
    if not _RE_DID.match(did):
        raise DemandeInvalide("identifiant d'appareil hors format")

    cle = str(brut.get("cle_publique", "")).strip().lower()
    if not _RE_HEX32.match(cle):
        raise DemandeInvalide("clé publique invalide : 32 octets hexadécimaux attendus")

    nom = str(brut.get("nom", "")).strip()
    if not 1 <= len(nom) <= 60:
        raise DemandeInvalide("le nom doit faire entre 1 et 60 caractères")

    # Les champs libres sont BORNÉS à la lecture. Un message de quarante mille
    # signes n'apporte rien à l'administrateur et alourdit la file pour tout le
    # monde.
    message = str(brut.get("message", "")).strip()[:500]
    appareil = str(brut.get("appareil", "")).strip()[:60] or "appareil inconnu"

    return Demande(did=did, cle_publique=cle, nom=nom, message=message,
                   appareil=appareil, demandee_le=int(time.time()))


class Profileur:
    """La file d'invitation, persistée en JSON.

    UNE DEMANDE PAR DID. Re-demander depuis le même appareil MET À JOUR la
    demande au lieu d'en empiler une seconde : sans cette règle, un client qui
    réessaie parce qu'il n'a pas vu de réponse remplit la file tout seul, et
    l'administrateur ne sait plus laquelle trancher.
    """

    def __init__(self, chemin: Path, creer_compte=None):
        self.chemin = Path(chemin)
        # `creer_compte(nom, profil, did)` est injecté : le profileur ne sait
        # pas créer un compte, il sait DÉCIDER qu'il faut en créer un. C'est
        # secubox-users qui sait, et les tests qui s'en passent.
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
        """État de SA demande. Le jeton évite qu'un tiers sonde l'état d'un
        DID qu'il aurait deviné."""
        d = self._demandes.get(did)
        if not d or not secrets.compare_digest(d.jeton, jeton or ""):
            return None
        if d.expiree():
            d.etat = "expiree"
            self._ecrit()
        return d.vue_demandeur()

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

    def accepte(self, did: str, *, par: str,
                profil: str = PROFIL_ADMISSION) -> Demande:
        d = self._demandes.get(did)
        if not d:
            raise DemandeInvalide("demande inconnue")
        if d.etat != "en_attente":
            raise DemandeInvalide(f"demande déjà {d.etat}")
        if profil not in PROFILS:
            raise DemandeInvalide(f"profil inconnu : {profil}")
        if profil == "admin":
            # L'admission ne fabrique jamais un administrateur. Promouvoir est
            # un geste séparé, fait en connaissance de cause sur un compte qui
            # existe déjà.
            raise DemandeInvalide(
                "l'admission ne crée pas d'administrateur — accepter puis promouvoir")

        d.etat = "acceptee"
        d.traitee_le = int(time.time())
        d.traitee_par = par
        d.profil = profil
        if self._creer_compte:
            self._creer_compte(d.nom, profil, d.did)
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
        effacée : garder la trace évite qu'un appareil écarté revienne sans
        que personne ne s'en souvienne."""
        d = self._demandes.get(did)
        if not d:
            raise DemandeInvalide("demande inconnue")
        d.etat = "refusee"
        d.profil = None
        d.traitee_par = par
        d.traitee_le = int(time.time())
        d.motif_refus = "accès révoqué"
        self._ecrit()
        return d

    def profil_de(self, did: str) -> str:
        """Le profil effectif d'un appareil. `guest` tant qu'il n'est pas
        admis — c'est ce qui fait qu'une PWA fraîchement installée n'a qu'une
        seule carlette."""
        d = self._demandes.get(did)
        return d.profil if (d and d.etat == "acceptee" and d.profil) else "guest"
