# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: COURTIER DE JETONS APPLICATIFS (#1298).

L'IDÉE. La box détient déjà des identifiants d'ADMINISTRATION pour ses services
embarqués — `/etc/secubox/secrets/peertube-admin`, l'`occ` de Nextcloud. Avec
eux, elle peut émettre, POUR CHAQUE UTILISATEUR ET CHAQUE APPLICATION, un jeton
dédié : un mot de passe d'application Nextcloud, un jeton d'API Gitea, un jeton
OAuth PeerTube.

CE QUE ÇA ÉVITE. Le mot de passe réel de l'utilisateur n'est jamais demandé,
jamais transmis, jamais stocké. La box ne l'a pas et n'en a pas besoin : elle
crée un jeton à côté.

RÉVOCABLE DES DEUX CÔTÉS, littéralement :
  • côté service — le jeton se retire dans l'application elle-même (un mot de
    passe d'application Nextcloud se révoque depuis Nextcloud, sans nous) ;
  • côté box — `revoque()` le retire par l'API d'administration, et l'appareil
    perd l'accès sans que l'utilisateur ait à changer quoi que ce soit ailleurs.

LE JETON NE VOYAGE JAMAIS EN CLAIR. Il est SCELLÉ pour la clé X25519 de
l'appareil qui l'a demandé (`Identity`/`Session` de secubox_core.crypto,
X25519 ECDH → HKDF-SHA256 → AES-256-GCM). Conséquence pratique : un jeton
intercepté est inutilisable, et un jeton destiné au téléphone ne s'ouvre pas sur
la tablette — chaque appareil a sa clé, donc son propre scellé.

L'AAD LIE LE SCELLÉ À SON CONTEXTE. On authentifie `did|service|utilisateur`
en donnée additionnelle : un scellé ne peut pas être présenté comme étant celui
d'un autre service ou d'un autre compte, même par qui l'a légitimement reçu.
"""
from __future__ import annotations

import json
import logging
import subprocess
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional, Protocol

log = logging.getLogger("secubox.identity.jetons")

#: Où l'on note ce qui a été émis. On garde de quoi RÉVOQUER — jamais le jeton.
REGISTRE = Path("/var/lib/secubox/identity/jetons-app.jsonl")


class JetonIndisponible(RuntimeError):
    """L'émission a échoué, et on le dit plutôt que de rendre un jeton factice."""


@dataclass(frozen=True)
class JetonEmis:
    """Ce qu'on retient d'une émission. `reference` sert à révoquer."""
    did: str            # l'appareil destinataire
    service: str        # "nextcloud", "peertube", "gitea"…
    utilisateur: str    # le compte DANS le service
    reference: str      # ce qu'il faut pour révoquer (id, nom, empreinte)
    emis_le: int

    def ligne(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)


class Minteur(Protocol):
    """Ce qu'un service doit savoir faire pour entrer dans le courtier.

    Trois verbes, pas un de plus. Un service qui ne sait pas RÉVOQUER n'a rien
    à faire ici : émettre sans pouvoir reprendre serait offrir un accès
    définitif à un appareil qu'on pourrait vouloir écarter.
    """

    nom: str

    def emet(self, utilisateur: str, etiquette: str) -> tuple[str, str]:
        """Rend (jeton, reference). La référence sert à `revoque`."""
        ...

    def revoque(self, utilisateur: str, reference: str) -> bool:
        ...


# ─────────────────────────────────────────────────────────────────────────────
# Nextcloud — le cas le plus propre
# ─────────────────────────────────────────────────────────────────────────────

class MinteurNextcloud:
    """Mot de passe d'application Nextcloud.

    POURQUOI C'EST LE MEILLEUR CAS. Nextcloud a une primitive FAITE POUR ÇA :
    un mot de passe d'application est par-utilisateur, par-appareil, visible
    dans les réglages du compte, et révocable par l'utilisateur LUI-MÊME. On ne
    détourne rien — on emploie le mécanisme prévu.
    """

    nom = "nextcloud"

    def __init__(self, occ: str = "/var/www/nextcloud/occ",
                 php: str = "php", delai_s: int = 30):
        self.occ, self.php, self.delai_s = occ, php, delai_s

    def _occ(self, *args: str) -> str:
        p = subprocess.run([self.php, self.occ, *args],
                           capture_output=True, text=True, timeout=self.delai_s)
        if p.returncode != 0:
            raise JetonIndisponible(
                f"occ {' '.join(args[:2])} : {p.stderr.strip()[:200]}")
        return p.stdout.strip()

    def emet(self, utilisateur: str, etiquette: str) -> tuple[str, str]:
        # L'étiquette est ce que l'utilisateur VERRA dans ses réglages Nextcloud.
        # Elle doit donc nommer l'appareil, pas un identifiant technique : c'est
        # ce qui lui permet de reconnaître — et de révoquer — le bon.
        sortie = self._occ("user:add-app-password", utilisateur, "--name", etiquette)
        jeton = sortie.split()[-1] if sortie else ""
        if not jeton:
            raise JetonIndisponible("occ n'a rendu aucun mot de passe")
        return jeton, etiquette

    def revoque(self, utilisateur: str, reference: str) -> bool:
        # Nextcloud ne révoque pas par nom en ligne de commande ; l'utilisateur
        # le fait depuis ses réglages. On le DIT plutôt que de prétendre l'avoir
        # fait — un `return True` menteur laisserait croire à un accès coupé.
        log.info("nextcloud: révocation de %r pour %s à faire dans les réglages "
                 "du compte (occ ne l'expose pas)", reference, utilisateur)
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Les autres services — déclarés, pas simulés
# ─────────────────────────────────────────────────────────────────────────────

class MinteurNonImplemente:
    """Place tenue pour un service qu'on n'a pas encore câblé.

    Il EXISTE et il REFUSE, au lieu d'être absent. La différence compte : une
    carlette peut alors afficher « pas encore disponible » plutôt que de
    disparaître ou d'échouer sans explication.
    """

    def __init__(self, nom: str, raison: str):
        self.nom, self.raison = nom, raison

    def emet(self, utilisateur: str, etiquette: str) -> tuple[str, str]:
        raise JetonIndisponible(f"{self.nom} : {self.raison}")

    def revoque(self, utilisateur: str, reference: str) -> bool:
        return False


def minteurs_par_defaut() -> dict[str, Minteur]:
    return {
        "nextcloud": MinteurNextcloud(),
        "peertube": MinteurNonImplemente(
            "peertube", "jeton OAuth via le compte admin — à câbler (#1298)"),
        "gitea": MinteurNonImplemente(
            "gitea", "jeton d'API via le compte admin — à câbler (#1298)"),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Le courtier
# ─────────────────────────────────────────────────────────────────────────────

class Courtier:
    """Émet un jeton applicatif et le SCELLE pour l'appareil demandeur.

    `sceller` est injecté plutôt qu'importé : c'est `IdentityManager.seal_for`
    en production, et une fonction d'essai dans les tests. Le courtier n'a pas
    à savoir comment le scellé est fait — seulement qu'il l'est.
    """

    def __init__(self, sceller, minteurs: Optional[dict] = None,
                 registre: Path = REGISTRE):
        self._sceller = sceller
        self.minteurs = minteurs or minteurs_par_defaut()
        self.registre = Path(registre)

    def _note(self, j: JetonEmis) -> None:
        try:
            self.registre.parent.mkdir(parents=True, exist_ok=True)
            with self.registre.open("a", encoding="utf-8") as f:
                f.write(j.ligne() + "\n")
        except OSError as e:
            # Ne pas pouvoir NOTER n'annule pas l'émission — mais il faut que ça
            # se voie, sinon un jeton devient irrévocable en silence.
            log.error("registre de jetons illisible (%s) : %s restera à "
                      "révoquer à la main", e, j.reference)

    def emet(self, *, did: str, cle_publique_hex: str, service: str,
             utilisateur: str, etiquette: str) -> bytes:
        """Émet, note, scelle. Rend le SCELLÉ — le jeton clair ne sort jamais
        de cette fonction."""
        m = self.minteurs.get(service)
        if m is None:
            raise JetonIndisponible(f"service inconnu : {service}")

        jeton, reference = m.emet(utilisateur, etiquette)
        self._note(JetonEmis(did=did, service=service, utilisateur=utilisateur,
                             reference=reference, emis_le=int(time.time())))

        # L'AAD lie le scellé à SON contexte : ni un autre service, ni un autre
        # compte, ni un autre appareil ne peuvent le revendiquer.
        aad = f"{did}|{service}|{utilisateur}".encode("utf-8")
        charge = json.dumps({
            "service": service, "utilisateur": utilisateur,
            "jeton": jeton, "emis_le": int(time.time()),
        }, ensure_ascii=False).encode("utf-8")
        return self._sceller(cle_publique_hex, charge, aad=aad)

    def revoque(self, *, did: str, service: str, utilisateur: str,
                reference: str) -> bool:
        m = self.minteurs.get(service)
        if m is None:
            return False
        fait = m.revoque(utilisateur, reference)
        self._note(JetonEmis(did=did, service=service, utilisateur=utilisateur,
                             reference=f"REVOQUE:{reference}" if fait
                             else f"REVOCATION-MANUELLE:{reference}",
                             emis_le=int(time.time())))
        return fait

    def emis_pour(self, did: str) -> list[dict]:
        """Ce qui a été émis pour un appareil — de quoi lui montrer, et
        révoquer. Ne contient aucun jeton : uniquement des références."""
        out: list[dict] = []
        try:
            for ligne in self.registre.read_text(encoding="utf-8").splitlines():
                try:
                    d = json.loads(ligne)
                except ValueError:
                    continue
                if d.get("did") == did:
                    out.append(d)
        except OSError:
            pass
        return out
