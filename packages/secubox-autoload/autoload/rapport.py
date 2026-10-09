# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: autoload :: le RAPPORT FINAL (#2192, parent #2182)

La box poste son rapport par le tunnel ; l'infrastructure le valide STRICTEMENT (clés connues, formes bornées, aucun secret possible : il n'y a pas de champ pour
en porter), le conserve, et l'envoie par courrier au client si l'administrateur a renseigné son contact. Le courrier est sobre : pas d'adresse de tunnel, pas de
paquet au-delà de quarante, destinataire validé AVANT toute connexion (aucune injection d'en-tête), délai borné.
"""
from __future__ import annotations

import ipaddress
import json
import re
import smtplib
from email.message import EmailMessage
from typing import Callable, Dict

RAPPORT_MAX = 64 * 1024
CLES = frozenset({"client", "profil", "paquets", "domaine", "comptes", "tunnel_adresse", "debut", "fin", "etapes"})
PAQUETS_MAX = 2000
PAQUETS_COURRIER = 30
SMTP_TIMEOUT_S = 20
PROFILS = {"lite": "Lite", "isp": "ISP", "full": "Full"}

_NOM = re.compile(r"^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$")
_PAQUET = re.compile(r"^[a-z0-9][a-z0-9+.-]{1,80}$")
_COMPTE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_ETAPE = re.compile(r"^[a-z0-9_-]{1,40}$")
_DOMAINE = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_EMAIL = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,24}$")


def courriel_valide(adresse) -> str:
    """Une seule adresse, sans retour à la ligne, sans virgule, sans chevrons : de quoi n'ouvrir aucune injection d'en-tête."""
    if not isinstance(adresse, str) or len(adresse) > 254 or ".." in adresse or not _EMAIL.match(adresse):
        raise ValueError("adresse de courrier invalide")
    return adresse


def _liste(champ: str, v, motif, maxi: int):
    if not isinstance(v, list) or len(v) > maxi or not all(isinstance(x, str) and motif.match(x) for x in v):
        raise ValueError(f"{champ} : une liste de noms valides, {maxi} au plus")


def valider(rap) -> Dict:
    """Valide le rapport de la box et le rend tel quel. Toute clé inconnue, forme hors motif ou taille hors borne est refusée."""
    if not isinstance(rap, dict) or set(rap) != CLES:
        raise ValueError("rapport : les champs attendus, et eux seuls")
    if len(json.dumps(rap, ensure_ascii=False).encode("utf-8")) > RAPPORT_MAX:
        raise ValueError(f"rapport : {RAPPORT_MAX} octets au plus")
    for champ in ("client", "profil"):
        if not isinstance(rap[champ], str) or not _NOM.match(rap[champ]):
            raise ValueError(f"{champ} : minuscules, chiffres et tirets")
    if not isinstance(rap["domaine"], str) or not _DOMAINE.match(rap["domaine"]):
        raise ValueError("domaine : un nom de domaine")
    _liste("paquets", rap["paquets"], _PAQUET, PAQUETS_MAX)
    _liste("comptes", rap["comptes"], _COMPTE, 20)
    _liste("etapes", rap["etapes"], _ETAPE, 20)
    try:
        adr = ipaddress.ip_interface(rap["tunnel_adresse"])
    except (ValueError, TypeError):
        raise ValueError("tunnel_adresse : une adresse de 10.64.0.0/16") from None
    if adr.network.prefixlen != 32 or adr.ip not in ipaddress.ip_network("10.64.0.0/16"):
        raise ValueError("tunnel_adresse : une /32 de 10.64.0.0/16")
    for champ in ("debut", "fin"):
        v = rap[champ]
        if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v < 4_000_000_000:
            raise ValueError(f"{champ} : une date (secondes Unix)")
    if rap["fin"] < rap["debut"]:
        raise ValueError("fin avant début")
    return rap


def texte(rap: Dict) -> str:
    """Le corps du courrier (et de l'affichage sur écran). Sobre : jamais d'adresse de tunnel, quarante paquets au plus."""
    minutes = max(1, round((rap["fin"] - rap["debut"]) / 60))
    paquets = rap["paquets"]
    lignes = ["Bonjour,", "", "Votre boîtier SecuBox est prêt.", "",
              f"  Profil installé : {PROFILS.get(rap['profil'], rap['profil'])}",
              f"  Adresse du boîtier : {rap['domaine']}",
              f"  Comptes créés : {', '.join(rap['comptes']) or 'aucun'}",
              f"  Durée de la mise en service : environ {minutes} minute{'s' if minutes > 1 else ''}",
              f"  Composants installés : {len(paquets)} paquets", ""]
    lignes += [f"    - {p}" for p in paquets[:PAQUETS_COURRIER]]
    if len(paquets) > PAQUETS_COURRIER:
        lignes.append(f"    … et {len(paquets) - PAQUETS_COURRIER} autres ({len(paquets)} paquets)")
    lignes += ["", "Aucun mot de passe n'est contenu dans ce message : il vous a été remis séparément ou se choisit à la première connexion.", "", "L'équipe SecuBox"]
    return "\n".join(lignes) + "\n"


def envoyer(rap: Dict, destinataire: str, hote: str, port: int, expediteur: str, ouvrir: Callable = smtplib.SMTP) -> None:
    destinataire, expediteur = courriel_valide(destinataire), courriel_valide(expediteur)
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = expediteur, destinataire, "Votre SecuBox est prête"
    msg.set_content(texte(rap))
    with ouvrir(hote, port, timeout=SMTP_TIMEOUT_S) as s:
        s.send_message(msg, from_addr=expediteur, to_addrs=[destinataire])
