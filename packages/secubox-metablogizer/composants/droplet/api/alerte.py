# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: Droplet — l'alerte de dépôt (#1026)

CyberMind — https://cybermind.fr
"""
from __future__ import annotations

import logging
import smtplib
import time
from email.message import EmailMessage

try:
    from .depot import Depot  # type: ignore
except ImportError:
    from depot import Depot

logger = logging.getLogger("droplet")


def taille_lisible(n: int) -> str:
    for seuil, unite in ((1 << 30, "Gio"), (1 << 20, "Mio"), (1 << 10, "Kio")):
        if n >= seuil:
            return f"{n / seuil:.1f} {unite}"
    return f"{n} o"


def corps(d: Depot, joint: bool, plafond: int) -> str:
    """Le texte de l'alerte.

    ON DIT CE QU'ON A CONSTATE, PAS CE QU'ON ESPERE : taille réelle, empreinte
    calculée à l'écriture, adresse d'origine, instant. Le nom affiché est celui
    du déposant, nettoyé — et il est présenté COMME TEL, pour qu'on ne le
    prenne pas pour une garantie.
    """
    lignes = [
        f"Dépôt {d.identifiant}",
        f"Reçu le  : {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(d.recu_le))}",
        f"Origine  : {d.origine}",
        f"Volume   : {taille_lisible(d.taille)} en {len(d.fichiers)} fichier(s)",
        "",
    ]
    if d.mot:
        lignes += ["Message laissé par le déposant :", "",
                   "  " + d.mot.replace("\n", "\n  "), ""]
    lignes.append("Fichiers (nom tel qu'annoncé par le déposant, nettoyé) :")
    for f in d.fichiers:
        lignes.append(f"  · {f.nom}")
        lignes.append(f"    {taille_lisible(f.taille)} — sha256 {f.sha256}")
    lignes += ["", f"Sur disque : {d.dossier}"]
    if not joint:
        # LE SILENCE SERAIT PIRE QUE L'ABSENCE. Une alerte sans pièce jointe et
        # sans explication laisse croire à un dépôt vide ; on dit donc pourquoi
        # elle manque et où aller la chercher.
        lignes += ["",
                   f"Les fichiers ne sont PAS joints : le dépôt dépasse le "
                   f"plafond d'envoi ({taille_lisible(plafond)}). Ils sont sur "
                   f"le disque, au chemin ci-dessus."]
    lignes += ["", "-- ", "SecuBox Droplet"]
    return "\n".join(lignes)


def compose(d: Depot, de: str, a: str, plafond_joint: int) -> EmailMessage:
    m = EmailMessage()
    m["From"] = de
    m["To"] = a
    # Le sujet porte le volume : la boîte de réception dit déjà l'essentiel,
    # avant même qu'on ouvre.
    m["Subject"] = (f"[droplet] dépôt de {taille_lisible(d.taille)} — "
                    f"{len(d.fichiers)} fichier(s)")
    # Un en-tête à nous, pour que le tri côté client ne dépende pas du sujet —
    # qui, lui, changera un jour.
    m["X-SecuBox-Droplet"] = d.identifiant

    joint = bool(d.fichiers) and (not plafond_joint or d.taille <= plafond_joint)
    m.set_content(corps(d, joint, plafond_joint))

    if joint:
        for f in d.fichiers:
            try:
                m.add_attachment(f.chemin.read_bytes(), maintype="application",
                                 subtype="octet-stream", filename=f.nom)
            except OSError as e:
                # UN FICHIER ILLISIBLE N'ANNULE PAS L'ALERTE. Prévenir avec une
                # pièce en moins vaut mieux que ne pas prévenir : le dépôt, lui,
                # a bien eu lieu.
                logger.warning("pièce jointe %s illisible : %s", f.chemin, e)
    return m


def envoie(d: Depot, *, de: str, a: str, hote: str, port: int,
           plafond_joint: int, delai: int = 300) -> dict:
    """Envoie l'alerte. NE LEVE JAMAIS.

    L'ECHEC DE L'ALERTE N'EST PAS L'ECHEC DU DEPOT. Les octets sont déjà sur le
    disque quand cette fonction est appelée ; rendre une erreur au déposant
    parce que NOTRE serveur de courrier est muet lui ferait renvoyer un fichier
    qu'on possède. On journalise, on le dit dans la réponse, et le dépôt reste
    bon.
    """
    try:
        m = compose(d, de, a, plafond_joint)
        with smtplib.SMTP(hote, port, timeout=delai) as s:
            s.send_message(m)
        return {"ok": True, "detail": f"alerte envoyée à {a}"}
    except (OSError, smtplib.SMTPException) as e:
        logger.error("alerte du dépôt %s non envoyée : %s", d.identifiant, e)
        return {"ok": False, "detail": f"alerte non envoyée : {e}"}
