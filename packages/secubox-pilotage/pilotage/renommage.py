# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: pilotage :: retour au maillage après un renommage (#3126 L2 tâche 5, D3)

Une box du maillage renommée par Device.X_SECUBOX_Nom.Renommer() garde, chez le maître, l'ancien nom (pair, noms
relayés `*.<nom>.secubox.in`, #3242). Après le X_SECUBOX_OperationDone RÉUSSI du renommage, le maître émet un code de
jonction lié au nouveau nom (`sbx-mesh-invite --code --nom <nouveau> --json`) et l'envoie par
Device.X_SECUBOX_Maillage.Rejoindre() {"code"} ; la box le passe à son ctl sur l'entrée standard (R-L2-2) puis à
secubox-automesh, et la jonction sous le nouveau nom renomme le pair (#3213).

Le code porte un jeton de jonction : il ne transite QUE par la file de la box (servie dans le tunnel). Jamais dans un
journal, l'audit (seuls box, nouveau nom et msg_id), un message d'erreur ou une exception.

Câblage (tâche 6) : la table des opérations du contrôleur sait quelle action portait un job ; à la première
X_SECUBOX_OperationDone, `pilotage.operations.Suivi` appelle `envoyer_rejoindre(files, box, operation, fin)`.
sbx-mesh-invite écrit les jetons de secubox-p2p au compte `secubox` : le service du maître (sans sudo, NoNewPrivileges)
l'obtient par `lanceur_assistant`, qui passe le seul nom à l'assistant `secubox-pilotage-invite` activé par socket.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import re
import socket
import subprocess
from pathlib import Path
from typing import Callable, Optional

from .identite import Box

log = logging.getLogger("pilotage.renommage")

INVITE = "/usr/bin/sbx-mesh-invite"
COMMANDE = "Device.X_SECUBOX_Maillage.Rejoindre()"
DELAI_INVITE = 30
RE_NOM = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")            # libellé DNS, le motif du ctl de la box
RE_CODE = re.compile(r"sbxmesh1\.[A-Za-z0-9_-]{8,590}\.[0-9a-f]{4}")
SORTIE_MAX = 4096
SOCKET_ASSISTANT = Path("/run/secubox-pilotage/invite.sock")   # secubox-pilotage-invite.socket (Accept=yes, 0600 au service)


class ErreurRejoindre(Exception):
    """Échec dit sans jamais recopier le code ni la sortie de sbx-mesh-invite."""


def code_valide(code) -> bool:
    if not isinstance(code, str) or len(code) > 600 or not RE_CODE.fullmatch(code):
        return False
    charge, somme = code[len("sbxmesh1."):].rsplit(".", 1)
    return hmac.compare_digest(hashlib.sha256(charge.encode("ascii")).hexdigest()[:4], somme)


def emettre_code(nom: str, lanceur: Callable = subprocess.run) -> str:
    """Code sbxmesh1 lié à `nom` (sbx-mesh-invite --code --nom <nom> --json). ErreurRejoindre sinon."""
    if not isinstance(nom, str) or not RE_NOM.fullmatch(nom):
        raise ErreurRejoindre("nom invalide")
    try:
        r = lanceur([INVITE, "--code", "--nom", nom, "--json"], capture_output=True, text=True,
                    stdin=subprocess.DEVNULL, timeout=DELAI_INVITE)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise ErreurRejoindre(f"sbx-mesh-invite indisponible ({e.__class__.__name__})") from None
    if getattr(r, "returncode", 1) != 0:
        raise ErreurRejoindre(f"sbx-mesh-invite en échec (code {getattr(r, 'returncode', '?')})")
    try:
        doc = json.loads((getattr(r, "stdout", "") or "")[:SORTIE_MAX])
    except ValueError:
        raise ErreurRejoindre("sortie de sbx-mesh-invite illisible") from None
    code = doc.get("code") if isinstance(doc, dict) else None
    if not code_valide(code):
        raise ErreurRejoindre("code émis invalide")
    if doc.get("nom") != nom:
        raise ErreurRejoindre("code émis pour un autre nom")
    return code


class _Sortie:
    __slots__ = ("returncode", "stdout")

    def __init__(self, returncode: int, stdout: str = "") -> None:
        self.returncode, self.stdout = returncode, stdout


def lanceur_assistant(chemin: Path = SOCKET_ASSISTANT) -> Callable:
    """Lanceur pour emettre_code : au lieu d'exécuter sbx-mesh-invite (le service du maître n'a ni sudo ni le compte des jetons),
    passe le NOM à l'assistant secubox-pilotage-invite par sa socket ; l'assistant (compte secubox) fixe lui-même l'argv
    `sbx-mesh-invite --code --nom <nom> --json` et rend sa sortie, ou rien en cas d'échec. Seul cet argv est accepté ici."""
    def run(argv, timeout: float = DELAI_INVITE, **_):
        if (not isinstance(argv, (list, tuple)) or len(argv) != 5 or list(argv[:3]) != [INVITE, "--code", "--nom"] or argv[4] != "--json"
                or not isinstance(argv[3], str) or not RE_NOM.fullmatch(argv[3])):
            return _Sortie(2)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:   # OSError (absente, refus, délai) : « indisponible »
            s.settimeout(timeout)
            s.connect(str(chemin))
            s.sendall(argv[3].encode("ascii") + b"\n")
            s.shutdown(socket.SHUT_WR)
            morceaux, total = [], 0
            while total <= SORTIE_MAX:
                m = s.recv(SORTIE_MAX + 1 - total)
                if not m:
                    break
                morceaux.append(m)
                total += len(m)
        brut = b"".join(morceaux)
        if not brut or len(brut) > SORTIE_MAX:
            return _Sortie(1)
        return _Sortie(0, brut.decode("utf-8", "replace"))
    return run


def emettre_code_par(lanceur: Callable) -> Callable[[str], str]:
    """emettre_code avec un lanceur donné (tests, ou lanceur privilégié posé par la tâche 6)."""
    return lambda nom: emettre_code(nom, lanceur=lanceur)


def nouveau_nom(box: Box, operation: dict, fin: dict) -> Optional[str]:
    """Le nouveau nom si l'opération terminée est un renommage RÉUSSI d'une box du maillage, sinon None. Une box cliente
    (Auto-Load) n'est pas au maillage : rien à rejoindre (son ctl refuserait, « box cliente : hors maillage »)."""
    if box.reseau != "maillage" or not isinstance(operation, dict) or operation.get("action") != "renommer":
        return None
    rc = (fin or {}).get("rc")
    if isinstance(rc, bool) or rc != 0:
        return None
    nom = (operation.get("args") or {}).get("nom")
    return nom if isinstance(nom, str) and RE_NOM.fullmatch(nom) else None


async def envoyer_rejoindre(files, box: Box, operation: dict, fin: dict, emettre: Callable[[str], str] = emettre_code,
                            audit: Optional[Callable[[str, dict], None]] = None) -> Optional[asyncio.Future]:
    """Après le X_SECUBOX_OperationDone d'un Renommer réussi : code émis pour le nouveau nom, déposé dans la file de la
    box (Device.X_SECUBOX_Maillage.Rejoindre()). Rend le futur de la réponse, ou None s'il n'y a rien à envoyer.
    ErreurRejoindre (sans le code) si l'émission ou le dépôt échoue."""
    nom = nouveau_nom(box, operation, fin)
    if nom is None:
        return None
    code = await asyncio.to_thread(emettre, nom)
    if not code_valide(code):
        raise ErreurRejoindre("code émis invalide")
    try:
        futur = files.deposer(box.cle, {"type": "OPERATE", "body": {"command": COMMANDE, "args": {"code": code}}})
    except Exception as e:  # noqa: BLE001 — file pleine ou autre : dit sans la requête (qui porte le code)
        raise ErreurRejoindre(f"dépôt impossible ({e.__class__.__name__})") from None
    finally:
        del code
    msg_id = _msg_id_du_dernier_depot(files, box.cle)
    log.info("rejoindre envoyé à %s sous le nom %s (msg_id %s)", box.nom, nom, msg_id)
    if audit is not None:
        await asyncio.to_thread(audit, "pilotage_rejoindre_envoye", {"box": box.nom, "nouveau": nom, "msg_id": msg_id})
    return futur


def _msg_id_du_dernier_depot(files, cle: str) -> Optional[str]:
    """msg_id de la dernière requête déposée pour la box (identifiant seulement, jamais la requête)."""
    attente = getattr(files, "_attente", {}).get(cle)
    return attente[-1] if attente else None
