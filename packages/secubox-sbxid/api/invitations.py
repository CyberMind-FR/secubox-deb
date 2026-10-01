# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: sbxid — invitations (#1816, #1802 étape 4)
CyberMind — https://cybermind.fr

UNE INVITATION VAUT APPROBATION (décision de l'exploitant, 2026-10-01) : qui
ouvre le lien entre, sans demande à trancher. D'où trois règles :
  - usage UNIQUE, durée bornée, révocable tant qu'elle n'a pas servi ;
  - seule l'EMPREINTE du code est gardée : la base ne permet pas de le refaire ;
  - deux sortes, distinguées par le rôle proposé :
      · « personne » (rôle posé) : une nouvelle personne, avec ce rôle ;
      · « appareil » (sans rôle) : un appareil de plus pour la personne qui l'a
        créée — elle-même, depuis un appareil à elle.

Table `sbx_invites` (schéma de secubox_core.sbxid), sans colonne ajoutée :
created_by = user_uuid de qui invite (ou compte système), role_propose = NULL
pour un appareil, validated_at/device_uuid = usage, refused_at = révocation.
"""
from __future__ import annotations

import hashlib
import secrets
import sqlite3
import time
import uuid
from typing import Any, Dict, List, Optional

#: Durées de vie. Une invitation se transmet (courriel, message) : trois jours.
#: Un appareil s'ajoute en face de l'écran qui montre le QR : dix minutes.
DUREE_PERSONNE_S = 72 * 3600
DUREE_APPAREIL_S = 10 * 60

#: Services ouverts à l'arrivée selon le rôle (défauts annoncés le 2026-10-01).
SERVICES_PAR_ROLE = {"guest": ["bbs"]}
SERVICES_DEFAUT = ["bbs", "email", "nextcloud", "peertube"]

#: Un membre n'invite que des invités.
ROLES_D_UN_MEMBRE = ("guest",)


class Refus(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


def empreinte(code: str) -> str:
    return hashlib.sha256((code or "").encode()).hexdigest()


def services_du_role(role: Optional[str]) -> List[str]:
    return list(SERVICES_PAR_ROLE.get(role or "", SERVICES_DEFAUT))


def cree(c: sqlite3.Connection, *, createur: str, role: Optional[str], pseudo: str = "",
         email: str = "", duree: Optional[int] = None) -> Dict[str, Any]:
    """Crée une invitation ; rend le CODE, une seule fois (il n'est pas gardé)."""
    code = secrets.token_urlsafe(18)
    maintenant = int(time.time())
    vie = duree or (DUREE_APPAREIL_S if role is None else DUREE_PERSONNE_S)
    iid = str(uuid.uuid4())
    c.execute("INSERT INTO sbx_invites (invite_uuid,email,pseudo_propose,role_propose,code_hash,"
              "created_by,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?)",
              (iid, email or None, pseudo or None, role, empreinte(code), createur,
               maintenant, maintenant + vie))
    return {"invite_uuid": iid, "code": code, "expire_le": maintenant + vie,
            "sorte": "appareil" if role is None else "personne"}


def _vue(r) -> Dict[str, Any]:
    return {"invite_uuid": r["invite_uuid"], "sorte": "appareil" if r["role_propose"] is None else "personne",
            "pseudo": r["pseudo_propose"], "role": r["role_propose"], "email": r["email"],
            "par": r["created_by"], "cree_le": r["created_at"], "expire_le": r["expires_at"]}


def valide(c: sqlite3.Connection, code: str) -> sqlite3.Row:
    """L'invitation d'un code, encore utilisable. Un seul message d'échec :
    inconnu, servi, révoqué ou expiré ne se distinguent pas."""
    r = c.execute("SELECT * FROM sbx_invites WHERE code_hash=?", (empreinte(code),)).fetchone()
    if (r is None or r["validated_at"] or r["refused_at"]
            or int(r["expires_at"] or 0) <= int(time.time())):
        raise Refus(404, "Invitation inconnue, déjà utilisée ou expirée")
    return r


def apercu(c: sqlite3.Connection, code: str, pseudo_de=None) -> Dict[str, Any]:
    """Ce qu'on montre à l'invité avant qu'il rejoigne : qui l'invite, en tant que quoi."""
    r = valide(c, code)
    v = _vue(r)
    de = pseudo_de(r["created_by"]) if pseudo_de else None
    return {"sorte": v["sorte"], "pseudo": v["pseudo"], "role": v["role"],
            "de": de or v["par"], "expire_le": v["expire_le"]}


def consomme(c: sqlite3.Connection, invite_uuid: str, device_uuid: str, par: str = "") -> bool:
    """Marque l'invitation SERVIE — atomiquement : deux usages simultanés,
    un seul gagne."""
    r = c.execute("UPDATE sbx_invites SET validated_at=?, validated_by=?, device_uuid=? "
                  "WHERE invite_uuid=? AND validated_at IS NULL AND refused_at IS NULL",
                  (int(time.time()), par or None, device_uuid, invite_uuid))
    return r.rowcount == 1


def revoque(c: sqlite3.Connection, invite_uuid: str, par: str) -> bool:
    r = c.execute("UPDATE sbx_invites SET refused_at=?, motif=? "
                  "WHERE invite_uuid=? AND validated_at IS NULL AND refused_at IS NULL",
                  (int(time.time()), f"révoquée par {par}"[:120], invite_uuid))
    return r.rowcount == 1


def en_cours(c: sqlite3.Connection, createur: Optional[str] = None) -> List[Dict[str, Any]]:
    """Invitations non servies, non révoquées, non expirées (toutes, ou d'un créateur)."""
    q = ("SELECT * FROM sbx_invites WHERE validated_at IS NULL AND refused_at IS NULL "
         "AND expires_at > ?")
    args: list = [int(time.time())]
    if createur is not None:
        q += " AND created_by=?"
        args.append(createur)
    return [_vue(r) for r in c.execute(q + " ORDER BY created_at DESC", args)]


def createur_de(c: sqlite3.Connection, invite_uuid: str) -> Optional[str]:
    r = c.execute("SELECT created_by FROM sbx_invites WHERE invite_uuid=?", (invite_uuid,)).fetchone()
    return r[0] if r else None
