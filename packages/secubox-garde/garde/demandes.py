# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Demandes de l'administrateur (#3794) : déposées par l'API, exécutées par le passage suivant (≤ 60 s).

L'API tourne sans sudo et sans la clé du WAF (profil AppArmor `secubox-garde`) : libérer, rouvrir, débannir et
l'envoi d'essai sont donc des lignes de `demandes`, que le passage (profil `secubox-garde-passage`) exécute par
`effets`. Jamais de verrou ad-guard pris par l'API. Une demande n'est déposée qu'une fois tant qu'elle attend.
"""
from __future__ import annotations

import sqlite3
from typing import Dict, Optional, Set, Tuple

from . import moteur

ACTIONS = ("liberer", "rouvrir", "debannir", "tester")
MENACE = {"liberer": "infection", "rouvrir": "evasion"}


def deposer(db: sqlite3.Connection, action: str, cible: str, par: Optional[str], maintenant: int) -> int:
    if action not in ACTIONS:
        raise ValueError("action")
    r = db.execute("SELECT id FROM demandes WHERE action=? AND cible=? AND etat='en_attente'",
                   (action, cible)).fetchone()
    if r:
        return int(r[0])
    cur = db.execute("INSERT INTO demandes(action, cible, par, cree, etat) VALUES (?,?,?,?,'en_attente')",
                     (action, cible, par, int(maintenant)))
    db.commit()
    return int(cur.lastrowid)


def en_attente(db: sqlite3.Connection) -> Set[Tuple[str, str]]:
    return {(a, c) for a, c in db.execute("SELECT action, cible FROM demandes WHERE etat='en_attente'")}


def _clore(db, did: int, etat: str, resultat: str, maintenant: int) -> None:
    db.execute("UPDATE demandes SET etat=?, resultat=?, traite=? WHERE id=?", (etat, resultat[:200], maintenant, did))


def executer(db: sqlite3.Connection, effets, notifs, maintenant: int) -> Dict[str, int]:
    """Exécute les demandes en attente. `faite` ; `reprise` (levée incomplète, réessayée par le moteur) ; `echec`."""
    maintenant = int(maintenant)
    n = {"faites": 0, "echecs": 0}
    for did, action, cible in db.execute(
            "SELECT id, action, cible FROM demandes WHERE etat='en_attente' ORDER BY id").fetchall():
        if action in MENACE:
            r = db.execute("SELECT menace, mac, motif FROM decisions WHERE id=? AND etat IN ('active','levee_en_cours')",
                           (cible,)).fetchone()
            if not r or r[0] != MENACE[action]:
                _clore(db, did, "echec", "décision absente ou déjà levée", maintenant)
                n["echecs"] += 1
                continue
            menace, mac, motif = r
            if moteur._terminer(db, effets, cible, menace, mac, f"{motif} — levée par l'administrateur",
                                "utilisateur", maintenant, notifs):
                _clore(db, did, "faite", "levée", maintenant)
                n["faites"] += 1
            else:
                _clore(db, did, "reprise", "levée incomplète, réessayée à chaque passage", maintenant)
                n["echecs"] += 1
        elif action == "debannir":
            ids = [x[0] for x in db.execute("SELECT id FROM decisions WHERE menace='intrusion' AND etat='active' "
                                            "AND ip=?", (cible,))]
            if not ids:
                _clore(db, did, "echec", "aucun ban actif de la garde", maintenant)
                n["echecs"] += 1
                continue
            res = effets.debannir(cible, "levée par l'administrateur")
            if res.get("ok"):
                db.executemany("UPDATE decisions SET etat='levee', leve_par='utilisateur' WHERE id=?",
                               [(i,) for i in ids])
                _clore(db, did, "faite", "débanni", maintenant)
                n["faites"] += 1
            elif str(res.get("motif") or "").endswith("etranger"):
                # Un autre mécanisme (sbxwaf, ai-ban, administrateur) a repris l'adresse plus longtemps : le WAF refuse
                # de lever SON ban. Issue finale : la décision de la garde est close, aucun nouvel essai.
                db.executemany("UPDATE decisions SET etat='levee', leve_par='autre' WHERE id=?", [(i,) for i in ids])
                _clore(db, did, "faite", "ban repris par un autre mécanisme", maintenant)
                n["faites"] += 1
            else:
                _clore(db, did, "echec", str(res.get("motif") or "échec"), maintenant)
                n["echecs"] += 1
        elif action == "tester":
            notifs.mettre_en_file(db, cible, f"test:{did}",
                                  "SecuBox Garde : message d'essai, les notifications fonctionnent.", maintenant)
            _clore(db, did, "faite", "mis en file", maintenant)
            n["faites"] += 1
        db.commit()
    db.commit()
    return n
