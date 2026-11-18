# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3794 — notifications de secubox-garde : file d'attente, courriel, SMS Free Mobile.

Jamais la clé SMS dans un journal ni dans une exception.
"""
import logging
import sqlite3
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable, Dict, Literal, Optional

log = logging.getLogger("secubox.garde.notifs")

CLE_SMS = Path("/etc/secubox/secrets/garde-sms")
INTERVALLE_SMS = 3600
ESSAIS_MAX = 48
PEREMPTION = 604800  # 7 jours
URL_FREE = "https://smsapi.free-mobile.fr/sendmsg"


def mettre_en_file(db: sqlite3.Connection, canal: Literal["courriel", "sms"],
                   cle: str, texte: str, maintenant: int) -> bool:
    """False si un SMS de même clé a été mis en file il y a moins d'une heure."""
    if db.in_transaction:
        db.commit()
    db.execute("BEGIN IMMEDIATE")
    try:
        if canal == "sms":
            r = db.execute("SELECT 1 FROM file_notifs WHERE canal='sms' AND cle=? AND cree>?",
                           (cle, maintenant - INTERVALLE_SMS)).fetchone()
            if r:
                db.rollback()
                return False
        db.execute("INSERT INTO file_notifs(canal, cle, texte, cree, essais, envoye) "
                   "VALUES (?,?,?,?,0,0)", (canal, cle, texte, maintenant))
        db.commit()
    except BaseException:
        db.rollback()
        raise
    return True


def lire_cle_sms(chemin: Path = CLE_SMS) -> str:
    try:
        return Path(chemin).read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def expediteur() -> str:
    from secubox_core.auth import nom_box_locale
    return f"{nom_box_locale() or 'secubox'}@secubox.in"


def sms_free(utilisateur: str, cle: str, texte: str, http=urllib.request) -> bool:
    """GET Free Mobile ; True sur 200. Aucune trace de la clé."""
    url = URL_FREE + "?" + urllib.parse.urlencode(
        {"user": utilisateur, "pass": cle, "msg": texte}, quote_via=urllib.parse.quote)
    try:
        with http.urlopen(url, timeout=10) as r:
            return getattr(r, "status", None) == 200
    except Exception as e:  # l'URL (donc la clé) peut figurer dans le message : on ne le journalise pas
        log.warning("SMS Free Mobile : échec d'envoi (%s)", type(e).__name__)
        return False


def _courriel_defaut(destinataire: str, sujet: str, texte: str) -> bool:
    """Envoi par le relais de la box, From = `expediteur()`."""
    try:
        from secubox_core import courriel
        courriel.envoie(destinataire, sujet, texte, expediteur=expediteur())
        return True
    except Exception as e:
        log.warning("courriel : échec d'envoi (%s)", type(e).__name__)
        return False


def _sms_defaut(utilisateur: str, cle: str, texte: str) -> bool:
    return sms_free(utilisateur, cle, texte)


def vider_file(db: sqlite3.Connection, reglages: Dict,
               envoyer_sms: Callable[[str, str, str], bool] = _sms_defaut,
               envoyer_courriel: Callable[[str, str, str], bool] = _courriel_defaut,
               maintenant: int = 0, cle_sms: Optional[str] = None) -> dict:
    """Rejoue la file ; `envoyer_sms(utilisateur, cle_secrète, texte)`,
    `envoyer_courriel(destinataire, sujet, texte)`. Abandon après 48 essais."""
    envoyes = 0
    cle = lire_cle_sms() if cle_sms is None else cle_sms
    rows = db.execute("SELECT id, canal, texte, essais, cree FROM file_notifs "
                      "WHERE envoye=0 ORDER BY id").fetchall()
    manquants = set()
    for id_, canal, texte, essais, cree in rows:
        if canal == "sms":
            dest = str(reglages.get("sms_utilisateur") or "")
            if not dest:
                manquants.add("sms_utilisateur")
            if not cle:
                manquants.add("clé SMS")
        else:
            dest = str(reglages.get("courriel") or "")
            if not dest:
                manquants.add("courriel")
        if not dest or (canal == "sms" and not cle):
            if maintenant - cree > PEREMPTION:
                db.execute("UPDATE file_notifs SET envoye=-1 WHERE id=?", (id_,))
                log.error("notification %s (%s) abandonnée : non configurée depuis plus de 7 jours",
                          id_, canal)
            continue
        if canal == "sms":
            ok = envoyer_sms(dest, cle, texte)
        else:
            sujet = (texte.splitlines() or [""])[0][:120]
            ok = envoyer_courriel(dest, sujet, texte)
        if ok:
            db.execute("UPDATE file_notifs SET envoye=1, essais=? WHERE id=?", (essais + 1, id_))
            envoyes += 1
        elif essais + 1 >= ESSAIS_MAX:
            db.execute("UPDATE file_notifs SET envoye=-1, essais=? WHERE id=?", (essais + 1, id_))
            log.error("notification %s (%s) abandonnée après %d essais", id_, canal, ESSAIS_MAX)
        else:
            db.execute("UPDATE file_notifs SET essais=? WHERE id=?", (essais + 1, id_))
    if manquants:
        log.warning("notifications en attente, réglage manquant : %s", ", ".join(sorted(manquants)))
    db.commit()
    n = db.execute("SELECT COUNT(*) FROM file_notifs WHERE envoye=0").fetchone()[0]
    return {"envoyes": envoyes, "en_attente": n}
