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
URL_FREE = "https://smsapi.free-mobile.fr/sendmsg"


def mettre_en_file(db: sqlite3.Connection, canal: Literal["courriel", "sms"],
                   cle: str, texte: str, maintenant: int) -> bool:
    """False si un SMS de même clé a été mis en file il y a moins d'une heure."""
    if canal == "sms":
        r = db.execute("SELECT 1 FROM file_notifs WHERE canal='sms' AND cle=? AND cree>?",
                       (cle, maintenant - INTERVALLE_SMS)).fetchone()
        if r:
            return False
    db.execute("INSERT INTO file_notifs(canal, cle, texte, cree, essais, envoye) "
               "VALUES (?,?,?,?,0,0)", (canal, cle, texte, maintenant))
    db.commit()
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


def envoyer_courriel(destinataire: str, sujet: str, texte: str) -> bool:
    """Envoi par le relais de la box (`secubox_core.courriel.envoie`)."""
    try:
        from secubox_core import courriel
        courriel.envoie(destinataire, sujet, texte)
        return True
    except Exception as e:
        log.warning("courriel : échec d'envoi (%s)", type(e).__name__)
        return False


def _sms_defaut(utilisateur: str, cle: str, texte: str) -> bool:
    return sms_free(utilisateur, cle, texte)


def vider_file(db: sqlite3.Connection, reglages: Dict,
               envoyer_sms: Callable[[str, str, str], bool] = _sms_defaut,
               envoyer_courriel: Callable[[str, str, str], bool] = envoyer_courriel,
               maintenant: int = 0, cle_sms: Optional[str] = None) -> dict:
    """Rejoue la file ; `envoyer_sms(utilisateur, cle_secrète, texte)`,
    `envoyer_courriel(destinataire, sujet, texte)`. Abandon après 48 essais."""
    envoyes = 0
    cle = lire_cle_sms() if cle_sms is None else cle_sms
    rows = db.execute("SELECT id, canal, texte, essais FROM file_notifs "
                      "WHERE envoye=0 ORDER BY id").fetchall()
    for id_, canal, texte, essais in rows:
        if canal == "sms":
            dest = str(reglages.get("sms_utilisateur") or "")
            if not dest or not cle:
                continue
            ok = envoyer_sms(dest, cle, texte)
        else:
            dest = str(reglages.get("courriel") or "")
            if not dest:
                continue
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
    db.commit()
    n = db.execute("SELECT COUNT(*) FROM file_notifs WHERE envoye=0").fetchone()[0]
    return {"envoyes": envoyes, "en_attente": n}
