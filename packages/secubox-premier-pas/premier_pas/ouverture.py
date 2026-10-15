# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: Premier Pas — l'ouverture DISTANTE de l'assistant (#2725)

Une box sans écran doit pouvoir se configurer depuis un navigateur du LAN. Choix assumé du mainteneur : l'assistant est ouvert au LAN comme
celui d'un routeur grand public, pendant une FENÊTRE COURTE et pour UN SEUL POSTE. Le premier poste du LAN qui arrive dans la fenêtre prend la
box : c'est le prix du choix, et ces règles en limitent la portée.

LES RÈGLES.
- FENÊTRE : l'ouverture n'est possible que les 15 premières minutes après le démarrage de la box. Elle se compte en temps ÉCOULÉ depuis le
  démarrage (horloge monotone), pas en date : une carte sans horloge matérielle (RPi400) saute de plusieurs jours quand le réseau règle l'heure, et
  une fenêtre calée sur une date serait close ou ouverte au hasard. Elle ne limite que l'OUVERTURE : une configuration commencée à la minute 14
  doit pouvoir se terminer.
- ORIGINE : seul un client que nginx déclare du LAN (`X-SecuBox-LAN: 1`) peut ouvrir. L'adresse IP ne prouve rien (nginx fait confiance à
  X-Forwarded-For venant du LAN) : elle n'est lue que pour la trace. Sans l'en-tête, on ferme.
- UN SEUL POSTE : le premier reçoit un SECRET aléatoire ; les suivants sont refusés (423) tant que sa session est active, soit 15 minutes
  depuis sa dernière action. Le secret identifie le poste, pas l'adresse : copier l'adresse d'un autre ne reprend pas sa session.
- SECRET : jamais écrit en clair. L'état (`session-distante.json`, 0600) ne garde que son empreinte SHA-256, l'identifiant de démarrage et la
  dernière activité. Une session d'avant un redémarrage n'est jamais reprise.
- TRACE : chaque ouverture et chaque refus part au journal systemd et, si l'écriture est possible, au journal d'audit. Le secret n'y figure pas.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import tempfile
import time
from pathlib import Path
from typing import Callable, Optional

FENETRE_S = 15 * 60
INACTIVITE_S = 15 * 60
FICHIER = "session-distante.json"

journal = logging.getLogger("secubox.premier-pas")


class Refus(Exception):
    """Un refus qui sait son statut HTTP."""

    def __init__(self, statut: int, message: str):
        super().__init__(message)
        self.statut = statut
        self.message = message


def depuis_le_demarrage() -> float:
    """Secondes écoulées depuis le démarrage, suspension comprise (CLOCK_BOOTTIME) : insensible aux sauts de l'heure murale."""
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def identifiant_demarrage() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        return ""


def _empreinte(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


class Ouverture:
    def __init__(self, dossier: Path, jeton_local: Path, audit: Optional[Path],
                 maintenant: Callable[[], float] = depuis_le_demarrage,
                 boot_id: Callable[[], str] = identifiant_demarrage):
        self.dossier = Path(dossier)
        self.jeton_local = Path(jeton_local)
        self.audit = Path(audit) if audit else None
        self.maintenant = maintenant
        self.boot_id = boot_id

    # ── trace ──────────────────────────────────────────────────────────
    def _trace(self, message: str) -> None:
        journal.warning("premier-pas : %s", message)
        if self.audit is None:
            return
        try:
            with self.audit.open("a", encoding="utf-8") as f:
                f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')} premier-pas {message}\n")
        except OSError:
            pass        # /var/log/secubox/audit.log est root 0644 : l'API (secubox) n'y écrit pas. Le journal systemd a la trace ; échouer fermerait l'assistant.

    # ── état ───────────────────────────────────────────────────────────
    def _lit(self) -> Optional[dict]:
        try:
            e = json.loads((self.dossier / FICHIER).read_text())
        except (OSError, ValueError):
            return None
        if not isinstance(e, dict) or e.get("boot") != self.boot_id():
            return None                                  # d'un démarrage précédent : l'horloge a repris à zéro
        return e

    def _ecrit(self, etat: dict) -> None:
        self.dossier.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.dossier, prefix=".session-")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(etat, f)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.dossier / FICHIER)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _active(self, etat: Optional[dict], now: float) -> bool:
        return bool(etat) and now - float(etat.get("dernier", -INACTIVITE_S)) < INACTIVITE_S

    # ── ouvrir ─────────────────────────────────────────────────────────
    def ouvre(self, lan: bool, adresse: str) -> str:
        """Rend le secret du poste, ou lève Refus(statut, message). Le marqueur « box configurée » est vérifié par l'appelant."""
        qui = (adresse or "?")[:64]
        try:
            pret = bool(self.jeton_local.read_text().strip())
        except OSError:
            pret = False
        if not pret:
            raise Refus(503, "Assistant pas encore prêt : jeton de démarrage absent.")
        if not lan:
            self._trace(f"refus ouverture distante : {qui} n'est pas du réseau local")
            raise Refus(403, "L'assistant distant s'ouvre depuis le réseau local de la box.")
        now = self.maintenant()
        if self._active(self._lit(), now):
            self._trace(f"refus ouverture distante : {qui}, une session est déjà active")
            raise Refus(423, "Un autre poste configure déjà cette box. Réessayez quand il aura fini (15 minutes sans action), ou configurez depuis l'écran de la box.")
        if now > FENETRE_S:
            self._trace(f"refus ouverture distante : {qui}, fenêtre de {FENETRE_S // 60} minutes après le démarrage close")
            raise Refus(403, f"La fenêtre d'ouverture à distance ({FENETRE_S // 60} minutes après le démarrage) est close. Redémarrez la box, ou configurez depuis son écran.")
        secret = secrets.token_urlsafe(24)
        self._ecrit({"empreinte": _empreinte(secret), "boot": self.boot_id(), "dernier": now})
        self._trace(f"session ouverte à distance depuis {qui}")
        return secret

    # ── reconnaître le poste ───────────────────────────────────────────
    def valide(self, fourni: Optional[str]) -> bool:
        """Le secret est-il celui de la session active ? Une action réussie prolonge la session."""
        if not fourni or not fourni.strip():
            return False
        etat = self._lit()
        now = self.maintenant()
        if not self._active(etat, now):
            return False
        if not hmac.compare_digest(str(etat.get("empreinte", "")), _empreinte(fourni.strip())):
            return False
        etat["dernier"] = now
        try:
            self._ecrit(etat)
        except OSError:
            pass            # ne pas refuser un poste légitime parce que le disque proteste ; la session expirera à l'heure prévue
        return True
