# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Effecteurs de secubox-garde (#3794) : ban par le WAF, quarantaine et évasion par ad-guard.

- `bannir` : `POST /garde/ban` sur `/run/secubox/waf.sock` (secubox-waf-ng), jeton EdDSA par requête
  frappé avec `/etc/secubox/secrets/garde-ban.pem` (compte de service `garde`).
- `isoler`/`liberer`/`fermer_evasion`/`rouvrir` : `sudo -n /usr/sbin/secubox-adguard-tv …` (sudoers
  `secubox-adguard-garde`), une entrée par adresse, sortie JSON `{"ok": …}`.
Chaque effet ajoute une ligne JSON à `/var/log/secubox/audit.log` et rend `{"ok": bool, "motif": str}`
(`"deja": True` pour un ban déjà actif ailleurs). Tous les accès extérieurs sont injectables.
"""
from __future__ import annotations

import http.client
import json
import logging
import socket
import subprocess
import time
from pathlib import Path
from typing import Callable, Iterable, Optional, Tuple

log = logging.getLogger("secubox-garde")

AUDIT = Path("/var/log/secubox/audit.log")
CLE_BAN = Path("/etc/secubox/secrets/garde-ban.pem")
SOCK_WAF = "/run/secubox/waf.sock"
CHEMIN_BAN = "/garde/ban"
CTL = "/usr/sbin/secubox-adguard-tv"


class _UnixHTTP(http.client.HTTPConnection):
    def __init__(self, chemin: str, timeout: float = 15):
        super().__init__("localhost", timeout=timeout)
        self._chemin = chemin

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._chemin)
        self.sock = s


def poster_unix(sock: str, chemin: str, corps: bytes, entetes: dict) -> Tuple[int, bytes]:
    cx = _UnixHTTP(sock)
    try:
        cx.request("POST", chemin, body=corps, headers=entetes)
        r = cx.getresponse()
        return r.status, r.read(65536)
    finally:
        cx.close()


def _ctl(args) -> str:
    return subprocess.run(["sudo", "-n", CTL, *args], capture_output=True, text=True, timeout=60,
                          check=False).stdout


def _frapper(cle_pem: bytes, corps: bytes, maintenant: float) -> str:
    from secubox_core.auth import nom_box_locale
    from secubox_core.compte_service import frapper_jeton
    return frapper_jeton(cle_pem, "garde", aud=nom_box_locale(), corps=corps, maintenant=maintenant)


class Effets:
    def __init__(self, audit: Path = AUDIT, cle: Path = CLE_BAN, sock: str = SOCK_WAF,
                 poster: Callable = poster_unix, ctl: Callable = _ctl,
                 frapper: Callable = _frapper, horloge: Callable[[], float] = time.time):
        self.audit_chemin, self.cle, self.sock = Path(audit), Path(cle), sock
        self.poster, self.ctl, self.frapper, self.horloge = poster, ctl, frapper, horloge

    # -- journal d'audit (ajout seul)
    def audit(self, action: str, cible: str, motif: str, resultat: str) -> None:
        ligne = json.dumps({"ts": int(self.horloge()), "module": "garde", "action": action,
                            "cible": cible, "motif": motif, "resultat": resultat}, ensure_ascii=False)
        try:
            with open(self.audit_chemin, "a", encoding="utf-8") as f:
                f.write(ligne + "\n")
        except OSError as e:
            log.error("audit.log non écrit (%s) : %s", type(e).__name__, ligne)

    def alerte(self, texte: str) -> None:
        log.warning("%s", texte)
        self.audit("alerte", "-", texte, "signale")

    # -- WAF
    def bannir(self, ip: str, duree_s: int, motif: str) -> dict:
        corps = json.dumps({"geste": "ban", "cible": ip, "duree_s": int(duree_s),
                            "motif": motif[:200]}).encode()
        try:
            jeton = self.frapper(self.cle.read_bytes(), corps, self.horloge())
            statut, brut = self.poster(self.sock, CHEMIN_BAN, corps, {
                "Authorization": f"Bearer {jeton}", "Content-Type": "application/json"})
        except (OSError, ValueError) as e:
            r = {"ok": False, "motif": type(e).__name__}
        else:
            try:
                d = json.loads(brut or b"{}")
            except ValueError:
                d = {}
            det = d.get("detail") if isinstance(d, dict) else None
            m = str(det.get("motif") if isinstance(det, dict) else (det or "")) or str(statut)
            if statut == 200:
                r = {"ok": True, "motif": ""}
            elif statut == 409 and m == "deja_actif":
                r = {"ok": True, "deja": True, "motif": "deja_actif"}
            else:
                r = {"ok": False, "motif": f"{statut} {m}"}
        self.audit("ban", ip, motif, "ok" if r["ok"] else f"echec {r['motif']}")
        return r

    # -- ad-guard
    def _geste(self, action: str, args, cible: str, motif: str) -> dict:
        try:
            d = json.loads(self.ctl(args) or "{}")
            ok = isinstance(d, dict) and d.get("ok") is True
            m = ""
            if not ok:
                m = str((d.get("erreur") or d.get("motif")) if isinstance(d, dict) else d) or "réponse vide"
        except (OSError, ValueError, subprocess.SubprocessError) as e:
            ok, m = False, type(e).__name__
        self.audit(action, cible, motif, "ok" if ok else f"echec {m}")
        return {"ok": ok, "motif": m}

    def isoler(self, ip: str, mac: Optional[str], fin: int, motif: str = "quarantaine") -> dict:
        return self._geste("isoler", ["quarantaine", "poser", ip, mac or "-", str(int(fin))], ip, motif)

    def liberer(self, ip: str, mac: Optional[str] = None, motif: str = "levée") -> dict:
        return self._geste("liberer", ["quarantaine", "lever", ip], ip, motif)

    def fermer_evasion(self, ip: str, mac: Optional[str], noms: Iterable[str], motif: str = "évasion") -> dict:
        return self._geste("fermer_evasion", ["evasion", "poser", ip, mac or "-", ",".join(sorted(set(noms)))],
                           ip, motif)

    def rouvrir(self, ip: str, mac: Optional[str] = None, motif: str = "levée") -> dict:
        return self._geste("rouvrir", ["evasion", "lever", ip], ip, motif)
