# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: auth — console locale du kiosque (#1695)
CyberMind — https://cybermind.fr

LE MODÈLE (décision de Gandalf) : administration par le WAN = second facteur ;
par le LAN = à voir ; à la CONSOLE de la box = sans authentification. Le
kiosque (Chromium sous le compte `secubox-kiosk`) doit ouvrir l'administration
sans mot de passe ni code.

« LOCAL » NE PEUT PAS VOULOIR DIRE « 127.0.0.1 ». HAProxy et sbxwaf arrivent à
nginx depuis la boucle locale, et nginx croit le X-Forwarded-For de la boucle :
une adresse locale se forge. Tout processus de la box, aussi, parle à la boucle.
La console est donc liée au KIOSQUE lui-même :

  1. nginx n'ouvre `/__console/jeton` que sur son port console (127.0.0.1:9078)
     et pour les hôtes exacts `hall.localhost` / `admin.localhost`, et y joint un SECRET (seul nginx le
     connaît, avec ce module) : la requête est passée par ce port-là ;
  2. nginx joint aussi la paire adresse:port de la connexion cliente, telle
     qu'il l'a acceptée ($realip_remote_*, jamais réécrite par X-Forwarded-For) ;
  3. ce module retrouve cette connexion dans /proc/net/tcp{,6} et exige qu'elle
     appartienne au compte `secubox-kiosk` et vise le port console.

Fermé par défaut, et sans dépendre d'une règle nft qu'un rechargement du
pare-feu effacerait (#1693). Un autre processus local, un client du LAN ou du
WAN, une page piégée qui viserait la boucle par rebond DNS : refusés.
"""

from __future__ import annotations

import hmac
import ipaddress
import pwd
from pathlib import Path
from typing import Optional, Tuple

PORT_CONSOLE = 9078
# Les deux origines de la console : le Hall, et l'administration qu'il encadre
# (webui.conf). Chacune a son localStorage, donc chacune demande sa session.
HOTES_CONSOLE = ("hall.localhost", "admin.localhost")
COMPTE_KIOSQUE = "secubox-kiosk"
COMPTE_CONSOLE = "console"
SECRET = Path("/etc/secubox/secrets/console.key")
PROC = Path("/proc")
# Une session console dure une demi-journée ; le Hall en redemande une seule.
DUREE = 12 * 3600

_ETABLIE = "01"  # TCP_ESTABLISHED dans /proc/net/tcp


def reglages(cfg: Optional[dict]) -> dict:
    """Section [console] de secubox.conf : `actif` (défaut vrai), `compte`."""
    cfg = cfg if isinstance(cfg, dict) else {}
    compte = str(cfg.get("compte") or COMPTE_CONSOLE).strip() or COMPTE_CONSOLE
    return {"actif": cfg.get("actif", True) is not False, "compte": compte}


def uid_kiosque(nom: str = COMPTE_KIOSQUE) -> Optional[int]:
    """uid du compte du kiosque, ou None si la box n'a pas de kiosque."""
    try:
        return pwd.getpwnam(nom).pw_uid
    except KeyError:
        return None


def secret_valide(fourni: str, chemin: Optional[Path] = None) -> bool:
    try:
        attendu = (chemin or SECRET).read_text().strip()
    except OSError:
        return False
    fourni = (fourni or "").strip()
    return bool(attendu) and bool(fourni) and hmac.compare_digest(fourni.encode(), attendu.encode())


def _ip(texte: str):
    ip = ipaddress.ip_address(texte.strip("[]"))
    mappee = getattr(ip, "ipv4_mapped", None)
    return mappee or ip


def lire_paire(paire: str) -> Tuple[ipaddress._BaseAddress, int]:
    """« 127.0.0.1:54321 » ou « ::1:54321 » ($realip_remote_addr n'a pas de
    crochets) → (adresse, port). ValueError si illisible."""
    hote, sep, port = (paire or "").strip().rpartition(":")
    if not sep or not hote:
        raise ValueError(f"paire illisible : {paire!r}")
    p = int(port)
    if not 0 < p < 65536:
        raise ValueError(f"port hors plage : {paire!r}")
    return _ip(hote), p


def _adresse_proc(champ: str) -> Tuple[ipaddress._BaseAddress, int]:
    """« 0100007F:D431 » (IPv4) ou 32 chiffres hexa (IPv6) — mots de 32 bits
    dans l'ordre de l'hôte (petit-boutiste sur arm64 et amd64)."""
    a, p = champ.split(":")
    b = bytes.fromhex(a)
    if len(b) == 4:
        ip = ipaddress.IPv4Address(b[::-1])
    elif len(b) == 16:
        ip = ipaddress.IPv6Address(b"".join(b[i:i + 4][::-1] for i in range(0, 16, 4)))
        ip = ip.ipv4_mapped or ip
    else:
        raise ValueError(champ)
    return ip, int(p, 16)


def connexion_du_kiosque(paire: str, uid: int, port_console: int = PORT_CONSOLE,
                         proc: Optional[Path] = None) -> bool:
    """La connexion cliente `paire` est-elle celle d'un processus du kiosque
    vers le port console ?

    /proc/net/tcp liste les DEUX bouts d'une connexion en boucle locale ; on
    cherche le bout client : adresse locale = la paire vue par nginx, adresse
    distante = boucle:port console, état établi, propriétaire = le kiosque."""
    try:
        ip, port = lire_paire(paire)
    except ValueError:
        return False
    if not ip.is_loopback:
        return False
    proc = proc or PROC
    for nom in ("net/tcp", "net/tcp6"):
        try:
            lignes = (proc / nom).read_text().splitlines()[1:]
        except OSError:
            continue
        for ligne in lignes:
            c = ligne.split()
            if len(c) < 8 or c[3] != _ETABLIE:
                continue
            try:
                local, distant = _adresse_proc(c[1]), _adresse_proc(c[2])
                proprietaire = int(c[7])
            except ValueError:
                continue
            if (local == (ip, port) and distant[1] == port_console
                    and distant[0].is_loopback and proprietaire == uid):
                return True
    return False


def refus(*, secret_fourni: str, paire: str, hote: str, origine: Optional[str],
          cfg: Optional[dict], uid: Optional[int],
          chemin_secret: Optional[Path] = None, proc: Optional[Path] = None) -> Optional[str]:
    """Motif de refus, ou None si la demande vient bien de la console.

    L'ordre va du moins coûteux au plus coûteux ; aucun motif ne dit à un
    demandeur étranger quelque chose qu'il ne sait déjà."""
    if not reglages(cfg)["actif"]:
        return "console désactivée ([console] actif = false)"
    if uid is None:
        return f"pas de kiosque sur cette box (compte {COMPTE_KIOSQUE} absent)"
    if not secret_valide(secret_fourni, chemin_secret):
        return "demande hors du port console"
    nom = (hote or "").split(":")[0].lower()
    if nom not in HOTES_CONSOLE:
        return "hôte refusé"
    # Rebond DNS / page piégée : une requête d'une autre origine porte son
    # Origin. La console n'en porte pas (même origine) ou porte la sienne.
    if origine and origine != f"http://{nom}:{PORT_CONSOLE}":
        return "origine refusée"
    if not connexion_du_kiosque(paire, uid, proc=proc):
        return "connexion étrangère au kiosque"
    return None
