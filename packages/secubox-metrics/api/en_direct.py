# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: metrics :: mesures en temps réel pour les cartes de la page /metrics/ (#2763).

Connexions TCP établies par PAYS (entrantes : ports 22/80/443 ; sortantes : le reste), débit réseau, charge, mémoire. Rapide, sans cache.
JAMAIS d'adresse IP dans la réponse : le navigateur ne reçoit que des pays et des compteurs. Le LAN et la boucle locale ne sont pas des pays :
la boucle locale est ignorée (la box qui se parle), le LAN est compté à part."""
from __future__ import annotations

import ipaddress
import os
import subprocess
import time
from typing import Callable, Dict, List, Optional, Tuple

PORTS_ENTRANTS = (22, 80, 443)
MAX_LIGNES = 5000
MAX_PAYS = 40
# Pas de lo (la box à elle-même), de veth* ni de pont : le même octet y serait compté plusieurs fois.
_EXCLUES = ("lo", "veth", "br", "lxcbr", "docker", "virbr")


def _adresse(texte: str) -> Optional[Tuple[str, int]]:
    """« 1.2.3.4:443 », « [::ffff:1.2.3.4]:443 » ou « [2001:db8::1]:443 » -> (adresse, port) ; None si illisible."""
    try:
        hote, port = texte.rsplit(":", 1)
        ip = ipaddress.ip_address(hote.strip("[]"))
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        return str(ip), int(port)
    except (ValueError, TypeError):
        return None


def analyse_ss(texte: str, max_lignes: int = MAX_LIGNES) -> List[Tuple[int, str]]:
    """Sortie de `ss -Htn state established` -> [(port local, adresse du pair)], bornée."""
    out: List[Tuple[int, str]] = []
    for ligne in (texte or "").splitlines():
        champs = ligne.split()
        if len(champs) < 4:
            continue
        loc, pair = _adresse(champs[-2]), _adresse(champs[-1])
        if not loc or not pair:
            continue
        out.append((loc[1], pair[0]))
        if len(out) >= max_lignes:
            break
    return out


def _compte(d: Dict[str, int], max_pays: int) -> List[dict]:
    return [{"code": c, "n": n} for c, n in sorted(d.items(), key=lambda kv: (-kv[1], kv[0]))[:max_pays]]


def _publique(ip: str) -> bool:
    """Un vrai pair d'Internet (ni privé, ni lien local, ni réservé, ni multicast) : même règle que les statistiques de sites."""
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast)
    except ValueError:
        return False


def agreger(conns: List[Tuple[int, str]], pays_de: Callable[[str], Optional[str]], max_pays: int = MAX_PAYS,
            publique: Callable[[str], bool] = _publique) -> dict:
    ent: Dict[str, int] = {}
    sor: Dict[str, int] = {}
    lan = inconnu = 0
    for port, ip in conns:
        a = ipaddress.ip_address(ip)
        if a.is_loopback:
            continue
        if not publique(ip):                     # privée, lien local, réservée… : un client du LAN, pas un pays
            lan += 1
            continue
        cc = pays_de(ip)
        if not cc or len(cc) != 2 or not cc.isalpha():
            inconnu += 1
            continue
        cible = ent if port in PORTS_ENTRANTS else sor
        cible[cc.upper()] = cible.get(cc.upper(), 0) + 1
    total = sum(ent.values()) + sum(sor.values()) + lan + inconnu
    return {"entrantes": _compte(ent, max_pays), "sortantes": _compte(sor, max_pays), "lan": lan, "inconnu": inconnu, "total": total}


def lire_debit(texte: str) -> Optional[Dict[str, int]]:
    """/proc/net/dev -> octets cumulés reçus et émis par les interfaces PHYSIQUES ; None si illisible."""
    rx = tx = 0
    trouve = False
    for ligne in (texte or "").splitlines()[2:]:
        if ":" not in ligne:
            continue
        nom, reste = ligne.split(":", 1)
        nom = nom.strip()
        if nom.startswith(_EXCLUES):
            continue
        v = reste.split()
        if len(v) < 9:
            continue
        try:
            rx += int(v[0])
            tx += int(v[8])
            trouve = True
        except ValueError:
            continue
    return {"rx": rx, "tx": tx} if trouve else None


def _lire_ss() -> Optional[str]:
    try:
        r = subprocess.run(["ss", "-Htn", "state", "established"], capture_output=True, text=True, timeout=3)
        return r.stdout if r.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def _lire_proc_net() -> str:
    try:
        with open("/proc/net/dev") as f:
            return f.read()
    except OSError:
        return ""


def _charge() -> Optional[float]:
    try:
        return round(os.getloadavg()[0], 2)
    except OSError:
        return None


def _memoire_pct() -> Optional[float]:
    try:
        m = {}
        with open("/proc/meminfo") as f:
            for ligne in f:
                k, _, v = ligne.partition(":")
                m[k] = int(v.split()[0])
        total, dispo = m["MemTotal"], m["MemAvailable"]
        return round(100.0 * (total - dispo) / total, 1) if total > 0 else None
    except (OSError, KeyError, ValueError, IndexError):
        return None


def _pays_de_la_box() -> str:
    """Pays où se trouve la box (pour tracer les arcs de la carte) : SECUBOX_PAYS (ISO-2), « FR » par défaut."""
    v = (os.environ.get("SECUBOX_PAYS") or "FR").strip().upper()
    return v if len(v) == 2 and v.isalpha() else "FR"


def instantane(pays_de: Callable[[str], Optional[str]], publique: Callable[[str], bool] = _publique) -> dict:
    ss = _lire_ss()
    return {
        "ts": time.time(),
        "box": _pays_de_la_box(),
        "connexions": agreger(analyse_ss(ss), pays_de, publique=publique) if ss is not None else None,
        "debit": lire_debit(_lire_proc_net()),
        "charge": _charge(),
        "memoire_pct": _memoire_pct(),
    }
