# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Registre des appareils de secubox-garde (#3794) : un appareil = un item, toutes ses adresses.

Clé = MAC ; sans MAC connue, clé = IP (provisoire), fusionnée dans la MAC dès qu'elle est connue.
Nom lisible : première source qui répond, chacune lue sans root, absente ou illisible → suivante :
  1. ad-guard / TV Privacy : `/var/lib/secubox/ad-guard/dnstv/etat.json`, `clients[].nom` par ip/mac ;
  2. NAC : `/var/lib/secubox/nac/devices.db`, table `devices` (mac, ip, hostname) ;
  3. baux DHCP : dnsmasq (`/var/lib/misc/dnsmasq.leases`) et Kea (`/var/lib/kea/kea-leases4.csv`) ;
  4. constructeur (OUI) : `/usr/share/ieee-data/oui.csv` ;
sinon « Appareil inconnu (<mac ou ip>) ». La Freebox (cache en mémoire seulement) et mDNS (aucun cache
fichier) n'ont pas de source lisible à ce jour : non lus.
"""
from __future__ import annotations

import csv
import json
import logging
import re
import sqlite3
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple

log = logging.getLogger("secubox-garde")

ADGUARD_ETAT = Path("/var/lib/secubox/ad-guard/dnstv/etat.json")
NAC_DB = Path("/var/lib/secubox/nac/devices.db")
BAUX_DNSMASQ = Path("/var/lib/misc/dnsmasq.leases")
BAUX_KEA = Path("/var/lib/kea/kea-leases4.csv")
OUI = Path("/usr/share/ieee-data/oui.csv")
RE_MAC = re.compile(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}")


def est_mac(v: str) -> bool:
    return bool(RE_MAC.fullmatch(str(v or "")))


def _mac(v) -> str:
    return str(v or "").strip().lower()


# -- lecteurs de noms : chacun rend {ip ou mac: nom} ; absent ou illisible : {}

def noms_adguard(chemin: Path = ADGUARD_ETAT) -> Dict[str, str]:
    try:
        d = json.loads(Path(chemin).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    out: Dict[str, str] = {}
    for c in (d.get("clients") if isinstance(d, dict) else None) or []:
        if not isinstance(c, dict) or not str(c.get("nom") or "").strip():
            continue
        nom = str(c["nom"]).strip()
        for k in (c.get("ip"), _mac(c.get("mac"))):
            if k:
                out.setdefault(str(k), nom)
    return out


def noms_nac(chemin: Path = NAC_DB) -> Dict[str, str]:
    if not Path(chemin).is_file():
        return {}
    try:
        cx = sqlite3.connect(f"file:{chemin}?mode=ro", uri=True, timeout=2)
        try:
            lignes = cx.execute("SELECT mac, ip, hostname FROM devices WHERE hostname IS NOT NULL "
                                "AND hostname != '' LIMIT 5000").fetchall()
        finally:
            cx.close()
    except sqlite3.Error:
        return {}
    out: Dict[str, str] = {}
    for mac, ip, nom in lignes:
        for k in (_mac(mac), ip):
            if k:
                out.setdefault(str(k), str(nom))
    return out


def noms_baux(dnsmasq: Path = BAUX_DNSMASQ, kea: Path = BAUX_KEA) -> Dict[str, str]:
    out: Dict[str, str] = {}
    try:
        for ligne in Path(dnsmasq).read_text(encoding="utf-8").splitlines():
            p = ligne.split()
            if len(p) >= 4 and p[3] != "*":
                out.setdefault(_mac(p[1]), p[3])
                out.setdefault(p[2], p[3])
    except OSError:
        pass
    try:
        with open(kea, encoding="utf-8", newline="") as f:
            for r in csv.DictReader(f):
                nom = (r.get("hostname") or "").strip().rstrip(".")
                if nom:
                    out.setdefault(_mac(r.get("hwaddr")), nom)
                    out.setdefault(str(r.get("address") or ""), nom)
    except (OSError, csv.Error):
        pass
    out.pop("", None)
    return out


def constructeurs(chemin: Path = OUI) -> Dict[str, str]:
    """Préfixe OUI (6 hex majuscules) → organisation ; absent : {}."""
    out: Dict[str, str] = {}
    try:
        with open(chemin, encoding="utf-8", newline="") as f:
            for r in csv.reader(f):
                if len(r) >= 3 and len(r[1]) == 6:
                    out[r[1].upper()] = r[2].strip()
    except (OSError, csv.Error):
        return {}
    return out


class Nommeur:
    """Sources lues une fois par passage ; `nom(ip, mac)` suit l'ordre de priorité."""

    def __init__(self, sources: Iterable[Dict[str, str]], oui: Optional[Dict[str, str]] = None):
        self.sources = list(sources)
        self.oui = oui or {}

    @classmethod
    def depuis_fichiers(cls) -> "Nommeur":
        return cls([noms_adguard(), noms_nac(), noms_baux()], constructeurs())

    def nom(self, ip: Optional[str], mac: Optional[str]) -> str:
        mac = _mac(mac)
        for src in self.sources:
            for k in (mac, ip):
                if k and src.get(k):
                    return src[k]
        if mac:
            org = self.oui.get(mac.replace(":", "")[:6].upper())
            if org:
                return f"{org} ({mac})"
        return f"Appareil inconnu ({mac or ip})"


# -- registre

def mettre_a_jour(db: sqlite3.Connection, couples: Iterable[Tuple[str, Optional[str]]],
                  nommer: Callable[[Optional[str], Optional[str]], str], maintenant: int) -> None:
    """Enregistre chaque (ip, mac) : une IP n'appartient qu'à un appareil ; une clé IP provisoire est
    fusionnée dans la MAC (adresses, décisions) dès que la MAC est connue."""
    for ip, mac in couples:
        if not ip:
            continue
        mac = _mac(mac) or None
        cle = mac or ip
        if mac:
            prov = db.execute("SELECT 1 FROM appareils WHERE cle=? AND mac IS NULL", (ip,)).fetchone()
            if prov:
                db.execute("INSERT OR IGNORE INTO appareil_ips(cle, ip, vu) "
                           "SELECT ?, ip, vu FROM appareil_ips WHERE cle=?", (mac, ip))
                db.execute("DELETE FROM appareil_ips WHERE cle=?", (ip,))
                ds = db.execute("SELECT dernier_signal FROM appareils WHERE cle=?", (ip,)).fetchone()
                db.execute("DELETE FROM appareils WHERE cle=?", (ip,))
                db.execute("UPDATE decisions SET cible=?, mac=? WHERE cible=? AND mac IS NULL "
                           "AND menace IN ('infection','evasion','signale')", (mac, mac, ip))
                db.execute("UPDATE liberations SET mac=? WHERE mac=?", (mac, ip))
                _assurer(db, mac, mac, nommer(ip, mac), maintenant)
                db.execute("UPDATE appareils SET dernier_signal=max(dernier_signal, ?) WHERE cle=?",
                           (ds[0] if ds else 0, mac))
        elif db.execute("SELECT 1 FROM appareil_ips i JOIN appareils a ON a.cle=i.cle "
                        "WHERE i.ip=? AND a.mac IS NOT NULL", (ip,)).fetchone():
            # IP déjà rattachée à une MAC connue : on ne crée pas de doublon provisoire.
            continue
        _assurer(db, cle, mac, nommer(ip, mac), maintenant)
        db.execute("DELETE FROM appareil_ips WHERE ip=? AND cle!=?", (ip, cle))
        db.execute("INSERT INTO appareil_ips(cle, ip, vu) VALUES (?,?,?) "
                   "ON CONFLICT(cle, ip) DO UPDATE SET vu=excluded.vu", (cle, ip, maintenant))
    db.commit()


def _assurer(db, cle, mac, nom, maintenant):
    db.execute("INSERT INTO appareils(cle, mac, nom, vu) VALUES (?,?,?,?) "
               "ON CONFLICT(cle) DO UPDATE SET vu=excluded.vu, "
               "nom=CASE WHEN excluded.nom LIKE 'Appareil inconnu%' AND appareils.nom IS NOT NULL "
               "THEN appareils.nom ELSE excluded.nom END", (cle, mac, nom, maintenant))


def cle_de(db: sqlite3.Connection, ip: str, mac: Optional[str]) -> str:
    mac = _mac(mac)
    if mac:
        return mac
    r = db.execute("SELECT cle FROM appareil_ips WHERE ip=?", (ip,)).fetchone()
    return r[0] if r else ip


def nom_de(db: sqlite3.Connection, cle: str) -> str:
    r = db.execute("SELECT nom FROM appareils WHERE cle=?", (cle,)).fetchone()
    return r[0] if r and r[0] else f"Appareil inconnu ({cle})"


def adresses_actuelles(cle: str, voisins: Dict[str, str], defaut: Iterable[str] = ()) -> List[str]:
    """Adresses présentes de l'appareil (voisins de même MAC) ; absent des voisins : `defaut`."""
    if est_mac(cle):
        vues = sorted(ip for ip, m in voisins.items() if _mac(m) == cle)
        if vues:
            return vues
        return sorted(set(defaut))
    return [cle]


def noter_signal(db: sqlite3.Connection, cle: str, ts: int) -> None:
    db.execute("UPDATE appareils SET dernier_signal=max(dernier_signal, ?) WHERE cle=?", (int(ts), cle))


def dernier_signal(db: sqlite3.Connection, cle: str) -> int:
    r = db.execute("SELECT dernier_signal FROM appareils WHERE cle=?", (cle,)).fetchone()
    return int(r[0] or 0) if r else 0
