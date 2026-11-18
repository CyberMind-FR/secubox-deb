# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Lecture des capteurs de secubox-garde (#3794) : alertes DNS, propositions actord, voisins, DoH.

Chaque lecteur reçoit ses chemins et ses exécuteurs en paramètres (tests sans réseau).

Source des requêtes DNS par client (pour `signaux_doh`) : table `dnstv_recents` (ts, client,
domaine, qtype, decision, categorie) de `/var/lib/secubox/ad-guard/dnstv/dnstv.db`, tenue par
ad-guard. Droits constatés (gk7) : base, `-wal` et `-shm` en 0640 secubox:secubox, dossiers 0755 ;
`secubox-garde` est du groupe `secubox` (lecture, pas d'écriture sur `-shm`). `lire_requetes_dns`
ouvre en `mode=ro` puis, si SQLite refuse (WAL), reprend une fois en `mode=ro&immutable=1` sur la
même requête bornée, avec un avertissement ; jamais d'écriture ; deux échecs : []. Réserve : immutable ignore le `-wal`, le repli ne voit que
les lignes déjà repliées dans la base (retard borné par le point de contrôle d'ad-guard).
Positions : `positions` est mise à jour après la lecture, donc au plus une fois (un signal perdu
si le moteur tombe entre les deux ; jamais de doublon).
Liste des résolveurs DoH : `/usr/share/secubox/ad-guard/lists/resolveurs-doh.txt`.
"""
from __future__ import annotations

import calendar
import ipaddress
import json
import logging
import os
import sqlite3
import subprocess
import time
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Set

from .politique import Signal

log = logging.getLogger("secubox-garde")

ALERTES = Path("/var/lib/secubox/dns-guard/alerts.jsonl")
PROPOSITIONS = Path("/run/secubox/actord-propositions.json")
DNSTV_DB = Path("/var/lib/secubox/ad-guard/dnstv/dnstv.db")
RESOLVEURS_DOH = Path("/usr/share/secubox/ad-guard/lists/resolveurs-doh.txt")
ETATS_VOISINS = {"REACHABLE", "STALE", "DELAY"}


def _ts_iso(v) -> Optional[int]:
    try:
        return calendar.timegm(time.strptime(str(v), "%Y-%m-%dT%H:%M:%SZ"))
    except (ValueError, TypeError):
        return None


def lire_alertes_dns(db: sqlite3.Connection, chemin: Path = ALERTES,
                     voisins: Optional[Dict[str, str]] = None) -> List[Signal]:
    """Lecture incrémentale (inode + offset dans `positions`) ; ligne invalide ou sans client ignorée."""
    voisins = voisins or {}
    source = f"alertes:{chemin}"
    try:
        st = os.stat(chemin)
    except OSError:
        return []
    r = db.execute("SELECT inode, offset FROM positions WHERE source=?", (source,)).fetchone()
    offset = 0
    if r and r[0] == st.st_ino and st.st_size >= r[1]:
        offset = r[1]
    out: List[Signal] = []
    with open(chemin, "rb") as f:
        f.seek(offset)
        donnees = f.read()
    fin = donnees.rfind(b"\n") + 1          # une ligne incomplète attend le prochain passage
    for brut in donnees[:fin].splitlines():
        try:
            a = json.loads(brut)
            if not isinstance(a, dict) or not a.get("client_ip"):
                continue
            ip = a["client_ip"]
            ts = _ts_iso(a.get("timestamp"))
            if ts is None:
                continue
            det = a.get("details") if isinstance(a.get("details"), dict) else {}
            out.append(Signal("dns-guard", str(a["type"]), str(ip), voisins.get(str(ip)),
                              str(a.get("domain") or ""), str(det.get("rule") or ""), ts))
        except (ValueError, KeyError, TypeError, AttributeError):
            continue
    db.execute("INSERT INTO positions(source, inode, offset) VALUES (?,?,?) "
               "ON CONFLICT(source) DO UPDATE SET inode=excluded.inode, offset=excluded.offset",
               (source, st.st_ino, offset + fin))
    db.commit()
    return out


def lire_propositions(chemin: Path = PROPOSITIONS, maintenant: Optional[int] = None) -> List[Signal]:
    """Un Signal `intrusion` par IP (dédoublonnée) des propositions d'actord ; absent ou illisible : []."""
    try:
        d = json.loads(Path(chemin).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(d, dict):
        return []
    now = int(time.time()) if maintenant is None else int(maintenant)
    g = d.get("genere_le")
    if isinstance(g, (int, float)) and not isinstance(g, bool):
        ts = int(g)
    else:
        ts = _ts_iso(g)
        if ts is None:
            ts = now
    vus: Set[str] = set()
    out: List[Signal] = []
    for p in d.get("propositions") or []:
        if not isinstance(p, dict):
            continue
        for ip in p.get("ips") or []:
            if not isinstance(ip, str) or ip in vus:
                continue
            vus.add(ip)
            out.append(Signal("actord", "intrusion", ip, None, "", str(p.get("raison") or ""), ts))
    return out


def charger_noms_doh(chemin: Path = RESOLVEURS_DOH) -> Set[str]:
    """Noms d'hôte (adresses IP exclues) de la liste des résolveurs DoH ; absent : ensemble vide."""
    noms: Set[str] = set()
    try:
        texte = Path(chemin).read_text(encoding="utf-8")
    except OSError:
        return noms
    for ligne in texte.splitlines():
        v = ligne.split("#", 1)[0].strip().lower().rstrip(".")
        if not v:
            continue
        try:
            ipaddress.ip_address(v)
        except ValueError:
            noms.add(v)
    return noms


def lire_requetes_dns(depuis: int, chemin: Path = DNSTV_DB, limite: int = 20000,
                      noms_doh: Optional[Iterable[str]] = None) -> List[dict]:
    """Requêtes DNS par client depuis `depuis` (table `dnstv_recents` d'ad-guard), jamais en écriture.

    Ouverture `mode=ro` ; si elle échoue (WAL sans droit d'écriture sur `-shm`), une seule reprise en
    `mode=ro&immutable=1` avec la même requête bornée (`ts >= depuis`), avertissement journalisé.
    Les deux échouent : avertissement, []. `noms_doh` filtre en SQL (nom exact ou sous-domaine) pour que
    les lignes récentes ne soient jamais écartées au profit d'anciennes."""
    f = Path(chemin)
    if not f.is_file():
        return []
    noms = sorted({n.lower().rstrip(".") for n in (noms_doh or []) if n})
    sql = "SELECT ts, client, domaine FROM dnstv_recents WHERE ts>=?"
    args: list = [int(depuis)]
    if noms_doh is not None:
        if not noms:
            return []
        cond = []
        for n in noms:
            cond.append("lower(domaine)=? OR lower(domaine) LIKE ? ESCAPE '\\'")
            args += [n, "%." + n.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")]
        sql += " AND (" + " OR ".join(cond) + ")"
    sql += " ORDER BY ts DESC LIMIT ?"
    args.append(int(limite))
    derniere = None
    for i, mode in enumerate(("mode=ro", "mode=ro&immutable=1")):
        try:
            cx = sqlite3.connect(f"file:{f}?{mode}", uri=True, timeout=5)
            try:
                lignes = cx.execute(sql, args).fetchall()
            finally:
                cx.close()
        except sqlite3.Error as e:   # OperationalError, DatabaseError
            derniere = e
            continue
        if i:
            log.warning("dnstv.db lu en immutable (WAL non ouvrable en lecture seule) : %s", derniere)
        return [{"client_ip": c, "domaine": d, "ts": t} for t, c, d in reversed(lignes)]
    log.warning("dnstv.db illisible : %s", derniere)
    return []


def signaux_doh(evenements_dns: Iterable[dict], noms_doh: Set[str],
                voisins: Optional[Dict[str, str]] = None) -> List[Signal]:
    """Un Signal `doh` par client ayant résolu un nom de résolveur DoH (nom exact ou sous-domaine)."""
    voisins = voisins or {}
    noms = {n.lower().rstrip(".") for n in noms_doh}
    vus: Set[str] = set()
    out: List[Signal] = []
    for e in evenements_dns:
        ip = e.get("client_ip")
        d = str(e.get("domaine") or "").lower().rstrip(".")
        if not ip or ip in vus or not d:
            continue
        if d in noms or any(d.endswith("." + n) for n in noms):
            vus.add(ip)
            out.append(Signal("ad-guard", "doh", str(ip), voisins.get(str(ip)), d, "doh", int(e.get("ts") or 0)))
    return out


def _ip_neigh(cmd) -> str:
    return subprocess.run(list(cmd), capture_output=True, text=True, timeout=10, check=False).stdout


def voisins(ip_neigh=("ip", "-j", "neigh"), runner: Callable = _ip_neigh) -> Dict[str, str]:
    """IP → MAC des voisins REACHABLE/STALE/DELAY (sortie JSON de `ip -j neigh`) ; échec : {}."""
    try:
        data = json.loads(runner(ip_neigh))
    except (OSError, ValueError, subprocess.SubprocessError):
        return {}
    out: Dict[str, str] = {}
    for n in data if isinstance(data, list) else []:
        if not isinstance(n, dict) or not n.get("dst") or not n.get("lladdr"):
            continue
        if ETATS_VOISINS & set(n.get("state") or []):
            out[str(n["dst"])] = str(n["lladdr"]).lower()
    return out
