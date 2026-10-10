# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: détournement d'un domaine NORMAL, lu dans les RÉPONSES d'Unbound (#2240, phase 2).

Un domaine connu (demandé depuis ≥ 3 jours) qui résout soudain vers une adresse ou un ASN inattendu peut être détourné ou empoisonné. Les journaux
d'Unbound (`log-replies`) ne contiennent PAS les adresses de réponse ; la source est donc un instantané du cache (`unbound-control dump_cache`,
pris par le contrôleur root, filtré aux seuls enregistrements A/AAAA). Sa lecture ne gêne pas le DNS (mesuré sur gk2 : 5 s pour 12 000 lignes, requêtes
simultanées à 24-52 ms).

Deux règles :
  dns.hijack.new_net  un nom d'un domaine connu et STABLE résout vers un réseau (ASN, sinon préfixe /16 ou /32) jamais vu pour ce domaine.
                      « Stable » = au plus 5 réseaux dans la référence : un CDN qui tourne sur dix réseaux n'a pas de référence, aucun signal.
                      La source de l'enveloppe est l'adresse inattendue (l'infrastructure distante est l'acteur).
  dns.hijack.special  un nom public (historique d'adresses publiques) résout vers loopback, privé, lien-local, nul, CGNAT ou multicast — rebinding
                      ou puits. La source est l'appareil du réseau qui a demandé ce domaine ; sans appareil connu, pas de constat.

Garde-fous : référence d'au moins 3 jours (apprentissage silencieux avant) ; un nom TOUJOURS privé (zone locale) n'est jamais jugé ; une adresse
suspecte n'ENTRE PAS dans la référence (elle ne devient pas « normale » à force de durer) — elle est re-signalée jusqu'à ce que l'opérateur l'accepte
(`secubox-adguard-dnssensor --accepter DOMAINE`, qui apprend alors le nouveau réseau).

Fonctions sans E/S réseau ; l'état est un SQLite local (reponses.db) dans le dossier d'ad-guard.
"""
from __future__ import annotations

import ipaddress
import re
import sqlite3
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

from api.dnstv_anomalies import registre_du_domaine

MIN_AGE_S = 3 * 86400
MAX_RESEAUX_STABLE = 5
MAX_LIGNES = 300_000
_RE_REP = re.compile(r"^([A-Za-z0-9_.*-]+?)\.?\s+\d+\s+IN\s+(A|AAAA)\s+([0-9A-Fa-f:.]+)$")
_CGNAT = ipaddress.ip_network("100.64.0.0/10")

SCHEMA = """
CREATE TABLE IF NOT EXISTS rep (registre TEXT NOT NULL, nom TEXT NOT NULL, ip TEXT NOT NULL, reseau TEXT NOT NULL,
    premiere INTEGER NOT NULL, derniere INTEGER NOT NULL, PRIMARY KEY (nom, ip));
CREATE INDEX IF NOT EXISTS rep_registre ON rep(registre);
CREATE TABLE IF NOT EXISTS accepte (registre TEXT PRIMARY KEY);
"""


def ouvrir(chemin) -> sqlite3.Connection:
    cx = sqlite3.connect(str(chemin), timeout=10)
    cx.executescript(SCHEMA)
    return cx


def parse_dump(texte: str) -> List[Tuple[str, str]]:
    """(nom, adresse) des seuls enregistrements A/AAAA d'un `dump_cache`, adresses valides, sans doublon, plafonné."""
    vus: Set[Tuple[str, str]] = set()
    for ligne in texte.splitlines():
        m = _RE_REP.match(ligne.strip())
        if not m:
            continue
        try:
            ip = str(ipaddress.ip_address(m.group(3)))
        except ValueError:
            continue
        vus.add((m.group(1).lower().rstrip("."), ip))
        if len(vus) >= MAX_LIGNES:
            break
    return sorted(vus)


_RE_NOM = re.compile(r"^[a-z0-9_.*-]{1,253}$")


def parse_tsv(texte: str) -> List[Tuple[str, str]]:
    """Relit « nom<TAB>adresse » (sortie du contrôleur, ou fichier rangé) en revalidant chaque champ : on ne fait confiance à aucune frontière."""
    out: Set[Tuple[str, str]] = set()
    for ligne in texte.splitlines():
        p = ligne.split("\t")
        if len(p) != 2 or not _RE_NOM.match(p[0]):
            continue
        try:
            out.add((p[0], str(ipaddress.ip_address(p[1]))))
        except ValueError:
            continue
        if len(out) >= MAX_LIGNES:
            break
    return sorted(out)


def est_special(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    return (a.is_private or a.is_loopback or a.is_link_local or a.is_unspecified or a.is_multicast or a.is_reserved
            or (a.version == 4 and a in _CGNAT))


def reseau_de(ip: str, asn_de: Callable[[str], Optional[int]]) -> str:
    """ASN si la base en donne un, sinon préfixe (IPv4 /16, IPv6 /32) : approximatif, mais déterministe et sans dépendance."""
    asn = asn_de(ip)
    if asn:
        return f"AS{asn}"
    a = ipaddress.ip_address(ip)
    if a.version == 4:
        o = ip.split(".")
        return f"4:{o[0]}.{o[1]}"
    h = a.exploded.split(":")
    return f"6:{int(h[0], 16):x}:{int(h[1], 16):x}"


def _apprendre(cx: sqlite3.Connection, registre: str, nom: str, ip: str, reseau: str, now: int) -> None:
    cx.execute("INSERT INTO rep(registre,nom,ip,reseau,premiere,derniere) VALUES (?,?,?,?,?,?) "
               "ON CONFLICT(nom,ip) DO UPDATE SET derniere=excluded.derniere", (registre, nom, ip, reseau, now, now))


def accepter(cx: sqlite3.Connection, registre: str, reponses: Iterable[Tuple[str, str]], now: int, asn_de) -> None:
    """L'opérateur confirme qu'un changement est légitime : le domaine est accepté et ses réponses actuelles entrent dans la référence."""
    cx.execute("INSERT OR IGNORE INTO accepte(registre) VALUES (?)", (registre,))
    for nom, ip in reponses:
        if registre_du_domaine(nom) == registre:
            _apprendre(cx, registre, nom, ip, reseau_de(ip, asn_de), now)
    cx.commit()


def analyser(cx: sqlite3.Connection, reponses: Iterable[Tuple[str, str]], now: int, connus: Set[str], asn_de: Callable[[str], Optional[int]],
             clients: Dict[str, str]) -> List[dict]:
    """reponses : (nom, adresse) du cache. connus : domaines enregistrés demandés depuis ≥ 3 jours. clients : registre → un appareil qui l'a demandé."""
    par_reg: Dict[str, List[Tuple[str, str]]] = {}
    for nom, ip in reponses:
        par_reg.setdefault(registre_du_domaine(nom), []).append((nom, ip))
    acceptes = {r for (r,) in cx.execute("SELECT registre FROM accepte")}
    out: List[dict] = []
    for reg, lst in par_reg.items():
        hist = cx.execute("SELECT nom, ip, reseau, premiere FROM rep WHERE registre=?", (reg,)).fetchall()
        paires = {(n, i) for n, i, _, _ in hist}
        publics = [(i, r) for _, i, r, _ in hist if not est_special(i)]
        reseaux = {r for _, r in publics}
        base_ok = bool(hist) and now - min(p for *_, p in hist) >= MIN_AGE_S
        juge = reg in connus and base_ok and reg not in acceptes
        for nom, ip in lst:
            if (nom, ip) in paires:
                _apprendre(cx, reg, nom, ip, "", now)
                continue
            reseau = reseau_de(ip, asn_de)
            if est_special(ip):
                if juge and publics:
                    appareil = clients.get(reg)
                    if appareil:
                        out.append({"client": appareil, "src_ip": appareil, "domaine": reg, "rule": "dns.hijack.special", "severity": 75,
                                    "tags": ["dns_hijack_suspect", "dns_anomaly"],
                                    "detail": f"{nom} résout vers {ip} (non routable) alors que ce domaine résolvait vers des adresses publiques"})
                    continue                                 # suspecte ou sans appareil à nommer : jamais apprise
                _apprendre(cx, reg, nom, ip, reseau, now)
                continue
            if juge and reseaux and reseau not in reseaux and len(reseaux) <= MAX_RESEAUX_STABLE:
                out.append({"client": ip, "src_ip": ip, "domaine": reg, "rule": "dns.hijack.new_net", "severity": 60,
                            "tags": ["dns_hijack_suspect", "dns_anomaly"],
                            "detail": f"{nom} résout vers {ip} ({reseau}), jamais vu pour ce domaine ; référence : {', '.join(sorted(reseaux))}"})
                continue                                     # suspecte : elle n'entre pas dans la référence
            _apprendre(cx, reg, nom, ip, reseau, now)
    cx.commit()
    return out
