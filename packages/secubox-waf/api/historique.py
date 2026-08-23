# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: WAF :: historique des menaces (#1062)
CyberMind — https://cybermind.fr

Agrège les threat logs TOURNÉS (waf-threats.log + .1 + .N.gz) en tendances par
jour : de quoi bâtir un rapport bien plus complet que le seul jour courant que
lit /stats (top attaquants persistants, catégories dans le temps, pics).

COÛT : les .gz font des Mo et le tout dépasse 200 k lignes. Cette fonction fait
un SCAN COMPLET — elle n'est JAMAIS appelée sur le chemin d'une requête : un
agrégat de fond horaire écrit son résultat dans un JSON que la webui/le PDF
relisent instantanément (même patron que le double-cache de /stats).
"""
from __future__ import annotations

import gzip
import ipaddress
import json
from collections import Counter, defaultdict
from typing import Iterable


def bucket_ip(ip: str) -> str:
    """Regroupe le trafic INTERNE sous « local ».

    Loopback (127.0.0.0/8, ::1), privé (10/8, 172.16/12, 192.168/16, fc00::/7)
    et link-local (169.254/16, fe80::/10) ne sont PAS des attaquants : c'est du
    trafic de la box vers elle-même (sondes host-anomaly, health-checks…). On le
    fond sous une seule étiquette « local » — même décision que sbxwaf côté Go
    (#1163) — pour qu'il ne trône pas en tête des « attaquants persistants ».
    Une valeur non parsable est laissée telle quelle (on ne masque pas l'inconnu).
    """
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if a.is_private or a.is_loopback or a.is_link_local:
        return "local"
    return ip


def _ouvrir(chemin):
    """Ouvre en texte, gzip si l'extension le dit."""
    s = str(chemin)
    return gzip.open(s, "rt", errors="replace") if s.endswith(".gz") else open(
        s, "r", errors="replace")


def agreger_historique(chemins: Iterable, top_n: int = 50) -> dict:
    """Agrège une liste de journaux de menaces (courant + tournés, gzip compris).

    Retourne ``{jours: {AAAA-MM-JJ: {total, categories, severites}}, top_ips,
    total}``. Une ligne illisible est ignorée (un journal ne s'arrête pas à un
    octet corrompu). Un fichier absent/illisible est sauté.
    """
    jours: dict = defaultdict(
        lambda: {"total": 0, "categories": Counter(), "severites": Counter()})
    top_ips: Counter = Counter()
    total = 0

    for chemin in chemins:
        try:
            f = _ouvrir(chemin)
        except OSError:
            continue
        try:
            for ligne in f:
                ligne = ligne.strip()
                if not ligne:
                    continue
                try:
                    e = json.loads(ligne)
                except (ValueError, TypeError):
                    continue
                jour = str(e.get("timestamp", ""))[:10]
                if len(jour) != 10:
                    continue
                d = jours[jour]
                d["total"] += 1
                total += 1
                cat = e.get("category")
                if cat:
                    d["categories"][cat] += 1
                sev = e.get("severity")
                if sev:
                    d["severites"][sev] += 1
                ip = e.get("client_ip") or e.get("ip")
                if ip:
                    top_ips[bucket_ip(ip)] += 1
        finally:
            f.close()

    return {
        "jours": {
            j: {
                "total": d["total"],
                "categories": dict(d["categories"]),
                "severites": dict(d["severites"]),
            }
            for j, d in sorted(jours.items())
        },
        "top_ips": dict(top_ips.most_common(top_n)),
        "total": total,
    }
