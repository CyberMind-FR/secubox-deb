# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Métriques du panneau DNS Guard (#1978) : d'après le puits DNS et les compteurs de `secubox-adguard-dnsfeed` (la source de #1963).

Le blocage réel vit dans Unbound ; la liste propre à ce module (dnsmasq) n'est pas celle qui bloque sur la box. Un chiffre ABSENT est dit absent
(None), jamais un zéro qui laisserait croire qu'il n'y a rien. Les bases d'ad-guard sont ouvertes en lecture seule."""
import json
import sqlite3
from contextlib import closing
from pathlib import Path
from urllib.parse import quote

TOP_MAX = 50
TOP_DEFAUT = 10
MAX_JSON = 1024 * 1024


def _lecture_seule(chemin):
    return sqlite3.connect(f"file:{quote(str(Path(chemin)))}?mode=ro", uri=True, timeout=5)


def compteurs_dns(chemin, jour: str):
    """{"requetes", "bloquees"} du jour (UTC) d'après `dnstv_counts`, ou None si la base est absente ou illisible."""
    try:
        with closing(_lecture_seule(chemin)) as cx:
            lignes = cx.execute("SELECT decision, SUM(hits) FROM dnstv_counts WHERE jour = ? GROUP BY decision", (jour,)).fetchall()
    except (sqlite3.Error, OSError):
        return None
    requetes = sum(int(s or 0) for _, s in lignes)
    bloquees = min(int(dict(lignes).get("BLOCKED", 0) or 0), requetes)
    return {"requetes": requetes, "bloquees": bloquees}


def top_bloques(chemin, jour: str, limite) -> list:
    """Les domaines les plus bloqués du jour, tous appareils confondus (aucune adresse n'en sort). `limite` est bornée à 1..50."""
    try:
        n = max(1, min(int(limite), TOP_MAX))
    except (TypeError, ValueError):
        n = TOP_DEFAUT
    try:
        with closing(_lecture_seule(chemin)) as cx:
            lignes = cx.execute("SELECT domaine, MAX(categorie), SUM(hits) AS s FROM dnstv_counts WHERE jour = ? AND decision = 'BLOCKED' "
                                "GROUP BY domaine ORDER BY s DESC, domaine LIMIT ?", (jour, n)).fetchall()
    except (sqlite3.Error, OSError):
        return []
    return [{"domain": d, "category": c or "inconnue", "hits": int(s)} for d, c, s in lignes]


def lire_puits(chemin):
    """{"blocklist_size", "actif"} d'après `sinkhole-status.json` d'ad-guard, ou None si le fichier est absent ou invalide."""
    try:
        with open(chemin, "rb") as f:
            brut = f.read(MAX_JSON + 1)
        d = json.loads(brut[:MAX_JSON].decode("utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(d, dict):
        return None
    n = d.get("blocked")
    if not isinstance(n, int) or isinstance(n, bool) or n < 0:
        return None
    return {"blocklist_size": n, "actif": bool(d.get("enabled", True))}


def menaces(alertes) -> list:
    """Les alertes du module, au format que lit le panneau."""
    return [{"timestamp": a.timestamp, "domain": a.domain, "type": getattr(a.type, "value", a.type), "client_ip": a.client_ip, "blocked": a.blocked}
            for a in alertes]
