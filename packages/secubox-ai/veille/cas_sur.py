# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Cas sûr LOCAL d'un `ban_bloc` (V2 § 10.2, #3723) : même ensemble et même seuil que gk2.

`CATEGORIES_SURES` et `SEUIL_BLOC` sont COPIÉS de `secubox-waf-ng/composants/waf/api/gestes_ia.py` ; le test
`test_cas_sur_identique_a_gk2` relit ce source et compare. gk2 recontrôle toujours (`/ai/ban`, 409 `pas_sur`) : le cas
sûr local ne sert qu'à ne pas proposer d'office ce que gk2 refuserait.

Règle (gestes_ia.cas_sur) : ≥ `SEUIL_BLOC` adresses distinctes du bloc ACTUELLEMENT bannies par le WAF, toutes de
familles sûres. Vu de gk3 : derniers faits `bans` / `bans_actifs` de chaque adresse du bloc sur 7 j ; une adresse
dont le dernier fait est une disparition (`bans_actifs`, `etat = disparu`) ou un ban échu (`exp` passé) n'est plus
bannie. Famille = celle du dernier ban (coupée à « : » et « | », comme gk2).
"""
import ipaddress
import json
from datetime import datetime, timedelta, timezone

from veille.regles import iso

SEUIL_BLOC = 20
CATEGORIES_SURES = frozenset({"scanners", "recon_crawler", "host_anomaly", "leurre", "product_absent_probes",
                              "honeypot", "waf_fingerprint"})
RECUL_S = 7 * 86400


def _famille(f):
    return str(f or "").split("|", 1)[0].split(":", 1)[0].strip()


def bloc_sur(db, bloc, maintenant: datetime) -> bool:
    """Vrai si le bloc /24 IPv4 est un cas sûr selon les faits de gk2 rangés dans veille.db."""
    try:
        reseau = ipaddress.IPv4Network(bloc, strict=True)
    except (ValueError, TypeError):
        return False
    if reseau.prefixlen != 24:
        return False
    derniers = {}
    for ip, source, famille, h, attributs in db.execute(
            "SELECT ip_src, source, famille, horodatage, attributs_json FROM evenements WHERE bloc24 = ? "
            "AND source IN ('bans', 'bans_actifs') AND horodatage >= ? AND horodatage <= ? ORDER BY horodatage, id",
            (str(reseau), iso(maintenant - timedelta(seconds=RECUL_S)), iso(maintenant))):
        if not ip:
            continue
        try:
            a = json.loads(attributs or "{}")
        except ValueError:
            a = {}
        derniers[ip] = (source, famille, a if isinstance(a, dict) else {})
    actives = {}
    for ip, (source, famille, a) in derniers.items():
        if source == "bans_actifs" and a.get("etat") == "disparu":
            continue
        exp = a.get("exp")
        if isinstance(exp, (int, float)) and not isinstance(exp, bool):
            try:
                if datetime.fromtimestamp(exp, timezone.utc) <= maintenant:
                    continue
            except (OverflowError, OSError, ValueError):
                continue
        actives[ip] = _famille(famille)
    return len(actives) >= SEUIL_BLOC and all(f in CATEGORIES_SURES for f in actives.values())
