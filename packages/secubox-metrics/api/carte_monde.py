# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: metrics :: carte du monde en points (la MEME que la page WAF du Hall).

Le fond de terre est une grille de 120 x 60 cases de 3 degres (codage par plages : une ligne par
latitude, « 0 » ou « 1 » pour l'etat de depart, puis les longueurs des plages alternees).
Un test garde ces constantes identiques a celles de composants/waf/www/waf/tableau.html.
"""
from __future__ import annotations

TERRE = "0120|0120|031,8,5,9,67|028,7,3,16,10,2,1,1,23,2,27|019,2,2,1,2,1,1,6,3,16,29,1,11,3,23|019,2,3,1,1,5,1,2,7,12,25,1,8,13,1,1,5,1,12|06,4,12,4,2,1,1,7,5,9,17,2,12,2,1,28,7|01,64,9,2,8,1,35|06,27,1,4,5,3,7,2,9,3,1,51,1|05,24,5,2,8,2,16,4,1,45,1,1,1,3,2|08,1,5,15,5,3,1,1,19,1,3,1,1,2,2,39,6,1,6|016,15,3,6,18,1,5,1,2,38,7,2,6|017,16,1,7,16,1,1,49,4,1,7|019,19,21,49,12|019,19,21,11,1,1,1,4,1,28,1,1,12|019,18,20,1,1,3,1,6,4,3,1,28,2,1,12|019,16,22,3,5,3,2,7,1,22,1,2,17|019,16,22,3,4,1,2,1,1,8,1,23,1,1,3,1,13|020,14,24,5,9,28,4,2,14|021,12,24,8,2,2,3,29,2,1,16|023,5,4,1,23,15,1,4,1,24,19|024,4,27,22,3,20,20|025,2,6,1,21,17,1,7,3,7,1,7,22|025,3,2,1,5,1,18,17,2,5,5,4,3,4,1,1,23|027,4,23,19,1,4,6,3,4,5,4,1,19|030,2,22,22,9,2,6,3,24|031,1,3,3,1,1,15,22,8,2,8,1,24|034,6,16,21,24,1,18|034,9,14,1,4,14,16,1,5,2,20|034,9,20,12,18,2,1,3,21|033,12,18,11,20,1,2,2,1,1,3,1,15|033,14,17,9,21,1,10,3,12|033,15,16,9,23,2,8,3,11|034,14,16,9,47|035,12,17,10,2,1,26,2,2,1,12|035,12,17,10,2,1,26,2,2,1,12|037,10,17,8,3,1,24,9,11|037,9,19,7,2,2,22,12,10|036,8,21,6,27,13,9|036,8,21,6,27,13,9|036,7,23,4,29,12,9|036,6,24,1,32,1,6,4,10|035,6,66,3,8,1,1|035,4,79,1,1|036,2,79,1,2|035,3,78,1,3|035,2,83|035,2,83|0120|0120|0120|0120|0120|0120|0120|0120|0120|0120|0120|0120"

# Centre de chaque pays : (latitude, longitude).
CENTRE = {
    "AD": (42.5, 1.5), "AE": (24, 54), "AL": (41, 20), "AM": (40, 45), "AR": (-34, -64), "AT": (47.5, 14.5),
    "AU": (-25, 134), "AZ": (40.3, 47.7), "BA": (44, 18), "BD": (24, 90), "BE": (50.6, 4.6),
    "BG": (42.7, 25.5), "BR": (-10, -52), "BY": (53.7, 28), "CA": (58, -100), "CH": (46.8, 8.2),
    "CL": (-35, -71), "CN": (35, 103), "CO": (4, -72), "CZ": (49.8, 15.5), "DE": (51, 10), "DK": (56, 10),
    "DZ": (28, 2), "EC": (-1.5, -78), "EE": (58.6, 25.5), "EG": (26, 30), "ES": (40, -4), "FI": (64, 26),
    "FR": (46.5, 2.5), "GB": (54, -2), "GE": (42, 43.5), "GR": (39, 22), "HK": (22.3, 114.2),
    "HR": (45.1, 15.2), "HU": (47, 19.5), "ID": (-2, 118), "IE": (53, -8), "IL": (31, 35), "IN": (22, 79),
    "IQ": (33, 44), "IR": (32, 53), "IS": (65, -18), "IT": (42.8, 12.5), "JP": (36, 138), "KE": (0, 38),
    "KG": (41.5, 74.5), "KR": (36.5, 128), "KZ": (48, 68), "LT": (55.3, 23.8), "LU": (49.8, 6.1),
    "LV": (56.9, 24.6), "MA": (32, -6), "MD": (47, 28.5), "MX": (23, -102), "MY": (4, 102), "NG": (9, 8),
    "NL": (52.2, 5.5), "NO": (62, 10), "NZ": (-41, 174), "PE": (-10, -76), "PH": (13, 122), "PK": (30, 70),
    "PL": (52, 19.4), "PT": (39.5, -8), "RO": (46, 25), "RS": (44, 21), "RU": (60, 90), "SA": (24, 45),
    "SE": (62, 15), "SG": (1.35, 103.8), "SI": (46.1, 14.8), "SK": (48.7, 19.5), "TH": (15, 101),
    "TN": (34, 9), "TR": (39, 35), "TW": (23.7, 121), "UA": (49, 32), "US": (39, -98), "UZ": (41, 64),
    "VE": (7, -66), "VN": (16, 106), "ZA": (-29, 24),
}

IGNORES = ("LAN", "LOCAL", "??", "")


def points_terre() -> list[tuple[float, float]]:
    """Centres des cases de terre : x = colonne + 0.5, y = ligne + 0.5 (y croit vers le sud)."""
    pts = []
    for j, ligne in enumerate(TERRE.split("|")):
        terre, x = ligne[0] == "1", 0
        for n in ligne[1:].split(","):
            n = int(n)
            if terre:
                pts.extend((x + i + 0.5, j + 0.5) for i in range(n))
            x += n
            terre = not terre
    return pts


def bulles(pays: dict) -> list[tuple[str, float, float, float]]:
    """(code, x, y, rayon) par pays connu, dans le repere de la grille ; rayon en cases, borne comme la page."""
    connus = {c: int(n) for c, n in pays.items() if c not in IGNORES and c in CENTRE and n}
    if not connus:
        return []
    fort = max(connus.values())
    out = []
    for c, n in sorted(connus.items(), key=lambda kv: -kv[1]):
        lat, lon = CENTRE[c]
        out.append((c, (lon + 180) / 3, (90 - lat) / 3, 1.2 + 2.6 * (n / fort) ** 0.5))
    return out
