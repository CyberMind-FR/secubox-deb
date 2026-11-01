# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: SBX TV Privacy lot 4 — forçage du DNS (#3374, arbitrage 2). Fonctions PURES ; le contrôleur root applique.

Pour les appareils du périmètre en PROTECT (`block`) ou AUTO effectifs, avec une MAC : le DNS (53) est redirigé vers le résolveur de la box,
DoT/DoQ (853) et les résolveurs DoH connus (443 vers leurs ADRESSES, liste livrée) sont rejetés. nftables seulement.

LIMITE, écrite noir sur blanc : ces règles ne voient que le trafic qui TRAVERSE gk2. Sur un LAN plat (passerelle Freebox), une TV qui
interroge 8.8.8.8 ne passe pas par gk2 : rien n'est redirigé. Seul le mode LAN (conception lot 4, § 10) les rend effectives.
Rien n'est posé pour un appareil en OBSERVE ou OFF (la pause et « Je débloque » passent par OBSERVE). Aucun domaine n'est bloqué ici :
ni contenu, ni CDN, ni DRM — seulement des adresses de résolveurs et le port 853.
"""
from __future__ import annotations

import ipaddress
import json
from typing import Iterable, List, Set

try:
    from . import dnstv
except ImportError:
    from api import dnstv

TABLE = "secubox_adguard_contournement"
MODES_FORCES = ("block", "auto")
DUREE_SUSPENSION_S = 86400
FICHIER_SUSPENSIONS = "contournement-suspendu.json"


def forces(etat: dict, suspendus: Iterable[str] = ()) -> List[str]:
    """MAC des appareils à forcer : PROTECT/AUTO effectif, MAC valide, non suspendus (lecture cassée)."""
    s = set(suspendus)
    return sorted({c["mac"] for c in etat.get("clients", []) if c.get("mode") in MODES_FORCES and c.get("mac")
                   and dnstv.MAC_RE.match(c["mac"]) and c["mac"] not in s})


def _elements(valeurs: List[str]) -> str:
    return f"\t\telements = {{ {', '.join(valeurs)} }}\n" if valeurs else ""


def rendre(etat: dict, doh: Iterable[str], suspendus: Iterable[str] = ()) -> str:
    """Le jeu de règles complet, remplacé d'un bloc (`table` + `delete table` + définition : atomique sous `nft -f`)."""
    v4, v6 = [], []
    for a in doh:
        try:
            ip = ipaddress.ip_address(str(a).strip())
        except ValueError:
            continue
        (v4 if ip.version == 4 else v6).append(str(ip))
    macs = forces(etat, suspendus)
    return (f"table inet {TABLE}\ndelete table inet {TABLE}\n"
            f"table inet {TABLE} {{\n"
            "\tcounter sbx_ct_dns_redirige {}\n\tcounter sbx_ct_dot_rejete {}\n\tcounter sbx_ct_doh_rejete {}\n"
            f"\tset sbx_tv_force {{\n\t\ttype ether_addr\n{_elements(macs)}\t}}\n"
            f"\tset sbx_doh_v4 {{\n\t\ttype ipv4_addr\n{_elements(sorted(set(v4)))}\t}}\n"
            f"\tset sbx_doh_v6 {{\n\t\ttype ipv6_addr\n{_elements(sorted(set(v6)))}\t}}\n"
            "\tchain prerouting {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n"
            "\t\tether saddr @sbx_tv_force udp dport 53 counter name sbx_ct_dns_redirige redirect to :53\n"
            "\t\tether saddr @sbx_tv_force tcp dport 53 counter name sbx_ct_dns_redirige redirect to :53\n\t}\n"
            "\tchain forward {\n\t\ttype filter hook forward priority filter - 2; policy accept;\n"
            "\t\tether saddr @sbx_tv_force tcp dport 853 counter name sbx_ct_dot_rejete reject with tcp reset\n"
            "\t\tether saddr @sbx_tv_force udp dport 853 counter name sbx_ct_dot_rejete reject\n"
            "\t\tether saddr @sbx_tv_force ip daddr @sbx_doh_v4 tcp dport 443 counter name sbx_ct_doh_rejete reject with tcp reset\n"
            "\t\tether saddr @sbx_tv_force ip daddr @sbx_doh_v4 udp dport 443 counter name sbx_ct_doh_rejete reject\n"
            "\t\tether saddr @sbx_tv_force ip6 daddr @sbx_doh_v6 tcp dport 443 counter name sbx_ct_doh_rejete reject with tcp reset\n"
            "\t\tether saddr @sbx_tv_force ip6 daddr @sbx_doh_v6 udp dport 443 counter name sbx_ct_doh_rejete reject\n\t}\n"
            "}\n")


def lire_suspensions(texte: str, maintenant: int) -> Set[str]:
    """MAC suspendues (lecture cassée) depuis moins de 24 h ; tout le reste est ignoré."""
    try:
        brut = json.loads(texte)
        items = brut.get("suspendus", {}).items() if isinstance(brut, dict) else []
    except (ValueError, AttributeError):
        return set()
    out = set()
    for m, ts in items:
        if isinstance(m, str) and dnstv.MAC_RE.match(m) and isinstance(ts, int) and 0 <= maintenant - ts <= DUREE_SUSPENSION_S:
            out.add(m)
    return out


def suspendre(texte: str, macs: Iterable[str], maintenant: int) -> str:
    """Ajoute des suspensions (moteur) ; les échues sont oubliées."""
    try:
        brut = json.loads(texte) if texte else {}
    except ValueError:
        brut = {}
    garde = {m: ts for m, ts in (brut.get("suspendus", {}) if isinstance(brut, dict) else {}).items()
             if isinstance(m, str) and dnstv.MAC_RE.match(m) and isinstance(ts, int) and 0 <= maintenant - ts <= DUREE_SUSPENSION_S}
    for m in macs:
        if dnstv.MAC_RE.match(m):
            garde[m] = maintenant
    return json.dumps({"version": 1, "suspendus": garde}, sort_keys=True)


def a_suspendre(changements: Iterable[dict], etat: dict) -> List[str]:
    """MAC forcées dont un essai vient d'être retiré parce que le contenu habituel n'est plus demandé (lecture cassée) : le forçage du DNS
    est suspendu 24 h pour elles, par prudence (on ne sait pas lequel, de la règle ou du forçage, a cassé la lecture)."""
    slugs = {c["appareil"] for c in changements if c.get("vers") == "retire" and c.get("motif") == "contenu habituel plus demandé"}
    f = set(forces(etat))
    return sorted({c["mac"] for c in etat.get("clients", []) if c.get("mac") in f and dnstv._slug(c["nom"]) in slugs})
