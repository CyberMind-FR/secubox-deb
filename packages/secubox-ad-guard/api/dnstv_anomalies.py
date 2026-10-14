# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: capteur DNS d'Actor Intelligence (#2240, phase 2).

RÈGLE DU PROPRIÉTAIRE : seuls les domaines MALVEILLANTS ou ANORMAUX produisent un signal. Une requête ordinaire n'en produit JAMAIS — ni
trace, ni compteur, ni enveloppe : le capteur n'est pas un journal de navigation. Et un domaine NORMAL peut avoir été corrompu : la dérive d'un
domaine connu compte donc aussi.

Cinq règles, toutes sans fournisseur externe (pas de liste commerciale, pas de service tiers) :

  dns.listed          le domaine, ou l'un de ses parents, figure dans la liste de l'opérateur (/etc/secubox/actor/dns-malveillants.txt, vide par défaut) ;
  dns.dga             ≥ 3 domaines enregistrés d'allure aléatoire, inconnus de l'historique, demandés par un même appareil en 10 min ;
  dns.tunnel          ≥ 30 sous-noms distincts à étiquette longue (≥ 20 car.) vers un même domaine en 10 min, OU ≥ 20 requêtes TXT/NULL/ANY vers lui
                      — même si ce domaine est parfaitement normal : c'est justement un domaine légitime détourné en canal ;
  dns.drift.spike     un domaine CONNU (vu ≥ 3 jours) demandé ≥ 10× son pic habituel dans l'heure (et ≥ 100 fois) ;
  dns.drift.subdomains  un domaine CONNU qui reçoit ≥ 25 sous-noms JAMAIS vus, à étiquette longue, en 10 min.

NON FAIT (dit, pas caché) : détecter qu'un domaine normal résout soudain vers une adresse ou un ASN inattendu (détournement, empoisonnement) demande
les RÉPONSES, que le magasin d'ad-guard ne conserve pas. Piste : journaliser les réponses d'Unbound (`log-replies` est déjà actif) — à décider.

Fonctions pures : aucune E/S ici ; le lancement (lecture du magasin, socket d'actord) est dans sbin/secubox-adguard-dnssensor.
"""
from __future__ import annotations

import hashlib
import math
import re
import time
from collections import Counter, defaultdict
from typing import Dict, Iterable, List, Optional, Set, Tuple

FENETRE_S = 600              # 10 min : DGA, tunnel, sous-noms
FENETRE_PIC_S = 3600         # 1 h : pic de requêtes
MIN_DGA = 3
MIN_SOUSNOMS_TUNNEL = 30
LABEL_LONG_TUNNEL = 20
MIN_TXT = 20
MIN_SOUSNOMS_DERIVE = 25
LABEL_LONG_DERIVE = 15
FACTEUR_PIC = 10
MIN_PIC = 100
REEMISSION_S = 6 * 3600
QTYPES_TUNNEL = {"TXT", "NULL", "ANY"}
SUFFIXES_2 = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp", "co.kr", "co.za", "com.br", "com.mx", "com.ar",
              "com.tr", "com.cn", "com.hk", "com.sg", "com.tw", "co.in", "co.id", "com.pl", "com.ua"}
_VOYELLES = set("aeiouy")


def registre_du_domaine(domaine: str) -> str:
    """Domaine enregistré (eTLD+1), avec une petite table de suffixes à deux niveaux : sans dépendance, volontairement approximatif."""
    labels = [l for l in domaine.lower().strip(".").split(".") if l]
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in SUFFIXES_2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def entropie(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def ressemble_dga(label: str) -> bool:
    """Étiquette d'allure aléatoire : longue, entropique, peu de voyelles, ou mêlant chiffres et lettres. Un mot lisible n'en est pas une."""
    l = label.lower()
    if len(l) < 12 or not re.fullmatch(r"[a-z0-9]+", l):
        return False
    voy = sum(1 for c in l if c in _VOYELLES) / len(l)
    chiffres = sum(1 for c in l if c.isdigit()) / len(l)
    return entropie(l) >= 3.3 and (voy < 0.30 or chiffres >= 0.20)


def _premiere_etiquette(domaine: str, registre: str) -> str:
    return domaine[: -len(registre)].strip(".").split(".")[-1] if domaine != registre else ""


def _dans_la_liste(domaine: str, liste: Set[str]) -> Optional[str]:
    d = domaine.lower().strip(".")
    while d:
        if d in liste:
            return d
        d = d.partition(".")[2]
    return None


def _constat(client: str, domaine: str, regle: str, gravite: int, etiquettes: List[str], detail: str) -> dict:
    return {"client": client, "domaine": domaine, "rule": regle, "severity": max(0, min(100, gravite)), "tags": etiquettes, "detail": detail}


def detecter(evts: Iterable[dict], now: int, connus: Set[str], base: Dict[Tuple[str, str], List[int]], noms_connus: Dict[str, Set[str]],
             liste: Set[str]) -> List[dict]:
    """evts : requêtes récentes {ts, client, domaine, qtype}. connus : domaines enregistrés vus ≥ 3 jours. base : (client, registre) → hits par jour.
    noms_connus : registre → noms complets déjà vus. liste : domaines malveillants déclarés par l'opérateur."""
    recents10 = [e for e in evts if now - e["ts"] <= FENETRE_S]
    recents60 = [e for e in evts if now - e["ts"] <= FENETRE_PIC_S]
    out: List[dict] = []

    # — liste de l'opérateur —
    vus_liste: Set[Tuple[str, str]] = set()
    for e in recents60:
        hit = _dans_la_liste(e["domaine"], liste) if liste else None
        if hit and (e["client"], hit) not in vus_liste:
            vus_liste.add((e["client"], hit))
            out.append(_constat(e["client"], hit, "dns.listed", 80, ["dns_malicious_listed"], "domaine de la liste de l'opérateur"))

    # — DGA : par appareil, domaines enregistrés aléatoires et inconnus —
    dga: Dict[str, Set[str]] = defaultdict(set)
    for e in recents10:
        reg = registre_du_domaine(e["domaine"])
        if reg in connus or reg in liste:
            continue
        if ressemble_dga(reg.split(".")[0]):
            dga[e["client"]].add(reg)
    for client, regs in dga.items():
        if len(regs) >= MIN_DGA:
            ex = sorted(regs)[0]
            out.append(_constat(client, ex, "dns.dga", 55 + 5 * (len(regs) - MIN_DGA), ["dns_dga", "dns_anomaly"], f"{len(regs)} domaines d'allure aléatoire inconnus en 10 min"))

    # — tunnel et dérive de sous-noms : par (appareil, domaine enregistré) —
    par: Dict[Tuple[str, str], List[dict]] = defaultdict(list)
    for e in recents10:
        par[(e["client"], registre_du_domaine(e["domaine"]))].append(e)
    for (client, reg), lst in par.items():
        sous = {e["domaine"] for e in lst if e["domaine"] != reg}
        longs = [s for s in sous if len(_premiere_etiquette(s, reg)) >= LABEL_LONG_TUNNEL]
        txt = sum(1 for e in lst if e.get("qtype", "A").upper() in QTYPES_TUNNEL)
        if len(longs) >= MIN_SOUSNOMS_TUNNEL:
            out.append(_constat(client, reg, "dns.tunnel", 70, ["dns_tunnel", "dns_anomaly"], f"{len(longs)} sous-noms longs distincts en 10 min"))
        elif txt >= MIN_TXT:
            out.append(_constat(client, reg, "dns.tunnel", 60, ["dns_txt_burst", "dns_anomaly"], f"{txt} requêtes TXT/NULL/ANY en 10 min"))
        elif reg in connus:
            nouveaux = [s for s in sous if s not in noms_connus.get(reg, set()) and len(_premiere_etiquette(s, reg)) >= LABEL_LONG_DERIVE]
            if len(nouveaux) >= MIN_SOUSNOMS_DERIVE:
                out.append(_constat(client, reg, "dns.drift.subdomains", 65, ["dns_drift", "dns_anomaly"],
                                    f"domaine connu : {len(nouveaux)} sous-noms jamais vus en 10 min"))

    # — dérive : pic de requêtes vers un domaine CONNU —
    h60: Counter = Counter((e["client"], registre_du_domaine(e["domaine"])) for e in recents60)
    for (client, reg), n in h60.items():
        if reg not in connus or n < MIN_PIC:
            continue
        jours = base.get((client, reg)) or []
        pic = max(jours) if jours else 0
        if pic and n >= FACTEUR_PIC * pic:
            out.append(_constat(client, reg, "dns.drift.spike", 50, ["dns_drift"], f"{n} requêtes en 1 h, {FACTEUR_PIC}× son pic quotidien habituel ({pic})"))
    return out


def enveloppe(c: dict, now: int) -> dict:
    """Enveloppe Actor Intelligence : l'APPAREIL est la source, le domaine ENREGISTRÉ est tout ce qu'on garde (jamais les sous-noms : ils peuvent
    porter des données)."""
    ident = hashlib.sha256(f"{c['client']}|{c['rule']}|{c['domaine']}|{now}".encode()).hexdigest()[:32]
    return {"event_id": "dns-" + ident, "timestamp": now, "sensor": "dns", "src_ip": c["client"], "dst_service": "dns", "transport": "udp",
            "protocol": "dns", "action": "observe", "rule_id": c["rule"], "severity": c["severity"], "path_shape": ("dns:" + c["domaine"])[:256],
            "behavior_tags": c["tags"][:8]}


def deduplique(constats: List[dict], etat: Dict[str, int], now: int) -> List[dict]:
    """Un même (appareil, règle, domaine) ne se ré-émet qu'au bout de 6 h ; l'état se purge de lui-même."""
    for k in [k for k, t in etat.items() if now - t > 2 * REEMISSION_S]:
        del etat[k]
    out = []
    for c in constats:
        cle = f"{c['client']}|{c['rule']}|{c['domaine']}"
        if now - etat.get(cle, -10**12) >= REEMISSION_S:
            etat[cle] = now
            out.append(c)
    return out


# ---------- alertes de dns-guard (#2702) ----------
# dns-guard affiche des « alertes DNS » (DnsAlert) ; faute de source, sa page restait vide. Le capteur y dépose ses constats, ET SEULEMENT eux : même règle
# que l'enveloppe d'Actor Intelligence — le domaine ENREGISTRÉ, l'appareil, la règle ; jamais un sous-nom ni le texte libre `detail` (il peut porter des données).

TYPES_DNSGUARD = {"dns.listed": "malicious", "dns.dga": "dga", "dns.tunnel": "tunneling", "dns.drift.spike": "high_rate", "dns.drift.subdomains": "exfiltration"}
LIBELLES_DNSGUARD = {
    "malicious": "Domaine de la liste de l'opérateur ou réponse détournée",
    "dga": "Domaines d'allure aléatoire demandés par un même appareil (DGA)",
    "tunneling": "Sous-noms et requêtes TXT en rafale vers un même domaine (tunnel DNS)",
    "high_rate": "Pic de requêtes sur un domaine connu",
    "exfiltration": "Sous-noms jamais vus, longs, sur un domaine connu (exfiltration possible)",
}
RATTRAPAGE_H = 24


def type_dnsguard(regle: str) -> str:
    """Règle du capteur → DetectionType de dns-guard. Une règle inconnue (ou un détournement dns.hijack.*) retombe sur « malicious » : elle ne disparaît pas."""
    return TYPES_DNSGUARD.get(regle, "malicious")


def gravite_dnsguard(score: int) -> str:
    return "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 40 else "low"


def _alerte(client: str, regle: str, domaine: str, score: int, tags: List[str], ts: int) -> dict:
    t = type_dnsguard(regle)
    ident = hashlib.sha256(f"{client}|{regle}|{domaine}|{ts}".encode()).hexdigest()[:24]
    return {"id": "dns-" + ident, "type": t, "severity": gravite_dnsguard(score), "domain": domaine, "client_ip": client or None,
            "description": LIBELLES_DNSGUARD[t], "details": {"rule": regle, "tags": list(tags)[:8], "source": "ad-guard"},
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts)) + "Z", "blocked": False}


def alerte_dnsguard(c: dict, now: int) -> dict:
    """Un constat du capteur → un DnsAlert (sans sous-nom ni détail libre)."""
    return _alerte(c["client"], c["rule"], c["domaine"], int(c.get("severity", 0)), c.get("tags", []), now)


def alertes_depuis_etat(emis: Dict[str, int], now: int, heures: int = RATTRAPAGE_H) -> List[dict]:
    """Rattrapage : l'état de dédoublonnage (« appareil|règle|domaine » → date) a gardé les constats déjà déposés ; ceux des dernières heures
    reviennent dans dns-guard. Score et étiquettes n'y sont pas conservés : gravité moyenne par défaut, dite telle quelle dans `details`."""
    out = []
    for cle, ts in sorted(emis.items(), key=lambda kv: kv[1]):
        parts = cle.split("|")
        if len(parts) != 3 or not isinstance(ts, (int, float)) or now - ts > heures * 3600 or ts > now:
            continue
        a = _alerte(parts[0], parts[1], parts[2], 50, [], int(ts))
        a["details"]["rattrape"] = True
        out.append(a)
    return out
