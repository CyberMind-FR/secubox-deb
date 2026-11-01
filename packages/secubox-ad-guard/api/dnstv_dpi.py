# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: SBX TV Privacy lot 4 — DPI par appareil, fonctions PURES (#3374).

Rien ici ne touche au réseau ni au flux : on lit ce que gk2 voit déjà (requêtes DNS, cache d'Unbound, conntrack, fichier par appareil de
sbxdpi) et on en tire des CONSTATS (sans DNS, DNS chiffré, contournement), des DÉCOUVERTES datées (repli publicitaire après un blocage,
spot de secours récurrent) et un badge SSAI honnête. Les seules découvertes qui deviennent candidates du moteur AUTO sont les replis de
catégorie bloquable ; la garde du lot 2 (`dnstv_taxonomie.refus_auto`) reste seule juge de l'essai.
"""
from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

try:
    from . import dnstv, dnstv_taxonomie
except ImportError:                                   # contrôleur et moteur importent `api.` directement
    from api import dnstv, dnstv_taxonomie

PUB = frozenset({"PUBLICITE", "TRACKING"})            # refus qui ouvrent une « coupure » et apparitions candidates
FENETRE_REPLI_S = 30                                  # une apparition compte si elle suit le refus de 30 s au plus
AVANT_S = 600                                         # « nouveau » : pas demandé dans les 10 min qui précèdent la coupure
ECART_COUPURE_S = 120                                 # deux refus à moins de 2 min = la même coupure
FENETRE_SECOURS_S = 60
TOLERANCE_SECOURS = 0.10
MEMOIRE_VOISINS_S = 86400
FENETRE_COUVERTURE_S = 3600
PORTS_IGNORES = frozenset({123, 1900, 5353, 3478, 3479, 67, 68, 546, 547})   # NTP, SSDP, mDNS, STUN, DHCP
APPLIS_IGNOREES = frozenset({"NTP", "SSDP", "MDNS", "STUN", "DHCP", "DHCPV6", "ICMP", "ICMPV6", "IGMP"})
APPLI_RE = re.compile(r"^[A-Za-z0-9._-]{1,48}$")
PROTO = ("tcp", "udp")


class ErreurDPI(ValueError):
    """Source DPI illisible ou invalide : on ne devine rien."""


def _ip(brut) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(str(brut).strip()))
    except ValueError:
        return None


def _publique(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    return a.is_global and not a.is_multicast


# ── rattachement adresse -> MAC ─────────────────────────────────────────────────────────────────────────────
def rattacher(adresses: Iterable[str], voisins: Dict[str, str], memoire: Dict[str, Tuple[str, int]], maintenant: int,
              ttl: int = MEMOIRE_VOISINS_S) -> Tuple[Dict[str, Optional[str]], Dict[str, Tuple[str, int]]]:
    """Adresse -> MAC par la table de voisinage du moment, sinon par la mémoire (24 h) ; jamais au hasard (None)."""
    mem = {a: (m, v) for a, (m, v) in memoire.items() if maintenant - v <= ttl}
    for a, m in voisins.items():
        if dnstv.MAC_RE.match(str(m or "")):
            mem[a] = (m, maintenant)
    out: Dict[str, Optional[str]] = {}
    for a in adresses:
        out[a] = mem[a][0] if a in mem else None
    return out, mem


# ── repli publicitaire (DNS) ────────────────────────────────────────────────────────────────────────────────
def _raison(delai: int, refus: str) -> str:
    return f"apparu {delai} s après le blocage de {refus}"


def correler(evts: List[dict], categorie: Callable[[str], str], fenetre: int = FENETRE_REPLI_S) -> List[dict]:
    """Découvertes `repli` / `repli-protege` d'UN appareil. `evts` : {ts, domaine, decision} (ordre quelconque).

    Coupure : refus PUB (les refus à moins de 2 min s'y rattachent). Apparition : domaine servi (non refusé) dans ]t0, t0 + fenêtre],
    non demandé dans les 10 min avant t0. Une découverte par domaine (la première coupure fixe la raison) ; `coupures` compte les
    coupures distinctes où il apparaît. Confiance : 40, +30 si sa catégorie est PUB, +20 s'il revient sur deux coupures ou plus.
    Un domaine protégé (hors INCONNU) est `repli-protege` : jamais candidat, seulement expliqué."""
    e = sorted(({"ts": int(x["ts"]), "domaine": dnstv.domaine_reel(str(x["domaine"]).lower().rstrip(".")), "decision": x.get("decision", "")}
                for x in evts if x.get("domaine")), key=lambda x: x["ts"])
    coupures: List[Tuple[int, str]] = []
    for x in e:
        if x["decision"] == "BLOCKED" and categorie(x["domaine"]) in PUB:
            if not coupures or x["ts"] - coupures[-1][0] > ECART_COUPURE_S:
                coupures.append((x["ts"], x["domaine"]))
    refuses = {x["domaine"] for x in e if x["decision"] == "BLOCKED"}
    trouves: Dict[str, dict] = {}
    for t0, refus in coupures:
        avant = {x["domaine"] for x in e if t0 - AVANT_S <= x["ts"] <= t0 and x["decision"] != "BLOCKED"}
        vus: Set[str] = set()
        for x in e:
            if not (t0 < x["ts"] <= t0 + fenetre) or x["decision"] == "BLOCKED":
                continue
            d = x["domaine"]
            if d in avant or d in vus or d in refuses:
                continue
            vus.add(d)
            if d in trouves:
                trouves[d]["coupures"] += 1
                continue
            cat = categorie(d)
            protege = cat in dnstv_taxonomie.PROTEGEES and cat != "INCONNU"
            delai = x["ts"] - t0
            trouves[d] = {"type": "repli-protege" if protege else "repli", "domaine": d, "categorie": cat, "refus_domaine": refus,
                          "refus_ts": t0, "ts": x["ts"], "delai_s": delai, "coupures": 1, "raison": _raison(delai, refus)}
    for d in trouves.values():
        d["confiance"] = 40 + (30 if d["categorie"] in PUB else 0) + (20 if d["coupures"] >= 2 else 0)
        if d["type"] == "repli-protege":
            d["raison"] += f" — catégorie {d['categorie']} protégée : jamais bloquée"
    return sorted(trouves.values(), key=lambda d: (d["ts"], d["domaine"]))


def candidats_repli(decouvertes: Iterable[dict]) -> List[dict]:
    """Replis qui peuvent entrer au moteur AUTO : catégorie PUB seulement (la garde `refus_auto` juge encore l'essai)."""
    return [d for d in decouvertes if d["type"] == "repli" and d["categorie"] in PUB]


# ── spot de secours (DPI) ───────────────────────────────────────────────────────────────────────────────────
def secours(flux: Iterable[dict], refus_ts: Iterable[int], fenetre: int = FENETRE_SECOURS_S) -> List[dict]:
    """Même hôte, volume comparable (± 10 %), dans la minute qui suit un refus, sur deux coupures ou plus. Hypothèse étiquetée."""
    refus = sorted(set(int(t) for t in refus_ts))
    par_hote: Dict[str, Dict[int, int]] = {}
    for f in flux:
        h, ts, o = str(f.get("hote") or ""), int(f.get("ts", 0)), int(f.get("octets", 0))
        if not h or o <= 0:
            continue
        for t0 in refus:
            if t0 < ts <= t0 + fenetre:
                par_hote.setdefault(h, {})
                par_hote[h][t0] = par_hote[h].get(t0, 0) + o
                break
    out = []
    for h, vols in par_hote.items():
        if len(vols) < 2:
            continue
        v = sorted(vols.values())
        if (v[-1] - v[0]) <= TOLERANCE_SECOURS * v[-1]:
            out.append({"type": "secours", "hote": h, "coupures": len(vols), "octets": v[-1], "refus_ts": sorted(vols),
                        "raison": f"même hôte et même volume après {len(vols)} coupures : spot de secours probable (hypothèse)"})
    return sorted(out, key=lambda x: x["hote"])


# ── SSAI ────────────────────────────────────────────────────────────────────────────────────────────────────
def charger_motifs_ssai(chemin: Path) -> List[re.Pattern]:
    out = []
    try:
        texte = chemin.read_text(encoding="utf-8")
    except OSError:
        return []
    for ligne in texte.splitlines():
        m = ligne.split("#", 1)[0].strip().lower()
        if not m or not re.fullmatch(r"[a-z0-9*.-]{3,200}", m):
            continue
        out.append(re.compile("^" + r"\.".join(re.escape(p).replace(r"\*", "[a-z0-9-]*") for p in m.split(".")) + "$"))
    return out


def est_ssai(domaine: str, motifs: Iterable[re.Pattern]) -> bool:
    d = dnstv.domaine_reel(str(domaine or "").lower().rstrip("."))
    return any(m.match(d) for m in motifs)


# ── constats sur les flux ───────────────────────────────────────────────────────────────────────────────────
def charger_resolveurs(chemin: Path) -> Tuple[Set[str], Set[str]]:
    """(adresses, noms) de la liste livrée des résolveurs DoH/DoT ; une ligne invalide est ignorée."""
    ips, noms = set(), set()
    try:
        texte = chemin.read_text(encoding="utf-8")
    except OSError:
        return ips, noms
    for ligne in texte.splitlines():
        v = ligne.split("#", 1)[0].strip().lower()
        if not v:
            continue
        ip = _ip(v)
        if ip:
            ips.add(ip)
        elif dnstv.valider_domaine(v) == v:
            noms.add(v)
    return ips, noms


def constats(flux: Iterable[dict], resolus: Set[str], box: Set[str], doh: Set[str], doh_noms: Set[str]) -> List[dict]:
    """`sans-dns` : adresse publique, aucun nom (SNI) et jamais résolue pour cet appareil ; `dns-chiffre` : DoT/DoQ (853), appli DoH_DoT,
    ou 443 vers un résolveur DoH connu ; `contournement` : DNS (53) vers un autre résolveur que la box. NTP, STUN, SSDP, mDNS, DHCP
    et multicast ne comptent jamais."""
    out, vus = [], set()
    for f in flux:
        d = _ip(f.get("distant", ""))
        if not d:
            continue
        port, appli, hote = int(f.get("port", 0)), str(f.get("appli", "")), str(f.get("hote", "") or "").lower()
        base = appli.split(".")[0].upper()
        if port in PORTS_IGNORES or base in APPLIS_IGNOREES or ipaddress.ip_address(d).is_multicast:
            continue
        typ = None
        if port == 53 or base == "DNS":
            typ = None if d in box else "contournement"
        elif port == 853 or "DOH" in appli.upper() or (port == 443 and (d in doh or hote in doh_noms)):
            typ = "dns-chiffre"
        elif _publique(d) and not hote and d not in resolus:
            typ = "sans-dns"
        if typ and (typ, d, port) not in vus:
            vus.add((typ, d, port))
            out.append({"type": typ, "local": f.get("local", ""), "distant": d, "port": port, "proto": f.get("proto", ""),
                        "appli": appli, "hote": hote})
    return out


def couverture(dernier_flux: Optional[int], maintenant: int) -> str:
    """`dns+dpi` si des flux de l'appareil ont été vus (DPI ou conntrack) dans l'heure ; sinon `dns` (DNS seulement)."""
    return "dns+dpi" if dernier_flux is not None and 0 <= maintenant - int(dernier_flux) <= FENETRE_COUVERTURE_S else "dns"


# ── sources ─────────────────────────────────────────────────────────────────────────────────────────────────
_CT = re.compile(r"^(ipv4|ipv6)\s+\d+\s+(tcp|udp)\s+\d+\s+\d+\s+(?:[A-Z_]+\s+)?src=(\S+)\s+dst=(\S+)\s+sport=(\d+)\s+dport=(\d+)")


def lire_conntrack(texte: str, perimetre: Set[str]) -> List[dict]:
    """Lignes `/proc/net/nf_conntrack` (sens d'origine) dont la source est une adresse du périmètre. Ne voit que le trafic TRANSFÉRÉ par gk2."""
    out = []
    for ligne in texte.splitlines()[:200000]:
        m = _CT.match(ligne.strip())
        if not m:
            continue
        src, dst = _ip(m.group(3)), _ip(m.group(4))
        if not src or not dst or src not in perimetre:
            continue
        out.append({"local": src, "distant": dst, "port": int(m.group(6)), "proto": m.group(2), "appli": "", "hote": ""})
    return out


MAX_FLUX_SBXDPI = 20000


def lire_sbxdpi(texte: str) -> dict:
    """Fichier par appareil de sbxdpi (`appareils.json`), REVALIDÉ champ par champ ; toute ligne douteuse est écartée."""
    try:
        brut = json.loads(texte)
    except ValueError as e:
        raise ErreurDPI("appareils.json illisible") from e
    if not isinstance(brut, dict) or brut.get("version") != 1 or not isinstance(brut.get("flux"), list):
        raise ErreurDPI("appareils.json : structure inattendue")
    out = []
    for f in brut["flux"][:MAX_FLUX_SBXDPI]:
        try:
            local = _ip(f["local"])
            appli = str(f.get("appli", ""))
            hote = str(f.get("hote", "") or "").lower().rstrip(".")
            distant = _ip(f["distant"]) if f.get("distant") else ""
            proto = str(f.get("proto", "")).lower()
            nums = [int(f[k]) for k in ("port", "flux", "octets", "premier", "dernier")]
        except (KeyError, TypeError, ValueError):
            continue
        if not local or not APPLI_RE.match(appli) or proto not in PROTO or (hote and dnstv.valider_domaine(hote) != hote) \
                or distant is None or any(n < 0 for n in nums) or nums[0] > 65535:
            continue
        cat = str(f.get("categorie", ""))[:32]
        out.append({"local": local, "appli": appli, "categorie": cat if APPLI_RE.match(cat or "x") else "", "hote": hote,
                    "distant": distant, "port": nums[0], "proto": proto, "flux": nums[1], "octets": nums[2], "premier": nums[3],
                    "dernier": nums[4]})
    try:
        genere = int(brut.get("genere", 0))
    except (TypeError, ValueError):
        genere = 0
    return {"genere": genere, "flux": out}
