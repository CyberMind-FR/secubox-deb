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
import bisect
import contextlib
import json
import os
import re
import sqlite3
import time
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
    cats: Dict[str, str] = {}

    def cat(d: str) -> str:
        if d not in cats:
            cats[d] = categorie(d)
        return cats[d]
    coupures: List[Tuple[int, str]] = []
    for x in e:
        if x["decision"] == "BLOCKED" and cat(x["domaine"]) in PUB:
            if not coupures or x["ts"] - coupures[-1][0] > ECART_COUPURE_S:
                coupures.append((x["ts"], x["domaine"]))
    refuses = {x["domaine"] for x in e if x["decision"] == "BLOCKED"}
    horo = [x["ts"] for x in e]
    trouves: Dict[str, dict] = {}
    for t0, refus in coupures:                         # I3 : fenêtre [t0 - 10 min, t0 + 30 s] par bissection, jamais toute la liste
        a, b, c = bisect.bisect_left(horo, t0 - AVANT_S), bisect.bisect_right(horo, t0), bisect.bisect_right(horo, t0 + fenetre)
        avant = {x["domaine"] for x in e[a:b] if x["decision"] != "BLOCKED"}
        vus: Set[str] = set()
        for x in e[b:c]:
            if x["decision"] == "BLOCKED":
                continue
            d = x["domaine"]
            if d in avant or d in vus or d in refuses:
                continue
            vus.add(d)
            if d in trouves:
                trouves[d]["coupures"] += 1
                continue
            cd = cat(d)
            protege = cd in dnstv_taxonomie.PROTEGEES and cd != "INCONNU"
            delai = x["ts"] - t0
            trouves[d] = {"type": "repli-protege" if protege else "repli", "domaine": d, "categorie": cd, "refus_domaine": refus,
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


# ── magasin borné : dpi-appareils.db ────────────────────────────────────────────────────────────────────────
RETENTION_FLUX_S = 7 * 86400
RETENTION_DECOUVERTES_S = 30 * 86400
MAX_DECOUVERTES = 5000
PEREMPTION_SBXDPI_S = 120
MAX_OCTETS = 20 * 1024 * 1024                         # B1 : plafond du fichier ; au-delà, les plus anciennes minutes partent
TYPES_DECOUVERTE = ("repli", "repli-protege", "secours", "sans-dns", "dns-chiffre", "contournement")

SCHEMA = """
CREATE TABLE IF NOT EXISTS flux (mac TEXT NOT NULL, minute INTEGER NOT NULL, appli TEXT NOT NULL, categorie_ndpi TEXT NOT NULL DEFAULT '',
    hote TEXT NOT NULL DEFAULT '', port INTEGER NOT NULL DEFAULT 0, distant TEXT NOT NULL DEFAULT '', flux INTEGER NOT NULL DEFAULT 0,
    octets INTEGER NOT NULL DEFAULT 0, sans_dns INTEGER NOT NULL DEFAULT 0, dns_chiffre INTEGER NOT NULL DEFAULT 0,
    local TEXT NOT NULL DEFAULT '', proto TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (mac, minute, local, proto, appli, hote, port, distant));
CREATE INDEX IF NOT EXISTS flux_mac ON flux(mac, minute);
CREATE TABLE IF NOT EXISTS decouvertes (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, mac TEXT NOT NULL, type TEXT NOT NULL,
    domaine TEXT NOT NULL, categorie TEXT NOT NULL DEFAULT '', appli TEXT NOT NULL DEFAULT '', confiance INTEGER NOT NULL DEFAULT 0,
    raison TEXT NOT NULL DEFAULT '', refus_domaine TEXT NOT NULL DEFAULT '', refus_ts INTEGER NOT NULL DEFAULT 0,
    delai_s INTEGER NOT NULL DEFAULT 0, coupures INTEGER NOT NULL DEFAULT 1, etat TEXT NOT NULL DEFAULT 'nouvelle',
    UNIQUE (mac, type, domaine, refus_ts));
CREATE TABLE IF NOT EXISTS voisins (adresse TEXT PRIMARY KEY, mac TEXT NOT NULL, vu INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS meta (cle TEXT PRIMARY KEY, valeur TEXT NOT NULL);
"""


class MagasinDPI:
    """SQLite du lot 4 : flux par appareil à la minute (7 j), découvertes (30 j, 5 000 au plus), mémoire adresse -> MAC (24 h), et
    20 Mio au plus (`auto_vacuum=INCREMENTAL`). Le MOTEUR crée, migre et écrit ; l'API ouvre en lecture seule (`mode=ro`), sans
    vérification ni écriture. Seule une vraie corruption (`DatabaseError` hors `OperationalError`, ou `quick_check` en échec) met la base
    de côté ; un verrou (`OperationalError`) est réessayé puis remonté, jamais pris pour une corruption."""

    def __init__(self, chemin, lecture_seule: bool = False, verifier: bool = False):
        self.chemin = Path(chemin)
        self.lecture_seule = lecture_seule
        self.corrompue_recreee = False
        if lecture_seule:
            return
        try:
            self._initialiser(verifier)
        except sqlite3.OperationalError:
            raise
        except sqlite3.DatabaseError:
            with contextlib.suppress(OSError):
                os.replace(self.chemin, self.chemin.with_name(self.chemin.name + ".corrompue"))
            self.corrompue_recreee = True
            self._initialiser(False)
        with contextlib.suppress(OSError):
            os.chmod(self.chemin, 0o640)

    def _initialiser(self, verifier: bool) -> None:
        for essai in range(3):
            try:
                with self._cx() as cx:
                    if verifier and cx.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                        raise sqlite3.DatabaseError("quick_check")
                    if cx.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()[0] == 0:
                        cx.execute("PRAGMA auto_vacuum=INCREMENTAL")         # avant toute table : effectif sur une base neuve
                    cx.executescript(SCHEMA)
                return
            except sqlite3.OperationalError:
                if essai == 2:
                    raise
                time.sleep(0.5)

    @contextlib.contextmanager
    def _cx(self):
        if self.lecture_seule:
            cx = sqlite3.connect(f"file:{self.chemin}?mode=ro", uri=True, timeout=10)
        else:
            cx = sqlite3.connect(str(self.chemin), timeout=10)
        try:
            with cx:
                yield cx
        finally:
            cx.close()

    def _lisible(self) -> bool:
        return not self.lecture_seule or self.chemin.is_file()

    def ingerer(self, lignes: Iterable[dict]) -> int:
        """Une ligne par (mac, minute, adresse locale, protocole, appli, hôte, port, distant) ; la valeur la plus récente d'une même minute
        REMPLACE (compteurs cumulés)."""
        rangs = [(x["mac"], int(x["minute"]), x["appli"], x.get("categorie_ndpi", ""), x.get("hote", ""), int(x.get("port", 0)),
                  x.get("distant", ""), int(x.get("flux", 0)), int(x.get("octets", 0)), int(bool(x.get("sans_dns"))),
                  int(bool(x.get("dns_chiffre"))), x.get("local", ""), x.get("proto", "")) for x in lignes]
        with self._cx() as cx:
            cx.executemany("INSERT OR REPLACE INTO flux (mac, minute, appli, categorie_ndpi, hote, port, distant, flux, octets, sans_dns, "
                           "dns_chiffre, local, proto) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", rangs)
        return len(rangs)

    def dernier_flux(self, mac: str) -> Optional[int]:
        if not self._lisible():
            return None
        with self._cx() as cx:
            v = cx.execute("SELECT MAX(minute) FROM flux WHERE mac=?", (mac,)).fetchone()[0]
        return None if v is None else int(v) * 60

    def applications(self, mac: str, depuis: int, limite: int = 50) -> List[dict]:
        if not self._lisible():
            return []
        with self._cx() as cx:
            lignes = cx.execute(
                "SELECT appli, MAX(categorie_ndpi), SUM(flux), SUM(octets), MIN(minute), MAX(minute), MAX(sans_dns), MAX(dns_chiffre) "
                "FROM flux WHERE mac=? AND minute>=? GROUP BY appli ORDER BY SUM(octets) DESC, appli LIMIT ?",
                (mac, int(depuis) // 60, max(1, min(int(limite), 200)))).fetchall()
            out = []
            for a, c, f, o, p, d, sd, dc in lignes:
                hotes = [h for (h,) in cx.execute("SELECT hote FROM flux WHERE mac=? AND appli=? AND minute>=? AND hote!='' GROUP BY hote "
                                                  "ORDER BY SUM(octets) DESC LIMIT 10", (mac, a, int(depuis) // 60))]
                out.append({"appli": a, "categorie_ndpi": c, "flux": int(f or 0), "octets": int(o or 0), "premier": int(p) * 60,
                            "dernier": int(d) * 60, "hotes": hotes, "sans_dns": bool(sd), "dns_chiffre": bool(dc)})
        return out

    def lignes_flux(self, mac: str, depuis: int, appli: Optional[str] = None, decalage: int = 0, limite: int = 50) -> Tuple[int, List[dict]]:
        if not self._lisible():
            return 0, []
        w, a = ["mac=?", "minute>=?"], [mac, int(depuis) // 60]
        if appli:
            w.append("appli=?")
            a.append(appli)
        with self._cx() as cx:
            total = cx.execute(f"SELECT COUNT(*) FROM flux WHERE {' AND '.join(w)}", a).fetchone()[0]
            lignes = cx.execute(f"SELECT minute, appli, categorie_ndpi, hote, port, distant, flux, octets, sans_dns, dns_chiffre FROM flux "
                                f"WHERE {' AND '.join(w)} ORDER BY minute DESC, octets DESC LIMIT ? OFFSET ?",
                                [*a, max(1, min(int(limite), 200)), max(0, int(decalage))]).fetchall()
        return int(total), [{"ts": m * 60, "appli": ap, "categorie_ndpi": c, "hote": h, "port": p, "distant": d, "flux": f, "octets": o,
                             "sans_dns": bool(sd), "dns_chiffre": bool(dc)} for m, ap, c, h, p, d, f, o, sd, dc in lignes]

    def ajouter_decouvertes(self, mac: str, decouvertes: Iterable[dict]) -> int:
        n = 0
        with self._cx() as cx:
            for d in decouvertes:
                if d.get("type") not in TYPES_DECOUVERTE:
                    continue
                cle = d.get("domaine") or d.get("hote") or ""
                cur = cx.execute("INSERT OR IGNORE INTO decouvertes (ts, mac, type, domaine, categorie, appli, confiance, raison, refus_domaine, "
                                 "refus_ts, delai_s, coupures) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                                 (int(d.get("ts", 0)), mac, d["type"], str(cle)[:260], d.get("categorie", ""), d.get("appli", ""),
                                  int(d.get("confiance", 0)), str(d.get("raison", ""))[:300], d.get("refus_domaine", ""),
                                  int(d.get("refus_ts", 0)), int(d.get("delai_s", 0)), int(d.get("coupures", 1))))
                if cur.rowcount:
                    n += 1
                elif d.get("coupures", 1) > 1:
                    cx.execute("UPDATE decouvertes SET coupures=MAX(coupures, ?), confiance=MAX(confiance, ?) WHERE mac=? AND type=? AND domaine=? "
                               "AND refus_ts=?", (int(d["coupures"]), int(d.get("confiance", 0)), mac, d["type"], str(cle)[:260],
                                                  int(d.get("refus_ts", 0))))
        return n

    def marquer(self, mac: str, domaine: str, etat: str) -> None:
        with self._cx() as cx:
            cx.execute("UPDATE decouvertes SET etat=? WHERE mac=? AND domaine=? AND type='repli' AND etat='nouvelle'", (etat, mac, domaine))

    def decouvertes(self, depuis_id: int = 0, type_: Optional[str] = None, mac: Optional[str] = None, limite: int = 100) -> List[dict]:
        if not self._lisible():
            return []
        w, a = ["id>?"], [int(depuis_id)]
        if type_:
            w.append("type=?")
            a.append(type_)
        if mac:
            w.append("mac=?")
            a.append(mac)
        cols = ("id", "ts", "mac", "type", "domaine", "categorie", "appli", "confiance", "raison", "refus_domaine", "refus_ts", "delai_s",
                "coupures", "etat")
        with self._cx() as cx:
            lignes = cx.execute(f"SELECT {', '.join(cols)} FROM decouvertes WHERE {' AND '.join(w)} ORDER BY id LIMIT ?",
                                [*a, max(1, min(int(limite), 500))]).fetchall()
        return [dict(zip(cols, row)) for row in lignes]

    def curseur(self, mac: str) -> int:
        with self._cx() as cx:
            r = cx.execute("SELECT valeur FROM meta WHERE cle=?", ("curseur:" + mac,)).fetchone()
        return int(r[0]) if r else 0

    def poser_curseur(self, mac: str, ts: int) -> None:
        with self._cx() as cx:
            cx.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", ("curseur:" + mac, str(int(ts))))

    def charger_voisins(self) -> Dict[str, Tuple[str, int]]:
        if not self._lisible():
            return {}
        with self._cx() as cx:
            return {a: (m, v) for a, m, v in cx.execute("SELECT adresse, mac, vu FROM voisins")}

    def ecrire_voisins(self, memoire: Dict[str, Tuple[str, int]]) -> None:
        with self._cx() as cx:
            cx.execute("DELETE FROM voisins")
            cx.executemany("INSERT INTO voisins VALUES (?,?,?)", [(a, m, v) for a, (m, v) in list(memoire.items())[:5000]])

    def taille(self) -> int:
        with self._cx() as cx:
            return int(cx.execute("PRAGMA page_count").fetchone()[0]) * int(cx.execute("PRAGMA page_size").fetchone()[0])

    def menage(self, maintenant: int, max_octets: Optional[int] = None) -> None:
        """Rétention par âge, puis plafond en octets : tant que la base dépasse, un dixième des plus anciennes lignes de flux part, puis
        `incremental_vacuum` rend les pages au système."""
        plafond = max_octets or MAX_OCTETS
        with self._cx() as cx:
            cx.execute("DELETE FROM flux WHERE minute < ?", ((maintenant - RETENTION_FLUX_S) // 60,))
            cx.execute("DELETE FROM decouvertes WHERE ts < ?", (maintenant - RETENTION_DECOUVERTES_S,))
            cx.execute("DELETE FROM decouvertes WHERE id <= (SELECT COALESCE(MAX(id), 0) FROM decouvertes) - ?", (MAX_DECOUVERTES,))
        self._vider()
        for _ in range(40):
            if self.taille() <= plafond:
                break
            with self._cx() as cx:
                n = cx.execute("SELECT COUNT(*) FROM flux").fetchone()[0]
                if not n:
                    break
                cx.execute("DELETE FROM flux WHERE rowid IN (SELECT rowid FROM flux ORDER BY minute LIMIT ?)", (n // 10 + 1,))
            self._vider()

    def _vider(self) -> None:
        cx = sqlite3.connect(str(self.chemin), timeout=10)
        try:
            cx.execute("PRAGMA incremental_vacuum").fetchall()        # une page par pas : il faut tout consommer
            cx.commit()
        finally:
            cx.close()


# ── un passage du moteur ────────────────────────────────────────────────────────────────────────────────────
def perimetre(etat: dict) -> Dict[str, dict]:
    """MAC -> client, pour les appareils déclarés hors OFF qui ont une MAC (le DPI observe aussi en OBSERVE ; il n'agit jamais)."""
    return {c["mac"]: c for c in etat.get("clients", []) if c.get("mac") and c.get("mode") != "off"}


def _adresses(etat: dict, voisins: Dict[str, str]) -> Dict[str, Set[str]]:
    per = perimetre(etat)
    out = {m: {c["ip"]} for m, c in per.items()}
    for a, m in voisins.items():
        if m in out and _ip(a):
            out[m].add(a)
    return out


def cibles(etat: dict, voisins: Dict[str, str]) -> dict:
    """`dpi-cibles.json` : MAC et adresses du périmètre, lu par sbxdpi (agrégat par adresse) et par le contrôleur root (filtre BPF)."""
    return {"version": 1, "appareils": [{"mac": m, "adresses": sorted(a)} for m, a in sorted(_adresses(etat, voisins).items())]}


def passage(etat: dict, mag_dns, mag: MagasinDPI, categorie: Callable[[str], str], maintenant: int, voisins: Dict[str, str],
            sbxdpi_texte: Optional[str], conntrack_texte: Optional[str], resolus: Set[str], box: Set[str],
            doh: Tuple[Set[str], Set[str]], memoire: Optional[Dict[str, Tuple[str, int]]] = None) -> dict:
    """Lit les sources, range les flux par MAC, relève constats et replis. Rend l'état affichable et les candidats de repli par MAC."""
    per = perimetre(etat)
    adr = _adresses(etat, voisins)
    sources = {"sbxdpi": "absent", "conntrack": "absent"}
    bruts: List[dict] = []
    if sbxdpi_texte is not None:
        try:
            s = lire_sbxdpi(sbxdpi_texte)
            if not 0 <= maintenant - s["genere"] <= PEREMPTION_SBXDPI_S:
                sources["sbxdpi"] = "perime"
            else:
                sources["sbxdpi"] = "ok"
                bruts += [dict(f, minute=f["dernier"] // 60) for f in s["flux"]]
        except ErreurDPI:
            sources["sbxdpi"] = "illisible"
    if conntrack_texte is not None:
        sources["conntrack"] = "ok"
        tous = set().union(*adr.values()) if adr else set()
        bruts += [dict(f, minute=maintenant // 60, flux=1, octets=0, categorie="") for f in lire_conntrack(conntrack_texte, tous)]
    connus = dict(voisins)
    connus.update({c["ip"]: m for m, c in per.items()})
    mem = mag.charger_voisins() if memoire is None else memoire
    rattache, mem = rattacher({f["local"] for f in bruts}, connus, mem, maintenant)
    mag.ecrire_voisins(mem)
    lignes, par_mac = [], {}
    for f in bruts:
        m = rattache.get(f["local"])
        if m in per:
            par_mac.setdefault(m, []).append(f)
    candidats: Dict[str, List[dict]] = {}
    for m, c in per.items():
        fl = par_mac.get(m, [])
        cs = constats(fl, resolus, box, doh[0], doh[1])
        signales = {(x["distant"], x["port"]): x["type"] for x in cs}
        for f in fl:
            t = signales.get((f["distant"], f["port"]))
            lignes.append({"mac": m, "minute": f["minute"], "local": f["local"], "proto": f["proto"], "appli": f["appli"] or f["proto"].upper(), "categorie_ndpi": f.get("categorie", ""),
                           "hote": f["hote"], "port": f["port"], "distant": "" if f["hote"] else f["distant"], "flux": f["flux"],
                           "octets": f["octets"], "sans_dns": t == "sans-dns", "dns_chiffre": t == "dns-chiffre"})
        mag.ajouter_decouvertes(m, [{"type": x["type"], "domaine": f"{x['distant']}:{x['port']}", "appli": x["appli"], "ts": maintenant,
                                     "confiance": 80, "raison": {"sans-dns": "adresse en dur : aucun nom DNS ni SNI",
                                                                 "dns-chiffre": "DNS chiffré (DoH/DoT) : la box ne voit pas ces requêtes",
                                                                 "contournement": "DNS envoyé à un autre résolveur que la box"}[x["type"]]}
                                    for x in cs])
        # I3 : incrémental — on ne relit que depuis la dernière coupure close (curseur par MAC), et une coupure n'est traitée qu'une fois
        # sa fenêtre de 30 s écoulée.
        curseur = mag.curseur(m)
        evts = mag_dns.evenements(sorted(adr.get(m, ())), max(maintenant - 3600, curseur - AVANT_S) if curseur else maintenant - 3600)
        dec = [d for d in correler(evts, categorie) if curseur < d["refus_ts"] <= maintenant - FENETRE_REPLI_S]
        mag.ajouter_decouvertes(m, dec)
        closes = [x for x in evts if x.get("decision") == "BLOCKED" and int(x["ts"]) <= maintenant - FENETRE_REPLI_S]
        if closes:
            mag.poser_curseur(m, max(curseur, max(int(x["ts"]) for x in closes)))
        refus = {d["refus_ts"] for d in dec}
        if refus and fl:
            mag.ajouter_decouvertes(m, [dict(s, domaine=s["hote"], ts=maintenant, confiance=60, refus_ts=s["refus_ts"][0])
                                        for s in secours([{"ts": f["dernier"] if "dernier" in f else maintenant, "hote": f["hote"],
                                                           "octets": f["octets"]} for f in fl], refus)])
        candidats[m] = candidats_repli(dec)
    mag.ingerer(lignes)
    appareils = [{"mac": m, "nom": c["nom"], "mode": c["mode"], "couverture": couverture(mag.dernier_flux(m), maintenant)}
                 for m, c in sorted(per.items(), key=lambda kv: kv[1]["nom"])]
    return {"etat": {"version": 1, "genere": maintenant, "sources": sources, "appareils": appareils}, "candidats": candidats, "memoire": mem}


# ── passage du moteur (secubox-adguard-auto, chaque minute) ─────────────────────────────────────────────────
FICHIER_ETAT = "etat-dpi.json"
PERIODE_CIBLES_S = 300
DUREE_CHARGE_S = 300                                  # saturation continue d'au moins 5 min : jamais sur un simple pic
SBXDPI_APPAREILS = Path(os.environ.get("SECUBOX_ADGUARD_SBXDPI", "/run/secubox/sbxdpi/appareils.json"))
SBXDPI_MAX = 8 * 1024 * 1024


def lire_etat_dpi(dossier: Optional[Path] = None) -> Optional[dict]:
    try:
        e = json.loads(((dossier or dnstv.DOSSIER_ETAT) / FICHIER_ETAT).read_text(encoding="utf-8"))
        return e if isinstance(e, dict) and e.get("version") == 1 else None
    except (OSError, ValueError):
        return None


def _ecrire_etat_dpi(e: dict, dossier: Optional[Path] = None) -> None:
    import tempfile
    d = dossier or dnstv.DOSSIER_ETAT
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".etat-dpi.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as h:
            os.fchmod(h.fileno(), 0o640)
            json.dump(e, h, ensure_ascii=False)
        os.replace(tmp, d / FICHIER_ETAT)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _resolus(maintenant: int) -> Set[str]:
    f = dnstv.DOSSIER_ETAT / "reponses.db"
    if not f.is_file():
        return set()
    try:
        cx = sqlite3.connect(f"file:{f}?mode=ro", uri=True, timeout=5)
        try:
            return {ip for (ip,) in cx.execute("SELECT ip FROM rep WHERE derniere >= ? LIMIT 200000", (maintenant - 86400,))}
        finally:
            cx.close()
    except sqlite3.Error:
        return set()


def moteur(maintenant: int, executer: Callable[[str], object], voisins: Dict[str, str], charge=os.getloadavg, cpus=None,
           sbxdpi_chemin: Optional[Path] = None) -> dict:
    """Un passage : cibles (toutes les 5 min ou si elles changent), conntrack (verbe root), fichier de sbxdpi, découvertes, garde de
    charge (charge à 5 min > nombre de cœurs pendant 5 min : arrêt de nDPId, reprise MANUELLE). N'échoue jamais le moteur."""
    etat, erreur = dnstv.lire_etat()
    if erreur or not etat.get("actif"):
        return {"ok": False}
    prev = lire_etat_dpi() or {}
    c = cibles(etat, voisins)
    cibles_ts = int(prev.get("cibles_ts", 0) or 0)
    if maintenant - cibles_ts >= PERIODE_CIBLES_S or prev.get("cibles") != c:
        executer("dpi-cibles")
        cibles_ts = maintenant
    ct = None
    r = executer("conntrack-dump")
    if getattr(r, "returncode", 1) == 0 and getattr(r, "stdout", ""):
        ct = r.stdout
    sbx = None
    chemin = sbxdpi_chemin or SBXDPI_APPAREILS
    try:
        if chemin.is_file() and not chemin.is_symlink():
            with open(chemin, encoding="utf-8") as h:
                sbx = h.read(SBXDPI_MAX)
    except OSError:
        sbx = None
    mag = MagasinDPI(dnstv.DOSSIER_ETAT / "dpi-appareils.db", verifier=maintenant // 60 % 60 == 0)   # quick_check une fois par heure
    taxo = dnstv_taxonomie.Taxonomie.depuis_dossier()
    doh = charger_resolveurs(dnstv.DOSSIER_LISTES / "resolveurs-doh.txt")
    res = passage(etat, dnstv.Magasin(dnstv.DOSSIER_ETAT / "dnstv.db"), mag, lambda d: taxo.classer(d)["categorie"], maintenant, voisins,
                  sbx, ct, _resolus(maintenant), dnstv.adresses_locales(), doh)
    mag.menage(maintenant)
    ch = dict(prev.get("charge") or {"haute_depuis": None, "pause": None})
    n = cpus or os.cpu_count() or 1
    if charge()[1] > n:
        ch["haute_depuis"] = ch.get("haute_depuis") or maintenant
        if ch.get("pause") is None and maintenant - ch["haute_depuis"] >= DUREE_CHARGE_S:
            executer("ndpid-arreter")
            ch["pause"] = maintenant
    else:
        ch["haute_depuis"] = None
    e = dict(res["etat"], charge=ch, cibles=c, cibles_ts=cibles_ts)
    _ecrire_etat_dpi(e)
    return {"ok": True, "etat": e}


def reprendre_manuellement(executer: Callable[[str], object]) -> dict:
    """Reprise de nDPId après une pause de charge : geste de l'administrateur seulement."""
    r = executer("ndpid-reprendre")
    e = lire_etat_dpi() or {"version": 1, "appareils": [], "sources": {}}
    e["charge"] = {"haute_depuis": None, "pause": None}
    _ecrire_etat_dpi(e)
    return {"ok": getattr(r, "returncode", 1) == 0}


def frise(evts: List[dict], categorie: Callable[[str], str], motifs_ssai: Iterable[re.Pattern] = (),
          fenetre: int = FENETRE_REPLI_S) -> List[dict]:
    """Par coupure : le refus à 0 s puis ce qui apparaît dans la fenêtre (domaines nouveaux, typés repli / repli-protege, SSAI)."""
    motifs = list(motifs_ssai)
    out: Dict[int, dict] = {}
    for d in correler(evts, categorie, fenetre):
        c = out.setdefault(d["refus_ts"], {"refus_ts": d["refus_ts"], "refus_domaine": d["refus_domaine"], "apparitions": []})
        c["apparitions"].append({"delai_s": d["delai_s"], "domaine": d["domaine"], "categorie": d["categorie"], "type": d["type"],
                                 "ssai": est_ssai(d["domaine"], motifs)})
    return [out[k] for k in sorted(out, reverse=True)]
