# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Jeu de référence de la veille V2 (#3718) : extrait des journaux RÉELS de gk2, anonymisé.

Usage (sur le poste, jamais sur la box) :
    python3 -I anonymiser.py <dossier brut> <dossier de sortie>

Le dossier brut contient des copies prises en LECTURE SEULE sur gk2 :
    threats1.jsonl, threats0.jsonl  (waf-threats.log.1 puis waf-threats.log)
    bans.jsonl                      (fin de /var/lib/secubox/waf/bans.jsonl)
    reeval.jsonl                    (fin de /var/lib/secubox/waf/reevaluations.jsonl)
    campagne-etat.json              (/var/lib/secubox/waf/campagne-ban-etat.json)
    ai-ban.jsonl                    (/var/lib/secubox/waf/ai-ban.jsonl)

Anonymisation (aucune donnée brute ne quitte le poste) :
- toute adresse globale → plages de documentation (RFC 5737 / 3849) par TABLE, jamais par condensé. Les deux /24 les
  plus peuplés de bans gardent leur structure (dernier octet conservé) : 203.0.113.0/24 (bloc « cas sûr », ≥ 20
  adresses) et 198.51.100.0/24 ; les autres adresses → 192.0.2.x dans l'ordre d'apparition ; IPv6 → 2001:db8:N::/64 ;
- noms d'hôtes : `secubox.in` → `example.net`, `gkN` → `boxN`, noms des services du propriétaire → `svc-N` (ou
  lettres tirées, forme gardée, s'ils portent un `_`), noms génériques et aléatoires gardés ; tout autre domaine →
  `site-N.example.org` ;
- comptes visés (SMTP) → `compte-N` ; empreintes, filigranes, signatures, jetons, clés → hexadécimal aléatoire de
  même longueur, constant pour une même valeur dans un tirage (sel aléatoire, jamais versionné) ;
- requêtes du LAN (`client_ip = local`) : chaîne de requête retirée.
Les horodatages, familles, sévérités, actions, chemins attaqués et agents des attaquants sont gardés : c'est ce que
le corrélateur doit apprendre à lire.
"""
from __future__ import annotations

import collections
import ipaddress
import json
import re
import secrets
import sys
from pathlib import Path

PAR_FAMILLE = {"host_anomaly:unrouted": 40, "auth_smtp:sasl_failed": 25, "recon_crawler": 20, "scanners": 20,
               "robots": 12, "host_anomaly:ip_literal": 12, "honeypot": 15, "waf_fingerprint": 11,
               "host_anomaly:dga": 7, "body-inspect-skipped": 2}
LOCAL_MAX = 8
DOUBLONS_MAX = 2          # groupes de doublons exacts réels (même seconde, même clé) gardés entiers
BANS_PAR_FAMILLE = 10
REEVAL_PAR_DECISION = 10
RE_IPV4 = re.compile(r"(?<![\w./:-])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])")
RE_IPV6 = re.compile(r"(?<![\w:])([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7})(?![\w:])")
GENERIQUES = frozenset({"www", "mail", "smtp", "imap", "apt", "autoconfig", "autodiscover", "openpgpkey", "*", "admin"})
CHAMPS_HEX = ("http_fingerprint", "filigrane", "signature", "jti", "cle", "id", "conseil")


def lire_jsonl(p: Path) -> list:
    if not p.exists():
        return []
    sortie = []
    for ligne in p.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            sortie.append(json.loads(ligne))
        except ValueError:
            continue
    return sortie


class Anonymiseur:
    def __init__(self, blocs_gardes: list[str]):
        self.sel = secrets.token_hex(16)
        self.ipv4: dict[str, str] = {}
        self.ipv6: dict[str, str] = {}
        self.blocs = {b: base for b, base in zip(blocs_gardes, ("203.0.113", "198.51.100"))}
        self.suivant = 1
        self.v6_suivant = 1
        self.hotes: dict[str, str] = {}
        self.etiquettes: dict[str, str] = {}
        self.comptes: dict[str, str] = {}
        self.hex: dict[str, str] = {}

    def ip(self, valeur: str) -> str:
        try:
            a = ipaddress.ip_address(valeur)
        except ValueError:
            return valeur
        if not a.is_global:
            return valeur
        if a.version == 6:
            pref = str(ipaddress.ip_network(f"{a}/64", strict=False).network_address)
            if pref not in self.ipv6:
                self.ipv6[pref] = f"2001:db8:{self.v6_suivant:x}::"
                self.v6_suivant += 1
            return self.ipv6[pref] + format(int(a) & 0xFFFF, "x")
        if valeur not in self.ipv4:
            bloc = valeur.rsplit(".", 1)[0]
            if bloc in self.blocs:
                self.ipv4[valeur] = self.blocs[bloc] + "." + valeur.rsplit(".", 1)[1]
            else:
                if self.suivant > 254:
                    raise SystemExit("plus de 254 adresses isolées : réduire l'échantillon")
                self.ipv4[valeur] = f"192.0.2.{self.suivant}"
                self.suivant += 1
        return self.ipv4[valeur]

    def cible(self, valeur: str) -> str:
        if "/" not in valeur:
            return self.ip(valeur)
        reseau = ipaddress.ip_network(valeur, strict=False)
        return str(ipaddress.ip_network(f"{self.ip(str(reseau.network_address))}/{reseau.prefixlen}", strict=False))

    def hote(self, h: str) -> str:
        if not h or h in ("smtp", "local"):
            return h
        try:
            ipaddress.ip_address(h.strip("[]"))
            return self.ip(h.strip("[]"))
        except ValueError:
            pass
        bas = h.lower().rstrip(".")
        if bas == "secubox.in" or bas.endswith(".secubox.in"):
            etiquettes = bas[: -len("secubox.in")].rstrip(".").split(".") if bas != "secubox.in" else []
            return ".".join([self.etiquette(e) for e in etiquettes] + ["example.net"])
        if bas not in self.hotes:
            self.hotes[bas] = f"site-{len(self.hotes) + 1}.example.org"
        return self.hotes[bas]

    def etiquette(self, e: str) -> str:
        """Une étiquette d'un nom du propriétaire : les noms de ses services ne sortent pas (carte de ses sites)."""
        if re.fullmatch(r"gk\d+", e):
            return "box" + e[2:]
        if e in GENERIQUES:
            return e
        if re.fullmatch(r"[a-z0-9]{12,}", e) and re.search(r"\d", e):
            return e                                   # nom tiré au hasard par un scanner : rien du propriétaire
        if e not in self.etiquettes:
            if "_" in e:                               # forme gardée (la détection « dga » en dépend), lettres tirées
                faux = re.sub(r"[a-z]", lambda _m: secrets.choice("abcdefghijklmnopqrstuvwxyz"), e)
            else:
                faux = f"svc-{len(self.etiquettes) + 1}"
            self.etiquettes[e] = faux
        return self.etiquettes[e]

    def compte(self, c: str) -> str:
        if c not in self.comptes:
            self.comptes[c] = f"compte-{len(self.comptes) + 1}"
        return self.comptes[c]

    def hexa(self, v: str) -> str:
        if not v:
            return v
        if v not in self.hex:
            self.hex[v] = secrets.token_hex((len(v) + 1) // 2)[: len(v)]
        return self.hex[v]

    def texte(self, s: str) -> str:
        s = RE_IPV4.sub(lambda m: self.ip(m.group(1)), s)
        s = RE_IPV6.sub(lambda m: self.ip(m.group(1)), s)
        for vrai, faux in sorted(self.hotes.items(), key=lambda kv: -len(kv[0])):
            s = re.sub(re.escape(vrai), faux, s, flags=re.I)
        s = re.sub(r"(?i)\b([\w*.-]+\.)?secubox\.in\b", lambda m: self.hote(m.group(0)), s)
        return re.sub(r"\bgk(\d+)\b", r"box\1", s)


def menace(a: Anonymiseur, e: dict) -> dict:
    e = dict(e)
    if e.get("client_ip") != "local":
        e["client_ip"] = a.ip(e["client_ip"])
    else:
        e["path"] = e.get("path", "").split("?", 1)[0]
    e["host"] = a.hote(e.get("host", ""))
    if e.get("category", "").startswith("auth_smtp") and e.get("path"):
        vrai = e["path"]
        e["path"] = a.compte(vrai)
        e["rule_id"] = e.get("rule_id", "").replace(f"« {vrai} »", f"« {e['path']} »")
    for k in CHAMPS_HEX:
        if isinstance(e.get(k), str):
            e[k] = a.hexa(e[k])
    for k in ("path", "user_agent", "rule_id"):
        if isinstance(e.get(k), str):
            e[k] = a.texte(e[k])
    return e


def choisir_menaces(lignes: list) -> list:
    pris, vus = [], collections.Counter()
    # doublons exacts réels : (horodatage, adresse, famille, hôte, chemin) répétés
    cles = collections.Counter((e["timestamp"], e["client_ip"], e["category"], e["host"], e["path"]) for e in lignes)
    groupes = [k for k, n in cles.items() if n >= 3 and k[1] != "local"][:DOUBLONS_MAX]
    gardes = {id(e) for e in lignes
              if (e["timestamp"], e["client_ip"], e["category"], e["host"], e["path"]) in groupes}
    # un pas régulier par famille : l'échantillon couvre toute la période relevée, pas seulement son début
    total = collections.Counter("local" if e.get("client_ip") == "local" else e.get("category", "") for e in lignes)
    quota = dict(PAR_FAMILLE, local=LOCAL_MAX)
    pas = {f: max(1, total[f] // q) for f, q in quota.items() if total[f]}
    rang = collections.Counter()
    for e in lignes:
        if id(e) in gardes:
            pris.append(e)
            continue
        f = "local" if e.get("client_ip") == "local" else e.get("category", "")
        if f not in pas:
            continue
        if rang[f] % pas[f] == 0 and vus[f] < quota[f]:
            pris.append(e)
            vus[f] += 1
        rang[f] += 1
    return pris


def choisir_bans(bans: list, blocs: list[str]) -> list:
    pris = [b for b in bans if b["ip"].rsplit(".", 1)[0] in blocs]
    vus = collections.Counter()
    for b in bans:
        fam = b["cat"].split(":", 1)[0].split("|", 1)[0]
        if b in pris or vus[fam] >= BANS_PAR_FAMILLE:
            continue
        if vus[fam] < BANS_PAR_FAMILLE // 2 or "|prolonge" in b["cat"]:
            pris.append(b)
            vus[fam] += 1
    return pris


def ban(a: Anonymiseur, b: dict) -> dict:
    b = dict(b, ip=a.ip(b["ip"]))
    if b["cat"].startswith("campagne:"):
        sig = b["cat"].split(":", 1)[1].split("|", 1)
        b["cat"] = "campagne:" + a.hexa(sig[0]) + ("|" + sig[1] if len(sig) > 1 else "")
    return b


def main(brut: Path, sortie: Path) -> None:
    menaces = lire_jsonl(brut / "threats1.jsonl") + lire_jsonl(brut / "threats0.jsonl")
    bans = lire_jsonl(brut / "bans.jsonl")
    peuples = collections.defaultdict(set)
    for b in bans:
        if ":" not in b["ip"]:
            peuples[b["ip"].rsplit(".", 1)[0]].add(b["ip"])
    blocs = [k for k, _ in sorted(peuples.items(), key=lambda kv: -len(kv[1]))[:2]]
    a = Anonymiseur(blocs)
    # les hôtes d'abord : leurs noms doivent être connus avant de nettoyer les textes libres
    choisies = choisir_menaces(menaces)
    for e in choisies:
        a.hote(e.get("host", ""))
    sortie.mkdir(parents=True, exist_ok=True)

    def ecrire(nom, objets):
        (sortie / nom).write_text("".join(json.dumps(o, ensure_ascii=False, sort_keys=True) + "\n" for o in objets),
                                  encoding="utf-8")
        return len(objets)

    n = ecrire("menaces.jsonl", [menace(a, e) for e in choisies])
    n += ecrire("bans.jsonl", [ban(a, b) for b in choisir_bans(bans, blocs)])
    reev, vus = [], collections.Counter()
    for r in lire_jsonl(brut / "reeval.jsonl"):
        if vus[r["decision"]] < REEVAL_PAR_DECISION:
            vus[r["decision"]] += 1
            reev.append(dict(r, ip=a.ip(r["ip"]), categorie=ban(a, {"ip": "", "cat": r["categorie"]})["cat"]))
    n += ecrire("reevaluations.jsonl", reev)
    try:
        etat = json.loads((brut / "campagne-etat.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        etat = {}
    cands = [dict(c, ip=a.ip(c["ip"]), signature=a.hexa(c["signature"])) for c in etat.get("candidats", [])[:12]]
    (sortie / "campagnes.json").write_text(json.dumps(dict(etat, candidats=cands), ensure_ascii=False, indent=1,
                                                      sort_keys=True) + "\n", encoding="utf-8")
    n += len(cands)
    ai = []
    for e in lire_jsonl(brut / "ai-ban.jsonl"):
        e = dict(e, cible=a.cible(e["cible"]))
        for k in CHAMPS_HEX:
            if isinstance(e.get(k), str):
                e[k] = a.hexa(e[k])
        e["motif"] = a.texte(e.get("motif", "")) if "motif" in e else e.get("motif")
        ai.append({k: v for k, v in e.items() if v is not None})
    n += ecrire("ai-ban.jsonl", ai)
    print(f"{n} événements écrits dans {sortie}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    main(Path(sys.argv[1]), Path(sys.argv[2]))
