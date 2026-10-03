#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: dns-tv-test — teste le DNS depuis une machine CLIENTE (POC « DNS AdBlock TV », #1943).

Pour chaque domaine : résolution, réponse, temps, serveur interrogé, et un STATUT honnête :
  ALLOWED          le serveur a répondu avec des adresses
  BLOCKED          preuve de blocage : le serveur répond NXDOMAIN/REFUSED/0.0.0.0 ALORS QU'un résolveur de référence résout le nom
  NXDOMAIN         le serveur dit « inexistant » ; sans résolveur de référence (--reference) on ne peut PAS dire si c'est un blocage
  ERROR            pas de réponse, SERVFAIL, réponse illisible

Python standard seulement (aucun dig requis). Ne contacte QUE les serveurs donnés (et le résolveur du système si --serveur est absent).

  python3 dns-tv-test.py example.com
  python3 dns-tv-test.py --serveur 192.168.1.200 --reference 1.1.1.1 doubleclick.net example.com
  python3 dns-tv-test.py --serveur 192.168.1.200 --list test-domains.txt --rapport reports/dns-test.json
"""
from __future__ import annotations

import argparse
import json
import os
import random
import socket
import struct
import sys
import time

RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
TYPES = {"A": 1, "AAAA": 28}
PUITS = {"0.0.0.0", "::", "127.0.0.1", "::1"}                    # adresses de « puits » : un nom qui y mène est un blocage par réponse


def construire(nom: str, qtype: str, ident: int) -> bytes:
    q = b"".join(bytes([len(e)]) + e.encode("idna") for e in nom.rstrip(".").split("."))
    return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + q + b"\x00" + struct.pack("!HH", TYPES[qtype], 1)


def _nom(paquet: bytes, i: int) -> int:
    while True:
        n = paquet[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:
            return i + 2
        i += 1 + n


def analyser(paquet: bytes, ident: int) -> dict:
    if len(paquet) < 12:
        raise ValueError("réponse trop courte")
    rid, flags, qd, an, _, _ = struct.unpack("!HHHHHH", paquet[:12])
    if rid != ident:
        raise ValueError("identifiant de réponse inattendu")
    i = 12
    for _ in range(qd):
        i = _nom(paquet, i) + 4
    adresses = []
    for _ in range(an):
        i = _nom(paquet, i)
        typ, _, _, ln = struct.unpack("!HHIH", paquet[i:i + 10])
        i += 10
        if typ == 1 and ln == 4:
            adresses.append(socket.inet_ntop(socket.AF_INET, paquet[i:i + 4]))
        elif typ == 28 and ln == 16:
            adresses.append(socket.inet_ntop(socket.AF_INET6, paquet[i:i + 16]))
        i += ln
    return {"rcode": RCODES.get(flags & 0x0F, str(flags & 0x0F)), "reponses": adresses, "tronque": bool(flags & 0x0200)}


def interroger(serveur: str, nom: str, qtype: str = "A", delai: float = 3.0) -> dict:
    hote, _, port = serveur.partition("#")
    adresse = (hote, int(port or 53))
    ident = random.randrange(65536)
    famille = socket.AF_INET6 if ":" in hote else socket.AF_INET
    debut = time.monotonic()
    try:
        s = socket.socket(famille, socket.SOCK_DGRAM)
        s.settimeout(delai)
        s.sendto(construire(nom, qtype, ident), adresse)
        donnees, _ = s.recvfrom(4096)
        r = analyser(donnees, ident)
        if r["tronque"]:                                           # repli TCP
            t = socket.create_connection(adresse, timeout=delai)
            q = construire(nom, qtype, ident)
            t.sendall(struct.pack("!H", len(q)) + q)
            n = struct.unpack("!H", t.recv(2))[0]
            r = analyser(t.recv(n), ident)
        r["ms"] = round((time.monotonic() - debut) * 1000, 1)
        return r
    except (OSError, ValueError, struct.error) as e:
        return {"rcode": "ERROR", "reponses": [], "ms": round((time.monotonic() - debut) * 1000, 1), "erreur": type(e).__name__}
    finally:
        try:
            s.close()
        except (OSError, UnboundLocalError):
            pass


def statut(r: dict, ref: dict | None) -> str:
    if r["rcode"] in ("ERROR", "SERVFAIL", "FORMERR", "NOTIMP"):
        return "ERROR"
    if r["rcode"] == "NOERROR" and r["reponses"]:
        if set(r["reponses"]) <= PUITS and ref and ref["reponses"] and not set(ref["reponses"]) <= PUITS:
            return "BLOCKED"
        return "ALLOWED"
    ref_ok = bool(ref and ref["rcode"] == "NOERROR" and ref["reponses"])
    if r["rcode"] in ("NXDOMAIN", "REFUSED"):
        return "BLOCKED" if ref_ok else "NXDOMAIN"
    return "ALLOWED" if r["rcode"] == "NOERROR" else "ERROR"


def serveur_systeme() -> str:
    try:
        for ligne in open("/etc/resolv.conf"):
            if ligne.startswith("nameserver"):
                return ligne.split()[1]
    except OSError:
        pass
    return "127.0.0.1"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("domaines", nargs="*")
    ap.add_argument("--serveur", help="DNS à tester (IP, ou IP#port) ; défaut : celui du système")
    ap.add_argument("--reference", help="résolveur de référence pour trancher « bloqué » / « inexistant »")
    ap.add_argument("--list", dest="liste", help="fichier de domaines (un par ligne, # = commentaire)")
    ap.add_argument("--type", default="A", choices=sorted(TYPES))
    ap.add_argument("--rapport", help="écrit le rapport JSON (ex. reports/dns-test.json)")
    ap.add_argument("--delai", type=float, default=3.0)
    a = ap.parse_args(argv)
    noms = list(a.domaines)
    if a.liste:
        noms += [ligne.split("#", 1)[0].strip() for ligne in open(a.liste, encoding="utf-8")]
    noms = [n for n in noms if n]
    if not noms:
        ap.error("aucun domaine (en argument ou avec --list)")
    serveur = a.serveur or serveur_systeme()
    lignes = []
    for n in noms:
        r = interroger(serveur, n, a.type, a.delai)
        ref = interroger(a.reference, n, a.type, a.delai) if a.reference else None
        st = statut(r, ref)
        lignes.append({"domaine": n, "statut": st, "rcode": r["rcode"], "reponses": r["reponses"], "ms": r["ms"],
                       **({"reference": {"rcode": ref["rcode"], "reponses": ref["reponses"]}} if ref else {})})
        print(f"{st:9} {n:40} {r['rcode']:9} {r['ms']:7.1f} ms  {', '.join(r['reponses'][:3])}")
    resume = {s: sum(1 for x in lignes if x["statut"] == s) for s in ("ALLOWED", "BLOCKED", "NXDOMAIN", "ERROR")}
    rapport = {"date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "serveur": serveur, "reference": a.reference,
               "type": a.type, "resume": resume, "resultats": lignes,
               "avertissement": "BLOCKED n'est affirmé qu'avec un résolveur de référence ; sans lui, NXDOMAIN reste « non tranché »."}
    if a.rapport:
        os.makedirs(os.path.dirname(os.path.abspath(a.rapport)), exist_ok=True)
        with open(a.rapport, "w", encoding="utf-8") as h:
            json.dump(rapport, h, ensure_ascii=False, indent=2)
        print(f"rapport : {a.rapport}")
    return 0 if resume["ERROR"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
