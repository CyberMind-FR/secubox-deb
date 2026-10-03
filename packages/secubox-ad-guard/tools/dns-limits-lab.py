#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: dns-limits-lab — démontre EXPÉRIMENTALEMENT ce que le DNS peut et ne peut pas faire (POC « DNS AdBlock TV », #1943).

BANC LOCAL, sans Internet et sans appareil réel : trois Unbound sur 127.0.0.1 (un amont qui sert des noms fictifs `.sbxlab`, la « box »
avec la vraie configuration générée par le POC, et un « résolveur externe » pour le cas DoH). Des « clients » sont des adresses 127.0.0.x.
Chaque cas A–G est OBSERVÉ (réponses DNS et journal réel d'Unbound), jamais supposé. Ce que ce banc ne prouve pas : le comportement d'une
vraie Freebox TV — voir la procédure du banc réel dans docs/poc-dns-adblock-tv.md.

  python3 dns-limits-lab.py [--rapport reports/dns-limits.json]     (nécessite le binaire `unbound`)
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ICI = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ICI))
sys.path.append("/usr/lib/secubox/ad-guard")          # paquet installé : la bibliothèque est sous /usr/lib
from api import dnstv  # noqa: E402

_spec = importlib.util.spec_from_file_location("dns_tv_test", ICI / "tools" / "dns-tv-test.py")
client = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(client)

P_AMONT, P_BOITE, P_EXTERNE = 5398, 5399, 5397
TV_OBSERVE, TV_BLOCK, AUTRE, TV_DOH = "127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5"

DONNEES_AMONT = {
    "ads.cdn-pub.sbxlab": "7.1.1.1",          # A  : publicité servie depuis un domaine publicitaire DISTINCT
    "metrics.tracker.sbxlab": "7.1.1.2",      # B  : tracking servi depuis un domaine distinct
    "video.studio.sbxlab": "7.2.2.2",         # C  : la vidéo ET sa publicité viennent de CE nom
    "stream.studio.sbxlab": "7.3.3.3",        # D  : publicité INTÉGRÉE au flux ; un seul nom, rien à séparer
    "cdn.sharedcloud.sbxlab": "7.4.4.4",      # G  : domaine partagé : contenu légitime ET publicité
    "news.sbxlab": "7.5.5.5",                 # un site ordinaire, qui ne doit jamais être touché
    "prod.sbxlab": "7.6.6.6",                 # listé dans le puits GLOBAL de production du banc (isolement du POC)
}
# Ce que les listes du POC déclarent dans le banc (volontairement incluant C et G pour montrer leurs dégâts).
LISTES_BANC = {"ads.cdn-pub.sbxlab": "advertising", "metrics.tracker.sbxlab": "tracking",
               "video.studio.sbxlab": "advertising", "cdn.sharedcloud.sbxlab": "advertising"}


def _conf_base(port: int, pid: str, extra: str = "") -> str:
    return (f'server:\n    interface: 127.0.0.1@{port}\n    port: {port}\n    access-control: 127.0.0.0/8 allow\n    do-ip6: no\n'
            f'    use-syslog: no\n    pidfile: "{pid}"\n    username: ""\n    chroot: ""\n    do-not-query-localhost: no\n'
            f'    verbosity: 1\n    domain-insecure: "sbxlab."\n{extra}')


class Banc:
    def __init__(self):
        self.dir = Path(tempfile.mkdtemp(prefix="sbx-lab-"))
        self.procs = []
        self.journal = self.dir / "boite.log"

    def _lancer(self, nom: str, conf: str, sortie=None):
        f = self.dir / f"{nom}.conf"
        f.write_text(conf)
        h = open(sortie or self.dir / f"{nom}.log", "w")
        p = subprocess.Popen(["unbound", "-d", "-c", str(f)], stdout=h, stderr=subprocess.STDOUT)
        self.procs.append(p)

    def demarrer(self, etat: dict, globales=("prod.sbxlab",)):
        donnees = "".join(f'    local-data: "{n}. A {ip}"\n' for n, ip in DONNEES_AMONT.items())
        donnees += '    local-data: "ads.cdn-pub.sbxlab.doh. A 7.1.1.1"\n'
        zone = '    local-zone: "sbxlab." static\n' + donnees
        self._lancer("amont", _conf_base(P_AMONT, str(self.dir / "amont.pid"), zone))
        self._lancer("externe", _conf_base(P_EXTERNE, str(self.dir / "externe.pid"),
                                           '    local-zone: "sbxlab." static\n' + donnees))
        drop = dnstv.rendre_unbound(etat, LISTES_BANC)
        prod = "".join(f'    local-zone: "{d}." always_nxdomain\n' for d in globales)      # le puits DNS global de la box
        boite = _conf_base(P_BOITE, str(self.dir / "boite.pid"), prod).rstrip("\n") + "\n" + drop.replace("server:\n", "", 1)
        boite += f'forward-zone:\n    name: "."\n    forward-addr: 127.0.0.1@{P_AMONT}\n'
        self._lancer("boite", boite, self.journal)
        for port in (P_AMONT, P_EXTERNE, P_BOITE):
            for _ in range(50):
                r = client.interroger(f"127.0.0.1#{port}", "news.sbxlab", delai=0.5)
                if r["rcode"] == "NOERROR":
                    break
                time.sleep(0.1)
            else:
                raise SystemExit(f"le serveur du banc (port {port}) ne répond pas")

    def arreter(self):
        for p in self.procs:
            p.send_signal(signal.SIGTERM)
        for p in self.procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        shutil.rmtree(self.dir, ignore_errors=True)


def resoudre(source: str, nom: str, port: int = P_BOITE) -> dict:
    """Une requête DEPUIS l'adresse `source` (un « appareil »)."""
    import random
    import socket
    import struct
    ident = random.randrange(65536)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((source, 0))
    s.settimeout(3)
    t0 = time.monotonic()
    try:
        s.sendto(client.construire(nom, "A", ident), ("127.0.0.1", port))
        r = client.analyser(s.recvfrom(4096)[0], ident)
    except (OSError, ValueError, struct.error):
        r = {"rcode": "ERROR", "reponses": []}
    finally:
        s.close()
    r["ms"] = round((time.monotonic() - t0) * 1000, 1)
    return r


def lignes_journal(banc: Banc) -> list:
    time.sleep(0.4)
    return banc.journal.read_text(errors="replace").splitlines()


def executer() -> dict:
    if not shutil.which("unbound"):
        raise SystemExit("le binaire `unbound` est requis pour le banc")
    banc = Banc()
    etat = {"actif": True, "clients": [{"ip": TV_OBSERVE, "nom": "tv-observe", "mode": "observe"},
                                       {"ip": TV_BLOCK, "nom": "tv-block", "mode": "block"},
                                       {"ip": TV_DOH, "nom": "tv-doh", "mode": "block"}]}
    cas = {}
    try:
        banc.demarrer(etat)
        pub, track, video, flux, partage, ordinaire = ("ads.cdn-pub.sbxlab", "metrics.tracker.sbxlab", "video.studio.sbxlab",
                                                       "stream.studio.sbxlab", "cdn.sharedcloud.sbxlab", "news.sbxlab")
        # A / B : domaine distinct, bloquable
        for ident, nom in (("A", pub), ("B", track)):
            o, b = resoudre(TV_OBSERVE, nom), resoudre(TV_BLOCK, nom)
            cas[ident] = {"nom": nom, "observe": o["rcode"], "block": b["rcode"],
                          "verdict": "bloquable" if o["rcode"] == "NOERROR" and b["rcode"] == "NXDOMAIN" else "NON DÉMONTRÉ"}
        # C : la vidéo et sa publicité partagent un nom : le bloquer bloque les deux
        o, b = resoudre(TV_OBSERVE, video), resoudre(TV_BLOCK, video)
        cas["C"] = {"nom": video, "observe": o["rcode"], "block": b["rcode"],
                    "verdict": "insuffisant : bloquer le nom supprime AUSSI la vidéo" if b["rcode"] == "NXDOMAIN" and o["rcode"] == "NOERROR"
                    else "NON DÉMONTRÉ"}
        # D : publicité dans le flux : le nom n'est pas dans les listes, rien à bloquer
        b = resoudre(TV_BLOCK, flux)
        cas["D"] = {"nom": flux, "block": b["rcode"], "classe": dnstv.Classifieur(LISTES_BANC).classer(flux)[0],
                    "verdict": "insuffisant : le nom du flux est résolu même en BLOCK (aucun nom publicitaire distinct)"
                    if b["rcode"] == "NOERROR" else "NON DÉMONTRÉ"}
        # G : domaine partagé : faux positif
        o, b = resoudre(TV_OBSERVE, partage), resoudre(TV_BLOCK, partage)
        cas["G"] = {"nom": partage, "observe": o["rcode"], "block": b["rcode"],
                    "verdict": "faux positif : le contenu légitime du même domaine est bloqué" if b["rcode"] == "NXDOMAIN" else "NON DÉMONTRÉ"}
        # ISOLEMENT : le puits global de production bloque `prod.sbxlab` pour tout le LAN, SAUF pour un appareil du périmètre du POC
        g_autre, g_obs = resoudre(AUTRE, "prod.sbxlab"), resoudre(TV_OBSERVE, "prod.sbxlab")
        cas["isolement"] = {"nom": "prod.sbxlab", "client_hors_perimetre": g_autre["rcode"], "tv_observe": g_obs["rcode"],
                            "verdict": "le POC n'altère pas le puits de production pour les autres clients ; l'appareil observé en est exempté"
                            if g_autre["rcode"] == "NXDOMAIN" and g_obs["rcode"] == "NOERROR" else "NON DÉMONTRÉ"}
        # un site ordinaire n'est jamais touché
        cas["ordinaire"] = {"nom": ordinaire, "block": resoudre(TV_BLOCK, ordinaire)["rcode"]}
        # E : IP codée en dur : l'appareil n'émet AUCUNE requête DNS ; la box n'a rien à bloquer ni à voir
        avant = len(lignes_journal(banc))
        cas["E"] = {"adresse": DONNEES_AMONT[pub], "requetes_dns_emises": 0, "lignes_journal_ajoutees": len(lignes_journal(banc)) - avant,
                    "verdict": "contourné : sans requête DNS, la box ne voit ni ne bloque rien"}
        # F : DoH : l'appareil résout par un AUTRE résolveur ; la box ne le voit pas, la publicité reste résolue
        ext = resoudre(TV_DOH, pub, P_EXTERNE)
        vus = [ligne for ligne in lignes_journal(banc) if f"reply: {TV_DOH} " in ligne]
        cas["F"] = {"nom": pub, "resolu_par_externe": ext["rcode"], "requetes_vues_par_la_boite": len(vus),
                    "verdict": "contourné : la box ne voit aucune requête de cet appareil" if ext["rcode"] == "NOERROR" and not vus else "NON DÉMONTRÉ"}
        # Le journal réel d'Unbound passe dans l'analyseur du POC
        an = dnstv.Analyseur()
        evts = [e for e in (an.ligne(ligne) for ligne in lignes_journal(banc)) if e]
        cas["journal_reel"] = {"evenements": len(evts), "decisions": {d: sum(1 for e in evts if e.decision == d) for d in dnstv.DECISIONS},
                               "clients": sorted({e.client for e in evts})}
    finally:
        banc.arreter()
    return {"date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "environnement": "banc local 127.0.0.x, Unbound réel, sans Internet",
            "non_valide_sur": "flux Freebox réel", "cas": cas}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--rapport", help="écrit le rapport JSON (ex. reports/dns-limits.json)")
    a = ap.parse_args()
    rapport = executer()
    for k, v in rapport["cas"].items():
        print(f"{k:12} {v.get('verdict', json.dumps(v, ensure_ascii=False))}")
    if a.rapport:
        os.makedirs(os.path.dirname(os.path.abspath(a.rapport)), exist_ok=True)
        Path(a.rapport).write_text(json.dumps(rapport, ensure_ascii=False, indent=2))
        print("rapport :", a.rapport)
    return 0


if __name__ == "__main__":
    sys.exit(main())
