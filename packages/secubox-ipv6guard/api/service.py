# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: ipv6guard :: surveillance PASSIVE
CyberMind — https://cybermind.fr

Lit la table des voisins (instantané) et les annonces mDNS (quelques secondes : mesurées en ARRIÈRE-PLAN, mises en cache le temps du
TTL). Rien n'est envoyé aux appareils. La réponse ne contient jamais d'adresse MAC complète : un identifiant stable (empreinte) et
les trois derniers octets, de quoi reconnaître un appareil sans le désigner.
"""
import hashlib
import re
import subprocess
import threading
import time

from . import collecte, verdict as _verdict

MDNS_TTL_S = 300


def executer(argv, delai=5):
    """Exécuteur réel : jamais de shell, délai borné, texte brut de la commande."""
    p = subprocess.run(argv, capture_output=True, text=True, timeout=delai, shell=False)
    return p.stdout


def interfaces_du_reseau_local(texte_route6, texte_route4):
    """Interfaces qui portent la route par défaut : c'est là que vit le réseau local (pas les ponts de conteneurs)."""
    ifs = set()
    for t in (texte_route6 or "", texte_route4 or ""):
        for m in re.finditer(r"^default\b.*?\bdev\s+(\S+)", t, re.M):
            ifs.add(m.group(1))
    return ifs


def _public(appareil):
    """Vue publique d'un appareil : pas d'adresse MAC complète."""
    mac = appareil["mac"]
    a = {k: v for k, v in appareil.items() if k != "mac"}
    a["id"] = hashlib.sha256(mac.encode()).hexdigest()[:10]
    a["mac_fin"] = mac[-8:]
    return a


class Surveillance:
    def __init__(self, executeur=executer, ttl_mdns=MDNS_TTL_S, horloge=time.time, interfaces_lan=None):
        self.executeur = executeur
        self.ttl_mdns = ttl_mdns
        self.horloge = horloge
        self.interfaces_lan = interfaces_lan
        self._mdns = {"valeur": [], "date": 0.0, "en_cours": False}
        self._verrou = threading.Lock()

    def _mesure_mdns(self):
        try:
            texte = self.executeur(["avahi-browse", "-a", "-r", "-t", "-p"], delai=20)
            valeur = collecte.parse_mdns(texte)
        except Exception:  # noqa: BLE001 — avahi absent ou muet : on garde l'ancien résultat
            valeur = None
        with self._verrou:
            if valeur is not None:
                self._mdns["valeur"] = valeur
            self._mdns["date"] = self.horloge()          # même un échec attend le prochain délai : pas de relance en boucle
            self._mdns["en_cours"] = False

    def _declencher_mdns(self):
        with self._verrou:
            perime = (self.horloge() - self._mdns["date"]) > self.ttl_mdns
            if perime and not self._mdns["en_cours"]:
                self._mdns["en_cours"] = True
                threading.Thread(target=self._mesure_mdns, name="ipv6guard-mdns", daemon=True).start()
            return list(self._mdns["valeur"]), self._mdns["en_cours"], self._mdns["date"]

    def lecture(self, freebox=None):
        mdns, en_cours, date_mdns = self._declencher_mdns()
        v6 = collecte.parse_voisins(self.executeur(["ip", "-6", "neigh", "show"]))
        v4 = collecte.parse_voisins(self.executeur(["ip", "-4", "neigh", "show"]))
        interfaces = self.interfaces_lan
        if interfaces is None:
            interfaces = interfaces_du_reseau_local(self.executeur(["ip", "-6", "route", "show", "default"]),
                                                    self.executeur(["ip", "-4", "route", "show", "default"])) or None
        appareils = collecte.rattacher(collecte.regrouper(v6, v4, interfaces_lan=interfaces), mdns)
        publics = [_public(a) for a in appareils]
        return {
            "mesure": {"date": int(self.horloge()), "mdns_en_cours": en_cours, "mdns_date": int(date_mdns) or None,
                       "interfaces": sorted(interfaces) if interfaces else None},
            "appareils": publics,
            "etapes": _verdict.etapes(appareils, freebox),
            "verdict": _verdict.verdict(appareils, freebox),
        }
