# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Lot 4 (#3374), passe 2 : I3 corrélation linéaire et incrémentale (une seule fois, dans `passage`), m3 frise sur toutes les adresses."""
import random
import time
from pathlib import Path

from api import dnstv, dnstv_auto as M, dnstv_dpi as D, dnstv_regles as R, dnstv_taxonomie as T

LISTES = Path(__file__).resolve().parents[1] / "lists"
TAXO = T.Taxonomie.depuis_dossier(LISTES)
MAC = "aa:bb:cc:00:00:01"


def cat(d):
    return TAXO.classer(d)["categorie"]


def test_correler_50000_evenements_en_moins_d_une_seconde():
    rnd = random.Random(7)
    e, ts = [], 0
    for i in range(50_000):
        ts += rnd.randint(0, 3)
        if i % 100 == 0:                                                  # 500 coupures
            e.append({"ts": ts, "domaine": "pagead2.googlesyndication.com", "decision": "BLOCKED"})
        e.append({"ts": ts, "domaine": f"d{rnd.randint(0, 3000)}.example.com", "decision": "ALLOWED"})
    cache = {}
    t0 = time.perf_counter()
    D.correler(e, lambda d: cache.setdefault(d, cat(d)))
    duree = time.perf_counter() - t0
    print(f"correler 50 000 événements : {duree:.3f} s")
    assert duree < 1.0, duree


class FauxDNS:
    def __init__(self, evts):
        self.evts, self.appels = evts, []

    def evenements(self, clients, depuis, limite=20000):
        self.appels.append(depuis)
        return [e for e in self.evts if e["client"] in clients and e["ts"] >= depuis]


def test_passage_incremental_ne_retraite_pas_les_coupures_deja_vues(tmp_path):
    now = 1_800_000_000
    evts = [{"ts": now - 300, "client": "192.168.1.50", "domaine": "pagead2.googlesyndication.com", "decision": "BLOCKED"},
            {"ts": now - 297, "client": "192.168.1.50", "domaine": "metaproxy.francetvpub.fr", "decision": "ALLOWED"},
            {"ts": now - 10, "client": "192.168.1.50", "domaine": "pagead2.googlesyndication.com", "decision": "BLOCKED"},
            {"ts": now - 5, "client": "192.168.1.50", "domaine": "audiences.free.fr", "decision": "ALLOWED"}]
    etat = {"actif": True, "clients": [{"ip": "192.168.1.50", "nom": "TV", "mode": "auto", "mac": MAC}]}
    m = D.MagasinDPI(tmp_path / "d.db")
    dns = FauxDNS(evts)
    args = dict(voisins={}, sbxdpi_texte=None, conntrack_texte=None, resolus=set(), box=set(), doh=(set(), set()))
    D.passage(etat, dns, m, cat, now, **args)
    assert [d["domaine"] for d in m.decouvertes()] == ["metaproxy.francetvpub.fr"]      # la 2e coupure n'a pas fini ses 30 s
    D.passage(etat, dns, m, cat, now + 60, **args)
    assert [d["domaine"] for d in m.decouvertes()] == ["metaproxy.francetvpub.fr", "audiences.free.fr"]
    assert dns.appels[-1] == now - 300 - D.AVANT_S                                        # ne relit que depuis la dernière coupure close
    D.passage(etat, dns, m, cat, now + 120, **args)
    assert dns.appels[-1] == now - 10 - D.AVANT_S and len(m.decouvertes()) == 2


def test_tick_ne_correle_plus_et_prend_les_replis_fournis(tmp_path):
    m = dnstv.Magasin(tmp_path / "m.db")
    r = R.Regles()
    etat = {"actif": True, "clients": [{"ip": "192.168.1.95", "nom": "TV banc", "mode": "auto", "mac": MAC}]}
    rep = {"tv-banc": [{"type": "repli", "domaine": "metaproxy.francetvpub.fr", "categorie": "PUBLICITE", "confiance": 70,
                        "raison": "apparu 3 s après le blocage de pagead2.googlesyndication.com"}]}
    M.tick(etat, r, m, lambda d: "", M.Reglage(auto_essai=True), int(time.time()), taxo=TAXO, replis=rep)
    assert {x["domaine"]: x["etat"] for x in r.liste()}["metaproxy.francetvpub.fr"] == "essai"
