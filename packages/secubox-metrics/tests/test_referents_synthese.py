# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Regroupement des référents + part de trafic direct (#1059 suite).

① « rassembler les référents » : les référents remontés en une synthèse (top).
② « % non rassemblés » : la part de visites SANS référent (accès direct), sur le
   total des visites du domaine (ou de la famille regroupée).
"""
from collections import Counter

import vhost_stats


def test_referents_synthese_top_trie_et_part_directe():
    refs = Counter({"google.com": 30, "x.com": 10})
    # 100 visites, 40 référées, donc 60 directes → 60 % d'accès direct.
    s = vhost_stats._referents_synthese(refs, sans_ref=60, visites=100)
    assert s["top"][0] == {"hote": "google.com", "n": 30}
    assert s["top"][1] == {"hote": "x.com", "n": 10}
    assert s["directs_pct"] == 60.0


def test_referents_synthese_zero_visite_ne_divise_pas_par_zero():
    s = vhost_stats._referents_synthese(Counter(), sans_ref=0, visites=0)
    assert s["directs_pct"] == 0.0
    assert s["top"] == []


def test_compter_incremente_sans_ref_pour_une_page_sans_referent():
    # Une page (non-accessoire) sans référent valide doit compter comme directe.
    ligne = ('anibal-amiot.fr 203.0.113.7 - - [19/Aug/2026:10:00:00 +0200] '
             '"GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0"')
    m = vhost_stats.LIGNE_HOTE.match(ligne)
    assert m is not None
    s = vhost_stats._vierge()
    vhost_stats._compter(s, m)
    assert s["sans_ref"] == 1
    assert sum(s["referents"].values()) == 0
