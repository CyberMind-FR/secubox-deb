# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3787 : un nom de régie publicitaire est découvert et mis à l'essai dès la première coupure (relevé gk7 du 17/11, pub RTL9+ OQEE)."""
from api import dnstv_detect as D, dnstv_taxonomie as T

# Chronologie réelle du Player (gk7, 17/11 14:11) : pagead2 bloqué ouvre la coupure, OQEE demande le reste dans la seconde.
EVTS = [{"ts": 100, "domaine": "pagead2.googlesyndication.com", "decision": "BLOCKED"},
        {"ts": 103, "domaine": "replay-02.oqee.net", "decision": "ALLOWED"},
        {"ts": 103, "domaine": "ads-canalplus.akamaized.net", "decision": "ALLOWED"},
        {"ts": 103, "domaine": "vizchoice.viznet.tv", "decision": "ALLOWED"},
        {"ts": 104, "domaine": "lbcdn.6cloud.fr", "decision": "ALLOWED"}]


def _detecter(evts=EVTS):
    return {c.domaine: c for c in D.detecter(evts, lambda d: d == "pagead2.googlesyndication.com", lambda d: "", set(),
                                             evts_declencheurs=evts)}


def test_mots_de_regie():
    assert T.nom_publicitaire("ads-canalplus.akamaized.net") and T.nom_publicitaire("pubads.g.doubleclick.net")
    assert T.nom_publicitaire("vast.exemple.co.uk") and not T.nom_publicitaire("ads.co.uk")
    for d in ("downloads.exemple.fr", "lbcdn.6cloud.fr", "ads.com", "ad.exemple.fr", "ssai.exemple.fr", "vizchoice.viznet.tv"):
        assert not T.nom_publicitaire(d), d


def test_une_coupure_suffit_pour_un_nom_de_regie_meme_sous_un_cdn():
    c = _detecter()
    assert "ads-canalplus.akamaized.net" in c and c["ads-canalplus.akamaized.net"].risque == "faible"
    assert "lbcdn.6cloud.fr" not in c and "vizchoice.viznet.tv" not in c and "replay-02.oqee.net" not in c


def test_nom_de_regie_vu_hors_coupure_reste_partage():
    evts = [{"ts": 1, "domaine": "ads-canalplus.akamaized.net", "decision": "ALLOWED"}] + EVTS
    assert _detecter(evts)["ads-canalplus.akamaized.net"].risque == "partage"


def test_garde_locataire_cdn_publicitaire_permis_reste_cdn_protege():
    t = T.Taxonomie.depuis_dossier()
    assert T.refus_auto(t, "ads-canalplus.akamaized.net") is None
    assert t.classer("ads-autre.akamaized.net")["source"] == "lexique"
    assert T.refus_auto(t, "video.akamaized.net") is not None          # le CDN générique reste protégé
    assert T.refus_auto(t, "ads.medias.france.tv") is not None         # jamais au-dessus du STREAMING
    assert t.classer("ads.inconnu-regie.fr")["categorie"] == "PUBLICITE"
