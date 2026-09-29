# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Moteur mixte : synthèse locale, reconnaissance au studio, repli local (#1649)."""
import asyncio

from api.moteur import MoteurMixte, MoteurIndisponible, construire, MODELE_ASR_DEFAUT


class Faux:
    def __init__(self, nom, echoue=False):
        self.nom, self.echoue, self.appels = nom, echoue, []
    async def dire(self, texte, voix, fmt):
        self.appels.append("dire"); return self.nom.encode()
    async def transcrire(self, audio, nom):
        self.appels.append("transcrire")
        if self.echoue:
            raise MoteurIndisponible("studio injoignable")
        return self.nom


def test_synthese_locale_reconnaissance_distante():
    l, d = Faux("local"), Faux("studio")
    m = MoteurMixte(l, d)
    assert asyncio.run(m.dire("x", "lexie-fr", "wav")) == b"local"
    assert asyncio.run(m.transcrire(b"a", "a.webm")) == "studio"
    assert d.appels == ["transcrire"] and l.appels == ["dire"]


def test_repli_local_si_studio_echoue():
    l, d = Faux("local"), Faux("studio", echoue=True)
    assert asyncio.run(MoteurMixte(l, d).transcrire(b"a", "a.webm")) == "local"


def test_construire_mixte_et_defauts():
    m = construire({"moteur": "mixte", "distant": {"url": "http://h:3900", "delai_s": 90}})
    assert isinstance(m, MoteurMixte) and m.distant.delai_s == 25
    assert str(construire({}).modele_asr) == MODELE_ASR_DEFAUT and "tiny" in MODELE_ASR_DEFAUT
