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


# ── #2037 : disjoncteur — un studio qui vient d'échouer n'est pas réinterrogé tout de suite ─────────────
# Constaté : gk3 saturée, le studio met 25 s à échouer à CHAQUE requête, puis la reconnaissance locale prend
# encore ~10 s : au-delà de la coupure de 30 s de HAProxy, ZIA affiche « Voix indisponible (504) ».

class Horloge:
    def __init__(self):
        self.t = 1000.0
    def __call__(self):
        return self.t


def test_apres_un_echec_le_studio_n_est_pas_reinterroge_pendant_la_pause():
    l, d, h = Faux("local"), Faux("studio", echoue=True), Horloge()
    m = MoteurMixte(l, d, pause_s=300, horloge=h)
    assert asyncio.run(m.transcrire(b"a", "a.webm")) == "local"          # 1re requête : essai du studio, échec
    assert d.appels == ["transcrire"]
    h.t += 60
    assert asyncio.run(m.transcrire(b"a", "a.webm")) == "local"          # pendant la pause : directement en local
    assert d.appels == ["transcrire"]                                    # le studio n'a PAS été rappelé


def test_la_pause_expire_et_le_studio_est_reessaye():
    l, d, h = Faux("local"), Faux("studio", echoue=True), Horloge()
    m = MoteurMixte(l, d, pause_s=300, horloge=h)
    asyncio.run(m.transcrire(b"a", "a.webm"))
    h.t += 301
    d.echoue = False                                                    # le studio est revenu
    assert asyncio.run(m.transcrire(b"a", "a.webm")) == "studio"
    assert d.appels == ["transcrire", "transcrire"]


def test_un_succes_ne_declenche_aucune_pause():
    l, d, h = Faux("local"), Faux("studio"), Horloge()
    m = MoteurMixte(l, d, pause_s=300, horloge=h)
    asyncio.run(m.transcrire(b"a", "a.webm"))
    asyncio.run(m.transcrire(b"a", "a.webm"))
    assert d.appels == ["transcrire", "transcrire"]
