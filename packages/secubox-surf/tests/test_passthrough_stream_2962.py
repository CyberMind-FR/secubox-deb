# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Le passthrough brut (images, polices, médias) se diffuse par morceaux,
jamais bufferisé entier en RAM (#2962).

Constat gk2 (2026-10-19) : `corps = r.content` chargeait un média relayé tel
quel ENTIER en mémoire avant de répondre — un flux vidéo complet proxié par
surf (ex. diffusion au parc) pouvait peser plusieurs centaines de Mo par
requête. Le service a tourné 2 jours, pic mémoire 3.2G + swap 4.9G, charge
système 25+, causant des timeouts en cascade ailleurs sur la box (dont le SSO
mail, via l'agrégateur saturé).
"""
import asyncio
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("SECUBOX_TOR_SOCKS", "127.0.0.1:9050")   # pas de sonde
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_egress_sortie import (  # noqa: E402
    PUBLIQUE, Base, FauxReseau, _client_async, _reponse,
)


class Passthrough(Base):
    """`serveur.app` de bout en bout, sur la couche réseau factice."""

    def _appel(self, chemin, reponse_amont):
        from surf import serveur
        reseau = FauxReseau({PUBLIQUE: reponse_amont})
        envoye = []

        async def recoit():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def envoie(msg):
            envoye.append(msg)

        async def go():
            serveur._clients["direct"] = _client_async(reseau)
            try:
                await serveur.app(scope, recoit, envoie)
            finally:
                await serveur._clients.pop("direct").aclose()

        scope = {"type": "http", "method": "GET", "path": chemin,
                 "raw_path": chemin.encode(), "query_string": b"",
                 "headers": [(b"host", b"surf-exemple-test.gk2.secubox.in")]}
        with mock.patch.object(serveur.jarre, "entete", lambda *a: ""):
            asyncio.run(go())
        return envoye

    def test_image_non_reecrite_diffusee_en_morceaux(self):
        gros = b"\x89PNG" + (b"x" * 40000)   # assez gros pour ne pas passer
                                              # inaperçu si bufferisé entier
        reponse = _reponse(200, [("content-type", "image/png")], gros)
        envoye = self._appel("/i.png", reponse)

        self.assertEqual(envoye[0]["status"], 200)
        corps = [m for m in envoye if m["type"] == "http.response.body"]
        # PASSTHROUGH = `repond_stream` (#2962) : un dernier message vide
        # marqué `more_body: False` termine la réponse — jamais un seul
        # message complet sans ce marqueur, comme le faisait `repond` avec
        # `corps = r.content` avant correctif.
        self.assertIn("more_body", corps[-1])
        self.assertFalse(corps[-1]["more_body"])
        self.assertEqual(b"".join(m["body"] for m in corps), gros)

    def test_html_reste_bufferise_dun_seul_bloc(self):
        # Un HTML est RÉÉCRIT (cookies/liens réinjectés) : il doit rester lu
        # entier avant de répondre — `repond`, un seul message, sans
        # `more_body`. Le confirmer évite qu'un futur changement fasse
        # glisser accidentellement la réécriture vers le flux.
        html = b"<html><body>bonjour</body></html>"
        reponse = _reponse(200, [("content-type", "text/html; charset=utf-8")],
                            html)
        envoye = self._appel("/page.html", reponse)

        self.assertEqual(envoye[0]["status"], 200)
        corps = [m for m in envoye if m["type"] == "http.response.body"]
        self.assertEqual(len(corps), 1)
        self.assertNotIn("more_body", corps[0])


if __name__ == "__main__":
    unittest.main()
