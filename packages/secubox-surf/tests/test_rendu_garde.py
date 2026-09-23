# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""La copie carbone doit être celle de la page demandée (#1323).

Le cas réel : le site navigue vers `gate.first-id.fr` pendant le rendu, la box
bloque la destination, Chromium rend sa page d'erreur — et c'est elle qui était
mise en cache cinq minutes sous le nom de l'article.
"""
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from surf import rendu  # noqa: E402

URL = "https://surf-www-bfmtv-com.gk2.secubox.in/meteo/article.html"
BONNE = ('<html><head><title>La météo</title></head><body>'
         '<a href="https://surf-www-bfmtv-com.gk2.secubox.in/x">suite</a>'
         + "." * 600 + "</body></html>")
PORTAIL = ('<html><head><title>gate.first-id.fr</title></head><body>'
           "Ce site est inaccessible" + "." * 600 + "</body></html>")


class Garde(unittest.TestCase):

    def _rends(self, dom, tmp):
        with mock.patch.object(rendu, "_CACHE", Path(tmp)), \
             mock.patch.object(rendu, "disponible", lambda: True), \
             mock.patch.object(rendu.subprocess, "run",
                               return_value=mock.Mock(stdout=dom)):
            return rendu.rends(URL)

    def test_une_copie_de_la_bonne_page_est_gardee(self):
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            out = self._rends(BONNE, t)
            self.assertIsNotNone(out)
            self.assertIn("La météo", out[0])
            self.assertTrue(list(Path(t).glob("*.html")), "elle doit être en cache")

    def test_une_page_d_erreur_n_est_NI_rendue_NI_cachee(self):
        """Le point qui fait mal : cachée, elle aurait tenu cinq minutes."""
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            self.assertIsNone(self._rends(PORTAIL, t))
            self.assertEqual(list(Path(t).glob("*.html")), [],
                             "une copie fausse ne doit pas entrer en cache")


if __name__ == "__main__":
    unittest.main()
