# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Le rendu ne sort que par le relais (#1609).

Le Chromium du rendu ne parle qu'aux origines surf en HTTPS sur 443 ; tout le
reste passe par un mandataire muet. Ces tests vérifient les drapeaux passés à
Chromium et le refus des URL qui ne sont pas une origine surf.
"""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from surf import relais, rendu  # noqa: E402

URL = "https://surf-www-example-com.gk2.secubox.in/article.html"
DOM = ('<html><body><a href="https://surf-www-example-com.gk2.secubox.in/x">'
       "suite</a>" + "." * 600 + "</body></html>")


class Drapeaux(unittest.TestCase):

    def _argv(self, url=URL):
        with tempfile.TemporaryDirectory() as t, \
             mock.patch.object(rendu, "_CACHE", Path(t)), \
             mock.patch.object(rendu, "disponible", lambda: True), \
             mock.patch.object(rendu.subprocess, "run",
                               return_value=mock.Mock(stdout=DOM)) as run:
            out = rendu.rends(url)
        return out, (run.call_args[0][0] if run.called else None)

    def test_chromium_recoit_le_mandataire_muet(self):
        _, argv = self._argv()
        self.assertIn("--proxy-server=" + rendu.MANDATAIRE_MUET, argv)

    def test_seule_exception_origine_surf_sur_443(self):
        _, argv = self._argv()
        bypass = [a for a in argv if a.startswith("--proxy-bypass-list=")]
        self.assertEqual(len(bypass), 1)
        regles = bypass[0].split("=", 1)[1].split(";")
        self.assertEqual(regles, ["<-loopback>",
                                  f"surf-*.{relais.SUFFIXE}:443"])

    def test_webrtc_sans_udp_direct(self):
        _, argv = self._argv()
        self.assertIn("--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                      argv)

    def test_drapeaux_avant_l_url(self):
        _, argv = self._argv()
        self.assertEqual(argv[-1], URL)
        self.assertLess(argv.index("--proxy-server=" + rendu.MANDATAIRE_MUET),
                        argv.index("--dump-dom"))

    def test_url_hors_origine_surf_non_rendue(self):
        for url in ("http://127.0.0.1/", "https://10.100.0.1/",
                    "https://[::1]/", "https://hall.gk2.secubox.in/",
                    "http://surf-www-example-com.gk2.secubox.in/",
                    "https://surf-www-example-com.gk2.secubox.in:9050/",
                    "https://surf-x.autre.gk2.secubox.in/",
                    "https://surf-x.gk2.secubox.in.exemple.org/"):
            with self.subTest(url=url):
                out, argv = self._argv(url)
                self.assertIsNone(out)
                self.assertIsNone(argv, "Chromium ne doit pas être lancé")

    def test_origine_surf_rendue(self):
        out, argv = self._argv()
        self.assertIsNotNone(out)
        self.assertIsNotNone(argv)

    def test_origine_onion_admise(self):
        onion = "https://surf-0" + "a" * 56 + ".gk2.secubox.in/"
        self.assertTrue(rendu.origine_surf(onion))


if __name__ == "__main__":
    unittest.main()
