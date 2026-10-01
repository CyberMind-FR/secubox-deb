# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Le relais ne transmet à l'amont que les cookies du site relayé (#1798)."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from surf import jarre  # noqa: E402


class CookiesDeLaBox(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        self._sauve = (jarre.CHEMIN, jarre.CHEMIN_ETAT, jarre._charge)
        jarre.CHEMIN, jarre.CHEMIN_ETAT = d / "jarre.json", d / "etat.json"
        jarre._jarre.clear(); jarre._etat.clear(); jarre._charge = False

    def tearDown(self):
        jarre.CHEMIN, jarre.CHEMIN_ETAT, jarre._charge = self._sauve
        jarre._jarre.clear(); jarre._etat.clear()
        self.tmp.cleanup()

    def test_navigateur_cookies_de_la_box_retires(self):
        h = jarre.entete("www.lemonde.fr",
                         "secubox_session=JWT.faux.x; sbx_bbs=b; sbx-tableau=1; "
                         "SECUBOX_TOKEN=t; consent=oui; lmd_a_s=abc")
        noms = {c.split("=", 1)[0] for c in h.split("; ") if c}
        self.assertEqual(noms, {"consent", "lmd_a_s"})
        self.assertNotIn("JWT.faux", h)

    def test_amont_ne_peut_pas_faire_apprendre_un_cookie_de_la_box(self):
        jarre.apprend("www.lemonde.fr", ["secubox_session=piege; Path=/", "panier=1; Path=/"])
        self.assertEqual(jarre.entete("www.lemonde.fr"), "panier=1")

    def test_semis_manuel_ignore_les_cookies_de_la_box(self):
        n = jarre.pose_manuel("www.lemonde.fr", {"secubox_session": "x", "consent": "oui"})
        self.assertEqual(n, 1)
        self.assertEqual(jarre.entete("www.lemonde.fr"), "consent=oui")

    def test_le_serveur_passe_par_le_filtre(self):
        src = (Path(__file__).resolve().parents[1] / "surf" / "serveur.py").read_text()
        self.assertIn('jarre.entete(cible, entetes_in.get("cookie", ""))', src)
        self.assertEqual(src.count('entetes_req["Cookie"]'), 1,
                         "un seul chemin construit le Cookie amont, et il passe par jarre.entete")


if __name__ == "__main__":
    unittest.main()
