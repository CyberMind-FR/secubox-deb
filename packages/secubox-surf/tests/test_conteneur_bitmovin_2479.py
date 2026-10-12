# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2479 — article vidéo BFM : le rendu headless n'a PAS construit le `<video>` (le lecteur Bitmovin attend un geste). Il reste le conteneur
`player_bitmovin_<id>` et son image d'attente ; la page porte pourtant l'URL du manifeste dans `data-video-url`. On ranime ce conteneur à partir de cette URL —
et de celle-là seulement : jamais un autre média de la page (le direct radio du pied de page, une réclame)."""
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from surf import relais  # noqa: E402

VIDEO = ("https://edge.api.brightcove.com/playback/v1/accounts/876450610001"
         "/videos/6406126635112/master.m3u8?bcov_auth=eyJhbGci.zzz")
RADIO = "https://hls-bfmradio.nextradiotv.com/ssai/master.m3u8"

CARBONE = """<html><body><div class="video_block"><div id="player_bitmovin_6406126635112" class="bitmovin-player-container"
 data-license-key="x" data-video-id="6406126635112" data-account-id="876450610001" data-video-url="%s">
<img src="https://surf-www-bfmtv-com.gk2.secubox.in/assets/placeholder.webp" width="16" height="9" alt="placeholder video" class="bitmovin-placeholder"></div></div>
<video title="Advertisement" playsinline="true"></video>
<a href="%s">le direct</a></body></html>""" % (VIDEO.replace("&", "&amp;"), RADIO)


def _sur_hote(h):
    return relais.origine_de(h)


def _sources(html):
    return re.findall(r'data-sbx-src="([^"]+)"', html)


class ConteneurBitmovin(unittest.TestCase):
    def test_le_conteneur_mort_recoit_une_video_a_partir_de_data_video_url(self):
        out = relais.ranime_media(CARBONE, "https://www.bfmtv.com/x.html", _sur_hote)
        src = _sources(out)
        self.assertEqual(len(src), 1)
        self.assertIn("surf-edge-api-brightcove-com", src[0])            # l'URL part vers l'origine surf : jamais en direct
        self.assertIn('data-sbx-media="hls"', out)
        self.assertIn("/_sbx/hls.js", out)                               # le script d'amorce est posé

    def test_la_video_est_dans_le_conteneur_avec_l_image_d_attente_en_poster(self):
        out = relais.ranime_media(CARBONE, "https://www.bfmtv.com/x.html", _sur_hote)
        m = re.search(r'<div id="player_bitmovin_6406126635112".*?<video[^>]*poster="([^"]*)"', out, re.S)
        self.assertTrue(m and "placeholder.webp" in m.group(1))

    def test_ni_la_radio_ni_la_reclame_ne_sont_ranimees(self):
        out = relais.ranime_media(CARBONE, "https://www.bfmtv.com/x.html", _sur_hote)
        self.assertFalse(any("bfmradio" in s for s in _sources(out)))
        self.assertIn('<video title="Advertisement" playsinline="true"></video>', out)

    def test_un_conteneur_sans_url_de_media_n_est_pas_ranime(self):
        sans = CARBONE.replace(' data-video-url="%s"' % VIDEO.replace("&", "&amp;"), "")
        out = relais.ranime_media(sans, "https://www.bfmtv.com/x.html", _sur_hote)
        self.assertEqual(_sources(out), [])

    def test_une_url_non_media_dans_data_video_url_est_refusee(self):
        for mauvaise in ("javascript:alert(1)", "https://x.test/page.html", "data:text/html,x"):
            html = CARBONE.replace(VIDEO.replace("&", "&amp;"), mauvaise)
            self.assertEqual(_sources(relais.ranime_media(html, "https://www.bfmtv.com/x.html", _sur_hote)), [], mauvaise)

    def test_le_cas_historique_blob_reste_inchange(self):
        vieux = ('<html><body><video id="bitmovinplayer-video-player_bitmovin_6405413659112" src="blob:https://x/1"></video>'
                 '<a href="https://edge.api.brightcove.com/playback/v1/accounts/1/videos/6405413659112/master.m3u8?a=b">v</a></body></html>')
        out = relais.ranime_media(vieux, "https://www.bfmtv.com/x.html", _sur_hote)
        self.assertEqual(len(_sources(out)), 1)

    def test_idempotent_apres_figement(self):
        une = relais.ranime_media(CARBONE, "https://www.bfmtv.com/x.html", _sur_hote)
        self.assertEqual(len(_sources(relais.ranime_media(une, "https://www.bfmtv.com/x.html", _sur_hote))), 1)


if __name__ == "__main__":
    unittest.main()
