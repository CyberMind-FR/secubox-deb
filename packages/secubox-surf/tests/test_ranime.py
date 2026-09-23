# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Ranimer le média d'une copie carbone (#1323).

Le cas qui a motivé le correctif : un article vidéo de BFMTV. La page figée
garde un `<video src="blob:…">` — le handle MediaSource du Chromium qui a rendu
la page, et qui ne désigne plus rien — plus DEUX manifestes HLS : le reportage,
et le direct radio de la chaîne posé en pied de page. Prendre « le premier »
ferait écouter la radio à la place de la vidéo.
"""
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from surf import relais  # noqa: E402

RADIO = "https://hls-bfmradio.nextradiotv.com/ssai/master.m3u8"
VIDEO = ("https://edge.api.brightcove.com/playback/v1/accounts/876450610001"
         "/videos/6405413659112/master.m3u8?bcov_auth=eyJhbGci.zzz")

CARBONE = """<html><body>
<div class="player">
<video id="bitmovinplayer-video-player_bitmovin_6405413659112"
       src="blob:https://surf-www-bfmtv-com.gk2.secubox.in/3280049a-3df6"></video>
<div class="bmpui-ui-uicontainer">decor mort</div>
</div>
<video title="Advertisement" playsinline="true"></video>
<a href="%s">le direct</a>
<span data-src="%s"></span>
</body></html>""" % (RADIO, VIDEO)


def _sur_hote(h):
    return relais.origine_de(h)


def _sources(html):
    """Les sources RÉELLEMENT posées sur un média — pas ce que la page cite
    encore par ailleurs. Sans cette distinction, un test « la radio n'apparaît
    pas » passerait ou échouerait au hasard du lien de pied de page, qui doit
    justement rester intact."""
    return re.findall(r'data-sbx-src="([^"]+)"', html)


class Ranime(unittest.TestCase):

    def test_prend_la_video_de_ce_lecteur_pas_la_radio(self):
        """L'identifiant du lecteur et l'URL du média portent le même numéro."""
        out = relais.ranime_media(CARBONE, "https://www.bfmtv.com/", _sur_hote)
        (src,) = _sources(out)
        self.assertIn("6405413659112/master.m3u8", src)
        self.assertNotIn("hls-bfmradio", src)
        # Le lien du direct, lui, reste dans la page : on ranime un lecteur,
        # on ne censure pas le reste.
        self.assertIn(RADIO, out)

    def test_la_source_passe_par_le_relais(self):
        """Ranimer en direct sortirait du relais — exactement ce qu'on refuse."""
        out = relais.ranime_media(CARBONE, "https://www.bfmtv.com/", _sur_hote)
        (src,) = _sources(out)
        self.assertTrue(src.startswith("https://surf-edge-api-brightcove-com."), src)

    def test_le_blob_perime_disparait(self):
        out = relais.ranime_media(CARBONE, "https://www.bfmtv.com/", _sur_hote)
        self.assertNotIn("blob:", out)

    def test_ne_ranime_pas_un_emplacement_publicitaire(self):
        """Le `<video>` SANS source n'a jamais rien joué : lui en donner une,
        ce serait installer une réclame là où il n'y en avait pas."""
        out = relais.ranime_media(CARBONE, "https://www.bfmtv.com/", _sur_hote)
        self.assertEqual(len(_sources(out)), 1)
        self.assertIn('<video title="Advertisement" playsinline="true">', out)

    def test_l_observation_du_rendu_prime_sur_le_dom(self):
        """Ce que le rendu a DEMANDÉ vaut mieux que ce que la page cite."""
        vu = "https://cdn.exemple.fr/vrai/6405413659112.mp4"
        out = relais.ranime_media(CARBONE, "https://www.bfmtv.com/", _sur_hote,
                                  observes=[vu])
        (src,) = _sources(out)
        self.assertIn('data-sbx-media="direct"', out)
        self.assertIn("surf-cdn-exemple-fr", src)
        self.assertNotIn("brightcove", src)

    def test_sans_media_on_ne_touche_a_rien(self):
        """Pas de candidat = pas de lecteur inventé : la page reste telle quelle."""
        nu = '<html><body><video src="blob:x"></video></body></html>'
        self.assertEqual(relais.ranime_media(nu, "https://x.fr/", _sur_hote), nu)

    def test_le_lecteur_n_est_injecte_qu_une_fois_servi(self):
        out = relais.ranime_media(CARBONE, "https://www.bfmtv.com/", _sur_hote)
        self.assertEqual(out.count("/_sbx/hls.js"), 1)
        self.assertIn("[data-sbx-media] ~ *{display:none", out)

    def test_fige_ranime_apres_avoir_retire_le_js(self):
        """L'ordre compte : notre amorce ne doit pas tomber sous le retrait."""
        out = relais.fige(CARBONE, "https://www.bfmtv.com/", _sur_hote)
        self.assertIn("/_sbx/hls.js", out)
        (src,) = _sources(out)
        self.assertIn("6405413659112/master.m3u8", src)


if __name__ == "__main__":
    unittest.main()


class Manifeste(unittest.TestCase):
    """Un manifeste cite ses pistes : servi tel quel, le lecteur les
    demanderait au vrai CDN. La page viendrait de la box, la vidéo non."""

    M3U8 = (
        "#EXTM3U\n"
        '#EXT-X-MEDIA:TYPE=AUDIO,URI="https://manifest.prod.boltdns.net/a.m3u8?t=1"\n'
        "#EXT-X-STREAM-INF:BANDWIDTH=377300\n"
        "https://manifest.prod.boltdns.net/v/rendition.m3u8?fastly_token=abc%3D%3D\n"
        "segment-relatif-0.ts\n"
    )

    def test_les_pistes_absolues_passent_par_le_relais(self):
        out = relais.reecris_manifeste(self.M3U8, "https://edge.api.brightcove.com/",
                                       _sur_hote)
        self.assertNotIn("https://manifest.prod.boltdns.net", out)
        self.assertEqual(out.count("surf-manifest-prod-boltdns-net"), 2)

    def test_le_jeton_de_la_piste_survit(self):
        """Réécrire l'hôte ne doit pas toucher la query : le jeton fastly y est."""
        out = relais.reecris_manifeste(self.M3U8, "https://edge.api.brightcove.com/",
                                       _sur_hote)
        self.assertIn("fastly_token=abc%3D%3D", out)

    def test_le_relatif_reste_relatif(self):
        """Il se résout contre le manifeste, déjà servi sur une origine surf :
        le réécrire le casserait."""
        out = relais.reecris_manifeste(self.M3U8, "https://edge.api.brightcove.com/",
                                       _sur_hote)
        self.assertIn("\nsegment-relatif-0.ts\n", out)
