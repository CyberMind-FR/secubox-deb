# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2030 — le studio VoiceStudio embarqué dans le Hall doit pouvoir demander le micro.

Le cadre « service embarqué » était créé avec allow="autoplay; fullscreen" pour TOUS les services, et le
Permissions-Policy du Hall n'autorisait le micro que pour lui-même et mood : « Accès au microphone
refusé » dans le studio natif. Le micro n'est délégué qu'au cadre embarqué des services qui le déclarent
(`micro_embed`), jamais à toutes les cartes ni à la console d'administration."""
import re
from pathlib import Path

PAQUET = Path(__file__).resolve().parents[1]
HALL = (PAQUET / "www" / "hall" / "index.html").read_text(encoding="utf-8")
VHOST = (PAQUET / "nginx" / "hall.vhost.conf").read_text(encoding="utf-8")


def _entree(identifiant):
    m = re.search(r'\{id:"%s",[^\n]*' % re.escape(identifiant), HALL)
    assert m, identifiant
    return m.group(0)


def test_l_entree_voicestudio_declare_le_micro_du_cadre_embarque():
    assert "micro_embed:true" in _entree("voicestudio")
    # la carte d'administration (même entrée) ne reçoit PAS le micro : micro_audio délègue aux cartes
    assert "micro_audio" not in _entree("voicestudio")


def test_le_cadre_embarque_ne_delegue_le_micro_qu_a_qui_le_declare():
    corps = HALL[HALL.index("function frameFor(mode)"):HALL.index("// ⧉ ne change pas la vue du Hall")]
    allow = re.search(r"setAttribute\('allow',(.+?)\);", corps).group(1)
    assert "microphone" in allow and "microEmbed" in allow and "mode==='embed'" in allow.replace(" ", "")
    assert "autoplay; fullscreen" in allow          # le reste est inchangé


def test_le_service_embarque_porte_le_drapeau():
    assert re.search(r"microEmbed:\s*!!\(f\s*&&\s*f\.micro_embed\)", HALL)


def test_le_permissions_policy_du_hall_autorise_l_origine_du_studio():
    assert re.search(r"map \$host \$sbx_voicestudio_du_hall", VHOST)
    # capture nommee a part : nginx refuse deux variables de meme nom dans deux map
    assert "voicestudio.$sbx_hall_dom_vs" in VHOST
    ligne = re.search(r'add_header Permissions-Policy "microphone=\(self.*\$sbx_mood_du_hall.*\), camera=\(\)" always;', VHOST)
    assert ligne and "$sbx_voicestudio_du_hall" in ligne.group(0)


# ── #2042 : les pochettes des services s'affichent dans le Hall ──────────────────────────────────────
# Les services annoncent leur vignette avec l'origine de leur PROPRE vhost (podcaster.<domaine>/…/cover) ;
# le Hall, d'origine différente, la bloquait (img-src 'self' data:). Il autorise déjà les cadres des
# sous-domaines de la box (frame-src … $sbx_cadres_box) : même source pour les images du document principal,
# sans ouvrir au monde extérieur.

def test_la_csp_du_hall_autorise_les_images_des_services_de_la_box():
    principale = next(l for l in VHOST.splitlines()
                      if "Content-Security-Policy" in l and "frame-ancestors 'none'" in l and "worker-src" in l)
    img = re.search(r"img-src ([^;]*);", principale).group(1)
    assert "$sbx_cadres_box" in img and "'self'" in img and "data:" in img
    assert "*" not in img.replace("$sbx_cadres_box", "")      # jamais de joker ouvert à l'extérieur
