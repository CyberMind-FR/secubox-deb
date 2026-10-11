# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2397 — vidéo hébergée jouée en grand dans la scène ; instant des commentaires RÉEL ou absent, jamais un faux instant."""
from pathlib import Path

A = Path(__file__).resolve().parents[1] / "api"
VUE = (A / "static/vue.js").read_text(encoding="utf-8")
IMM = (A / "static/immersif.js").read_text(encoding="utf-8")
TPL = (A / "templates/billet.html").read_text(encoding="utf-8")


def test_la_scene_porte_l_url_de_la_video_hebergee_et_un_play():
    assert 'data-video="/media/{{ hosted.filename }}"' in TPL
    assert "'▶' if (billet.embed_is_video or hosted)" in TPL
    assert "m.mime.startswith('video/')" in TPL


def test_le_clic_joue_la_video_dans_la_scene_et_suit_lecture_et_pause():
    assert "scene.dataset.video" in VUE and 'document.createElement("video")' in VUE
    for ev in ('"play"', '"pause"', '"ended"'):
        assert f"hv.addEventListener({ev}" in VUE


def test_la_position_d_une_video_hebergee_est_son_currentTime():
    assert "if (hv) return hv.currentTime;" in VUE


def test_youtube_donne_sa_position_reelle_par_l_api_postmessage():
    for src in (VUE, IMM):
        assert "enablejsapi=1" in src and '"infoDelivery"' in src and 'event: "listening"' in src
        assert "e.source" in src                      # on n'écoute que l'iframe du lecteur


def test_l_estimation_est_bornee_et_un_instant_inconnu_n_est_jamais_envoye():
    for src in (VUE, IMM):
        assert "MAX_EST = 3 * 3600" in src and "isFinite(" in src
    assert "if (vt !== null && vt >= 0 && vt <= 86400) fd.append" in IMM
    assert 'champT.value = pv !== null ? String(pv) : ""' in VUE
    # plus de position écrite en mémoire locale sans garde (NaN)
    assert "LS.set(\"bpos:\" + playing.dataset.id, Math.max(0, Math.floor(t)))" not in IMM
